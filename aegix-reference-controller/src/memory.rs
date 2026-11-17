//! Actor memory, held in memory, and the one function that runs a worker's
//! memory op against it.
//!
//! A read is served to a request that passed admission and the
//! dispatch-binding gate (both in [`crate::data_plane`]). A mutation is also
//! put to the actor's write ceiling here, immediately before the store is
//! touched, with the worker's own audit name for the op. What the operator
//! writes over the control socket ([`MemoryStore::put`]) is outside the
//! ceiling: the ceiling bounds what a MODULE may write to its actor.
//!
//! Not kept: embeddings, an entity graph, encryption at rest (nothing is at
//! rest). `search` is a case-insensitive substring match and says so in its
//! `method`.

use crate::counters::{Decision, Refusals};
use aegix_rpc_gates::write_ceiling::{
    self, CeilingDecision, AGENT_MEMORY_DELETE_OP, AGENT_MEMORY_STORE_WITH_EMBEDDING_OP,
};
use aegix_rpc_gates::GateLedger;
use aegix_rpc_protocol::memory_rpc::{
    MemoryHit, MemoryOp, MemoryOpResult, MemoryRpcError, MAX_EXCLUDE_KINDS, MAX_EXCLUDE_KIND_LEN,
    MAX_PREFIX_LEN, MAX_RESULT_LIMIT, MAX_SEARCH_QUERY_LEN, SUBJECT_MEMORY_OP,
};
use aegix_rpc_protocol::{
    is_valid_memory_type, validate_memory_key, MAX_METADATA_BYTES, MAX_TTL_HOURS, MAX_VALUE_BYTES,
};
use aegix_workflow_engine_core::AGENT_MEMORY_SET_OP;
use std::collections::{BTreeMap, HashMap};
use std::sync::Mutex;
use uuid::Uuid;

/// Keys one actor may hold. A write that would add a key beyond it is
/// `StorageFull`.
pub const MAX_KEYS_PER_ACTOR: usize = 10_000;

/// The expiry a write gets when it names none and is not `semantic`
/// (a `semantic` write with no TTL never expires).
pub const DEFAULT_TTL_HOURS: f64 = 168.0;

/// What `search` reports as its method: there is no embedding here.
pub const SEARCH_METHOD: &str = "keyword";

#[derive(Debug, Clone, PartialEq)]
struct Entry {
    value: serde_json::Value,
    memory_type: String,
    metadata: Option<serde_json::Value>,
    created_at_unix: u64,
    expires_at_unix: Option<u64>,
}

impl Entry {
    fn live_at(&self, now_unix: u64) -> bool {
        self.expires_at_unix.is_none_or(|at| at > now_unix)
    }

    fn kind(&self) -> Option<&str> {
        self.metadata.as_ref()?.get("kind")?.as_str()
    }
}

/// Seconds since the Unix epoch.
#[must_use]
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// When a write made at `now_unix` expires. `Err` is the caller-facing
/// reason a TTL is refused.
fn expiry(
    memory_type: &str,
    ttl_hours: Option<f64>,
    now_unix: u64,
) -> Result<Option<u64>, &'static str> {
    let hours = match ttl_hours {
        Some(h) if !h.is_finite() || h <= 0.0 => return Err("ttl_hours must be a positive number"),
        Some(h) if h > MAX_TTL_HOURS => return Err("ttl_hours is above the maximum"),
        Some(h) => h,
        None if memory_type == "semantic" => return Ok(None),
        None => DEFAULT_TTL_HOURS,
    };
    // `hours` is finite, positive and at most MAX_TTL_HOURS (ten years), so
    // the product fits u64 with room to spare.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let secs = (hours * 3600.0).ceil() as u64;
    Ok(Some(now_unix.saturating_add(secs)))
}

/// Every actor's memory.
#[derive(Debug, Default)]
pub struct MemoryStore {
    actors: Mutex<HashMap<Uuid, BTreeMap<String, Entry>>>,
}

/// Why a write was not stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PutError {
    Invalid(String),
    Full,
}

impl std::fmt::Display for PutError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(why) => write!(f, "{why}"),
            Self::Full => write!(f, "the actor already holds {MAX_KEYS_PER_ACTOR} keys"),
        }
    }
}

impl MemoryStore {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, BTreeMap<String, Entry>>> {
        self.actors.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Store one value. The checks every write passes, whoever makes it: the
    /// key rule, the memory type, the value's and metadata's size, the TTL
    /// and the actor's key count. The write ceiling is NOT here: it is asked
    /// in [`execute`], of a module's write only.
    pub fn put(
        &self,
        actor_id: Uuid,
        key: &str,
        value: serde_json::Value,
        memory_type: &str,
        ttl_hours: Option<f64>,
        metadata: Option<serde_json::Value>,
        now_unix: u64,
    ) -> Result<(), PutError> {
        let key = validate_memory_key(key).map_err(|why| PutError::Invalid(why.to_string()))?;
        if !is_valid_memory_type(memory_type) {
            return Err(PutError::Invalid(format!(
                "memory_type must be one of {}",
                aegix_rpc_protocol::MEMORY_TYPES.join(", ")
            )));
        }
        let value_len = serde_json::to_vec(&value).map_or(usize::MAX, |v| v.len());
        if value_len > MAX_VALUE_BYTES {
            return Err(PutError::Invalid(format!(
                "value is larger than {MAX_VALUE_BYTES} bytes"
            )));
        }
        // Metadata that is not an object is ignored, as the platform does.
        let metadata = metadata.filter(serde_json::Value::is_object);
        if let Some(meta) = &metadata {
            if serde_json::to_vec(meta).map_or(usize::MAX, |v| v.len()) > MAX_METADATA_BYTES {
                return Err(PutError::Invalid(format!(
                    "metadata is larger than {MAX_METADATA_BYTES} bytes"
                )));
            }
        }
        let expires_at_unix = expiry(memory_type, ttl_hours, now_unix)
            .map_err(|why| PutError::Invalid(why.into()))?;

        let mut actors = self.lock();
        let entries = actors.entry(actor_id).or_default();
        // Expired rows do not count against the actor: drop them first.
        entries.retain(|_, e| e.live_at(now_unix));
        let created_at_unix = match entries.get(key) {
            Some(existing) => existing.created_at_unix,
            None if entries.len() >= MAX_KEYS_PER_ACTOR => return Err(PutError::Full),
            None => now_unix,
        };
        entries.insert(
            key.to_string(),
            Entry {
                value,
                memory_type: memory_type.to_string(),
                metadata,
                created_at_unix,
                expires_at_unix,
            },
        );
        Ok(())
    }

    /// Remove one key. `true` when it was held.
    pub fn remove(&self, actor_id: Uuid, key: &str) -> bool {
        self.lock()
            .get_mut(&actor_id)
            .is_some_and(|entries| entries.remove(key.trim()).is_some())
    }

    fn get(&self, actor_id: Uuid, key: &str, now_unix: u64) -> Option<Entry> {
        self.lock()
            .get(&actor_id)?
            .get(key)
            .filter(|e| e.live_at(now_unix))
            .cloned()
    }

    /// The actor's live keys, in order, that start with `prefix`.
    #[must_use]
    pub fn keys(&self, actor_id: Uuid, prefix: &str, limit: usize, now_unix: u64) -> Vec<String> {
        self.lock()
            .get(&actor_id)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(k, e)| k.starts_with(prefix) && e.live_at(now_unix))
                    .map(|(k, _)| k.clone())
                    .take(limit)
                    .collect()
            })
            .unwrap_or_default()
    }

    fn search(
        &self,
        actor_id: Uuid,
        query: &str,
        limit: usize,
        exclude_kinds: &[String],
        now_unix: u64,
    ) -> Vec<MemoryHit> {
        let needle = query.to_lowercase();
        self.lock()
            .get(&actor_id)
            .map(|entries| {
                entries
                    .iter()
                    .filter(|(_, e)| e.live_at(now_unix))
                    // A scratchpad row is bookkeeping, read by key only.
                    .filter(|(_, e)| e.memory_type != "scratchpad")
                    .filter(|(_, e)| {
                        e.kind()
                            .is_none_or(|kind| !exclude_kinds.iter().any(|x| x == kind))
                    })
                    .filter_map(|(key, e)| {
                        let value = e.value.to_string();
                        (key.to_lowercase().contains(&needle)
                            || value.to_lowercase().contains(&needle))
                        .then(|| MemoryHit {
                            key: key.clone(),
                            value,
                            score: 1.0,
                            metadata: e.metadata.as_ref().map(ToString::to_string),
                        })
                    })
                    .take(limit)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Ask the actor's write ceiling about one mutation, and count a refusal.
async fn ceiling_permits<L: GateLedger + Sync>(
    ledger: &L,
    refusals: &Refusals,
    actor_id: Uuid,
    op: &'static str,
    key: &str,
) -> bool {
    // `enforced` is not a setting here: this controller always enforces.
    // allow-forked-sql-classifier: this gate is reached by a memory set and a
    // memory delete only. This controller answers `talos.database.query` "not
    // available" and classifies no SQL (structural check 85).
    match write_ceiling::gate(ledger, true, actor_id, op, SUBJECT_MEMORY_OP, key).await {
        CeilingDecision::Permit => true,
        CeilingDecision::Refuse(reason) => {
            refusals.count(
                Decision::WriteCeiling,
                SUBJECT_MEMORY_OP,
                reason.metric_label(),
            );
            false
        }
    }
}

/// Run one memory op for `actor_id`.
///
/// The caller has admitted the request and passed the dispatch-binding gate:
/// `actor_id` is the SIGNED actor and never anything the op carries. Each
/// mutation asks the write ceiling after its key is validated and before the
/// store changes.
pub async fn execute<L: GateLedger + Sync>(
    store: &MemoryStore,
    ledger: &L,
    refusals: &Refusals,
    actor_id: Uuid,
    op: MemoryOp,
) -> Result<MemoryOpResult, MemoryRpcError> {
    let now = now_unix();
    let invalid = |why: &str| MemoryRpcError::InvalidInput(why.to_string());
    match op {
        MemoryOp::Get { key } => {
            let key = validate_memory_key(&key).map_err(invalid)?;
            let entry = store
                .get(actor_id, key, now)
                .ok_or(MemoryRpcError::KeyNotFound)?;
            Ok(MemoryOpResult::GetValue {
                value: entry.value.to_string(),
                created_at_unix: Some(entry.created_at_unix),
                expires_at_unix: entry.expires_at_unix,
                memory_type: Some(entry.memory_type),
            })
        }
        MemoryOp::Set {
            key,
            value,
            memory_type,
            ttl_hours,
            metadata,
        } => {
            let key = validate_memory_key(&key).map_err(invalid)?;
            let op_label = if memory_type == "semantic" {
                AGENT_MEMORY_STORE_WITH_EMBEDDING_OP
            } else {
                AGENT_MEMORY_SET_OP
            };
            if !ceiling_permits(ledger, refusals, actor_id, op_label, key).await {
                return Err(MemoryRpcError::WriteCeiling);
            }
            store
                .put(actor_id, key, value, &memory_type, ttl_hours, metadata, now)
                .map_err(|e| match e {
                    PutError::Invalid(why) => MemoryRpcError::InvalidInput(why),
                    PutError::Full => MemoryRpcError::StorageFull,
                })?;
            Ok(MemoryOpResult::Ok)
        }
        MemoryOp::Delete { key } => {
            let key = validate_memory_key(&key).map_err(invalid)?;
            if !ceiling_permits(ledger, refusals, actor_id, AGENT_MEMORY_DELETE_OP, key).await {
                return Err(MemoryRpcError::WriteCeiling);
            }
            store.remove(actor_id, key);
            Ok(MemoryOpResult::Ok)
        }
        MemoryOp::ListKeys { prefix } => {
            let prefix = prefix.unwrap_or_default();
            if prefix.chars().count() > MAX_PREFIX_LEN {
                return Err(invalid("prefix is too long"));
            }
            Ok(MemoryOpResult::Keys {
                keys: store.keys(actor_id, &prefix, MAX_RESULT_LIMIT as usize, now),
            })
        }
        MemoryOp::Search {
            query,
            limit,
            exclude_kinds,
            ..
        } => {
            if query.trim().is_empty() {
                return Err(invalid("query is empty"));
            }
            if query.len() > MAX_SEARCH_QUERY_LEN {
                return Err(invalid("query is too long"));
            }
            if exclude_kinds.len() > MAX_EXCLUDE_KINDS
                || exclude_kinds.iter().any(|k| k.len() > MAX_EXCLUDE_KIND_LEN)
            {
                return Err(invalid("exclude_kinds is too long"));
            }
            let limit = limit.clamp(1, MAX_RESULT_LIMIT) as usize;
            Ok(MemoryOpResult::SearchHits {
                hits: store.search(actor_id, query.trim(), limit, &exclude_kinds, now),
                method: SEARCH_METHOD.to_string(),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::testing::actor;
    use crate::ledger::Ledger;
    use aegix_workflow_engine_core::WriteCeiling;
    use serde_json::json;

    struct Fixture {
        store: MemoryStore,
        ledger: Ledger,
        refusals: Refusals,
        writable: Uuid,
        read_only: Uuid,
    }

    fn fixture() -> Fixture {
        let ledger = Ledger::default();
        let writable = actor("rw", WriteCeiling::Write);
        let read_only = actor("ro", WriteCeiling::ReadOnly);
        ledger.put_actor(writable.clone());
        ledger.put_actor(read_only.clone());
        Fixture {
            store: MemoryStore::default(),
            ledger,
            refusals: Refusals::default(),
            writable: writable.id,
            read_only: read_only.id,
        }
    }

    impl Fixture {
        async fn run(&self, actor: Uuid, op: MemoryOp) -> Result<MemoryOpResult, MemoryRpcError> {
            execute(&self.store, &self.ledger, &self.refusals, actor, op).await
        }
        fn ceiling_refusals(&self, reason: &str) -> u64 {
            self.refusals
                .get(Decision::WriteCeiling, SUBJECT_MEMORY_OP, reason)
        }
    }

    fn set(key: &str, value: serde_json::Value) -> MemoryOp {
        MemoryOp::Set {
            key: key.to_string(),
            value,
            memory_type: "episodic".to_string(),
            ttl_hours: None,
            metadata: None,
        }
    }

    fn get(key: &str) -> MemoryOp {
        MemoryOp::Get {
            key: key.to_string(),
        }
    }

    #[tokio::test]
    async fn a_writable_actor_reads_back_what_it_wrote_as_json_text() {
        let f = fixture();
        assert!(matches!(
            f.run(f.writable, set("notes/a", json!({"n": 1}))).await,
            Ok(MemoryOpResult::Ok)
        ));
        match f.run(f.writable, get("notes/a")).await {
            Ok(MemoryOpResult::GetValue {
                value,
                memory_type,
                created_at_unix,
                expires_at_unix,
            }) => {
                assert_eq!(value, r#"{"n":1}"#);
                assert_eq!(memory_type.as_deref(), Some("episodic"));
                let created = created_at_unix.expect("created");
                assert_eq!(expires_at_unix, Some(created + 168 * 3600));
            }
            other => panic!("expected the value, got {other:?}"),
        }
        assert_eq!(f.ceiling_refusals("policy"), 0);
    }

    #[tokio::test]
    async fn a_read_only_actor_writes_and_deletes_nothing_and_each_refusal_is_counted() {
        let f = fixture();
        // The operator leaves a value; the module may read it.
        f.store
            .put(
                f.read_only,
                "demo/readable",
                json!("left"),
                "working",
                None,
                None,
                now_unix(),
            )
            .unwrap();
        assert!(matches!(
            f.run(f.read_only, get("demo/readable")).await,
            Ok(MemoryOpResult::GetValue { .. })
        ));

        assert_eq!(
            f.run(f.read_only, set("demo/x", json!(1)))
                .await
                .unwrap_err(),
            MemoryRpcError::WriteCeiling
        );
        assert_eq!(f.ceiling_refusals("policy"), 1);
        assert_eq!(
            f.run(f.read_only, get("demo/x")).await.unwrap_err(),
            MemoryRpcError::KeyNotFound,
            "a refused write stored nothing"
        );

        let semantic = MemoryOp::Set {
            key: "demo/y".to_string(),
            value: json!("v"),
            memory_type: "semantic".to_string(),
            ttl_hours: None,
            metadata: None,
        };
        assert_eq!(
            f.run(f.read_only, semantic).await.unwrap_err(),
            MemoryRpcError::WriteCeiling
        );
        assert_eq!(
            f.run(
                f.read_only,
                MemoryOp::Delete {
                    key: "demo/readable".to_string()
                }
            )
            .await
            .unwrap_err(),
            MemoryRpcError::WriteCeiling
        );
        assert_eq!(f.ceiling_refusals("policy"), 3);
        assert!(
            matches!(
                f.run(f.read_only, get("demo/readable")).await,
                Ok(MemoryOpResult::GetValue { .. })
            ),
            "a refused delete removed nothing"
        );
    }

    #[tokio::test]
    async fn an_actor_the_ledger_does_not_hold_is_refused_as_unreadable() {
        let f = fixture();
        let stranger = Uuid::new_v4();
        assert_eq!(
            f.run(stranger, set("k", json!(1))).await.unwrap_err(),
            MemoryRpcError::WriteCeiling
        );
        assert_eq!(f.ceiling_refusals("unreadable"), 1);
        assert_eq!(f.ceiling_refusals("policy"), 0);
    }

    #[tokio::test]
    async fn one_actor_never_reads_lists_or_finds_anothers_memory() {
        let f = fixture();
        f.run(f.writable, set("shared/name", json!("mine")))
            .await
            .unwrap();
        assert_eq!(
            f.run(f.read_only, get("shared/name")).await.unwrap_err(),
            MemoryRpcError::KeyNotFound
        );
        assert!(matches!(
            f.run(f.read_only, MemoryOp::ListKeys { prefix: None }).await,
            Ok(MemoryOpResult::Keys { keys }) if keys.is_empty()
        ));
        let search = MemoryOp::Search {
            query: "mine".to_string(),
            limit: 10,
            min_score: 0.0,
            exclude_kinds: Vec::new(),
        };
        assert!(matches!(
            f.run(f.read_only, search).await,
            Ok(MemoryOpResult::SearchHits { hits, .. }) if hits.is_empty()
        ));
    }

    #[tokio::test]
    async fn a_bad_key_is_invalid_before_the_ceiling_is_asked() {
        let f = fixture();
        for op in [
            set("   ", json!(1)),
            get(""),
            MemoryOp::Delete { key: String::new() },
        ] {
            assert!(matches!(
                f.run(f.read_only, op).await,
                Err(MemoryRpcError::InvalidInput(_))
            ));
        }
        assert_eq!(f.ceiling_refusals("policy"), 0);
    }

    #[tokio::test]
    async fn a_write_is_held_to_its_type_size_ttl_and_the_actors_key_count() {
        let f = fixture();
        let bad_type = MemoryOp::Set {
            key: "k".to_string(),
            value: json!(1),
            memory_type: "forever".to_string(),
            ttl_hours: None,
            metadata: None,
        };
        assert!(matches!(
            f.run(f.writable, bad_type).await,
            Err(MemoryRpcError::InvalidInput(_))
        ));
        let too_large = set("k", json!("x".repeat(MAX_VALUE_BYTES + 1)));
        assert!(matches!(
            f.run(f.writable, too_large).await,
            Err(MemoryRpcError::InvalidInput(_))
        ));
        for ttl in [0.0, -1.0, f64::NAN, f64::INFINITY, MAX_TTL_HOURS + 1.0] {
            let op = MemoryOp::Set {
                key: "k".to_string(),
                value: json!(1),
                memory_type: "episodic".to_string(),
                ttl_hours: Some(ttl),
                metadata: None,
            };
            assert!(
                matches!(
                    f.run(f.writable, op).await,
                    Err(MemoryRpcError::InvalidInput(_))
                ),
                "ttl_hours {ttl} must be refused"
            );
        }

        let now = now_unix();
        for i in 0..MAX_KEYS_PER_ACTOR {
            f.store
                .put(
                    f.writable,
                    &format!("k/{i}"),
                    json!(i),
                    "working",
                    None,
                    None,
                    now,
                )
                .unwrap();
        }
        assert_eq!(
            f.run(f.writable, set("one/more", json!(1)))
                .await
                .unwrap_err(),
            MemoryRpcError::StorageFull
        );
        // Replacing a held key is not a new key.
        assert!(f.run(f.writable, set("k/0", json!("again"))).await.is_ok());
    }

    #[test]
    fn a_value_expires_and_an_expired_value_is_not_read_listed_or_counted() {
        let store = MemoryStore::default();
        let actor = Uuid::new_v4();
        store
            .put(actor, "short", json!(1), "working", Some(1.0), None, 1_000)
            .unwrap();
        store
            .put(actor, "kept", json!(2), "semantic", None, None, 1_000)
            .unwrap();
        assert!(store.get(actor, "short", 1_000 + 3599).is_some());
        assert!(store.get(actor, "short", 1_000 + 3600).is_none());
        assert!(
            store.get(actor, "kept", u64::MAX - 1).is_some(),
            "a semantic write with no TTL never expires"
        );
        assert_eq!(store.keys(actor, "", 10, 1_000 + 3600), vec!["kept"]);
        assert_eq!(expiry("episodic", None, 0), Ok(Some(168 * 3600)));
        assert_eq!(expiry("semantic", Some(2.0), 10), Ok(Some(10 + 7200)));
    }

    #[tokio::test]
    async fn search_matches_text_skips_excluded_kinds_and_scratchpad_and_names_its_method() {
        let f = fixture();
        let now = now_unix();
        let put = |key: &str, value: serde_json::Value, ty: &str, kind: Option<&str>| {
            f.store
                .put(
                    f.writable,
                    key,
                    value,
                    ty,
                    None,
                    kind.map(|k| json!({"kind": k})),
                    now,
                )
                .unwrap();
        };
        put(
            "meeting/monday",
            json!("Budget review with Ana"),
            "episodic",
            None,
        );
        put(
            "brief/monday",
            json!("budget summary"),
            "episodic",
            Some("daily_brief"),
        );
        put("count/budget", json!(3), "scratchpad", None);
        put("other", json!("unrelated"), "episodic", None);

        let search = |exclude: Vec<String>| MemoryOp::Search {
            query: "BUDGET".to_string(),
            limit: 0,
            min_score: 0.3,
            exclude_kinds: exclude,
        };
        match f.run(f.writable, search(Vec::new())).await.unwrap() {
            MemoryOpResult::SearchHits { hits, method } => {
                assert_eq!(method, SEARCH_METHOD);
                assert_eq!(hits.len(), 1, "limit 0 is clamped to 1");
            }
            other => panic!("{other:?}"),
        }
        let all = MemoryOp::Search {
            query: "budget".to_string(),
            limit: 50,
            min_score: 0.3,
            exclude_kinds: vec!["daily_brief".to_string()],
        };
        match f.run(f.writable, all).await.unwrap() {
            MemoryOpResult::SearchHits { hits, .. } => {
                let keys: Vec<&str> = hits.iter().map(|h| h.key.as_str()).collect();
                assert_eq!(keys, vec!["meeting/monday"]);
                assert_eq!(hits[0].value, r#""Budget review with Ana""#);
            }
            other => panic!("{other:?}"),
        }
        let empty = MemoryOp::Search {
            query: "  ".to_string(),
            limit: 5,
            min_score: 0.0,
            exclude_kinds: Vec::new(),
        };
        assert!(matches!(
            f.run(f.writable, empty).await,
            Err(MemoryRpcError::InvalidInput(_))
        ));
    }

    #[tokio::test]
    async fn list_keys_is_ordered_prefixed_and_capped() {
        let f = fixture();
        let now = now_unix();
        for key in ["b/2", "a/1", "b/1", "c"] {
            f.store
                .put(f.writable, key, json!(1), "working", None, None, now)
                .unwrap();
        }
        let list = |prefix: Option<&str>| MemoryOp::ListKeys {
            prefix: prefix.map(str::to_string),
        };
        assert!(matches!(
            f.run(f.writable, list(Some("b/"))).await,
            Ok(MemoryOpResult::Keys { keys }) if keys == ["b/1", "b/2"]
        ));
        assert!(matches!(
            f.run(f.writable, list(None)).await,
            Ok(MemoryOpResult::Keys { keys }) if keys == ["a/1", "b/1", "b/2", "c"]
        ));
        assert!(matches!(
            f.run(f.writable, list(Some(&"p".repeat(MAX_PREFIX_LEN + 1))))
                .await,
            Err(MemoryRpcError::InvalidInput(_))
        ));
    }

    /// The op names this controller puts to the ceiling are the names the
    /// worker's own gate uses for the same host calls, and each is one the
    /// gates crate lists as controller-served.
    #[test]
    fn the_ops_gated_here_are_the_workers_ops() {
        let worker_ops = aegix_capability_world::write_gated_ops_str("agent-node");
        for op in [
            AGENT_MEMORY_SET_OP,
            AGENT_MEMORY_STORE_WITH_EMBEDDING_OP,
            AGENT_MEMORY_DELETE_OP,
        ] {
            assert!(worker_ops.contains(&op), "the worker does not gate {op}");
            assert!(
                write_ceiling::CONTROLLER_SERVED_WRITE_OPS
                    .iter()
                    .any(|(served, subject)| *subject == SUBJECT_MEMORY_OP && *served == op),
                "{op} is not listed as controller-served on {SUBJECT_MEMORY_OP}"
            );
        }
    }
}
