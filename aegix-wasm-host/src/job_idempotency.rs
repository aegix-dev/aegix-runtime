//! Worker-side `job_id` idempotency cache (FU-2 / review finding R2-5).
//!
//! ## The problem
//!
//! The controller's NATS dispatcher retries a job on a **transport delivery
//! error** (`Ok(Err(..))` from `request`), re-signing the payload with a FRESH
//! `job_nonce` (so the worker's replay-nonce cache can't reject it — see
//! `dispatcher::resign_payload_for_retry`). The `job_id` is preserved across the
//! retry. Without idempotency here, a transport error that occurs AFTER the
//! worker already executed (the module ran and produced side effects, but the
//! reply was lost on the wire) causes the retry to **re-execute the module** —
//! a double side effect (double HTTP POST / webhook / DB write).
//!
//! ## What the dispatcher retries — and what this cache must therefore hold
//!
//! The dispatcher retries on TWO conditions, both under the SAME `job_id`
//! (`dispatcher::execute_job_with_retry`): a **transport error**, and an
//! **application-level failure** — `JobStatus::Failed`, or `Success` whose
//! payload carries `success: false` (the `database-query` shape). It does NOT
//! retry a timeout. Each retry re-signs with a fresh nonce and bumps
//! `JobRequest::dispatch_attempt`.
//!
//! That second condition is why this cache holds **only terminal successes**
//! (`JobResult::is_terminal_success`, the dispatcher's own predicate, ONE
//! home in the protocol crate). An application-failure retry is the
//! controller asking for a FRESH RUN: until 2026-09-10 the cache stored every
//! terminal result, so the retry found the first attempt's `Failed` result
//! and re-published it verbatim — every engine retry was a no-op replay of
//! one transient failure, and the whole retry budget was spent re-reading it.
//! The old header here said the dispatcher retried "only on a transport
//! error", which was the false premise the caching decision rested on.
//! Belt-and-braces at the hit site: a re-dispatch (`dispatch_attempt > 0`)
//! whose cached result is not a terminal success is treated as a MISS, which
//! covers an entry a pre-fix worker wrote to Redis during a rolling upgrade.
//!
//! For a transport-error retry the cached SUCCESS is exactly right: the
//! original execution has finished (the send that failed was the reply), so
//! the retry is **sequential** with it and a cache of recently-completed
//! results — checked before execution, populated after the result is signed
//! but before publish, so a retry-after-publish-failure still finds it —
//! turns the re-execution into a cheap re-publish of the identical signed
//! result.
//!
//! The cached result is re-published **as-is** (no re-signing): `JobResult`
//! verification at the controller allows a 300 s freshness window
//! (`max_age_secs = 300`), which dwarfs the bounded retry window (a few retries
//! × per-call timeout + backoff, with timeouts not retried at all), so a
//! re-published result is always comfortably fresh.
//!
//! ## Two tiers: in-process + Redis (fleet-wide)
//!
//! The in-process `DashMap` tier only covers a retry redelivered to the SAME
//! worker. Jobs are consumed from a NATS **queue group**, so a controller
//! transport-retry can land on a *different* worker whose local cache is cold
//! — re-executing side effects in any multi-worker fleet (2026-07-01 review
//! finding). The Redis tier (`shared_get` / `shared_put`, initialized from
//! `REDIS_URL` at startup — the same Redis the OCI module cache uses) makes
//! the dedup fleet-wide. Local tier is checked first (free); Redis is the
//! fallback. Redis down / unconfigured degrades to exactly the old
//! same-worker-only behavior — never an error.
//!
//! **Trust model for Redis-sourced entries**: the worker does NOT blindly
//! re-publish bytes from Redis. [`vouched_shared_entry`] is the one rule: the
//! entry must be signed for THIS worker's id and verify under this worker's
//! own key(s), and must answer this request's job and execution at this or an
//! earlier attempt (`JobResult::answers`). Until 2026-11-06 any registered
//! worker's signature for the job id was enough, and every worker's Redis user
//! may write the prefix, so on a re-dispatch an honest worker could re-publish
//! a sibling's result as its own (security review finding 10). The Redis tier
//! therefore spans one worker IDENTITY's processes (its restarts, or replicas
//! that share one id), not the whole fleet; a retry that lands on a worker
//! with another id re-executes. Refusal falls through to normal re-execution,
//! and the hit path is still one `GET`.
//!
//! ## What this does NOT cover (documented, bounded)
//!
//! - **Concurrent** redelivery of the same `job_id` while the original is still
//!   executing is NOT deduped (both miss the not-yet-populated cache and run).
//!   Core NATS request-reply is at-most-once, so this requires an at-least-once
//!   transport (JetStream) redelivering mid-flight — rare, and no worse than
//!   today (which dedupes nothing). Adding single-flight waiting was rejected as
//!   not worth the deadlock surface for the incidence.
//! - `dry_run` single jobs are never cached (no side effects; cheap to re-run).
//! - Results larger than [`MAX_CACHED_RESULT_BYTES`] are not cached (bounds
//!   memory; large outputs are rare and a double-run of one is the residual).
//!
//! ## Memory bounds
//!
//! TTL eviction ([`CACHE_TTL`], read-path + a periodic sweep per the CLAUDE.md
//! cache rule) plus a hard entry cap ([`MAX_ENTRIES`]) and the per-result size
//! cap. Steady-state footprint is `min(rate × TTL, MAX_ENTRIES)` entries, each
//! ≤ `MAX_CACHED_RESULT_BYTES`.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use aegix_workflow_job_protocol::JobResult;
use dashmap::DashMap;
use uuid::Uuid;

/// How long a completed result stays re-publishable. Must exceed the controller
/// retry window (seconds) and stay within the `JobResult` 300 s freshness window
/// (a result older than that can't be validated by the controller anyway, so
/// caching it longer is pointless). 90 s is comfortably inside both bounds.
const CACHE_TTL: Duration = Duration::from_secs(90);

/// Hard cap on cached entries. At the cap a sweep is attempted; if still full,
/// new results are simply not cached (that job falls back to re-execution on a
/// retry — no worse than the pre-FU-2 behavior).
///
/// HARD memory ceiling per cache instance = `MAX_ENTRIES × MAX_CACHED_RESULT_BYTES`
/// = 2048 × 128 KiB = **256 MiB** worst case. Realistic footprint is far smaller: results are
/// usually KB-scale, and the cache only needs to span the controller's
/// transport-retry window (seconds — timeouts aren't retried), so even a busy
/// worker keeps only `rate × ~tens-of-seconds` live entries. The bound was
/// tightened from 4096 × 256 KiB (1 GiB) after a review flagged that worst case
/// as too large for a worker pod.
const MAX_ENTRIES: usize = 2048;

/// Per-result size cap. Results whose serialized form exceeds this are not
/// cached, so a single huge output can't dominate the budget. 128 KiB covers
/// the overwhelming majority of module outputs; larger ones fall back to
/// re-execution on a retry (the rare residual).
const MAX_CACHED_RESULT_BYTES: usize = 128 * 1024;

struct Entry<V> {
    result: V,
    stored_at: Instant,
}

/// A bounded, TTL-evicting cache of completed results keyed on `job_id`.
///
/// Generic over the cached value `V`; the single-job path stores the typed
/// `JobResult` (re-published via `publish_result_with_retry`). The bound, TTL
/// and sweep logic do not depend on the value type.
pub struct JobResultCache<V> {
    map: DashMap<Uuid, Entry<V>>,
}

impl<V: Clone> JobResultCache<V> {
    fn new() -> Self {
        Self {
            map: DashMap::new(),
        }
    }

    /// Return the cached result for `job_id` if present and not expired.
    pub fn get(&self, job_id: Uuid) -> Option<V> {
        self.get_at(job_id, Instant::now())
    }

    fn get_at(&self, job_id: Uuid, now: Instant) -> Option<V> {
        let entry = self.map.get(&job_id)?;
        if now.duration_since(entry.stored_at) <= CACHE_TTL {
            Some(entry.result.clone())
        } else {
            // Expired but not yet swept; treat as a miss (the sweep reaps it).
            None
        }
    }

    /// Cache a completed (signed) result. `serialized_len` is the size of the
    /// result as it will be published; oversized results are skipped. No-op for
    /// a result whose serialized form exceeds the size cap or when the cache is
    /// full of live entries.
    pub fn put(&self, job_id: Uuid, result: V, serialized_len: usize) {
        self.put_at(job_id, result, serialized_len, Instant::now());
    }

    fn put_at(&self, job_id: Uuid, result: V, serialized_len: usize, now: Instant) {
        if serialized_len > MAX_CACHED_RESULT_BYTES {
            return;
        }
        // Only enforce the cap when this would be a NEW key (overwriting an
        // existing key, e.g. a same-job re-store, doesn't grow the map).
        if self.map.len() >= MAX_ENTRIES && !self.map.contains_key(&job_id) {
            self.sweep_at(now);
            if self.map.len() >= MAX_ENTRIES {
                return; // still full — skip caching; the job just isn't deduped
            }
        }
        self.map.insert(
            job_id,
            Entry {
                result,
                stored_at: now,
            },
        );
    }

    /// Drop expired entries. Called from a periodic sweep task and from the
    /// put-path when at capacity.
    pub fn sweep(&self) {
        self.sweep_at(Instant::now());
    }

    fn sweep_at(&self, now: Instant) {
        self.map
            .retain(|_, e| now.duration_since(e.stored_at) <= CACHE_TTL);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.map.len()
    }
}

/// Process-global completed single-job-result cache. Keyed on `job_id` (a fresh
/// v4 UUID per dispatch, preserved across transport retries), so there is no
/// cross-job key collision.
pub static JOB_RESULT_CACHE: LazyLock<JobResultCache<JobResult>> =
    LazyLock::new(JobResultCache::new);

// ── Redis tier (fleet-wide dedup across queue-group members) ─────────────

/// Redis key prefix for completed single-job results (serialized signed
/// `JobResult` JSON).
pub const REDIS_JOB_PREFIX: &str = "talos:idem:job:";
/// Redis entry TTL — matches [`CACHE_TTL`] for the same reason (must exceed
/// the controller retry window, pointless past the 300 s result-freshness
/// window).
const REDIS_TTL_SECS: u64 = 90;

/// Shared multiplexed connection, initialized once at startup when REDIS_URL
/// is configured. `ConnectionManager` auto-reconnects, so a Redis restart
/// heals without worker intervention. Absent (None) → the Redis tier is a
/// no-op and dedup is same-worker-only (the pre-fleet-fix behavior).
static REDIS_CM: tokio::sync::OnceCell<redis::aio::ConnectionManager> =
    tokio::sync::OnceCell::const_new();

/// Wire the fleet-wide tier to the worker's Redis. Call once at startup;
/// failure to connect is a WARN + same-worker-only degradation, never fatal
/// (matching the OCI cache's posture toward Redis availability).
pub async fn init_redis(client: redis::Client) {
    match aegix_redis::manager(client).await {
        Ok(cm) => {
            if REDIS_CM.set(cm).is_ok() {
                ::tracing::info!("job idempotency: fleet-wide Redis tier enabled");
            }
        }
        Err(e) => ::tracing::warn!(
            error = %e,
            "job idempotency: Redis tier unavailable — dedup degrades to same-worker-only"
        ),
    }
}

/// Fetch a cached serialized result from the fleet-wide tier. `None` on
/// miss, Redis-unconfigured, Redis error, or an oversized entry (which is
/// also deleted — it can only be garbage, `shared_put` never writes one).
pub async fn shared_get(prefix: &str, job_id: Uuid) -> Option<Vec<u8>> {
    let mut cm = REDIS_CM.get()?.clone();
    let key = format!("{prefix}{job_id}");
    match redis::cmd("GET")
        .arg(&key)
        .query_async::<Option<Vec<u8>>>(&mut cm)
        .await
    {
        Ok(Some(bytes)) if bytes.len() <= MAX_CACHED_RESULT_BYTES => Some(bytes),
        Ok(Some(bytes)) => {
            ::tracing::warn!(
                %job_id,
                bytes = bytes.len(),
                "job idempotency: oversized Redis entry ignored and deleted"
            );
            let _: Result<(), _> = redis::cmd("DEL").arg(&key).query_async(&mut cm).await;
            None
        }
        Ok(None) => None,
        Err(e) => {
            ::tracing::debug!(%job_id, error = %e, "job idempotency: Redis GET failed (treated as miss)");
            None
        }
    }
}

/// Store a serialized signed result in the fleet-wide tier. Best-effort:
/// oversized entries are skipped (same cap as the local tier) and Redis
/// errors are logged at debug — the local tier already covers same-worker
/// retries.
pub async fn shared_put(prefix: &str, job_id: Uuid, bytes: &[u8]) {
    if bytes.len() > MAX_CACHED_RESULT_BYTES {
        return;
    }
    let Some(cm) = REDIS_CM.get() else { return };
    let mut cm = cm.clone();
    let key = format!("{prefix}{job_id}");
    if let Err(e) = redis::cmd("SET")
        .arg(&key)
        .arg(bytes)
        .arg("EX")
        .arg(REDIS_TTL_SECS)
        .query_async::<()>(&mut cm)
        .await
    {
        ::tracing::debug!(%job_id, error = %e, "job idempotency: Redis SET failed (local tier still covers same-worker retries)");
    }
}

/// Why an entry read from the fleet-shared tier is not re-published.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedEntryRefusal {
    /// Not a `JobResult`.
    Unparseable,
    /// Signed for another worker id. Every worker's Redis user may write the
    /// `talos:idem:` prefix, so an entry another worker wrote is one this
    /// worker cannot vouch for, however validly that worker signed it.
    AnotherWorker,
    /// Names another job or execution, a LATER attempt than this request, or
    /// no execution at all (a result from before the binding).
    AnotherDispatch,
    /// This worker's own key does not verify it, or it is stale.
    Unverified,
}

/// The one rule for re-publishing a result read back from the fleet-shared
/// tier (security review 2026-11-06, finding 10). Admitted only when it is
/// signed for THIS worker's id, answers THIS request's job and execution at
/// this or an earlier attempt, and `verify_own` (signature and freshness under
/// this worker's OWN key, never the registry's keys for the id the entry
/// names) passes. Until then any registered worker's signature for the job id
/// was enough, so on a re-dispatch an honest worker could return a sibling's
/// result. Pure: the caller does the one `GET` and supplies the verifier.
///
/// Under a legacy HMAC result the id is self-reported, so the rule is as
/// strong as the result signature (production retires that path with
/// `AEGIX_RESULT_REQUIRE_ED25519`). A fleet that gives every replica one id
/// (`AEGIX_WORKER_ID=fleet`) shares one vouching identity: the rule is per
/// worker identity, not per process.
pub fn vouched_shared_entry(
    bytes: &[u8],
    request: &aegix_workflow_job_protocol::DispatchIdentity,
    own_worker_id: &str,
    verify_own: impl FnOnce(&JobResult) -> bool,
) -> Result<JobResult, SharedEntryRefusal> {
    use aegix_workflow_job_protocol::ResultAnswer;
    let entry: JobResult =
        serde_json::from_slice(bytes).map_err(|_| SharedEntryRefusal::Unparseable)?;
    if own_worker_id.is_empty() || entry.worker_id != own_worker_id {
        return Err(SharedEntryRefusal::AnotherWorker);
    }
    match entry.answers(request) {
        ResultAnswer::ThisDispatch | ResultAnswer::EarlierAttempt => {}
        ResultAnswer::Unbound | ResultAnswer::Mismatch => {
            return Err(SharedEntryRefusal::AnotherDispatch)
        }
    }
    if !verify_own(&entry) {
        return Err(SharedEntryRefusal::Unverified);
    }
    Ok(entry)
}

/// Interval for the background sweep of expired entries. Read-path eviction
/// handles active job_ids; this reaps entries for workers that go idle so the
/// map can't retain expired results indefinitely (CLAUDE.md cache rule:
/// TTL cache = read-path eviction + periodic sweep).
pub const SWEEP_INTERVAL_SECS: u64 = 60;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn result(job_id: Uuid) -> JobResult {
        JobResult {
            dispatch_attempt: 0,
            workflow_execution_id: None,
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id,
            status: aegix_workflow_job_protocol::JobStatus::Success,
            output_payload: json!({"ok": true}).into(),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
            fuel: None,
        }
    }

    /// Finding 10 (2026-11-06): a shared entry is re-published only when this
    /// worker can vouch for it — its own id, this job and execution, this or an
    /// earlier attempt, and its own key's verdict. Mutation-proved: with the
    /// `entry.worker_id != own_worker_id` arm removed, the sibling's entry is
    /// admitted and this test fails.
    #[test]
    fn a_shared_entry_is_republished_only_when_this_worker_can_vouch_for_it() {
        let job_id = Uuid::new_v4();
        let execution = Uuid::new_v4();
        let request = aegix_workflow_job_protocol::DispatchIdentity {
            job_id,
            dispatch_attempt: 2,
            workflow_execution_id: execution,
        };
        let entry = |worker: &str, attempt: u32, exec: Option<Uuid>| {
            let mut r = result(job_id);
            r.worker_id = worker.to_string();
            r.dispatch_attempt = attempt;
            r.workflow_execution_id = exec;
            serde_json::to_vec(&r).unwrap()
        };
        let verified = |_: &JobResult| true;

        let mine = entry("me", 1, Some(execution));
        assert!(vouched_shared_entry(&mine, &request, "me", verified).is_ok());
        let this_attempt = entry("me", 2, Some(execution));
        assert!(vouched_shared_entry(&this_attempt, &request, "me", verified).is_ok());

        let sibling = entry("sibling", 1, Some(execution));
        assert_eq!(
            vouched_shared_entry(&sibling, &request, "me", verified).unwrap_err(),
            SharedEntryRefusal::AnotherWorker,
            "a validly signed sibling entry is not this worker's to serve"
        );
        assert_eq!(
            vouched_shared_entry(&mine, &request, "", verified).unwrap_err(),
            SharedEntryRefusal::AnotherWorker,
            "a worker with no id vouches for nothing"
        );
        for (attempt, exec) in [(3, Some(execution)), (1, Some(Uuid::new_v4())), (0, None)] {
            assert_eq!(
                vouched_shared_entry(&entry("me", attempt, exec), &request, "me", verified)
                    .unwrap_err(),
                SharedEntryRefusal::AnotherDispatch,
                "attempt {attempt}, execution {exec:?}"
            );
        }
        let mut other_job = result(Uuid::new_v4());
        other_job.worker_id = "me".into();
        other_job.workflow_execution_id = Some(execution);
        assert_eq!(
            vouched_shared_entry(
                &serde_json::to_vec(&other_job).unwrap(),
                &request,
                "me",
                verified
            )
            .unwrap_err(),
            SharedEntryRefusal::AnotherDispatch
        );
        assert_eq!(
            vouched_shared_entry(&mine, &request, "me", |_| false).unwrap_err(),
            SharedEntryRefusal::Unverified
        );
        assert_eq!(
            vouched_shared_entry(b"not json", &request, "me", verified).unwrap_err(),
            SharedEntryRefusal::Unparseable
        );
    }

    #[test]
    fn put_then_get_returns_the_result() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(id, result(id), 100, t0);
        let got = cache.get_at(id, t0 + Duration::from_secs(1));
        assert!(got.is_some(), "a freshly cached result must be returned");
        assert_eq!(got.unwrap().job_id, id);
    }

    #[test]
    fn miss_for_unknown_job() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        assert!(cache.get(Uuid::new_v4()).is_none());
    }

    #[test]
    fn expired_entry_is_a_miss() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(id, result(id), 100, t0);
        // Just past the TTL.
        let got = cache.get_at(id, t0 + CACHE_TTL + Duration::from_secs(1));
        assert!(got.is_none(), "an entry past the TTL must read as a miss");
    }

    #[test]
    fn oversized_result_is_not_cached() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(id, result(id), MAX_CACHED_RESULT_BYTES + 1, t0);
        assert!(
            cache.get_at(id, t0).is_none(),
            "a result larger than the size cap must not be cached"
        );
    }

    #[test]
    fn sweep_drops_only_expired() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let old = Uuid::new_v4();
        let fresh = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(old, result(old), 100, t0);
        let later = t0 + CACHE_TTL - Duration::from_secs(1);
        cache.put_at(fresh, result(fresh), 100, later);
        // Sweep at a time where `old` is expired but `fresh` is not.
        cache.sweep_at(t0 + CACHE_TTL + Duration::from_secs(1));
        assert!(cache
            .get_at(old, t0 + CACHE_TTL + Duration::from_secs(1))
            .is_none());
        assert!(cache
            .get_at(fresh, later + Duration::from_secs(1))
            .is_some());
    }

    #[test]
    fn re_store_same_job_does_not_grow_map() {
        let cache: JobResultCache<JobResult> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        cache.put_at(id, result(id), 100, t0);
        cache.put_at(id, result(id), 100, t0);
        assert_eq!(
            cache.len(),
            1,
            "re-storing the same job_id must not grow the map"
        );
    }

    /// Redis unconfigured (REDIS_CM never set in tests) → the fleet tier
    /// degrades to a silent miss/no-op, exactly the pre-fleet behavior.
    #[tokio::test]
    async fn shared_tier_degrades_silently_without_redis() {
        let id = Uuid::new_v4();
        assert!(shared_get(REDIS_JOB_PREFIX, id).await.is_none());
        // Must not panic or block.
        shared_put(REDIS_JOB_PREFIX, id, b"{}").await;
    }

    #[test]
    fn generic_cache_works_for_bytes() {
        // A `Bytes` value takes the same TTL + size-cap logic via the generic
        // `JobResultCache<V>`.
        let cache: JobResultCache<bytes::Bytes> = JobResultCache::new();
        let id = Uuid::new_v4();
        let t0 = Instant::now();
        let payload = bytes::Bytes::from_static(b"signed-result");

        cache.put_at(id, payload.clone(), payload.len(), t0);
        assert_eq!(
            cache.get_at(id, t0 + Duration::from_secs(1)),
            Some(payload.clone())
        );

        // Oversized payload is not cached.
        let other = Uuid::new_v4();
        cache.put_at(other, payload.clone(), MAX_CACHED_RESULT_BYTES + 1, t0);
        assert!(cache.get_at(other, t0).is_none());

        // Expiry applies to the bytes instance too.
        assert!(cache
            .get_at(id, t0 + CACHE_TTL + Duration::from_secs(1))
            .is_none());
    }
}
