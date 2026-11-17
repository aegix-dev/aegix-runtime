//! Admission: what a controller checks about a signed data-plane request
//! before it reads anything else, in the one order that is safe.
//!
//! 1. the raw length, against the protocol's own limit (nothing about an
//!    oversized message is worth a parse);
//! 2. the parse;
//! 3. the protocol's `verify()`: freshness, structure, then the signature;
//! 4. the nonce's shape (it is inside the signature, so any key holder picks
//!    it: a non-canonical one is refused before it is written anywhere);
//! 5. the replay store the controller's replicas share, when there is one;
//! 6. this process's own nonce cache, which records the nonce.
//!
//! [`Admitted<T>`] has a private field and [`admit_from_bytes`] is its only
//! constructor, so code that takes one cannot be handed a request that
//! skipped or reordered a step. The two gates in this crate
//! ([`crate::dispatch_binding`], [`crate::write_ceiling`]) are asked after
//! admission, about a request that is already known to be whose it says.
//!
//! A protocol is named by a [`Protocol<T>`] value, not by a trait on the
//! request type: the request types live in `aegix-rpc-protocol`, and a
//! controller crate must be able to describe one without owning it.

use aegix_rpc_protocol::rpc_auth::{self, VerifyFailure};
use serde::de::DeserializeOwned;
use std::future::Future;
use uuid::Uuid;

/// Fixed headroom for a request's envelope (ids, nonce, signature, field
/// names) on top of its content limits.
pub const WIRE_ENVELOPE_BYTES: usize = 64 * 1024;

/// The most a JSON string can grow when serialised: a control character is
/// written as `\u00XX`, six bytes for one.
pub const JSON_ESCAPE_FACTOR: usize = 6;

/// A protocol's raw wire cap from its content limit: every content byte at
/// its worst-case JSON escape, plus the envelope.
#[must_use]
pub const fn wire_cap(content_bytes: usize) -> usize {
    content_bytes * JSON_ESCAPE_FACTOR + WIRE_ENVELOPE_BYTES
}

/// The signed-RPC canonical nonce: exactly 32 lowercase hex characters. The
/// same rule as `aegix_rpc_protocol::rpc_auth`'s private check;
/// `canonical_nonce_rule_matches_the_local_cache` holds the two equal.
#[must_use]
pub fn is_canonical_rpc_nonce(nonce: &str) -> bool {
    nonce.len() == 32
        && nonce
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// One signed request/reply protocol, as admission needs to know it.
pub struct Protocol<T> {
    /// The NATS subject the request arrives on. The key prefix in the shared
    /// replay store.
    pub wire_subject: &'static str,
    /// The subject string inside the signature, and the key of this process's
    /// nonce cache. Distinct from the wire subject by design.
    pub signing_subject: &'static str,
    /// The largest raw payload a legitimate request can be, from the
    /// protocol's own field limits ([`wire_cap`]).
    pub max_wire_bytes: usize,
    /// The protocol's own `verify()`: its cheap gates, then its signature.
    pub verify: fn(&T) -> Result<(), VerifyFailure>,
    /// The actor the signature binds.
    pub actor_id: fn(&T) -> Uuid,
    /// The nonce the signature binds.
    pub nonce: fn(&T) -> &str,
}

/// The largest raw `talos.memory.op` request: a value and its metadata at
/// their limits.
pub const MEMORY_OP_MAX_WIRE_BYTES: usize =
    wire_cap(aegix_rpc_protocol::MAX_VALUE_BYTES + aegix_rpc_protocol::MAX_METADATA_BYTES);

/// `talos.memory.op`, the protocol every controller serves.
#[must_use]
pub fn memory_op() -> Protocol<aegix_rpc_protocol::memory_rpc::MemoryRpcRequest> {
    use aegix_rpc_protocol::memory_rpc::{MemoryRpcRequest, SUBJECT_MEMORY_OP, SUBJECT_NAME};
    Protocol {
        wire_subject: SUBJECT_MEMORY_OP,
        signing_subject: SUBJECT_NAME,
        max_wire_bytes: MEMORY_OP_MAX_WIRE_BYTES,
        verify: MemoryRpcRequest::verify,
        actor_id: |req| req.actor_id,
        nonce: |req| &req.nonce,
    }
}

/// The replay store a controller's replicas share. A nonce this process has
/// never seen may still have been spent at another replica; this is where
/// that is asked.
pub trait SharedReplay {
    /// Whether the request may go on: `true` when the store vouches that the
    /// nonce is new (and has now recorded it), or when the deployment's
    /// policy admits without a store. `false` for a replay, and for a store
    /// that cannot vouch where the policy fails closed. The implementation
    /// logs which; the caller is told only to refuse.
    fn admits(
        &self,
        wire_subject: &'static str,
        actor_id: Uuid,
        nonce: &str,
    ) -> impl Future<Output = bool> + Send;
}

/// A controller that is ONE process: there is no other replica a nonce could
/// have been spent at, so this process's own cache is the whole defence.
/// Running two such controllers on one broker gives a signed request one use
/// per controller within the freshness window; a deployment with replicas
/// implements [`SharedReplay`] over a store they share.
#[derive(Debug, Clone, Copy, Default)]
pub struct OneController;

impl SharedReplay for OneController {
    async fn admits(&self, _wire_subject: &'static str, _actor_id: Uuid, _nonce: &str) -> bool {
        true
    }
}

/// Proof that a request passed every admission step, in order. Private
/// field: the only constructor is [`admit_from_bytes`].
pub struct Admitted<T>(T);

// Opaque on purpose: an admitted request can carry a tenant's value, and a
// `{:?}` of the proof must not put it in a log.
impl<T> std::fmt::Debug for Admitted<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Admitted(..)")
    }
}

impl<T> Admitted<T> {
    /// Consume the proof and take the request.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> std::ops::Deref for Admitted<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

/// Why an `Unauthorized` admission failure happened. For the controller's
/// own log and nothing else: see [`AdmitError::Unauthorized`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// The protocol's `verify()` refused the request.
    Verify(VerifyFailure),
    /// The request verified, and the shared replay store did not admit its
    /// nonce.
    CrossReplicaReplay,
}

impl RejectReason {
    /// Stable snake_case token for the rejection log. Append, never rename.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Verify(f) => f.as_str(),
            Self::CrossReplicaReplay => "cross_replica_replay",
        }
    }
}

/// Why admission failed.
#[derive(Debug)]
pub enum AdmitError {
    /// The payload was too large or did not parse. Carries text about the
    /// caller's own bytes, which is not sensitive.
    Malformed(String),
    /// The signature, freshness or structure check failed, or the shared
    /// replay store refused the nonce.
    ///
    /// `reason` is a CONTROLLER-SIDE LOG FIELD. The reply a caller is sent
    /// must be the same bytes for every reason: a caller that could tell
    /// `stale` from `bad_signature` could map the freshness window and
    /// confirm a key as two separate probes.
    Unauthorized { reason: RejectReason },
    /// The nonce is not canonical, or this process has already seen it.
    Replay,
}

/// THE admission sequence. Fails closed at each step, and records the nonce
/// only for a request that passed every step before it.
pub async fn admit_from_bytes<T, R>(
    protocol: &Protocol<T>,
    replay: &R,
    payload: &[u8],
) -> Result<Admitted<T>, AdmitError>
where
    T: DeserializeOwned,
    R: SharedReplay + Sync,
{
    if payload.len() > protocol.max_wire_bytes {
        return Err(AdmitError::Malformed(format!(
            "payload of {} bytes exceeds this subject's {} byte limit",
            payload.len(),
            protocol.max_wire_bytes
        )));
    }
    let req: T =
        serde_json::from_slice(payload).map_err(|e| AdmitError::Malformed(e.to_string()))?;
    // The protocol's verify first (its own cheap gates run before its
    // crypto); the shared store, which costs a round trip, only for a request
    // that already verified.
    if let Err(failure) = (protocol.verify)(&req) {
        return Err(AdmitError::Unauthorized {
            reason: RejectReason::Verify(failure),
        });
    }
    let actor_id = (protocol.actor_id)(&req);
    // Before the shared store writes the nonce into a key: a 1 MiB nonce was
    // a 1 MiB key. The local cache would refuse it with this same error.
    if !is_canonical_rpc_nonce((protocol.nonce)(&req)) {
        return Err(AdmitError::Replay);
    }
    if !replay
        .admits(protocol.wire_subject, actor_id, (protocol.nonce)(&req))
        .await
    {
        return Err(AdmitError::Unauthorized {
            reason: RejectReason::CrossReplicaReplay,
        });
    }
    if !rpc_auth::check_and_record_nonce(protocol.signing_subject, actor_id, (protocol.nonce)(&req))
    {
        return Err(AdmitError::Replay);
    }
    Ok(Admitted(req))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    // A stand-in protocol, so the sequence is held without a registered key:
    // its `verify` reports what the request says it should.
    #[derive(serde::Serialize, serde::Deserialize)]
    struct FakeReq {
        actor_id: Uuid,
        nonce: String,
        /// Index into `FAILURES`; `None` verifies.
        failure_index: Option<usize>,
    }

    const FAILURES: [VerifyFailure; 5] = [
        VerifyFailure::Stale,
        VerifyFailure::NonFinite,
        VerifyFailure::OversizedStructure,
        VerifyFailure::UnknownSignerKey,
        VerifyFailure::BadSignature,
    ];

    fn fake() -> Protocol<FakeReq> {
        Protocol {
            wire_subject: "talos.test.admission",
            signing_subject: "gates_admission_test_rpc",
            max_wire_bytes: 4 * 1024,
            verify: |req| match req.failure_index {
                Some(i) => Err(FAILURES[i]),
                None => Ok(()),
            },
            actor_id: |req| req.actor_id,
            nonce: |req| &req.nonce,
        }
    }

    fn canonical_nonce() -> String {
        hex(&Uuid::new_v4().into_bytes())
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn request(failure: Option<VerifyFailure>) -> FakeReq {
        FakeReq {
            actor_id: Uuid::new_v4(),
            nonce: canonical_nonce(),
            failure_index: failure.map(|f| {
                FAILURES
                    .iter()
                    .position(|c| *c == f)
                    .expect("a mapped failure")
            }),
        }
    }

    fn bytes(req: &FakeReq) -> Vec<u8> {
        serde_json::to_vec(req).expect("serialise")
    }

    /// A shared store that counts what it was asked and answers as told.
    #[derive(Default)]
    struct Store {
        refuses: AtomicBool,
        asked: AtomicUsize,
    }

    impl Store {
        fn refusing() -> Self {
            let store = Self::default();
            store.refuses.store(true, Ordering::SeqCst);
            store
        }
        fn asked(&self) -> usize {
            self.asked.load(Ordering::SeqCst)
        }
    }

    impl SharedReplay for Store {
        async fn admits(&self, _subject: &'static str, _actor_id: Uuid, _nonce: &str) -> bool {
            self.asked.fetch_add(1, Ordering::SeqCst);
            !self.refuses.load(Ordering::SeqCst)
        }
    }

    #[tokio::test]
    async fn a_request_that_passes_every_step_is_admitted_once() {
        let store = Store::default();
        let req = request(None);
        let admitted = admit_from_bytes(&fake(), &store, &bytes(&req))
            .await
            .expect("admitted");
        assert_eq!(admitted.actor_id, req.actor_id, "Deref reaches the request");
        assert_eq!(admitted.into_inner().nonce, req.nonce);
        assert_eq!(store.asked(), 1);

        // The same bytes again: this process has seen the nonce.
        assert!(matches!(
            admit_from_bytes(&fake(), &store, &bytes(&req)).await,
            Err(AdmitError::Replay)
        ));
    }

    #[tokio::test]
    async fn an_oversized_payload_is_refused_before_it_is_parsed() {
        // Valid JSON for the protocol, padded past the cap with whitespace:
        // were it parsed, it would verify.
        let mut payload = bytes(&request(None));
        payload.resize(fake().max_wire_bytes + 1, b' ');
        let store = Store::default();
        match admit_from_bytes(&fake(), &store, &payload).await {
            Err(AdmitError::Malformed(why)) => assert!(why.contains("exceeds"), "{why}"),
            other => panic!("an oversized payload must be Malformed, got {other:?}"),
        }
        assert_eq!(store.asked(), 0);

        // At the cap exactly, it is read.
        let mut at_cap = bytes(&request(None));
        at_cap.resize(fake().max_wire_bytes, b' ');
        assert!(admit_from_bytes(&fake(), &store, &at_cap).await.is_ok());
    }

    #[tokio::test]
    async fn a_payload_that_does_not_parse_is_malformed_whatever_it_would_have_verified_as() {
        let store = Store::default();
        assert!(matches!(
            admit_from_bytes(&fake(), &store, b"{not json").await,
            Err(AdmitError::Malformed(_))
        ));
        // A request that would fail `verify`, with one field of the wrong
        // type: the parse error is the answer, not `Unauthorized`.
        let wrong_type = format!(
            r#"{{"actor_id":"{}","nonce":7,"failure_index":4}}"#,
            Uuid::new_v4()
        );
        assert!(matches!(
            admit_from_bytes(&fake(), &store, wrong_type.as_bytes()).await,
            Err(AdmitError::Malformed(_))
        ));
        assert_eq!(store.asked(), 0);
    }

    #[tokio::test]
    async fn every_verify_failure_is_unauthorized_names_itself_and_spends_nothing() {
        for failure in FAILURES {
            let store = Store::default();
            let req = request(Some(failure));
            match admit_from_bytes(&fake(), &store, &bytes(&req)).await {
                Err(AdmitError::Unauthorized { reason }) => {
                    assert_eq!(reason, RejectReason::Verify(failure));
                    assert_eq!(reason.as_str(), failure.as_str());
                }
                other => panic!("{failure:?} must be Unauthorized, got {other:?}"),
            }
            assert_eq!(
                store.asked(),
                0,
                "{failure:?}: an unverified request is never taken to the shared store"
            );
            // And its nonce is not spent: the same nonce on a request that
            // verifies is admitted.
            let honest = FakeReq {
                failure_index: None,
                ..req
            };
            assert!(
                admit_from_bytes(&fake(), &store, &bytes(&honest))
                    .await
                    .is_ok(),
                "{failure:?}: a refused request must not burn its nonce"
            );
        }
    }

    #[tokio::test]
    async fn a_non_canonical_nonce_is_refused_before_the_shared_store_sees_it() {
        for nonce in [
            String::new(),
            "abc".to_string(),
            "A".repeat(32),   // upper case
            "g".repeat(32),   // not hex
            "0".repeat(31),   // short
            "0".repeat(33),   // long
            "0".repeat(1024), // what a key holder could send
        ] {
            let store = Store::default();
            let req = FakeReq {
                nonce: nonce.clone(),
                ..request(None)
            };
            assert!(
                matches!(
                    admit_from_bytes(&fake(), &store, &bytes(&req)).await,
                    Err(AdmitError::Replay)
                ),
                "nonce {nonce:?} must be refused"
            );
            assert_eq!(store.asked(), 0, "nonce {nonce:?} reached the shared store");
        }
    }

    #[tokio::test]
    async fn a_nonce_the_shared_store_refuses_is_unauthorized_and_not_recorded_here() {
        let refusing = Store::refusing();
        let req = request(None);
        match admit_from_bytes(&fake(), &refusing, &bytes(&req)).await {
            Err(AdmitError::Unauthorized { reason }) => {
                assert_eq!(reason, RejectReason::CrossReplicaReplay);
                assert_eq!(reason.as_str(), "cross_replica_replay");
            }
            other => panic!("a store refusal must be Unauthorized, got {other:?}"),
        }
        assert_eq!(refusing.asked(), 1);
        // The local cache was not written: under a store that admits, the
        // same request goes through.
        assert!(admit_from_bytes(&fake(), &Store::default(), &bytes(&req))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn the_shared_store_is_asked_before_the_local_cache_records() {
        // Admit once (the local cache now holds the nonce), then present the
        // same request to a store that refuses: the store's answer is the one
        // returned, so it was asked first.
        let req = request(None);
        admit_from_bytes(&fake(), &Store::default(), &bytes(&req))
            .await
            .expect("admitted");
        assert!(matches!(
            admit_from_bytes(&fake(), &Store::refusing(), &bytes(&req)).await,
            Err(AdmitError::Unauthorized {
                reason: RejectReason::CrossReplicaReplay
            })
        ));
    }

    #[tokio::test]
    async fn one_controller_admits_without_a_store_and_the_local_cache_still_holds() {
        let req = request(None);
        assert!(admit_from_bytes(&fake(), &OneController, &bytes(&req))
            .await
            .is_ok());
        assert!(matches!(
            admit_from_bytes(&fake(), &OneController, &bytes(&req)).await,
            Err(AdmitError::Replay)
        ));
    }

    #[test]
    fn canonical_nonce_rule_matches_the_local_cache() {
        // What `rpc_auth::random_nonce` mints is canonical, and the local
        // cache takes it; what this rule refuses, the local cache refuses.
        let minted = rpc_auth::random_nonce();
        assert!(is_canonical_rpc_nonce(&minted), "{minted}");
        let actor = Uuid::new_v4();
        assert!(rpc_auth::check_and_record_nonce(
            "gates_admission_rule_test",
            actor,
            &minted
        ));
        for bad in ["", "abc", &"A".repeat(32), &"0".repeat(33)] {
            assert!(!is_canonical_rpc_nonce(bad), "{bad:?}");
            assert!(
                !rpc_auth::check_and_record_nonce("gates_admission_rule_test", actor, bad),
                "the local cache took a nonce this rule refuses: {bad:?}"
            );
        }
    }

    #[test]
    fn the_wire_cap_is_every_content_byte_escaped_plus_the_envelope() {
        assert_eq!(wire_cap(0), WIRE_ENVELOPE_BYTES);
        assert_eq!(wire_cap(10), 10 * JSON_ESCAPE_FACTOR + WIRE_ENVELOPE_BYTES);
        assert_eq!(
            MEMORY_OP_MAX_WIRE_BYTES,
            wire_cap(aegix_rpc_protocol::MAX_VALUE_BYTES + aegix_rpc_protocol::MAX_METADATA_BYTES)
        );
    }

    #[test]
    fn the_memory_protocol_names_the_subjects_the_worker_signs_and_sends_on() {
        let p = memory_op();
        assert_eq!(p.wire_subject, "talos.memory.op");
        assert_eq!(p.signing_subject, "memory_rpc");
        assert_ne!(p.wire_subject, p.signing_subject);
        assert_eq!(p.max_wire_bytes, MEMORY_OP_MAX_WIRE_BYTES);
    }
}
