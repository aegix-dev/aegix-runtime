//! The signed command a controller sends the fleet to stop an execution.
//!
//! Moved out of `lib.rs` 2026-11-18, unchanged; every public item is
//! re-exported at the crate root, where it was.

#[cfg(test)]
use crate::HmacSha256;
use crate::{
    DispatchSigningKey, DispatchVerifyingKey, SignedMessage, VerifyError, VerifyFailureKind,
    CRYPTO_SCHEME_ED25519, CRYPTO_SCHEME_HMAC,
};
#[cfg(test)]
use hmac::Mac;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Domain-separation prefix for the operator-initiated execution CANCEL
/// command.
///
/// Distinct from every other tag on the bus for the usual reason — a MAC over
/// one message type must never verify as another — and for one specific to
/// this message: it is the only signed message on the platform whose entire
/// authority is *destructive*. A byte sequence that could be read both as a
/// heartbeat and as a cancel would turn an observability publish into a
/// fleet-wide abort primitive. Prefix-freedom against the other tags is
/// asserted in `cancel_command_tests::the_cancel_domain_is_distinct_and_prefix_free`.
pub const EXECUTION_CANCEL_DOMAIN: &[u8] = b"talos/execution-cancel/v1";

/// Freshness window a [`CancelCommand`] is verified under, in seconds.
///
/// Deliberately SHORT. A cancel is a fire-and-forget command with no reply, so
/// unlike a job dispatch there is no request/response round-trip to size
/// against — the only latency it must tolerate is controller→NATS→worker,
/// which is milliseconds. Combined with the process-local nonce cache (which
/// refuses a nonce already seen inside the window), a captured cancel is
/// usable for **0 replays** and is inert after this many seconds.
///
/// It is a third of the 300 s used for `JobRequest`, and that asymmetry is the
/// point: a stale job dispatch wastes work, a stale cancel destroys it.
pub const EXECUTION_CANCEL_MAX_AGE_SECS: u64 = 100;

/// Operator-initiated cancellation of one workflow execution, broadcast to the
/// whole worker fleet.
///
/// # Why this message carries no tenancy
///
/// There is no `user_id` field, and adding one would be decoration. The worker
/// is credential-free — it has no Postgres connection and cannot evaluate
/// ownership of an execution — so a `user_id` on the wire would be a claim
/// nobody could check. **Tenancy is enforced entirely at the producer**: the
/// controller publishes only when
/// `ExecutionRepository::mark_execution_cancelled(exec_id, user_id)` returns
/// `Ok(true)`, i.e. only after a row matched BOTH the execution id and the
/// caller's `user_id`. A caller who does not own the execution updates zero
/// rows and nothing is published.
///
/// # Why it is signed
///
/// Without a signature this is a denial-of-service primitive: anyone able to
/// publish on the bus could abort arbitrary executions by guessing or
/// observing execution ids. The signature is what makes "can reach NATS"
/// insufficient.
///
/// # What it does NOT do
///
/// It does not bypass audit. It sets the worker's job-scoped `cancelled` flag,
/// which the in-worker egress guards read; the job then fails through the
/// ordinary path and still writes its `node_failed` row and its DLQ entry. It
/// is not a `select!`-race that drops the reactor future, and it deliberately
/// does not touch the engine's in-process `CancellationToken` for that reason.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CancelCommand {
    /// The `workflow_executions.id` the operator cancelled. Workers match this
    /// against the execution id every in-flight job was dispatched under.
    pub workflow_execution_id: Uuid,
    /// Signature scheme (see [`JobRequest::crypto_scheme`]): 0 = legacy
    /// `WORKER_SHARED_KEY` HMAC, 1 = controller Ed25519.
    #[serde(default)]
    pub crypto_scheme: u8,
    /// HMAC-SHA256 (scheme 0) or Ed25519 (scheme 1) signature.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Nonce for replay prevention: `"{unix_secs}:{random_hex}"`.
    #[serde(default)]
    pub cancel_nonce: String,
}

impl CancelCommand {
    /// An unsigned command for `workflow_execution_id`. Call one of the `sign`
    /// methods before publishing — an unsigned command is refused by every
    /// worker.
    #[must_use]
    pub fn new(workflow_execution_id: Uuid) -> Self {
        Self {
            workflow_execution_id,
            crypto_scheme: CRYPTO_SCHEME_HMAC,
            signature: Vec::new(),
            cancel_nonce: String::new(),
        }
    }

    /// Canonical signing payload: domain tag, then the length-prefixed
    /// execution-id bytes and nonce, in the same construction as
    /// [`WorkerHeartbeat::signing_payload`].
    ///
    /// The uuid is a fixed 16 bytes, so the length prefix is not load-bearing
    /// for *it* — it is there so the framing rule is uniform and a later field
    /// cannot be appended without a prefix by pattern-copying the line above
    /// it. `crypto_scheme` is deliberately NOT bound, exactly as on
    /// `JobRequest`: it is an unsigned routing hint, and flipping it only ever
    /// routes the message to a verifier that then rejects it.
    fn signing_payload(&self) -> Vec<u8> {
        fn put(v: &mut Vec<u8>, field: &[u8]) {
            v.extend_from_slice(&(field.len() as u64).to_le_bytes());
            v.extend_from_slice(field);
        }
        let mut v = Vec::with_capacity(EXECUTION_CANCEL_DOMAIN.len() + 64);
        v.extend_from_slice(EXECUTION_CANCEL_DOMAIN);
        put(&mut v, self.workflow_execution_id.as_bytes());
        put(&mut v, self.cancel_nonce.as_bytes());
        v
    }

    /// Sign under the legacy `WORKER_SHARED_KEY` HMAC scheme.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.crypto_scheme = CRYPTO_SCHEME_HMAC;
        self.sign_core(key)
    }

    /// Sign under the Ed25519 dispatch scheme with the controller's private key.
    pub fn sign_ed25519(&mut self, signing_key: &DispatchSigningKey) -> Result<(), String> {
        self.crypto_scheme = CRYPTO_SCHEME_ED25519;
        self.sign_core_ed25519(signing_key)
    }

    /// Scheme-dispatching **primary** verify for the worker — the single
    /// verify-once action point for this message type in a worker process.
    /// Routes on `self.crypto_scheme` exactly like
    /// [`JobRequest::verify_dispatch`].
    ///
    /// **Verify-once rule (CLAUDE.md).** Call this from exactly ONE subscriber
    /// per process. A second `verify_dispatch` against the same command fails
    /// with `"cancel_nonce already seen"` — both would insert into the shared
    /// `JOB_NONCE_CACHE`. Passive observers use
    /// [`Self::verify_no_replay_dispatch`].
    pub fn verify_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_ed25519_core(ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC cancel refused (Ed25519-only enforcement enabled)".to_string(),
                    ));
                }
                self.verify_with_ring_core(hmac_ring, max_age_secs)
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown cancel crypto_scheme: {other}"),
            )),
        }
    }

    /// Observer half of [`Self::verify_dispatch`]: signature + freshness with
    /// **no** replay-cache write.
    ///
    /// Shipped alongside the primary from day one per CLAUDE.md's "add both
    /// `verify()` and `verify_no_replay()` together up front" rule — the
    /// prophylactic split is cheap, and the r300/r301 regression it prevents
    /// is total. It has no production caller today; that is deliberate and is
    /// recorded rather than hidden.
    pub fn verify_no_replay_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<u64, VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_no_replay_ed25519_core(ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC cancel refused (Ed25519-only enforcement enabled)".to_string(),
                    ));
                }
                self.verify_no_replay_with_ring_core(hmac_ring, max_age_secs)
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown cancel crypto_scheme: {other}"),
            )),
        }
    }

    /// MAC the current fields WITHOUT minting a fresh nonce, so a test can pin
    /// the send timestamp and exercise the freshness boundary. Test-only.
    #[cfg(test)]
    pub(crate) fn sign_core_with_fixed_nonce_for_test(&mut self, key: &[u8]) {
        self.crypto_scheme = CRYPTO_SCHEME_HMAC;
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("HMAC key");
        mac.update(&self.signing_payload());
        self.signature = mac.finalize().into_bytes().to_vec();
    }
}

impl SignedMessage for CancelCommand {
    const NONCE_LABEL: &'static str = "cancel_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn nonce(&self) -> &str {
        &self.cancel_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.cancel_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}
