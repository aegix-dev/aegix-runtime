//! What a worker reports about a job while it runs.
//!
//! Moved out of `lib.rs` 2026-11-18, unchanged; every public item is
//! re-exported at the crate root, where it was.

use crate::{
    check_result_worker_id_shape, validate_worker_id, DispatchSigningKey, DispatchVerifyingKey,
    SignedMessage, VerifyError, VerifyFailureKind, CRYPTO_SCHEME_ED25519, CRYPTO_SCHEME_HMAC,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What a worker reports about a job while it runs.
///
/// Only one fact is reported today: whether the job is WAITING for the
/// local-inference slot. The controller pauses the attempt's deadline while a
/// job is waiting, so a job never fails because other workflows' inference was
/// ahead of it in the queue. See `aegix_dispatch_types::inference_wait`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobProgressState {
    /// The job is queued for the local-inference slot.
    Waiting,
    /// The job has the slot (or stopped waiting for it) and is working again.
    Admitted,
}

impl JobProgressState {
    /// The token bound into the signing payload. Closed set; never
    /// caller-derived.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            JobProgressState::Waiting => "waiting",
            JobProgressState::Admitted => "admitted",
        }
    }
}

/// A signed worker→controller progress report for one dispatch of one job,
/// published to [`subjects::job_progress_for`] (the job's signed reply inbox
/// plus `.progress`).
///
/// Signed exactly like [`JobResult`] — the worker's Ed25519 key when it has one,
/// the fleet HMAC key otherwise — and verified by the dispatcher that owns the
/// dispatch, which is its ONLY consumer (verify-once rule: the dispatcher calls
/// [`Self::verify_dispatch`]; [`Self::verify_no_replay_dispatch`] exists up front
/// for any future observer).
///
/// **What a forger could do, stated.** A party holding the fleet key can sign a
/// `waiting` report for any job whose reply inbox it has seen. The worst it buys
/// is that the controller waits longer for that job's result, by at most
/// `LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS` per attempt; it cannot change a
/// result, skip a gate or extend the worker's own deadlines.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobProgress {
    pub job_id: Uuid,
    /// Which controller dispatch of the job this report is about. The reply
    /// inbox is reused across a job's attempts, so a late report from an
    /// earlier attempt must be told apart from the current one.
    pub dispatch_attempt: u32,
    pub state: JobProgressState,
    /// The reporting worker's identity, bound into the signature
    /// (charset-checked like [`JobResult::worker_id`]).
    #[serde(default)]
    pub worker_id: String,
    /// `"{unix_secs}:{random_hex}"`, bound into the signature.
    #[serde(default)]
    pub progress_nonce: String,
    #[serde(default)]
    pub signature: Vec<u8>,
    /// [`CRYPTO_SCHEME_HMAC`] or [`CRYPTO_SCHEME_ED25519`]; an unsigned routing
    /// hint exactly as on [`JobResult`].
    #[serde(default)]
    pub crypto_scheme: u8,
}

impl JobProgress {
    /// An unsigned report.
    #[must_use]
    pub fn new(job_id: Uuid, dispatch_attempt: u32, state: JobProgressState) -> Self {
        Self {
            job_id,
            dispatch_attempt,
            state,
            worker_id: String::new(),
            progress_nonce: String::new(),
            signature: Vec::new(),
            crypto_scheme: CRYPTO_SCHEME_HMAC,
        }
    }

    /// Canonical signed bytes. The leading `progress:` is a DOMAIN tag: a
    /// `JobResult` payload starts with the job id, so no result signature can be
    /// replayed as a progress report or the reverse.
    pub(crate) fn signing_payload(&self) -> Vec<u8> {
        format!(
            "progress:{}:{}:{}:{}:{}",
            self.job_id,
            self.dispatch_attempt,
            self.state.as_str(),
            self.progress_nonce,
            self.worker_id,
        )
        .into_bytes()
    }

    /// Sign under the fleet HMAC key and bind `worker_id`.
    pub fn sign_with_worker_id(&mut self, key: &[u8], worker_id: &str) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        self.worker_id = worker_id.to_string();
        self.crypto_scheme = CRYPTO_SCHEME_HMAC;
        self.sign_core(key)
    }

    /// Sign under the worker's own Ed25519 key and bind `worker_id` (which must
    /// be non-empty, as for [`JobResult::sign_ed25519_with_worker_id`]).
    pub fn sign_ed25519_with_worker_id(
        &mut self,
        signing_key: &DispatchSigningKey,
        worker_id: &str,
    ) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        if worker_id.is_empty() {
            return Err("Ed25519 progress signing requires a non-empty worker_id".to_string());
        }
        self.worker_id = worker_id.to_string();
        self.crypto_scheme = CRYPTO_SCHEME_ED25519;
        self.sign_core_ed25519(signing_key)
    }

    /// **Primary** verify (the dispatcher): scheme-routed exactly like
    /// [`JobResult::verify_dispatch`], and records the nonce once.
    pub fn verify_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        worker_ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_ed25519_core(worker_ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC progress refused (Ed25519-only enforcement enabled)"
                            .to_string(),
                    ));
                }
                self.verify_with_ring_core(hmac_ring, max_age_secs)
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown progress crypto_scheme: {other}"),
            )),
        }
    }

    /// **Observer** verify: freshness + signature, never the replay cache.
    pub fn verify_no_replay_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        worker_ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self
                .verify_no_replay_ed25519_core(worker_ed_keys, max_age_secs)
                .map(|_| ()),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC progress refused (Ed25519-only enforcement enabled)"
                            .to_string(),
                    ));
                }
                self.verify_no_replay_with_ring_core(hmac_ring, max_age_secs)
                    .map(|_| ())
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown progress crypto_scheme: {other}"),
            )),
        }
    }
}

impl SignedMessage for JobProgress {
    const NONCE_LABEL: &'static str = "progress_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn check_payload_shape(&self) -> Result<(), VerifyError> {
        check_result_worker_id_shape(&self.worker_id)
    }
    fn nonce(&self) -> &str {
        &self.progress_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.progress_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}
