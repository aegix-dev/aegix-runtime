//! RFC 0010 P3 (D3b) — worker-side secret claim client.
//!
//! When a dispatch arrives with `sealing == SEALING_CLAIM_ECIES`, the worker
//! does NOT find its secrets inline in `encrypted_secrets`. Instead it:
//!   1. generates a fresh per-execution ephemeral X25519 keypair,
//!   2. sends a `SecretClaim` (Ed25519-signed by its long-term registered key,
//!      binding the ephemeral public key) to the dispatch's `claim_inbox`,
//!   3. verifies the controller-signed `SealedSecrets` reply and opens it with
//!      the ephemeral secret (consumed → forward secrecy),
//!   4. loads the resulting [`SecretMap`] into the `SecretProvider`.
//!
//! Every map this module returns is a [`SecretMap`]: `Zeroizing` values from
//! the moment the JSON parses, so no plain copy of a value exists in the
//! worker after the box opens (security review 2026-10-15, C-10).
//!
//! The crypto handshake is split into pure `build_claim` / `process_reply`
//! functions (unit-testable without a broker) and a thin `claim_secrets` NATS
//! wrapper.

use std::time::Duration;
use zeroize::Zeroizing;

use aegix_workflow_job_protocol::{
    ClaimResponse, DispatchSigningKey, DispatchVerifyingKey, SecretClaim, SecretMap,
    WorkerEphemeral,
};
use uuid::Uuid;

/// The worker's downgrade guard (RFC 0010 P3): under
/// `AEGIX_ENVELOPE_SEALING=required`, a dispatch that is not claim-sealed and
/// carries a NON-EMPTY inline envelope is refused before anything decrypts it.
/// An empty inline envelope decrypts nothing (a node with no secrets) and is
/// allowed, or every secretless node would break. Under `off`/`audit` both
/// shapes are handled. The controller's module-bound fallback
/// (`aegix_integration_helpers::finish_dispatch_delivery`) and the fleet
/// identity gate both rely on this answer; until 2026-11-06 it was inline in
/// `main.rs` and a mutant that disabled it passed every worker test (security
/// review finding 6). `main.rs` calls it as the whole condition of its
/// refusal, held by `sealing_refusal_pin`.
#[must_use]
pub fn inline_envelope_refused(
    sealing_required: bool,
    req: &aegix_workflow_job_protocol::JobRequest,
) -> bool {
    sealing_required
        && req.sealing != aegix_workflow_job_protocol::SEALING_CLAIM_ECIES
        && !req.encrypted_secrets.ciphertext.is_empty()
}

/// How long the worker waits for the controller's `SealedSecrets` reply before
/// giving up (and failing the job). The claim is an in-cluster request/reply;
/// the controller seals synchronously, so this is generous.
const CLAIM_TIMEOUT: Duration = Duration::from_secs(10);

/// Freshness window (seconds) the worker allows on the controller's
/// `SealedSecrets` — matches the dispatch-verify window elsewhere.
const SEALED_MAX_AGE_SECS: u64 = 300;

/// Everything that can go wrong obtaining sealed secrets. All map to "fail the
/// job" — a job whose secrets can't be obtained cannot run (fail-closed, never
/// run secretless).
#[derive(Debug)]
pub enum ClaimClientError {
    /// `sealing == 1` but the dispatch carried no `claim_inbox` (malformed).
    MissingClaimInbox,
    /// No controller public key configured — cannot verify the reply.
    NoControllerKey,
    /// NATS request failed or timed out.
    Transport(String),
    /// The controller rejected the claim (unknown/already-claimed execution,
    /// unauthorized, seal failure). The worker drops the job without running.
    Rejected(String),
    /// The reply's controller signature did not verify.
    VerifyFailed,
    /// ECDH/AEAD open failed (wrong key or tampered ciphertext).
    OpenFailed(String),
    /// (De)serialization of the claim or reply failed.
    Serde(String),
}

impl std::fmt::Display for ClaimClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingClaimInbox => write!(f, "dispatch has sealing=1 but no claim_inbox"),
            Self::NoControllerKey => write!(f, "no controller public key configured"),
            Self::Transport(e) => write!(f, "claim transport error: {e}"),
            Self::Rejected(r) => write!(f, "claim rejected by controller: {r}"),
            Self::VerifyFailed => write!(f, "SealedSecrets signature did not verify"),
            Self::OpenFailed(e) => write!(f, "failed to open sealed secrets: {e}"),
            Self::Serde(e) => write!(f, "claim (de)serialization error: {e}"),
        }
    }
}

impl std::error::Error for ClaimClientError {}

/// Generate the ephemeral keypair and build the signed `SecretClaim` for an
/// execution. `exec_id` is the id the controller registered the seal context
/// under (the dispatch `job_id` for both single-node and pipeline jobs). Returns
/// the ephemeral (to open the reply with) and the serialized claim payload. Pure
/// except for the ephemeral RNG.
pub fn build_claim(
    exec_id: Uuid,
    dispatch_attempt: u32,
    worker_id: &str,
    worker_signing_key: &DispatchSigningKey,
) -> Result<(WorkerEphemeral, Vec<u8>), ClaimClientError> {
    let we = WorkerEphemeral::generate();
    // The claim names the attempt this worker received (finding 8): the
    // controller answers it only from the context armed for that attempt.
    let claim = SecretClaim::new_signed_for_attempt(
        exec_id,
        dispatch_attempt,
        worker_id.to_string(),
        we.public_key(),
        worker_signing_key,
    );
    let payload = serde_json::to_vec(&claim).map_err(|e| ClaimClientError::Serde(e.to_string()))?;
    Ok((we, payload))
}

/// Verify + open the controller's reply, returning the RAW opened plaintext
/// bytes. Consumes the ephemeral (single-use → forward secrecy). The caller
/// deserializes the bytes into whatever shape it sealed — a flat [`SecretMap`]
/// (single-node) or a per-step `Vec<SecretMap>` (pipeline). Pure and testable.
pub fn process_reply_raw(
    we: WorkerEphemeral,
    exec_id: Uuid,
    worker_id: &str,
    controller_keys: &[DispatchVerifyingKey],
    reply_bytes: &[u8],
) -> Result<Zeroizing<Vec<u8>>, ClaimClientError> {
    if controller_keys.is_empty() {
        return Err(ClaimClientError::NoControllerKey);
    }
    let resp: ClaimResponse =
        serde_json::from_slice(reply_bytes).map_err(|e| ClaimClientError::Serde(e.to_string()))?;
    let sealed = match resp {
        ClaimResponse::Sealed(s) => s,
        ClaimResponse::Rejected { reason } => return Err(ClaimClientError::Rejected(reason)),
    };
    // The reply must be signed by a currently-trusted controller key (current or
    // rotated-out overlap key).
    if !controller_keys
        .iter()
        .any(|vk| sealed.verify(vk, SEALED_MAX_AGE_SECS).is_ok())
    {
        return Err(ClaimClientError::VerifyFailed);
    }
    we.open(
        &sealed.epk_c,
        exec_id,
        worker_id,
        &sealed.ciphertext,
        &sealed.nonce,
    )
    .map_err(ClaimClientError::OpenFailed)
}

/// Move step `i`'s map out of the claimed per-step vector (empty when absent),
/// leaving nothing behind. What is not taken — or everything, on an early
/// return — is wiped when the vector drops, because every value is `Zeroizing`.
/// (Until 2026-10-15 a `ZeroizingSecretMaps` newtype carried a `Drop` that did
/// this by hand over plain `String`s; the type now does it.)
pub fn take_step_secrets(per_step: &mut [SecretMap], i: usize) -> SecretMap {
    per_step.get_mut(i).map(std::mem::take).unwrap_or_default()
}

/// Verify + open the controller's reply into a flat secrets map (single-node
/// convenience over [`process_reply_raw`]).
pub fn process_reply(
    we: WorkerEphemeral,
    exec_id: Uuid,
    worker_id: &str,
    controller_keys: &[DispatchVerifyingKey],
    reply_bytes: &[u8],
) -> Result<SecretMap, ClaimClientError> {
    let plaintext = process_reply_raw(we, exec_id, worker_id, controller_keys, reply_bytes)?;
    serde_json::from_slice(plaintext.as_slice()).map_err(|e| ClaimClientError::Serde(e.to_string()))
}

/// Full claim round-trip over NATS returning the RAW opened plaintext bytes.
/// `claim_inbox` is the subject the dispatch named (`None` ⇒ malformed dispatch).
/// The caller deserializes the bytes into the shape it expects (a flat map for
/// a single node).
pub async fn claim_secrets_raw(
    nc: &async_nats::Client,
    exec_id: Uuid,
    dispatch_attempt: u32,
    claim_inbox: Option<&str>,
    worker_id: &str,
    worker_signing_key: &DispatchSigningKey,
    controller_keys: &[DispatchVerifyingKey],
) -> Result<Zeroizing<Vec<u8>>, ClaimClientError> {
    let claim_inbox = claim_inbox.ok_or(ClaimClientError::MissingClaimInbox)?;
    if controller_keys.is_empty() {
        return Err(ClaimClientError::NoControllerKey);
    }

    let (we, payload) = build_claim(exec_id, dispatch_attempt, worker_id, worker_signing_key)?;

    let reply = tokio::time::timeout(
        CLAIM_TIMEOUT,
        nc.request(claim_inbox.to_string(), payload.into()),
    )
    .await
    .map_err(|_| ClaimClientError::Transport("claim request timed out".to_string()))?
    .map_err(|e| ClaimClientError::Transport(e.to_string()))?;

    process_reply_raw(we, exec_id, worker_id, controller_keys, &reply.payload)
}

/// Full claim round-trip over NATS returning a flat secrets map (single-node
/// convenience over [`claim_secrets_raw`]).
pub async fn claim_secrets(
    nc: &async_nats::Client,
    exec_id: Uuid,
    dispatch_attempt: u32,
    claim_inbox: Option<&str>,
    worker_id: &str,
    worker_signing_key: &DispatchSigningKey,
    controller_keys: &[DispatchVerifyingKey],
) -> Result<SecretMap, ClaimClientError> {
    let plaintext = claim_secrets_raw(
        nc,
        exec_id,
        dispatch_attempt,
        claim_inbox,
        worker_id,
        worker_signing_key,
        controller_keys,
    )
    .await?;
    serde_json::from_slice(plaintext.as_slice()).map_err(|e| ClaimClientError::Serde(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegix_workflow_job_protocol::{seal_secrets, SealedSecrets};

    fn request(sealing: u8, inline_ciphertext: Vec<u8>) -> aegix_workflow_job_protocol::JobRequest {
        use aegix_workflow_job_protocol::{EncryptedSecrets, JobRequest, LlmTier, WriteCeiling};
        JobRequest {
            crypto_scheme: 0,
            sealing,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://m/v1".to_string(),
            input_payload: serde_json::json!({}).into(),
            encrypted_secrets: EncryptedSecrets {
                ciphertext: inline_ciphertext,
                nonce: vec![0u8; 12],
            },
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            http_verb_ceiling: None,
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            read_only_posts: Vec::new(),
            reply_topic: None,
            idempotency_key: None,
            dispatch_attempt: 0,
        }
    }

    /// The claim a worker builds names the attempt it received, signed
    /// (finding 8).
    #[test]
    fn a_claim_names_the_attempt_the_worker_received() {
        let sk = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let (_we, payload) = build_claim(Uuid::new_v4(), 3, "w", &sk).unwrap();
        let claim: SecretClaim = serde_json::from_slice(&payload).unwrap();
        assert_eq!(claim.dispatch_attempt, 3);
        claim
            .verify(&sk.verifying_key(), 60)
            .expect("signed over the attempt it names");
    }

    /// Finding 6 (2026-11-06): under `required` an inline envelope that would
    /// decrypt something is refused; an empty one, a claim-sealed dispatch,
    /// and every shape outside `required` are not. Mutation-proved: with the
    /// `sealing_required &&` arm replaced by `false &&`, the first assertion
    /// fails.
    #[test]
    fn under_required_only_a_non_empty_inline_envelope_is_refused() {
        use aegix_workflow_job_protocol::SEALING_CLAIM_ECIES;
        let fleet_key_envelope = vec![1u8; 48];
        assert!(
            inline_envelope_refused(true, &request(0, fleet_key_envelope.clone())),
            "a sealing=0 envelope with ciphertext is the refused downgrade"
        );
        assert!(
            !inline_envelope_refused(true, &request(0, Vec::new())),
            "an empty inline envelope decrypts nothing (a secretless node)"
        );
        assert!(!inline_envelope_refused(
            true,
            &request(SEALING_CLAIM_ECIES, Vec::new())
        ));
        assert!(
            !inline_envelope_refused(
                true,
                &request(SEALING_CLAIM_ECIES, fleet_key_envelope.clone())
            ),
            "a claim-sealed dispatch never opens its inline field"
        );
        assert!(
            !inline_envelope_refused(false, &request(0, fleet_key_envelope)),
            "off/audit handle the inline envelope"
        );
    }

    #[test]
    fn a_taken_step_map_leaves_nothing_behind() {
        let map = |v: &str| -> SecretMap {
            [("k".to_string(), Zeroizing::new(v.to_string()))]
                .into_iter()
                .collect()
        };
        let mut maps = vec![map("s0"), map("s1")];
        assert_eq!(
            take_step_secrets(&mut maps, 0).get("k").unwrap().as_str(),
            "s0"
        );
        assert!(
            take_step_secrets(&mut maps, 0).is_empty(),
            "a taken map is moved, not copied"
        );
        assert!(take_step_secrets(&mut maps, 9).is_empty());
        assert_eq!(
            take_step_secrets(&mut maps, 1).get("k").unwrap().as_str(),
            "s1"
        );
    }

    /// The claim client's maps are `SecretMap`s: a value is `Zeroizing`, which
    /// is what wipes it on drop. This pins the type at the one place a sealed
    /// reply is parsed, so a plain `HashMap<String, String>` cannot come back
    /// without this test changing (structural lint check 107 holds the rest).
    #[test]
    fn a_parsed_reply_holds_zeroizing_values() {
        fn is_zeroizing(_: &Zeroizing<String>) {}
        let map: SecretMap = serde_json::from_str(r#"{"k":"v"}"#).unwrap();
        is_zeroizing(map.get("k").unwrap());
        let steps: Vec<SecretMap> = serde_json::from_str(r#"[{"k":"v"},{}]"#).unwrap();
        is_zeroizing(steps[0].get("k").unwrap());
    }

    #[test]
    fn build_and_process_roundtrip_against_simulated_controller() {
        let worker_sk = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let controller_sk = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let controller_vk = controller_sk.verifying_key();
        let job_id = uuid::Uuid::new_v4();

        // Worker builds the claim.
        let (we, claim_payload) = build_claim(job_id, 0, "worker-7", &worker_sk).unwrap();
        let claim: SecretClaim = serde_json::from_slice(&claim_payload).unwrap();
        assert_eq!(claim.exec_id, job_id);

        // Simulate the controller: seal the secrets to the claim's epk_w.
        let secrets: SecretMap = [(
            "anthropic/api_key".to_string(),
            Zeroizing::new("sk-ant-x".to_string()),
        )]
        .into_iter()
        .collect();
        let secrets_json = serde_json::to_vec(&secrets).unwrap();
        let out =
            seal_secrets(&claim.epk_w, claim.exec_id, &claim.worker_id, &secrets_json).unwrap();
        let sealed = SealedSecrets::new_signed(claim.exec_id, out, &controller_sk);
        let reply = serde_json::to_vec(&ClaimResponse::Sealed(sealed)).unwrap();

        // Worker opens the reply.
        let map = process_reply(we, job_id, "worker-7", &[controller_vk], &reply).unwrap();
        assert_eq!(map.get("anthropic/api_key").unwrap().as_str(), "sk-ant-x");
    }

    #[test]
    fn rejected_reply_fails_closed() {
        let worker_sk = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let controller_vk =
            aegix_workflow_job_protocol::generate_dispatch_signing_key().verifying_key();
        let job_id = uuid::Uuid::new_v4();
        let (we, _payload) = build_claim(job_id, 0, "w", &worker_sk).unwrap();
        let reply = serde_json::to_vec(&ClaimResponse::Rejected {
            reason: "unknown execution".to_string(),
        })
        .unwrap();
        let err = process_reply(we, job_id, "w", &[controller_vk], &reply).unwrap_err();
        assert!(matches!(err, ClaimClientError::Rejected(_)));
    }

    #[test]
    fn wrong_controller_key_fails_verify() {
        let worker_sk = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let real_controller = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let wrong_vk = aegix_workflow_job_protocol::generate_dispatch_signing_key().verifying_key();
        let job_id = uuid::Uuid::new_v4();
        let (we, claim_payload) = build_claim(job_id, 0, "w", &worker_sk).unwrap();
        let claim: SecretClaim = serde_json::from_slice(&claim_payload).unwrap();
        let out = seal_secrets(&claim.epk_w, claim.exec_id, &claim.worker_id, b"{}").unwrap();
        let sealed = SealedSecrets::new_signed(claim.exec_id, out, &real_controller);
        let reply = serde_json::to_vec(&ClaimResponse::Sealed(sealed)).unwrap();
        // Worker only trusts `wrong_vk` → verify fails.
        let err = process_reply(we, job_id, "w", &[wrong_vk], &reply).unwrap_err();
        assert!(matches!(err, ClaimClientError::VerifyFailed));
    }
}
