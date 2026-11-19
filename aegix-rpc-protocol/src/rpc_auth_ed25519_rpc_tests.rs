//! RFC 0010 P2 inc.3: per-worker Ed25519 RPC signing. These exercise the
//! pure key-explicit cores so they need neither the process-global signing
//! slot nor the `AEGIX_WORKER_PUBLIC_KEYS` env registry.
use super::*;
use aegix_workflow_job_protocol::DispatchSigningKey;

fn keypair() -> DispatchSigningKey {
    aegix_workflow_job_protocol::generate_dispatch_signing_key()
}

#[test]
fn sign_verify_roundtrip() {
    let sk = keypair();
    let pk = sk.verifying_key();
    let actor = Uuid::new_v4();
    let nonce = random_nonce();
    let body = b"canonical-body-bytes";
    let sig = sign_ed25519_with_key(&sk, "memory_rpc", actor, &nonce, body, "worker-7");
    assert_eq!(sig.len(), 64, "Ed25519 signatures are 64 bytes");
    assert!(verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &nonce,
        body,
        "worker-7",
        &sig,
        &[pk]
    ));
}

#[test]
fn wrong_worker_key_fails() {
    // A request signed by worker-a's key must not verify against worker-b's
    // key — a compromised worker can only sign as itself.
    let a = keypair();
    let b_pk = keypair().verifying_key();
    let actor = Uuid::new_v4();
    let nonce = random_nonce();
    let sig = sign_ed25519_with_key(&a, "memory_rpc", actor, &nonce, b"x", "worker-a");
    assert!(!verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &nonce,
        b"x",
        "worker-a",
        &sig,
        &[b_pk]
    ));
}

#[test]
fn tampered_worker_id_fails() {
    // `worker_id` is bound into the signed input, so swapping it (to try to
    // impersonate another worker whose key the controller trusts) breaks
    // the signature.
    let sk = keypair();
    let pk = sk.verifying_key();
    let actor = Uuid::new_v4();
    let nonce = random_nonce();
    let sig = sign_ed25519_with_key(&sk, "memory_rpc", actor, &nonce, b"x", "worker-a");
    assert!(!verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &nonce,
        b"x",
        "worker-b",
        &sig,
        &[pk]
    ));
}

#[test]
fn tampered_subject_actor_nonce_body_fail() {
    let sk = keypair();
    let pk = sk.verifying_key();
    let actor = Uuid::new_v4();
    let nonce = random_nonce();
    let sig = sign_ed25519_with_key(&sk, "memory_rpc", actor, &nonce, b"body", "w");
    // Cross-subject replay (memory sig presented as graph) fails.
    assert!(!verify_ed25519_with_keys(
        "graph_rpc",
        actor,
        &nonce,
        b"body",
        "w",
        &sig,
        &[pk]
    ));
    // Cross-actor replay fails.
    assert!(!verify_ed25519_with_keys(
        "memory_rpc",
        Uuid::new_v4(),
        &nonce,
        b"body",
        "w",
        &sig,
        &[pk]
    ));
    // Tampered body fails.
    assert!(!verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &nonce,
        b"body2",
        "w",
        &sig,
        &[pk]
    ));
    // Tampered nonce fails.
    assert!(!verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &random_nonce(),
        b"body",
        "w",
        &sig,
        &[pk]
    ));
}

#[test]
fn rotation_overlap_verifies() {
    // Signed under the current key; a controller carrying [rotated_in, old]
    // still validates (first match wins), so a worker-key rotation with an
    // overlap window doesn't drop in-flight RPC.
    let old = keypair();
    let new_pk = keypair().verifying_key();
    let actor = Uuid::new_v4();
    let nonce = random_nonce();
    let sig = sign_ed25519_with_key(&old, "memory_rpc", actor, &nonce, b"x", "w");
    assert!(verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &nonce,
        b"x",
        "w",
        &sig,
        &[new_pk, old.verifying_key()]
    ));
}

#[test]
fn empty_worker_id_or_keyset_fails_closed() {
    let sk = keypair();
    let pk = sk.verifying_key();
    let actor = Uuid::new_v4();
    let nonce = random_nonce();
    let sig = sign_ed25519_with_key(&sk, "memory_rpc", actor, &nonce, b"x", "");
    // Empty worker_id: fail closed even with a matching key.
    assert!(!verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &nonce,
        b"x",
        "",
        &sig,
        &[pk]
    ));
    // Empty keyset (unknown worker): fail closed.
    let sig2 = sign_ed25519_with_key(&sk, "memory_rpc", actor, &nonce, b"x", "w");
    assert!(!verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &nonce,
        b"x",
        "w",
        &sig2,
        &[]
    ));
}

#[test]
fn malformed_signature_fails_closed() {
    let pk = keypair().verifying_key();
    let actor = Uuid::new_v4();
    let nonce = random_nonce();
    // Not 64 bytes → Signature::from_slice errors → false, no panic.
    assert!(!verify_ed25519_with_keys(
        "memory_rpc",
        actor,
        &nonce,
        b"x",
        "w",
        b"short",
        &[pk]
    ));
}

/// The classification split at its source. `verify_ed25519_classified`
/// is the only place that can tell "no key for this signer" apart from
/// "key present, bytes disagree", and the two verdicts send an operator
/// in opposite directions (register/rotate a key vs. roll the fleet), so
/// the split is pinned against the REAL registry rather than the
/// key-explicit core.
///
/// Registers a key under a test-only `worker_id`; the registry setter
/// merges over the env base and other tests here never consult it, so
/// this cannot perturb them.
#[test]
fn classified_ed25519_splits_unknown_signer_from_bad_signature() {
    const WID: &str = "rpc-classification-test-worker";
    let sk = keypair();
    aegix_workflow_job_protocol::set_dynamic_worker_public_keys([(
        WID.to_string(),
        sk.verifying_key(),
    )]);
    let actor = Uuid::new_v4();
    let nonce = random_nonce();
    let sig = sign_ed25519_with_key(&sk, "memory_rpc", actor, &nonce, b"body", WID);

    assert_eq!(
        verify_ed25519_classified("memory_rpc", actor, &nonce, b"body", WID, &sig),
        Ok(())
    );

    // Key present, bytes disagree → the deploy-skew class.
    assert_eq!(
        verify_ed25519_classified("memory_rpc", actor, &nonce, b"other-body", WID, &sig),
        Err(VerifyFailure::BadSignature)
    );

    // Same signature, a signer we hold no key for → the config class.
    assert_eq!(
        verify_ed25519_classified(
            "memory_rpc",
            actor,
            &nonce,
            b"body",
            "some-other-worker",
            &sig
        ),
        Err(VerifyFailure::UnknownSignerKey)
    );

    // A malformed (wrong-width) signature from a KNOWN signer is a bytes
    // problem, not a key-resolution one.
    assert_eq!(
        verify_ed25519_classified("memory_rpc", actor, &nonce, b"body", WID, b"short"),
        Err(VerifyFailure::BadSignature)
    );
}

#[test]
fn ed25519_input_domain_separated_from_hmac_payload() {
    // The Ed25519 input must never equal the bare HMAC payload — otherwise
    // a signature could be lifted between schemes. The domain tag + bound
    // worker_id guarantee the extra suffix.
    let actor = Uuid::new_v4();
    let hmac_payload = signing_payload("memory_rpc", actor, "n", b"body");
    let ed_input = ed25519_signing_input("memory_rpc", actor, "n", b"body", "w");
    assert!(ed_input.len() > hmac_payload.len());
    assert!(ed_input.starts_with(&hmac_payload));
}
