//! The crate's main test module: the signed messages end to end. It reads
//! the crate root as it did when it was the last 2,900 lines of `lib.rs`
//! (moved 2026-11-18; `lib.rs` declares it).

use super::*;

fn test_key() -> Vec<u8> {
    vec![0x42u8; 32] // 32-byte test key
}

#[test]
fn test_encrypt_decrypt_roundtrip() {
    let key = test_key();
    let mut secrets = HashMap::new();
    secrets.insert("slack/token".to_string(), "xoxb-secret".to_string());
    secrets.insert("api/key".to_string(), "sk-12345".to_string());

    let encrypted = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
    assert!(!encrypted.ciphertext.is_empty());
    assert_eq!(encrypted.nonce.len(), 12);

    let decrypted = encrypted.decrypt(&key).unwrap();
    assert_eq!(plain_secret_map(&decrypted), secrets);
}

#[test]
fn test_wrong_key_fails_decryption() {
    let key1 = test_key();
    let key2 = vec![0xFFu8; 32];
    let mut secrets = HashMap::new();
    secrets.insert("key".to_string(), "value".to_string());

    let encrypted = EncryptedSecrets::encrypt(&secrets, &key1).unwrap();
    let result = encrypted.decrypt(&key2);
    assert!(result.is_err());
}

/// L-1: AAD round-trip — encrypt with AAD, decrypt with the same
/// AAD, get the original plaintext back.
#[test]
fn aad_round_trip_succeeds() {
    let key = test_key();
    let mut secrets = HashMap::new();
    secrets.insert("anthropic/api_key".to_string(), "sk-xyz".to_string());
    let aad = b"job:abc-123";
    let enc = EncryptedSecrets::encrypt_with_aad(&secrets, &key, aad).unwrap();
    let dec = enc.decrypt_with_aad(&key, aad).unwrap();
    assert_eq!(plain_secret_map(&dec), secrets);
}

/// L-1: decrypting with a DIFFERENT AAD must fail. This is the
/// core anti-transposition property — an attacker who lifts an
/// EncryptedSecrets blob from one JobRequest into another (under
/// the same shared key) cannot decrypt the lifted ciphertext if
/// the new JobRequest's AAD differs from the original.
#[test]
fn aad_mismatch_fails_decryption() {
    let key = test_key();
    let mut secrets = HashMap::new();
    secrets.insert("anthropic/api_key".to_string(), "sk-xyz".to_string());
    let enc = EncryptedSecrets::encrypt_with_aad(&secrets, &key, b"job:abc").unwrap();
    // Same key, same ciphertext — but different AAD context.
    let bad = enc.decrypt_with_aad(&key, b"job:zzz");
    assert!(
        bad.is_err(),
        "decrypt with different AAD must fail (anti-transposition gate)"
    );
    let msg = bad.unwrap_err();
    assert!(
        msg.contains("decryption failed"),
        "expected GCM tag error, got: {msg}"
    );
}

/// The envelope cipher key is an HKDF subkey of the root, not the
/// root itself — so it is distinct from the HMAC signing key, which
/// uses the root bytes directly. Derivation is deterministic so the
/// controller (seal) and worker (open) compute the same subkey.
#[test]
fn envelope_subkey_is_domain_separated_and_deterministic() {
    let root = [7u8; 32];
    let subkey = derive_envelope_aead_key_v1(&root);
    assert_ne!(
        &subkey[..],
        &root[..],
        "envelope subkey must differ from the root (== the signing key)"
    );
    assert_eq!(
        subkey,
        derive_envelope_aead_key_v1(&root),
        "derivation must be deterministic across processes"
    );
    // v2 per-job derivation: distinct jobs derive distinct keys, and
    // each differs from the v1 static key (finding #1).
    let k_a = derive_envelope_aead_key_v2(&root, b"job:aaa");
    let k_b = derive_envelope_aead_key_v2(&root, b"job:bbb");
    assert_ne!(
        k_a, k_b,
        "different jobs must derive different envelope keys"
    );
    assert_ne!(
        k_a, subkey,
        "v2 per-job key must differ from the v1 static key"
    );
    assert_eq!(
        k_a,
        derive_envelope_aead_key_v2(&root, b"job:aaa"),
        "v2 derivation must be deterministic across processes"
    );
}

/// An envelope sealed under the legacy v1 static key with a per-job AAD
/// does not open: the v2→v1 fallback for a not-yet-rolled controller was
/// removed on 2026-10-14 (B-10), four months after v2 sealing shipped.
#[test]
fn a_per_job_envelope_does_not_open_under_the_v1_key() {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};
    let key = test_key();
    let mut secrets = HashMap::new();
    secrets.insert("anthropic/api_key".to_string(), "sk-legacy".to_string());
    let aad = b"job:legacy-1";

    // Hand-seal a v1 envelope: static key + aad bound in the tag.
    let v1_key = derive_envelope_aead_key_v1(&key);
    let cipher = Aes256Gcm::new_from_slice(&v1_key).unwrap();
    let nonce_bytes = [3u8; 12];
    let plaintext = serde_json::to_vec(&secrets).unwrap();
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce_bytes),
            Payload {
                msg: plaintext.as_ref(),
                aad,
            },
        )
        .unwrap();
    let env = EncryptedSecrets {
        ciphertext,
        nonce: nonce_bytes.to_vec(),
    };
    // Since 2026-10-14 (B-10) a per-job envelope opens only under its v2
    // key: the v1 static key no longer opens one.
    assert!(env.decrypt_with_aad(&key, aad).is_err());
}

/// The strongest proof the slice does what Part 2 claims: a sealed
/// envelope must NOT open under the raw root key (which is also the
/// HMAC signing key), only under the derived subkey that
/// `decrypt_with_aad` reconstructs.
#[test]
fn envelope_does_not_open_under_the_raw_signing_key() {
    use aes_gcm::{
        aead::{Aead, KeyInit, Payload},
        Aes256Gcm, Nonce,
    };
    let root = [9u8; 32];
    let mut secrets = HashMap::new();
    secrets.insert("api_key".to_string(), "sk-xyz".to_string());
    let aad = b"exec-123";

    let env = EncryptedSecrets::encrypt_with_aad(&secrets, &root, aad).unwrap();

    // Opens via the normal path (which derives the subkey).
    assert_eq!(
        plain_secret_map(&env.decrypt_with_aad(&root, aad).unwrap()),
        secrets
    );

    // Must NOT open if you treat the raw root as the AES-GCM key.
    let raw_cipher = Aes256Gcm::new_from_slice(&root).unwrap();
    let nonce = <&Nonce<_>>::try_from(env.nonce.as_slice()).unwrap();
    let opened_raw = raw_cipher.decrypt(
        nonce,
        Payload {
            msg: env.ciphertext.as_ref(),
            aad,
        },
    );
    assert!(
        opened_raw.is_err(),
        "ciphertext must not open under the raw signing key"
    );
}

/// L-1: backwards compatibility — `encrypt`/`decrypt` (no AAD)
/// continue to interoperate with each other. Critical so
/// existing dispatch paths that haven't migrated to the AAD form
/// keep working.
#[test]
fn no_aad_round_trip_still_works() {
    let key = test_key();
    let mut secrets = HashMap::new();
    secrets.insert("k".to_string(), "v".to_string());
    let enc = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
    let dec = enc.decrypt(&key).unwrap();
    assert_eq!(plain_secret_map(&dec), secrets);
}

/// L-1: encrypt-no-AAD + decrypt-with-AAD must fail. Confirms the
/// AES-GCM tag binding is one-way — there's no "matches when one
/// side is empty" silent-success path.
#[test]
fn mixed_aad_modes_fail_decryption() {
    let key = test_key();
    let mut secrets = HashMap::new();
    secrets.insert("k".to_string(), "v".to_string());
    let enc = EncryptedSecrets::encrypt(&secrets, &key).unwrap();
    // Encrypted with empty AAD; decrypt with non-empty AAD.
    let bad = enc.decrypt_with_aad(&key, b"any");
    assert!(bad.is_err());

    let enc2 = EncryptedSecrets::encrypt_with_aad(&secrets, &key, b"any").unwrap();
    // Encrypted with AAD; decrypt with empty (legacy `decrypt`).
    let bad2 = enc2.decrypt(&key);
    assert!(bad2.is_err());
}

#[test]
fn test_replay_within_window_is_rejected() {
    // Sign a request, verify it once (admitted), then verify the
    // same bytes again — the nonce cache should reject the second
    // verify as a replay even though HMAC + freshness still pass.
    //
    // Serialized against the tests that wipe/bulk-fill the process-global
    // nonce cache — see NONCE_CACHE_TEST_SERIAL.
    let _serial = crate::NONCE_CACHE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let key = test_key();
    let mut req = JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "wasm://module/v1".to_string(),
        input_payload: serde_json::json!({"replay_test": true}).into(),
        encrypted_secrets: EncryptedSecrets::empty(),
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
    };
    req.sign(&key).unwrap();

    // First verification admits the nonce.
    req.verify(&key, 300).expect("first verify should succeed");

    // Second verification of the same JobRequest must now fail —
    // the nonce was already recorded. Error message should mention
    // replay so operators can correlate logs.
    let err = req
        .verify(&key, 300)
        .expect_err("second verify should be rejected as replay");
    assert!(
        err.contains("replay"),
        "replay rejection message should contain 'replay'; got: {err}"
    );
}

#[test]
fn test_sign_and_verify() {
    let key = test_key();
    let mut req = JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "wasm://module/v1".to_string(),
        input_payload: serde_json::json!({}).into(),
        encrypted_secrets: EncryptedSecrets::empty(),
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
    };

    req.sign(&key).unwrap();
    assert!(!req.signature.is_empty());
    assert!(!req.job_nonce.is_empty());

    // Verification should pass
    req.verify(&key, 300).unwrap();
}

#[test]
fn test_tampered_signature_fails() {
    let key = test_key();
    let mut req = JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "wasm://module/v1".to_string(),
        input_payload: serde_json::json!({}).into(),
        encrypted_secrets: EncryptedSecrets::empty(),
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
    };
    req.sign(&key).unwrap();
    req.module_uri = "wasm://evil-module/v1".to_string(); // tamper
    let result = req.verify(&key, 300);
    assert!(result.is_err());
}

#[test]
fn test_job_result_sign_and_verify() {
    let key = test_key();
    let mut result = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({"answer": 42}).into(),
        logs: vec![],
        execution_time_ms: 150,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };

    result.sign(&key).unwrap();
    assert!(!result.signature.is_empty());
    assert!(!result.result_nonce.is_empty());

    result.verify(&key, 300).unwrap();
}

#[test]
fn test_job_result_tampered_fails() {
    let key = test_key();
    let mut result = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({"answer": 42}).into(),
        logs: vec![],
        execution_time_ms: 150,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };
    result.sign(&key).unwrap();
    result.output_payload = serde_json::json!({"answer": 99}).into(); // tamper
    assert!(result.verify(&key, 300).is_err());
}

/// L-4: `verify_as(Verifier::Primary)` matches `verify()` exactly —
/// records the nonce, so a second `Primary` call against the same
/// result trips the replay cache. `verify_as(Verifier::Observer)`
/// matches `verify_no_replay()` — no cache mutation, so repeated
/// `Observer` calls succeed and an `Observer` followed by a
/// `Primary` also succeeds (the primary records the nonce on its
/// first call).
#[test]
fn verifier_primary_records_replay_observer_does_not() {
    // Serialized against the tests that wipe/bulk-fill the process-global
    // nonce cache — see NONCE_CACHE_TEST_SERIAL.
    let _serial = crate::NONCE_CACHE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let key = test_key();
    let mut a = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({}).into(),
        logs: vec![],
        execution_time_ms: 1,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };
    a.sign(&key).unwrap();

    // Observer is idempotent — repeated calls succeed.
    a.verify_as(&key, 300, Verifier::Observer).unwrap();
    a.verify_as(&key, 300, Verifier::Observer).unwrap();

    // Primary records the nonce — second Primary call must fail.
    a.verify_as(&key, 300, Verifier::Primary).unwrap();
    let second = a.verify_as(&key, 300, Verifier::Primary);
    assert!(
        second.is_err(),
        "second Primary verify must trip the replay cache"
    );
    let msg = second.unwrap_err();
    assert!(
        msg.contains("already seen"),
        "expected replay-cache error, got: {msg}"
    );
}

/// L-4: an Observer-first-then-Primary sequence is the canonical
/// production pattern (audit subscriber runs concurrently with
/// the primary). Both must succeed; only the second Primary
/// would fail (covered by the test above).
#[test]
fn verifier_observer_then_primary_both_succeed() {
    let key = test_key();
    let mut a = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({}).into(),
        logs: vec![],
        execution_time_ms: 1,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };
    a.sign(&key).unwrap();
    a.verify_as(&key, 300, Verifier::Observer).unwrap();
    a.verify_as(&key, 300, Verifier::Primary).unwrap();
}

/// L-4: tampering still gates both roles via the HMAC check.
#[test]
fn verifier_rejects_tampered_signature_in_both_roles() {
    let key = test_key();
    let mut a = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({"answer": 42}).into(),
        logs: vec![],
        execution_time_ms: 1,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };
    a.sign(&key).unwrap();
    a.output_payload = serde_json::json!({"answer": 99}).into();
    assert!(a.verify_as(&key, 300, Verifier::Observer).is_err());
    assert!(a.verify_as(&key, 300, Verifier::Primary).is_err());
}

#[test]
fn test_tampered_allowed_methods_fails() {
    let key = test_key();
    let mut req = JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "wasm://module/v1".to_string(),
        input_payload: serde_json::json!({}).into(),
        encrypted_secrets: EncryptedSecrets::empty(),
        timeout_ms: 30000,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        allowed_hosts: vec!["api.example.com".to_string()],
        allowed_methods: vec!["GET".to_string()],
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
    };
    req.sign(&key).unwrap();
    // An attacker cannot escalate from GET-only to POST by modifying the field.
    req.allowed_methods = vec!["GET".to_string(), "POST".to_string()];
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered allowed_methods must fail verification"
    );
}

#[test]
fn test_allowed_methods_order_independent() {
    let key = test_key();
    let mut req = JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "wasm://module/v1".to_string(),
        input_payload: serde_json::json!({}).into(),
        encrypted_secrets: EncryptedSecrets::empty(),
        timeout_ms: 30000,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        allowed_hosts: vec![],
        allowed_methods: vec!["POST".to_string(), "GET".to_string()],
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
    };
    req.sign(&key).unwrap();
    // Reordering must not affect verification (sorted before hashing).
    req.allowed_methods = vec!["GET".to_string(), "POST".to_string()];
    req.verify(&key, 300)
        .expect("order-independent allowed_methods must still verify");
}

#[test]
fn test_job_result_unsigned_fails() {
    let key = test_key();
    let result = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({}).into(),
        logs: vec![],
        execution_time_ms: 0,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };
    assert!(result.verify(&key, 300).is_err());
}

/// Helper for the new wire-format binding tests below: build a
/// minimal JobRequest with the named overrides applied. Callers
/// `.sign()` themselves before tampering / re-verifying.
fn make_test_request(actor_id: Option<Uuid>) -> JobRequest {
    JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "wasm://m/v1".to_string(),
        input_payload: serde_json::json!({}).into(),
        encrypted_secrets: EncryptedSecrets::empty(),
        timeout_ms: 30000,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec!["slack/token".to_string()],
        allowed_sql_operations: vec!["SELECT".to_string()],
        allow_tier2_exposure: false,
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        max_write_ceiling: WriteCeiling::default(),
        egress_scope: None,
        http_verb_ceiling: None,
        job_nonce: String::new(),
        actor_id,
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

// ── RFC 0010 P1: Ed25519 dispatch scheme tests ────────────────────────

/// The ACTUAL 2026-07-27 root cause: `serde_json`'s f64 round-trip is not
/// idempotent, so a payload carrying an unstable float hashed differently
/// on each side and every such dispatch failed Ed25519 verification.
///
/// Uses the exact bit pattern found by the search, plus a computed ratio
/// of the kind the operator digest is full of (pass_rate, agreement,
/// Wilson bounds) — ~10% of which are unstable.
#[test]
fn signing_survives_floats_whose_json_round_trip_is_not_idempotent() {
    // Precondition: this float really does drift through a round trip.
    // If serde_json ever fixes this, the assert below documents why the
    // canonicalisation existed rather than silently becoming dead weight.
    let drifty = f64::from_bits(0x2284_3773_1ab4_9c0f);
    let once = serde_json::json!({ "x": drifty }).to_string();
    let twice = serde_json::from_str::<serde_json::Value>(&once)
        .unwrap()
        .to_string();
    assert_ne!(once, twice, "expected a non-idempotent float round trip");

    let sk = ed_keypair();
    let vk = sk.verifying_key();
    for payload in [
        serde_json::json!({ "avg_score": drifty }),
        // A digest-shaped body: computed ratios at several magnitudes.
        serde_json::json!({
            "judge_scores": (1..40).map(|i| serde_json::json!({
                "avg_score": f64::from(i) / 37.0,
                "pass_rate": f64::from(i) / 91.0,
                "ci95": [f64::from(i) / 7.0, f64::from(i) / 13.0],
            })).collect::<Vec<_>>(),
        }),
    ] {
        let mut req = minimal_req();
        req.input_payload = payload.into();
        req.sign_ed25519(&sk).unwrap();

        // The wire hop: the worker re-parses, landing on the DRIFTED
        // float, and must still verify.
        let wire = serde_json::to_vec(&req).unwrap();
        let received: JobRequest = serde_json::from_slice(&wire).unwrap();
        received
            .verify_ed25519(&[vk], 300)
            .expect("signature must survive a non-idempotent float round trip");
    }
}

/// Reproduction attempt for the 2026-07-27 `pa-autonomy-digest` incident:
/// Ed25519 dispatch verification fails reproducibly for one node whose
/// `input_payload` is 50-61 KB, while a comparable node at ~21 KB verifies.
///
/// Exercises the FULL wire path — sign, serialise to JSON as the dispatcher
/// publishes, deserialise as the worker receives, verify — across sizes
/// spanning both cases, with a nested/heterogeneous shape resembling the
/// operator digest (floats with long mantissas, prose strings, arrays of
/// objects) rather than one flat blob, since a size-dependent fault is more
/// likely to live in structure than in raw length.
#[test]
fn ed25519_dispatch_verifies_across_realistic_input_sizes() {
    let sk = ed_keypair();
    let vk = sk.verifying_key();

    for target_kb in [1usize, 21, 50, 61, 80, 130] {
        // Build a digest-shaped payload until it exceeds target_kb.
        let mut rows = Vec::new();
        while serde_json::to_string(&rows).unwrap().len() < target_kb * 1024 {
            let i = rows.len();
            rows.push(serde_json::json!({
                "name": format!("workflow-{i}"),
                "avg_score": 0.927_272_727_272_727_2_f64,
                "ci95": [0.329_942_360_025_097_3_f64, 0.644_311_954_041_314_1_f64],
                "note": "every run scored identically at the maximum — this judge \
                          has not been observed to fail anything, so it may be a \
                          shape check rather than a quality gate",
                "nested": { "by_label": [["archive", 538], ["to_read", 409]] },
            }));
        }
        let payload = serde_json::json!({ "rows": rows, "days": 1 });
        let byte_len = payload.to_string().len();

        let mut req = JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "redis:wasm:tenant:module".to_string(),
            input_payload: payload.into(),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 120_000,
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
            actor_id: Some(Uuid::new_v4()),
            wasm_bytes: None,
            capability_world: Some("secrets-node".to_string()),
            integration_name: None,
            user_id: Uuid::new_v4(),
            expected_wasm_hash: None,
            max_fuel: 12_000_000,
            dry_run: false,
            read_only_posts: Vec::new(),
            reply_topic: None,
            idempotency_key: None,
            dispatch_attempt: 0,
        };
        req.sign_ed25519(&sk).unwrap();

        // The wire hop the dispatcher/worker actually perform.
        let wire = serde_json::to_vec(&req).expect("serialise");
        let received: JobRequest = serde_json::from_slice(&wire).expect("deserialise");

        // The RAW length, which is now what the signature covers — the
        // received payload's text must be the transmitted text byte-for-byte.
        assert_eq!(
            received.input_payload.raw_len(),
            byte_len,
            "input length changed across the wire at {target_kb} KB"
        );
        received.verify_ed25519(&[vk], 300).unwrap_or_else(|e| {
            panic!("Ed25519 verify FAILED at ~{target_kb} KB ({byte_len} bytes): {e}")
        });
    }
}

/// Minimal signable JobRequest for signing tests.
fn minimal_req() -> JobRequest {
    JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "redis:wasm:tenant:module".to_string(),
        input_payload: serde_json::json!({}).into(),
        encrypted_secrets: EncryptedSecrets::empty(),
        timeout_ms: 120_000,
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
        actor_id: Some(Uuid::new_v4()),
        wasm_bytes: None,
        capability_world: Some("secrets-node".to_string()),
        integration_name: None,
        user_id: Uuid::new_v4(),
        expected_wasm_hash: None,
        max_fuel: 12_000_000,
        dry_run: false,
        read_only_posts: Vec::new(),
        reply_topic: None,
        idempotency_key: None,
        dispatch_attempt: 0,
    }
}

// ── Wire-invariant property harness ───────────────────────────────────
//
// The 2026-07-27 dispatch-signature outage was found by SEARCH, not by
// deduction: six reasoned hypotheses were wrong, and a property test that
// simply asked "is the round trip ever unstable?" found the cause in
// seconds. These tests encode that technique so the next wire-format
// change is checked the same way.
//
// Every existing hand-written sign/verify test uses `json!({})` payloads,
// which is structurally incapable of catching a payload-DEPENDENT fault.
// The generator deliberately produces the shapes that broke us: floats
// from raw bit patterns (the actual failure), deep nesting, mixed arrays,
// unicode, and integers at type boundaries.
//
// The generator itself lives in `crate::test_support` — also published to
// downstream dev-builds behind the non-default `test-support` feature —
// so the aegix-memory signed-wire suite tests against the SAME adversary
// rather than a copy. The #598 fork of this generator drifted within one
// release: it never grew the size-independence, text-vs-meaning, or
// transcode assertions this suite has.
use crate::test_support::{arbitrary_json, round_trip_unstable_count};

/// The public surface of the SHARED generic and its `Value` alias.
///
/// `SignedJson` is a `pub type` alias of `RawSigned<serde_json::Value>`,
/// so the two accessor spellings must BOTH resolve on it: the generic
/// `get()`/`into_inner()` (what `aegix-memory` calls on
/// `RawSigned<MemoryOp>`) and the Value-flavoured `value()`/`into_value()`
/// (what ~70 dispatch call sites call). Pinned as an executable fact
/// because the whole point of the alias was ZERO call-site churn across
/// the unification — drop either spelling and one of the two crates stops
/// compiling, which this catches in the crate that owns the type rather
/// than downstream.
///
/// Also pins `raw_len()` on the GENERIC (not the specialisation): the
/// signature diagnostics report it via `diag_hashes`, so a length that
/// described anything other than the signed bytes would make an outage
/// harder to read, not easier.
#[test]
fn raw_signed_exposes_both_accessor_spellings_and_raw_len() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Op {
        key: String,
        n: u32,
    }
    let payload: SignedJson = serde_json::json!({"a": 1}).into();

    // Generic spelling.
    assert_eq!(payload.get(), &serde_json::json!({"a": 1}));
    // Value-flavoured spelling — same object, different name.
    assert_eq!(payload.value(), &serde_json::json!({"a": 1}));

    // The signed bytes and their length describe the SAME text.
    assert_eq!(payload.raw_bytes(), br#"{"a":1}"#);
    assert_eq!(payload.raw_len(), payload.raw_bytes().len());
    assert_eq!(payload.raw_len(), 7);

    // Both consuming accessors yield the parsed payload.
    assert_eq!(payload.clone().into_inner(), serde_json::json!({"a": 1}));
    assert_eq!(payload.into_value(), serde_json::json!({"a": 1}));

    // The generic instantiates over a typed payload too, and `From`
    // mints the same compact text `Value::to_string` would.
    let typed: RawSigned<Op> = Op {
        key: "k".to_string(),
        n: 1,
    }
    .into();
    assert_eq!(typed.raw_bytes(), br#"{"key":"k","n":1}"#);
    assert_eq!(typed.raw_len(), 17);
    assert_eq!(typed.get().n, 1);
    assert_eq!(typed.into_inner().key, "k");
}

/// INVARIANT 1: the SIGNED BYTES survive the wire unchanged.
///
/// The load-bearing property, and the one that replaced "the canonical form
/// is a fixed point" (#595): no fixed point exists — some floats cycle
/// forever (see `some_floats_have_no_round_trip_fixed_point_known_gap`) —
/// so the fix stopped re-deriving the signed form altogether. What must
/// hold instead is that the payload text the sender hashed is EXACTLY the
/// text the receiver hashes, for arbitrary JSON.
///
/// Asserted at all three levels the signature depends on: the raw bytes,
/// their SHA-256, and — load-bearing — that the digest the REAL
/// `signing_payload()` embeds is that same one. The third assertion is the
/// one with teeth: without it the first two are self-referential (the test
/// would hash `raw_bytes()` itself and prove nothing about the production
/// hash site), so a refactor that quietly re-derived the digest from the
/// parsed value would sail past. Verified by mutation: flipping
/// `signing_payload`'s input hash to `value().to_string()` fails this test.
#[test]
fn signed_payload_bytes_survive_the_wire_for_arbitrary_json() {
    use sha2::Digest;
    let mut seed = 0x5eed_1234_abcd_0001_u64;
    for i in 0..20_000 {
        let mut req = minimal_req();
        req.input_payload = arbitrary_json(&mut seed, 4).into();

        let sent_bytes = req.input_payload.raw_bytes().to_vec();
        let sent_hash = Sha256::digest(&sent_bytes);
        let sent_hash_hex = hex::encode(sent_hash);

        let wire = serde_json::to_vec(&req).expect("serialise");
        let received: JobRequest = serde_json::from_slice(&wire).expect("deserialise");

        assert_eq!(
            received.input_payload.raw_bytes(),
            sent_bytes.as_slice(),
            "iter {i}: signed payload bytes changed across the wire — \
                 signing would break for {}",
            req.input_payload.value()
        );
        assert_eq!(
            Sha256::digest(received.input_payload.raw_bytes()),
            sent_hash,
            "iter {i}: signed payload DIGEST changed across the wire"
        );
        // The digest the signature actually commits to must be the
        // wire-bytes digest, on BOTH sides of the hop.
        for (side, req) in [("sender", &req), ("receiver", &received)] {
            let signed = req.signing_payload();
            // Lossy on purpose: the assertion is an ASCII-hex substring
            // search, so a future non-UTF-8 field must not turn this into
            // an unrelated panic.
            assert!(
                String::from_utf8_lossy(&signed).contains(&sent_hash_hex),
                "iter {i}: {side}'s signing payload does not commit to the \
                     wire-bytes digest — it is hashing a re-derived form"
            );
        }
    }
}

/// INVARIANT 2: sign -> wire -> verify holds for arbitrary payloads.
///
/// The end-to-end property the outage violated. Exercises the real hop:
/// the worker verifies a value it PARSED, never the one the controller
/// held.
#[test]
fn job_request_survives_the_wire_for_arbitrary_payloads() {
    let sk = ed_keypair();
    let vk = sk.verifying_key();
    let mut seed = 0x5eed_1234_abcd_0002_u64;
    for i in 0..2_000 {
        let mut req = minimal_req();
        req.input_payload = arbitrary_json(&mut seed, 4).into();
        req.sign_ed25519(&sk).unwrap();
        let wire = serde_json::to_vec(&req).expect("serialise");
        let received: JobRequest = serde_json::from_slice(&wire).expect("deserialise");
        received.verify_ed25519(&[vk], 300).unwrap_or_else(|e| {
            panic!(
                "iter {i}: verify failed for payload {}: {e}",
                req.input_payload.value()
            )
        });
    }
}

/// INVARIANT 3: the same, for the RESULT direction (worker -> controller).
///
/// `output_payload` is signed by the same mechanism, so it carries the
/// same hazard — a module returning computed floats would have broken
/// result verification identically. Covered explicitly rather than
/// assumed, since the request path is the only one the outage exercised.
#[test]
fn job_result_survives_the_wire_for_arbitrary_payloads() {
    let sk = ed_keypair();
    let vk = sk.verifying_key();
    let mut seed = 0x5eed_1234_abcd_0003_u64;
    for i in 0..2_000 {
        let mut res = JobResult {
            dispatch_attempt: 0,
            workflow_execution_id: None,
            job_id: Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: arbitrary_json(&mut seed, 4).into(),
            logs: vec!["line".to_string()],
            execution_time_ms: 12,
            signature: Vec::new(),
            result_nonce: String::new(),
            worker_id: "worker-1".to_string(),
            crypto_scheme: 0,
            llm_usage: Vec::new(),
            fuel: None,
        };
        res.sign_ed25519_with_worker_id(&sk, "worker-1").unwrap();
        let wire = serde_json::to_vec(&res).expect("serialise");
        let received: JobResult = serde_json::from_slice(&wire).expect("deserialise");
        received
            .verify_ed25519(&[vk], 300)
            .unwrap_or_else(|e| panic!("iter {i}: result verify failed: {e}"));
    }
}

/// The generator must actually produce the hazard it exists to cover —
/// otherwise the three tests above pass vacuously and we would never know.
#[test]
fn generator_actually_produces_round_trip_unstable_floats() {
    let mut seed = 0x5eed_1234_abcd_0004_u64;
    let unstable = round_trip_unstable_count(&mut seed, 20_000, 3);
    assert!(
        unstable > 0,
        "generator produced NO round-trip-unstable value — the wire tests \
             would be passing vacuously"
    );
}

/// Pins the REASON [`SignedJson`] exists as an executable fact rather than
/// a comment.
///
/// #595 normalised signed JSON to its round-trip "fixed point", which
/// closed the observed outage because the digest's floats happened to
/// settle after one pass. This value does NOT settle — it cycles between
/// two representations forever, so no finite number of passes canonicalises
/// it and any signature derived by RE-SERIALISING can still diverge.
///
/// Measured over 199_902 random finite f64: 39_495 settle after one pass,
/// 19_721 need more than one, and some (like this) never do.
///
/// The complete fix was to stop re-deriving: [`SignedJson`] signs the bytes
/// sent and verifies the bytes received, so the cycle below is simply never
/// entered. This test is KEPT rather than deleted — its counterexample is
/// what proves the wire-invariant property tests above are not vacuous, and
/// what would flag a "simplification" back to hashing a re-serialised value.
#[test]
fn some_floats_have_no_round_trip_fixed_point_known_gap() {
    let step = |s: &str| {
        serde_json::from_str::<serde_json::Value>(s)
            .unwrap()
            .to_string()
    };
    // One lead-in step, then a permanent 2-cycle:
    //   ...906e-115 -> ...905e-115 -> ...9045e-115 -> ...905e-115 -> ...
    let x0 = "5.455171886890906e-115".to_string();
    let x1 = step(&x0);
    let x2 = step(&x1);
    let x3 = step(&x2);
    let x4 = step(&x3);
    assert_ne!(x0, x1, "first round trip must drift");
    assert_ne!(x1, x2, "second round trip must drift again");
    assert_eq!(x3, x1, "must enter a 2-cycle");
    assert_eq!(x4, x2, "and stay in it");
    assert_ne!(
        x1, x2,
        "the two cycle members differ — so NO fixed point exists"
    );
}

/// Transcoding a signed message through `serde_json::Value`
/// (`to_value` → `from_value`) SILENTLY BREAKS ITS SIGNATURE.
///
/// This is a trap worth an executable warning, because it does not fail
/// loudly anywhere else: the transcode compiles, runs, and produces a
/// structurally-identical message — but it re-parses and re-serialises the
/// payload, so a round-trip-unstable float lands on different bytes than
/// the ones the sender signed. Serialising to TEXT (what NATS actually
/// carries) preserves the bytes exactly, which is why the wire path is
/// safe and the `Value` detour is not.
///
/// Rule for callers: move `JobRequest` / `JobResult`
/// over the wire as bytes or a string, never via `serde_json::Value`.
#[test]
fn value_transcoding_loses_signed_bytes_but_text_round_trip_does_not() {
    // The known 2-cycle counterexample — see
    // `some_floats_have_no_round_trip_fixed_point_known_gap`.
    let v: serde_json::Value = serde_json::from_str(r#"{"x":5.455171886890906e-115}"#).unwrap();
    let mut r = make_test_result();
    r.output_payload = v.into();
    let signed_bytes = r.output_payload.raw_bytes().to_vec();

    // Text round trip: byte-preserving, so the signature still verifies.
    let wire = serde_json::to_string(&r).unwrap();
    let via_text: JobResult = serde_json::from_str(&wire).unwrap();
    assert_eq!(
        via_text.output_payload.raw_bytes(),
        signed_bytes.as_slice(),
        "the wire path MUST preserve the signed bytes"
    );

    // Value transcode: re-derives the text, and the float drifts.
    let as_value = serde_json::to_value(&r).unwrap();
    let via_value: JobResult = serde_json::from_value(as_value).unwrap();
    assert_ne!(
        via_value.output_payload.raw_bytes(),
        signed_bytes.as_slice(),
        "if this ever starts preserving bytes, serde_json changed — relax \
             the rule deliberately rather than by accident"
    );
}

/// The signature binds the payload's exact TEXT, not its meaning — the
/// security consequence of [`SignedJson`] carrying raw bytes.
///
/// `SignedJson` can hold text no `Value` would ever emit: duplicate keys,
/// padding, non-shortest number spellings. Consumers read the deduplicated
/// parse, so the natural worry is a signed/executed split. This pins both
/// halves of why there isn't one:
///
/// 1. A KEYLESS on-path attacker cannot exploit it. Every rewrite below is
///    semantics-preserving — each parses to the very `Value` the sender
///    signed, so a "canonical form" signature would have ACCEPTED them —
///    and every one is refused, because the digest covers the bytes.
/// 2. A KEY HOLDER can of course sign exotic text, and when it does the
///    two halves stay consistent: the verifier checks the exact bytes and
///    the module executes the last-wins parse of those same bytes. There is
///    no view of the message that disagrees with the one that was signed.
#[test]
fn signature_binds_payload_text_not_meaning() {
    let key = test_key();
    let mut req = minimal_req();
    req.input_payload = serde_json::json!({"a": 1}).into();
    req.sign(&key).unwrap();
    let wire = String::from_utf8(serde_json::to_vec(&req).unwrap()).unwrap();
    let sent = r#""input_payload":{"a":1}"#;
    assert!(wire.contains(sent), "payload text not found on the wire");

    // 1. Keyless rewrites: same meaning, different bytes → all refused.
    for rewrite in [
        r#""input_payload":{"a" : 1}"#,     // interior padding
        r#""input_payload":{"a":0,"a":1}"#, // duplicate key, last-wins
        r#""input_payload":{"a":1.0}"#,     // different number spelling
        // escaped key spelling: same key name, different bytes
        r#""input_payload":{"\u0061":1}"#,
    ] {
        let tampered: JobRequest = serde_json::from_str(&wire.replace(sent, rewrite))
            .unwrap_or_else(|e| panic!("rewrite {rewrite} must still be valid JSON: {e}"));
        assert_eq!(
            tampered.input_payload.value().get("a").unwrap().as_f64(),
            Some(1.0),
            "precondition: {rewrite} must be semantics-preserving, or the \
                 test proves nothing about text-vs-meaning"
        );
        assert!(
            tampered.verify_no_replay(&key, 300).is_err(),
            "rewriting the payload text to {rewrite} must invalidate the \
                 signature — duplicate-key smuggling requires the signing key"
        );
    }

    // 2. Key holder signs duplicate-key text: raw survives the wire and
    //    the parsed view is the last-wins reading of those same bytes.
    let dup = r#""input_payload":{"a":9,"a":1}"#;
    let mut exotic: JobRequest = serde_json::from_str(&wire.replace(sent, dup)).unwrap();
    exotic.sign(&key).unwrap();
    let received: JobRequest =
        serde_json::from_slice(&serde_json::to_vec(&exotic).unwrap()).unwrap();
    assert_eq!(
        received.input_payload.raw_bytes(),
        br#"{"a":9,"a":1}"#,
        "the exotic text must survive the wire verbatim"
    );
    assert_eq!(received.input_payload.value(), &serde_json::json!({"a": 1}));
    received
        .verify_no_replay(&key, 300)
        .expect("text the key holder actually signed must verify");
}

fn ed_keypair() -> DispatchSigningKey {
    crate::generate_dispatch_signing_key()
}

fn hmac_ring(key: &[u8]) -> aegix_dispatch_types::WorkerKeyRing {
    aegix_dispatch_types::WorkerKeyRing::single(aegix_dispatch_types::WorkerSharedKey::new(
        key.to_vec(),
    ))
}

fn make_test_result() -> JobResult {
    JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({"ok": true}).into(),
        logs: vec![],
        execution_time_ms: 12,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    }
}

// ── RFC 0010 P2: per-worker Ed25519 RESULT signing tests ──────────────

#[test]
fn result_ed25519_sign_verify_roundtrip() {
    let worker_signing = ed_keypair();
    let worker_verifying = worker_signing.verifying_key();
    let mut r = make_test_result();
    r.sign_ed25519_with_worker_id(&worker_signing, "talos-worker-7")
        .unwrap();
    assert_eq!(r.crypto_scheme, CRYPTO_SCHEME_ED25519);
    assert_eq!(r.worker_id, "talos-worker-7");
    r.verify_no_replay_ed25519(&[worker_verifying], 300)
        .expect("controller verifies against the worker's public key");
}

#[test]
fn result_ed25519_requires_worker_id() {
    let worker_sk = ed_keypair();
    let mut r = make_test_result();
    assert!(
        r.sign_ed25519_with_worker_id(&worker_sk, "").is_err(),
        "empty worker_id has no registered key to verify against"
    );
}

#[test]
fn result_ed25519_wrong_worker_key_fails() {
    // A result signed by worker-A's key does not verify against worker-B's
    // key — a compromised worker can only sign results as itself.
    let a = ed_keypair();
    let b_pk = ed_keypair().verifying_key();
    let mut r = make_test_result();
    r.sign_ed25519_with_worker_id(&a, "worker-a").unwrap();
    assert!(r.verify_no_replay_ed25519(&[b_pk], 300).is_err());
}

#[test]
fn result_ed25519_tampered_output_fails() {
    let sk = ed_keypair();
    let pk = sk.verifying_key();
    let mut r = make_test_result();
    r.sign_ed25519_with_worker_id(&sk, "worker-a").unwrap();
    r.output_payload = serde_json::json!({"ok": false}).into();
    assert!(r.verify_no_replay_ed25519(&[pk], 300).is_err());
}

/// **The regression this PR exists to prevent.**
///
/// A `JobResult` that is correctly signed but arrived after its freshness
/// window must be distinguishable from one whose signature does not verify
/// — at the type level, not by reading prose — and it must still be
/// REJECTED. Drives the real `verify_dispatch` path, not a re-implementation.
#[test]
fn a_stale_result_is_typed_as_liveness_and_a_forged_one_is_not() {
    // Serialized against the tests that wipe/bulk-fill the process-global
    // nonce cache — see NONCE_CACHE_TEST_SERIAL.
    let _serial = crate::NONCE_CACHE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let key = test_key();
    let ring = hmac_ring(&key);
    let sk = ed_keypair();
    let pk = sk.verifying_key();

    // (1) Correctly signed 715 s ago — the measured shape of the 2026-08-24
    //     cluster (host suspend froze the controller for 718.6 s).
    let mut stale = make_test_result();
    stale.worker_id = "worker-a".to_string();
    stale.sign_backdated_for_test(&key, 715);

    let e = stale
        .verify_dispatch(&ring, &[pk], 300, true)
        .expect_err("fail-closed: a stale result is STILL rejected");
    assert_eq!(e.kind(), VerifyFailureKind::Stale);
    assert!(e.is_liveness());
    assert_eq!(e.age_secs(), Some(715));
    // The byte-stable protocol text is preserved verbatim inside the error.
    assert_eq!(e.to_string(), "result_nonce is too old (715 s, max 300)");

    // (2) The signature on those exact bytes IS valid — verified by
    //     re-checking under a window wide enough to admit it. Without this
    //     leg, "stale, not forged" would be an assertion rather than a
    //     measurement, which is the very defect class being fixed.
    stale
        .verify_dispatch(&ring, &[pk], 10_000, true)
        .expect("the same bytes verify once the window admits them");

    // (3) A FRESH result with a corrupted signature is a security failure.
    let mut forged = make_test_result();
    forged.worker_id = "worker-a".to_string();
    forged.sign_with_worker_id(&key, "worker-a").unwrap();
    forged.signature[0] ^= 0xff;
    let f = forged
        .verify_dispatch(&ring, &[pk], 300, true)
        .expect_err("a corrupted signature is rejected");
    assert_eq!(f.kind(), VerifyFailureKind::BadSignature);
    assert!(!f.is_liveness());
    assert_eq!(f.age_secs(), None);

    // (4) The operator-facing headlines must not be confusable.
    let stale_headline = describe_verify_failure("Job result", &e);
    let forged_headline = describe_verify_failure("Job result", &f);
    assert!(
        !stale_headline.contains("signature verification failed"),
        "a liveness failure must never be headlined as tampering: {stale_headline}"
    );
    assert!(stale_headline.contains(LIVENESS_REJECTION_MARKER));
    assert!(stale_headline.contains("715 s"));
    assert!(forged_headline.contains("signature verification failed"));
    assert!(!forged_headline.contains(LIVENESS_REJECTION_MARKER));
}

/// The headline/kind mapping must be total and self-consistent: exactly the
/// liveness kinds carry the shared marker, and no liveness kind is ever
/// headlined as a signature failure. Iterates `ALL`, so a new variant that
/// forgets its arm fails here rather than silently reading as tampering.
#[test]
fn every_failure_kind_headlines_consistently_with_its_liveness_flag() {
    for &kind in VerifyFailureKind::ALL {
        let e = VerifyError::from_parts(kind, "detail", None);
        let h = describe_verify_failure("Job result", &e);
        assert_eq!(
            h.contains(LIVENESS_REJECTION_MARKER),
            kind.is_liveness(),
            "marker/liveness disagreement for {kind:?}: {h}"
        );
        assert!(
            !(kind.is_liveness() && h.contains("signature verification failed")),
            "{kind:?} headlined as tampering: {h}"
        );
        assert!(h.contains("detail"), "{kind:?} dropped the protocol detail");
    }
    // Labels are a closed, unique set — a metric or log field built on them
    // cannot silently collapse two classes into one series.
    let mut labels: Vec<&str> = VerifyFailureKind::ALL.iter().map(|k| k.label()).collect();
    let n = labels.len();
    labels.sort_unstable();
    labels.dedup();
    assert_eq!(labels.len(), n, "VerifyFailureKind labels must be unique");
}

#[test]
fn result_verify_dispatch_routes_and_enforces_p4() {
    let key = test_key();
    let ring = hmac_ring(&key);
    let sk = ed_keypair();
    let pk = sk.verifying_key();

    // HMAC result: accepted during rollout, refused under enforcement.
    let mut hmac_r = make_test_result();
    hmac_r.sign_with_worker_id(&key, "worker-a").unwrap();
    hmac_r
        .verify_dispatch(&ring, &[pk], 300, true)
        .expect("HMAC result accepted during rollout");
    let mut hmac_r2 = make_test_result();
    hmac_r2.sign_with_worker_id(&key, "worker-a").unwrap();
    assert!(
        hmac_r2.verify_dispatch(&ring, &[pk], 300, false).is_err(),
        "P4: HMAC result refused under Ed25519-only enforcement"
    );

    // Ed25519 result: accepted regardless of the legacy flag.
    let mut ed_r = make_test_result();
    ed_r.sign_ed25519_with_worker_id(&sk, "worker-a").unwrap();
    ed_r.verify_dispatch(&ring, &[pk], 300, false)
        .expect("Ed25519 result accepted under enforcement");
}

#[test]
fn result_downgrade_flip_rejected() {
    let key = test_key();
    let ring = hmac_ring(&key);
    let sk = ed_keypair();
    let mut r = make_test_result();
    r.sign_ed25519_with_worker_id(&sk, "worker-a").unwrap();
    r.crypto_scheme = CRYPTO_SCHEME_HMAC; // tamper the hint
    assert!(r
        .verify_dispatch(&ring, &[sk.verifying_key()], 300, true)
        .is_err());
}

#[test]
fn worker_public_key_registry_parses_and_verifies() {
    // Two workers, plus a rotated-in second key for worker-a — the exact
    // shape the controller loads from AEGIX_WORKER_PUBLIC_KEYS.
    let a_old = ed_keypair();
    let a_new = ed_keypair();
    let b = ed_keypair();
    let raw = format!(
        "worker-a={},worker-b={},worker-a={}",
        hex::encode(a_old.verifying_key().to_bytes()),
        hex::encode(b.verifying_key().to_bytes()),
        hex::encode(a_new.verifying_key().to_bytes()),
    );
    let reg = parse_worker_public_keys(&raw);

    // worker-a carries BOTH keys (rotation overlap); worker-b carries one.
    assert_eq!(reg.get("worker-a").map(Vec::len), Some(2));
    assert_eq!(reg.get("worker-b").map(Vec::len), Some(1));
    assert!(!reg.contains_key("worker-c"));

    // A result signed under either of worker-a's keys verifies against the
    // registered set (first match wins).
    let mut r = make_test_result();
    r.sign_ed25519_with_worker_id(&a_new, "worker-a").unwrap();
    r.verify_no_replay_ed25519(reg.get("worker-a").unwrap(), 300)
        .expect("rotated-in worker key must verify");
}

#[test]
fn worker_public_key_registry_skips_malformed_entries() {
    let good = ed_keypair();
    // Garbage, a keyless bareword, an empty worker_id, and trailing commas
    // are all skipped without poisoning the one valid pair.
    let raw = format!(
        "  , notanentry , =deadbeef , worker-x=zzzz , worker-ok={} ,,",
        hex::encode(good.verifying_key().to_bytes()),
    );
    let reg = parse_worker_public_keys(&raw);
    assert_eq!(reg.len(), 1, "only the one well-formed pair survives");
    assert_eq!(reg.get("worker-ok").map(Vec::len), Some(1));
}

#[test]
fn worker_public_keys_empty_input_is_empty() {
    assert!(parse_worker_public_keys("").is_empty());
    assert!(parse_worker_public_keys(
        "   , \
                                           , "
    )
    .is_empty());
}

/// The fleet-report enumerator: worker ids + key COUNTS, sorted, and never
/// key bytes. Mirrors the parser's tolerance because it consumes the parser's
/// output verbatim — a ring the parser accepts must be enumerable.
#[test]
fn static_ring_summary_counts_keys_per_worker_in_sorted_order() {
    let a_old = ed_keypair();
    let a_new = ed_keypair();
    let b = ed_keypair();
    // Deliberately declared out of alphabetical order, with worker-a split
    // across two non-adjacent entries (the rotation-overlap shape).
    let raw = format!(
        "worker-b={},worker-a={},worker-a={}",
        hex::encode(b.verifying_key().to_bytes()),
        hex::encode(a_old.verifying_key().to_bytes()),
        hex::encode(a_new.verifying_key().to_bytes()),
    );
    let summary = summarize_worker_ring(&parse_worker_public_keys(&raw));
    assert_eq!(
        summary,
        vec![("worker-a".to_string(), 2), ("worker-b".to_string(), 1)],
        "sorted by worker_id, one entry per id, count = registered keys"
    );
}

#[test]
fn static_ring_summary_skips_malformed_entries_like_the_parser() {
    let good = ed_keypair();
    let raw = format!(
        "  , notanentry , =deadbeef , worker-x=zzzz , worker-ok={} ,,",
        hex::encode(good.verifying_key().to_bytes()),
    );
    assert_eq!(
        summarize_worker_ring(&parse_worker_public_keys(&raw)),
        vec![("worker-ok".to_string(), 1)],
        "a malformed entry must not surface as a phantom fleet member"
    );
}

#[test]
fn static_ring_summary_of_empty_env_is_empty() {
    // An unset / empty AEGIX_WORKER_PUBLIC_KEYS must yield NO rows — the
    // fleet report then shows only registered workers, exactly as before
    // this accessor existed.
    assert!(summarize_worker_ring(&parse_worker_public_keys("")).is_empty());
    assert!(summarize_worker_ring(&parse_worker_public_keys("  ,, ")).is_empty());
}

// RFC 0010 P2 inc.4: the DB-backed dynamic overlay. Uses a worker_id no other
// test references and no AEGIX_WORKER_PUBLIC_KEYS env (unset in the test proc),
// so the env base is empty and this test owns its slice of the global snapshot.
#[test]
fn dynamic_worker_public_keys_overlay_union_dedup_and_replace() {
    let a = ed_keypair();
    let b = ed_keypair();
    let wid = "inc4-dynamic-worker";

    // Install two keys for the worker (rotation overlap): both resolve.
    set_dynamic_worker_public_keys([
        (wid.to_string(), a.verifying_key()),
        (wid.to_string(), b.verifying_key()),
    ]);
    let keys = worker_public_keys(wid);
    assert_eq!(keys.len(), 2, "both dynamic keys present");

    // Dedup: re-installing with a byte-identical repeat does not double it.
    set_dynamic_worker_public_keys([
        (wid.to_string(), a.verifying_key()),
        (wid.to_string(), a.verifying_key()),
    ]);
    assert_eq!(
        worker_public_keys(wid).len(),
        1,
        "byte-identical keys dedup"
    );
    assert_eq!(
        worker_public_keys(wid)[0].to_bytes(),
        a.verifying_key().to_bytes()
    );

    // Full-replacement: an empty overlay drops the worker entirely (models a
    // worker whose every key was deactivated in the DB).
    set_dynamic_worker_public_keys(std::iter::empty());
    assert!(
        worker_public_keys(wid).is_empty(),
        "empty refresh clears the dynamic overlay for this worker"
    );

    // A result signed by the worker verifies only while its key is installed.
    set_dynamic_worker_public_keys([(wid.to_string(), a.verifying_key())]);
    let mut r = make_test_result();
    r.sign_ed25519_with_worker_id(&a, wid).unwrap();
    r.verify_no_replay_ed25519(&worker_public_keys(wid), 300)
        .expect("installed dynamic key verifies the worker's result");
    // Reset the global so we don't leak state into other tests.
    set_dynamic_worker_public_keys(std::iter::empty());
}

#[test]
fn ed25519_sign_verify_roundtrip() {
    let sk = ed_keypair();
    let pk = sk.verifying_key();
    let mut req = make_test_request(Some(Uuid::new_v4()));
    req.sign_ed25519(&sk).unwrap();
    assert_eq!(req.crypto_scheme, CRYPTO_SCHEME_ED25519);
    assert_eq!(req.signature.len(), 64, "Ed25519 signatures are 64 bytes");
    req.verify_no_replay_ed25519(&[pk], 300)
        .expect("valid Ed25519 signature must verify");
}

#[test]
fn ed25519_tampered_payload_fails() {
    let sk = ed_keypair();
    let pk = sk.verifying_key();
    let mut req = make_test_request(Some(Uuid::new_v4()));
    req.sign_ed25519(&sk).unwrap();
    // Tamper a signed field.
    req.max_llm_tier = LlmTier::Tier1;
    assert!(
        req.verify_no_replay_ed25519(&[pk], 300).is_err(),
        "tampered payload must fail Ed25519 verification"
    );
}

#[test]
fn ed25519_wrong_key_fails() {
    let sk = ed_keypair();
    let other_pk = ed_keypair().verifying_key();
    let mut req = make_test_request(None);
    req.sign_ed25519(&sk).unwrap();
    assert!(
        req.verify_no_replay_ed25519(&[other_pk], 300).is_err(),
        "a different controller key must not verify"
    );
}

#[test]
fn ed25519_empty_keyset_rejects() {
    let sk = ed_keypair();
    let mut req = make_test_request(None);
    req.sign_ed25519(&sk).unwrap();
    assert!(
        req.verify_no_replay_ed25519(&[], 300).is_err(),
        "no configured key must fail closed, not pass"
    );
}

#[test]
fn ed25519_key_rotation_overlap() {
    // Signed under the CURRENT key; a verifier carrying [rotated_in, old]
    // still validates (first match wins), so a controller-key rotation with
    // an overlap window doesn't drop in-flight dispatches.
    let old = ed_keypair();
    let new = ed_keypair();
    let mut req = make_test_request(None);
    req.sign_ed25519(&old).unwrap();
    req.verify_no_replay_ed25519(&[new.verifying_key(), old.verifying_key()], 300)
        .expect("previous-key overlap must verify");
}

#[test]
fn schemes_do_not_cross_validate() {
    let key = test_key();
    let sk = ed_keypair();
    let pk = sk.verifying_key();

    // HMAC-signed request must not verify as Ed25519.
    let mut hmac_req = make_test_request(None);
    hmac_req.sign(&key).unwrap();
    assert!(hmac_req.verify_no_replay_ed25519(&[pk], 300).is_err());

    // Ed25519-signed request must not verify as HMAC (domain-separated
    // input + a 64-byte non-HMAC signature).
    let mut ed_req = make_test_request(None);
    ed_req.sign_ed25519(&sk).unwrap();
    assert!(ed_req.verify_no_replay(&key, 300).is_err());
}

#[test]
fn verify_dispatch_routes_by_scheme_and_enforces_p4() {
    let key = test_key();
    let ring = hmac_ring(&key);
    let sk = ed_keypair();
    let pk = sk.verifying_key();

    // HMAC request: admitted while legacy HMAC is accepted (rollout window).
    let mut hmac_req = make_test_request(None);
    hmac_req.sign(&key).unwrap();
    hmac_req
        .verify_dispatch(&ring, &[pk], 300, true)
        .expect("HMAC dispatch accepted during rollout");

    // Same HMAC request REFUSED once Ed25519-only enforcement is on (P4).
    let mut hmac_req2 = make_test_request(None);
    hmac_req2.sign(&key).unwrap();
    assert!(
        hmac_req2.verify_dispatch(&ring, &[pk], 300, false).is_err(),
        "P4: legacy HMAC dispatch must be refused when enforcement is on"
    );

    // Ed25519 request: admitted regardless of the legacy flag.
    let mut ed_req = make_test_request(None);
    ed_req.sign_ed25519(&sk).unwrap();
    ed_req
        .verify_dispatch(&ring, &[pk], 300, false)
        .expect("Ed25519 dispatch accepted under enforcement");
}

/// A dispatch the controller signed and that has since aged out is still
/// the controller's; the same aged bytes with another signature are not.
/// Both are refused by `verify_dispatch` as `Stale` (age is read before
/// the signature), so the age refusal alone says nothing about who wrote
/// them: `verify_signature_only_dispatch` is what does.
#[test]
fn the_signature_alone_tells_an_aged_dispatch_from_a_forged_one() {
    use ed25519_dalek::Signer;
    let key = test_key();
    let ring = hmac_ring(&key);
    let sk = ed_keypair();
    let pk = sk.verifying_key();

    // HMAC, signed 900 s ago.
    let mut aged = make_test_request(None);
    aged.sign_backdated_for_test(&key, 900);
    let e = aged
        .verify_no_replay_dispatch(&ring, &[pk], 300, true)
        .expect_err("an aged dispatch is refused");
    assert_eq!(e.kind(), VerifyFailureKind::Stale);
    aged.verify_signature_only_dispatch(&ring, &[pk], true)
        .expect("the controller's signature holds whatever the age");

    // The same shape with a signature nobody's key made.
    let mut forged = aged.clone();
    forged.signature[0] ^= 0xff;
    assert_eq!(
        forged
            .verify_no_replay_dispatch(&ring, &[pk], 300, true)
            .expect_err("refused")
            .kind(),
        VerifyFailureKind::Stale,
        "refused on age exactly as the genuine one is"
    );
    assert_eq!(
        forged
            .verify_signature_only_dispatch(&ring, &[pk], true)
            .expect_err("a forged signature does not hold")
            .kind(),
        VerifyFailureKind::BadSignature
    );
    // A field changed after signing is not the controller's either.
    let mut retargeted = aged.clone();
    retargeted.reply_topic = Some("_INBOX.someone-else".to_string());
    assert!(retargeted
        .verify_signature_only_dispatch(&ring, &[pk], true)
        .is_err());

    // Ed25519, signed 900 s ago.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time")
        .as_secs();
    let mut aged_ed = make_test_request(None);
    aged_ed.crypto_scheme = CRYPTO_SCHEME_ED25519;
    aged_ed.job_nonce = format!("{}:{}", now - 900, hex::encode([9u8; 16]));
    aged_ed.signature = sk
        .sign(&aged_ed.ed25519_signing_input())
        .to_bytes()
        .to_vec();
    assert_eq!(
        aged_ed
            .verify_no_replay_dispatch(&ring, &[pk], 300, false)
            .expect_err("refused on age")
            .kind(),
        VerifyFailureKind::Stale
    );
    aged_ed
        .verify_signature_only_dispatch(&ring, &[pk], false)
        .expect("the controller's Ed25519 signature holds whatever the age");
    let other = ed_keypair().verifying_key();
    assert!(
        aged_ed
            .verify_signature_only_dispatch(&ring, &[other], false)
            .is_err(),
        "another key does not vouch for it"
    );
    assert_eq!(
        aged_ed
            .verify_signature_only_dispatch(&ring, &[], false)
            .expect_err("no key, no answer")
            .kind(),
        VerifyFailureKind::KeyError
    );

    // The scheme rules are `verify_dispatch`'s: a legacy HMAC dispatch is
    // not vouched for once Ed25519 is required, nor is an unknown scheme.
    assert_eq!(
        aged.verify_signature_only_dispatch(&ring, &[pk], false)
            .expect_err("legacy HMAC refused under enforcement")
            .kind(),
        VerifyFailureKind::SchemeRefused
    );
    let mut unknown = aged.clone();
    unknown.crypto_scheme = 200;
    assert_eq!(
        unknown
            .verify_signature_only_dispatch(&ring, &[pk], true)
            .expect_err("unknown scheme refused")
            .kind(),
        VerifyFailureKind::SchemeRefused
    );
}

#[test]
fn downgrade_flip_is_rejected() {
    // An on-wire attacker flips a valid Ed25519 request's scheme hint to 0
    // to force the HMAC path. Without the HMAC key they cannot produce a
    // valid HMAC, so verify_dispatch fails.
    let key = test_key();
    let ring = hmac_ring(&key);
    let sk = ed_keypair();
    let mut req = make_test_request(None);
    req.sign_ed25519(&sk).unwrap();
    req.crypto_scheme = CRYPTO_SCHEME_HMAC; // tamper the hint
    assert!(
        req.verify_dispatch(&ring, &[sk.verifying_key()], 300, true)
            .is_err(),
        "scheme downgrade must fail (no valid HMAC for the payload)"
    );
}

#[test]
fn unknown_scheme_is_rejected() {
    let key = test_key();
    let ring = hmac_ring(&key);
    let sk = ed_keypair();
    let mut req = make_test_request(None);
    req.sign_ed25519(&sk).unwrap();
    req.crypto_scheme = 200; // unknown
    assert!(req
        .verify_dispatch(&ring, &[sk.verifying_key()], 300, true)
        .is_err());
}

#[test]
fn ed25519_primary_verify_records_replay() {
    // Serialized against the tests that wipe/bulk-fill the process-global
    // nonce cache — see NONCE_CACHE_TEST_SERIAL.
    let _serial = crate::NONCE_CACHE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let sk = ed_keypair();
    let pk = sk.verifying_key();
    let mut req = make_test_request(None);
    req.sign_ed25519(&sk).unwrap();
    // Primary verify records the nonce…
    req.verify_ed25519(&[pk], 300).expect("first verify ok");
    // …so a second primary verify of the same nonce is a replay.
    assert!(
        req.verify_ed25519(&[pk], 300).is_err(),
        "replayed Ed25519 dispatch must be rejected"
    );
}

#[test]
fn ed25519_key_hex_parse_roundtrip() {
    let sk = ed_keypair();
    let pk = sk.verifying_key();
    let pk_hex = hex::encode(pk.to_bytes());
    let parsed = parse_ed25519_verifying_key_hex(&pk_hex).expect("parse pubkey");
    assert_eq!(parsed.to_bytes(), pk.to_bytes());
    let sk_hex = hex::encode(sk.to_bytes());
    let parsed_sk = parse_ed25519_signing_key_hex(&sk_hex).expect("parse signkey");
    assert_eq!(parsed_sk.to_bytes(), sk.to_bytes());
    // Wrong lengths fail closed.
    assert!(parse_ed25519_verifying_key_hex("deadbeef").is_err());
    assert!(parse_ed25519_signing_key_hex("").is_err());
}

#[test]
fn worker_registration_proof_roundtrip_and_field_binding() {
    let sk = ed_keypair();
    let pk = sk.verifying_key().to_bytes();
    let (wid, sealing, ts, nonce) = ("worker-9", true, 1_700_000_000_000u64, "nonce-abc");

    let proof = sign_worker_registration_proof(&sk, wid, &pk, sealing, ts, nonce);
    assert_eq!(proof.len(), 64, "Ed25519 signature is 64 bytes");
    verify_worker_registration_proof(&pk, wid, sealing, ts, nonce, &proof)
        .expect("a faithfully-signed proof verifies");

    // EVERY signed field is bound — flipping any one breaks verification.
    assert!(verify_worker_registration_proof(&pk, "worker-8", sealing, ts, nonce, &proof).is_err());
    assert!(verify_worker_registration_proof(&pk, wid, !sealing, ts, nonce, &proof).is_err());
    assert!(verify_worker_registration_proof(&pk, wid, sealing, ts + 1, nonce, &proof).is_err());
    assert!(verify_worker_registration_proof(&pk, wid, sealing, ts, "nonce-xyz", &proof).is_err());

    // A proof for a DIFFERENT key does not verify against this key — the
    // registrant can only prove possession of a key it actually holds, so it
    // cannot register another party's (or another worker's) public key.
    let other_pk = ed_keypair().verifying_key().to_bytes();
    assert!(verify_worker_registration_proof(&other_pk, wid, sealing, ts, nonce, &proof).is_err());

    // Tampered / malformed signatures fail closed.
    let mut bad = proof.clone();
    bad[0] ^= 0x01;
    assert!(verify_worker_registration_proof(&pk, wid, sealing, ts, nonce, &bad).is_err());
    assert!(verify_worker_registration_proof(&pk, wid, sealing, ts, nonce, &proof[..63]).is_err());
    // A non-point public_key is rejected before any verify.
    assert!(verify_worker_registration_proof(&[2u8; 32], wid, sealing, ts, nonce, &proof).is_err());
}

/// The liveness proof is the ONLY credential its endpoint accepts, so its
/// field binding and its separation from the registration proof are both
/// load-bearing.
#[test]
fn worker_liveness_proof_roundtrip_and_field_binding() {
    let sk = ed_keypair();
    let pk = sk.verifying_key().to_bytes();
    let (wid, ts, nonce) = ("worker-9", 1_700_000_000_000u64, "nonce-abc");

    let proof = sign_worker_liveness_proof(&sk, wid, &pk, ts, nonce);
    assert_eq!(proof.len(), 64, "Ed25519 signature is 64 bytes");
    verify_worker_liveness_proof(&pk, wid, ts, nonce, &proof)
        .expect("a faithfully-signed proof verifies");

    // Every signed field is bound.
    assert!(verify_worker_liveness_proof(&pk, "worker-8", ts, nonce, &proof).is_err());
    assert!(verify_worker_liveness_proof(&pk, wid, ts + 1, nonce, &proof).is_err());
    assert!(verify_worker_liveness_proof(&pk, wid, ts, "nonce-xyz", &proof).is_err());

    // A proof for a DIFFERENT key does not verify against this key — the
    // pinger can only assert liveness for a key it actually holds, so one
    // worker cannot keep another worker's identity alive in the trust ring.
    let other_pk = ed_keypair().verifying_key().to_bytes();
    assert!(verify_worker_liveness_proof(&other_pk, wid, ts, nonce, &proof).is_err());

    // Tampered / malformed signatures and non-point keys fail closed.
    let mut bad = proof.clone();
    bad[0] ^= 0x01;
    assert!(verify_worker_liveness_proof(&pk, wid, ts, nonce, &bad).is_err());
    assert!(verify_worker_liveness_proof(&pk, wid, ts, nonce, &proof[..63]).is_err());
    assert!(verify_worker_liveness_proof(&[2u8; 32], wid, ts, nonce, &proof).is_err());
}

/// Domain separation, asserted rather than assumed: a registration proof
/// must not be accepted as a liveness proof, and vice versa. Without the
/// distinct domain prefix an attacker who captured one message could
/// replay it at the other endpoint.
#[test]
fn liveness_and_registration_proofs_are_not_interchangeable() {
    let sk = ed_keypair();
    let pk = sk.verifying_key().to_bytes();
    let (wid, ts, nonce) = ("worker-x", 1_700_000_000_000u64, "n");

    let reg = sign_worker_registration_proof(&sk, wid, &pk, false, ts, nonce);
    let live = sign_worker_liveness_proof(&sk, wid, &pk, ts, nonce);

    assert_ne!(reg, live, "the two proofs must not be the same bytes");
    assert!(
        verify_worker_liveness_proof(&pk, wid, ts, nonce, &reg).is_err(),
        "a registration proof must not pass as a liveness proof"
    );
    assert!(
        verify_worker_registration_proof(&pk, wid, false, ts, nonce, &live).is_err(),
        "a liveness proof must not pass as a registration proof"
    );
}

#[test]
fn worker_liveness_pop_message_is_unambiguous() {
    // Same length-prefix property as the registration message: moving a
    // byte from the end of worker_id to the start of nonce must change the
    // bytes.
    let pk = [7u8; 32];
    let a = worker_liveness_pop_message("ab", &pk, 1, "cd");
    let b = worker_liveness_pop_message("abc", &pk, 1, "d");
    assert_ne!(a, b, "ambiguous concatenation would make these equal");
}

#[test]
fn worker_registration_pop_message_is_unambiguous() {
    // Length-prefixing prevents a field-boundary collision: moving a byte
    // from the end of worker_id to the start of nonce must change the bytes.
    let pk = [7u8; 32];
    let a = worker_registration_pop_message("ab", &pk, false, 1, "cd");
    let b = worker_registration_pop_message("abc", &pk, false, 1, "d");
    assert_ne!(a, b, "ambiguous concatenation would make these equal");
}

#[test]
fn verifying_key_from_bytes_roundtrips_and_rejects_noncanonical() {
    // The bytes path (used by the inc.4 DB-overlay refresh) agrees with the
    // hex path and with the key's own encoding.
    let pk = ed_keypair().verifying_key();
    let bytes = pk.to_bytes();
    let parsed = parse_ed25519_verifying_key_bytes(&bytes).expect("canonical point parses");
    assert_eq!(parsed.to_bytes(), bytes);
    // A value that is not a valid curve point fails closed rather than
    // yielding a key that would silently never verify. (`[2u8; 32]` does not
    // decompress to an Edwards point.)
    assert!(parse_ed25519_verifying_key_bytes(&[2u8; 32]).is_err());
}

#[test]
fn generated_keypair_hex_roundtrips_and_matches() {
    let (seed_hex, pub_hex) = generate_ed25519_keypair_hex();
    assert_eq!(seed_hex.len(), 64, "seed is 32 bytes = 64 hex chars");
    assert_eq!(pub_hex.len(), 64, "public key is 32 bytes = 64 hex chars");
    // Both parse in the exact shape the env loaders accept.
    let sk = parse_ed25519_signing_key_hex(&seed_hex).expect("seed parses");
    let pk = parse_ed25519_verifying_key_hex(&pub_hex).expect("pubkey parses");
    // The emitted public key is the one derived from the emitted seed —
    // an operator pasting the two halves into peer processes gets a
    // matching pair, and a signature made with the seed verifies under it.
    assert_eq!(sk.verifying_key().to_bytes(), pk.to_bytes());
    let mut req = make_test_request(None);
    req.sign_ed25519(&sk).unwrap();
    req.verify_no_replay_ed25519(&[pk], 300)
        .expect("seed-signed request verifies under the emitted public key");
    // Two calls yield distinct keys (not a constant).
    let (seed2, _) = generate_ed25519_keypair_hex();
    assert_ne!(seed_hex, seed2, "keygen must be random per call");
}

/// RFC 0010 end-to-end: the exact hex strings the
/// `generate-worker-trust-keypair` subcommand prints, fed through the SAME
/// pure loaders the controller and worker read env with, must compose across
/// BOTH trust directions — controller→worker dispatch (P1) and
/// worker→controller results (P2) — using ONE per-worker keypair (the same
/// key the RPC path uses). This is the "did we ship something an operator can
/// actually turn on" check: it fails if the keygen output format drifts from
/// what `parse_ed25519_*` / `parse_worker_public_keys` accept, or if the two
/// verify paths diverge.
#[test]
fn operator_keygen_config_composes_both_directions() {
    // --- what the operator generates + pastes into env ---
    // `--role controller`: seed on controller, pub on every worker.
    let (ctrl_seed_hex, ctrl_pub_hex) = generate_ed25519_keypair_hex();
    // `--role worker --worker-id worker-1`: seed on the worker, the
    // `worker_id=pub` pair appended to the controller's registry string.
    let (w1_seed_hex, w1_pub_hex) = generate_ed25519_keypair_hex();
    let worker_public_keys_env = format!("worker-1={w1_pub_hex}");

    // === P1 dispatch: controller signs, worker verifies ===
    // Controller side — build the signer exactly as configured_dispatch_signer.
    let ctrl_signer = DispatchSigner::Ed25519(std::sync::Arc::new(
        parse_ed25519_signing_key_hex(&ctrl_seed_hex).expect("controller seed parses"),
    ));
    let mut req = make_test_request(Some(Uuid::new_v4()));
    ctrl_signer
        .sign_job(&mut req)
        .expect("controller signs dispatch");
    assert_eq!(req.crypto_scheme, CRYPTO_SCHEME_ED25519);
    // Worker side — parse AEGIX_CONTROLLER_PUBLIC_KEY and verify. The ring
    // holds only an unrelated dummy key: the Ed25519 path never touches the
    // symmetric ring, and accept_legacy_hmac=false proves it holds under P4
    // enforcement (a signature forged under the dummy HMAC key is refused).
    let ctrl_pub = parse_ed25519_verifying_key_hex(&ctrl_pub_hex).expect("ctrl pub parses");
    let unrelated_ring = hmac_ring(b"unrelated-hmac-key-never-touched-on-ed25519-path");
    req.verify_dispatch(&unrelated_ring, &[ctrl_pub], 300, false)
        .expect("worker verifies the controller-signed dispatch");

    // === P2 result: worker signs, controller verifies via the registry ===
    let w1_sk = parse_ed25519_signing_key_hex(&w1_seed_hex).expect("worker seed parses");
    let mut result = make_test_result();
    result
        .sign_ed25519_with_worker_id(&w1_sk, "worker-1")
        .expect("worker signs its result");
    // Controller side — resolve the verifying key(s) for worker-1 out of the
    // parsed AEGIX_WORKER_PUBLIC_KEYS registry, then verify.
    let registry = parse_worker_public_keys(&worker_public_keys_env);
    let w1_keys = registry.get("worker-1").expect("worker-1 is registered");
    result
        .verify_dispatch(&unrelated_ring, w1_keys, 300, false)
        .expect("controller verifies the worker-signed result");

    // === Core security property, driven through the config path ===
    // A result claiming to be worker-1 but signed by a DIFFERENT key (a
    // compromised/rogue worker impersonating worker-1) fails against the
    // registered key. The asymmetric boundary means holding a valid worker
    // key never lets you forge as another worker_id.
    let (rogue_seed_hex, _) = generate_ed25519_keypair_hex();
    let rogue_sk = parse_ed25519_signing_key_hex(&rogue_seed_hex).unwrap();
    let mut forged = make_test_result();
    forged
        .sign_ed25519_with_worker_id(&rogue_sk, "worker-1")
        .unwrap();
    assert!(
        forged
            .verify_dispatch(&unrelated_ring, w1_keys, 300, false)
            .is_err(),
        "a rogue key claiming worker-1 must not verify against worker-1's registered key"
    );
}

/// M-4: tampering with `actor_id` MUST invalidate the signature.
/// Pre-fix the field was excluded from the signing payload, so a
/// NATS-channel attacker could redirect the worker's downstream
/// `MemoryRpcRequest` writes to a different actor's memory namespace.
#[test]
fn tampered_actor_id_fails_verification() {
    let key = test_key();
    let actor_a = Uuid::new_v4();
    let actor_b = Uuid::new_v4();
    let mut req = make_test_request(Some(actor_a));
    req.sign(&key).unwrap();

    // Tamper: swap actor_a → actor_b. Pre-fix this passed.
    req.actor_id = Some(actor_b);
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered actor_id must fail verification (M-4)"
    );
}

/// M-4: actor_id None → Some MUST also be tamper-evident.
#[test]
fn actor_id_none_to_some_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();

    req.actor_id = Some(Uuid::new_v4());
    assert!(
        req.verify(&key, 300).is_err(),
        "swapping actor_id from None to Some must fail (M-4)"
    );
}

/// M-5: tampering with `allowed_secrets` MUST invalidate signature.
/// Even though encrypted_secrets is the active enforcement layer,
/// capability claims should be self-consistent with the signed
/// message.
#[test]
fn tampered_allowed_secrets_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();

    req.allowed_secrets = vec!["openai/api_key".to_string(), "*".to_string()];
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered allowed_secrets must fail verification (M-5)"
    );
}

/// M-5: tampering with `allow_tier2_exposure` MUST invalidate.
/// Pre-fix an attacker could flip the tier-2 bit on the wire,
/// granting the module Tier-2 capability the operator never
/// intended.
#[test]
fn tampered_allow_tier2_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.allow_tier2_exposure = false;
    req.sign(&key).unwrap();

    req.allow_tier2_exposure = true;
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered allow_tier2_exposure must fail verification (M-5)"
    );
}

/// M-5: tampering with `allowed_sql_operations` MUST invalidate.
#[test]
fn tampered_allowed_sql_operations_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();

    req.allowed_sql_operations = vec![
        "SELECT".to_string(),
        "INSERT".to_string(),
        "DELETE".to_string(),
    ];
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered allowed_sql_operations must fail verification (M-5)"
    );
}

/// M-5: order-independence — re-ordering allowed_secrets must NOT
/// invalidate. Same property as `test_allowed_methods_order_independent`
/// but for the new fields.
#[test]
fn allowed_secrets_order_independent() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.allowed_secrets = vec!["b".to_string(), "a".to_string(), "c".to_string()];
    req.sign(&key).unwrap();

    req.allowed_secrets = vec!["a".to_string(), "b".to_string(), "c".to_string()];
    req.verify(&key, 300)
        .expect("order-independent allowed_secrets must still verify (M-5)");
}

/// L-9: payload-collision regression guard. Two semantically-distinct
/// requests whose `module_uri` + `job_nonce` could collide under the
/// pre-length-prefix scheme MUST produce different signatures.
/// Pre-fix the colon delimiter could collide between
/// `(module_uri="a", job_nonce="b:c")` and `(module_uri="a:b", job_nonce="c")`
/// — same signing-payload bytes. The length-prefix on module_uri
/// disambiguates.
#[test]
fn length_prefix_prevents_module_uri_collision() {
    let key = test_key();
    let mut req_a = make_test_request(None);
    req_a.module_uri = "a".to_string();
    req_a.sign(&key).unwrap();

    let mut req_b = make_test_request(None);
    // Try to construct a colliding payload by stuffing bytes into
    // module_uri that, under the pre-fix concatenation, would have
    // matched req_a's bytes. With length-prefixing the byte counts
    // differ so no collision is possible.
    req_b.module_uri = "a:b".to_string();
    req_b.job_id = req_a.job_id;
    req_b.workflow_execution_id = req_a.workflow_execution_id;
    req_b.job_nonce = req_a.job_nonce.clone();
    // Sign req_b with its own values but check that the resulting
    // signing_payload bytes differ from req_a's even under
    // adversarial field choices. (Direct inspection of the payload
    // bytes — we don't need to actually swap signatures.)
    let payload_a = req_a.signing_payload();
    let payload_b = req_b.signing_payload();
    assert_ne!(
            payload_a, payload_b,
            "length-prefixed module_uri must prevent collision between adversarially-chosen field values (L-9)"
        );
}

/// L-10: tampering with `JobResult.logs` MUST invalidate the
/// signature. Pre-fix the logs field was unsigned; an attacker
/// could inject misleading audit-trail entries in flight.
#[test]
fn tampered_job_result_logs_fails_verification() {
    let key = test_key();
    let mut result = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({"answer": 42}).into(),
        logs: vec!["legit log line".to_string()],
        execution_time_ms: 100,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };
    result.sign(&key).unwrap();

    // Tamper: append a misleading log line.
    result
        .logs
        .push("FAKE: user authorized critical action".to_string());
    assert!(
        result.verify(&key, 300).is_err(),
        "tampered logs must fail verification (L-10)"
    );
}

/// H-1: tampering with `reply_topic` MUST invalidate the signature.
/// Pre-fix the field was excluded from the signing payload, so a
/// NATS-channel attacker could redirect the worker's signed
/// JobResult to an attacker-controlled subject.
#[test]
fn tampered_reply_topic_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.reply_topic = Some("_INBOX.legit.abc123".to_string());
    req.sign(&key).unwrap();

    // Tamper: swap to a malicious subject.
    req.reply_topic = Some("talos.admin.commands".to_string());
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered reply_topic must fail verification (H-1)"
    );
}

/// H-1: reply_topic None → Some MUST also be tamper-evident
/// (sentinel `-` differs from a real subject).
#[test]
fn reply_topic_none_to_some_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();
    req.reply_topic = Some("talos.admin.commands".to_string());
    assert!(
        req.verify(&key, 300).is_err(),
        "injecting reply_topic must fail verification (H-1)"
    );
}

/// H-1: reply_topic Some → None MUST also be tamper-evident
/// (stripping the field shouldn't downgrade verification to the
/// legacy "trust msg.reply" path).
#[test]
fn reply_topic_some_to_none_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.reply_topic = Some("_INBOX.legit.abc123".to_string());
    req.sign(&key).unwrap();
    req.reply_topic = None;
    assert!(
        req.verify(&key, 300).is_err(),
        "stripping reply_topic must fail verification (H-1)"
    );
}

/// L-10: empty-logs case — signature must round-trip correctly.
#[test]
fn job_result_with_empty_logs_round_trips() {
    let key = test_key();
    let mut result = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: serde_json::json!({}).into(),
        logs: vec![],
        execution_time_ms: 0,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };
    result.sign(&key).unwrap();
    result
        .verify(&key, 300)
        .expect("empty-logs result should verify");
}

// ========================================================================
// Wasm-security review 2026-05-23: tampering tests for the H-3 / H-7 / C-2
// signing-payload extensions.
// ========================================================================
//
// Each `tampered_<field>_fails_verification` test follows the same shape:
// 1. Build a clean request and sign it.
// 2. Mutate exactly one field that USED to be unsigned.
// 3. Re-verify and assert failure.
//
// Pre-fix, every one of these mutations would have passed verification —
// anyone with NATS publish on the job subject could perform the mutation
// in flight without the worker detecting it.

/// H-3: `capability_world` is now HMAC-bound. Pre-fix an attacker could
/// flip `minimal-node` → `automation-node` to trick the worker into
/// selecting a wider tiered linker (important for precompiled WASM
/// where the embedded world name may not survive Wizer).
#[test]
fn tampered_capability_world_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.capability_world = Some("minimal-node".to_string());
    req.sign(&key).unwrap();

    req.capability_world = Some("automation-node".to_string());
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered capability_world must fail verification (H-3)"
    );
}

/// H-3: stripping the `capability_world` (Some → None) must also be
/// tamper-evident — the sentinel `-` for None makes the absence
/// signed.
#[test]
fn capability_world_some_to_none_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.capability_world = Some("minimal-node".to_string());
    req.sign(&key).unwrap();

    req.capability_world = None;
    assert!(
        req.verify(&key, 300).is_err(),
        "stripping capability_world must fail verification (H-3)"
    );
}

/// H-7: `dry_run` is now HMAC-bound. Pre-fix an attacker could flip
/// `true → false` to convert a planning-mode run into a real one
/// (real HTTP POSTs, real webhooks).
#[test]
fn tampered_dry_run_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.dry_run = true;
    req.sign(&key).unwrap();

    req.dry_run = false;
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered dry_run must fail verification (H-7)"
    );
}

/// H-7: `priority` is now HMAC-bound. Pre-fix an attacker could
/// promote arbitrary jobs to starve legitimate high-priority work.
#[test]
fn tampered_priority_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.priority = 100;
    req.sign(&key).unwrap();

    req.priority = 1;
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered priority must fail verification (H-7)"
    );
}

/// H-7: `deadline_unix_secs` is now HMAC-bound. Pre-fix an attacker
/// could set a past timestamp to force premature failure.
#[test]
fn tampered_deadline_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.deadline_unix_secs = 0;
    req.sign(&key).unwrap();

    req.deadline_unix_secs = 1;
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered deadline_unix_secs must fail verification (H-7)"
    );
}

/// H-7: `cancellation_token` is now HMAC-bound. Pre-fix an attacker
/// could strip the token, leaving an in-flight job uncancellable.
#[test]
fn tampered_cancellation_token_fails_verification() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.cancellation_token = Some("token-abc".to_string());
    req.sign(&key).unwrap();

    req.cancellation_token = None;
    assert!(
        req.verify(&key, 300).is_err(),
        "tampered cancellation_token must fail verification (H-7)"
    );
}

/// H-3 + H-7 (combined positive case): a clean round-trip with all
/// the newly-bound fields populated must verify.
#[test]
fn newly_bound_fields_round_trip() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.capability_world = Some("automation-node".to_string());
    req.dry_run = true;
    req.priority = 200;
    req.deadline_unix_secs = 1_700_000_000;
    req.cancellation_token = Some("abc-123".to_string());
    req.sign(&key).unwrap();

    req.verify(&key, 300)
        .expect("clean request with newly-bound H-3/H-7 fields must verify");
}

// ────────────────────────────────────────────────────────────────
// 2026-05-28 audit F5: verify_no_replay parity tests
//
// CLAUDE.md "Verify-once rule for signed NATS messages": every
// signed message type MUST have BOTH `verify()` (records to nonce
// cache) AND `verify_no_replay()` (HMAC + freshness only). Pre-fix
// JobRequest and WorkerHeartbeat had only
// `verify()` — today only one consumer per type so no dual-cache
// bug, but adding the split BEFORE the second consumer lands is
// the architectural mandate. Tests pin the split's three core
// properties:
//   1. verify_no_replay accepts a valid signed message.
//   2. verify_no_replay does NOT poison the cache (subsequent
//      `verify()` on the same nonce still succeeds).
//   3. verify_no_replay rejects forgery / freshness violations.
// ────────────────────────────────────────────────────────────────

#[test]
fn job_request_verify_no_replay_accepts_valid_signature() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();
    let ts = req
        .verify_no_replay(&key, 300)
        .expect("verify_no_replay must accept a valid signature");
    assert!(ts > 0, "parsed timestamp should be > 0");
}

#[test]
fn job_request_verify_no_replay_does_not_poison_cache() {
    // The key invariant: an observer's verify_no_replay must NOT
    // record the nonce. Otherwise the primary verify() on the
    // same message would fail with "already seen" — the dual-
    // consumer regression the architectural mandate exists to
    // prevent.
    //
    // Serialized against the tests that wipe/bulk-fill the process-global
    // nonce cache — see NONCE_CACHE_TEST_SERIAL.
    let _serial = crate::NONCE_CACHE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();
    req.verify_no_replay(&key, 300)
        .expect("observer call succeeds");
    // Primary consumer's verify must STILL succeed.
    req.verify(&key, 300)
        .expect("primary verify must not collide with observer's verify_no_replay");
    // And THIS verify() should have recorded the nonce, so the
    // next verify() on the same signature must fail.
    assert!(
        req.verify(&key, 300).is_err(),
        "second verify() on the same nonce must fail (replay protection)"
    );
}

#[test]
fn job_request_verify_no_replay_rejects_forgery() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();
    // Tamper with the signature.
    req.signature[0] ^= 0xff;
    assert!(
        req.verify_no_replay(&key, 300).is_err(),
        "tampered signature must fail in verify_no_replay too"
    );
}

#[test]
fn job_request_verify_no_replay_rejects_stale_nonce() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();
    // Rewrite the nonce timestamp to be 1 hour in the past so the
    // freshness window check trips deterministically (same-second
    // sign+verify would otherwise pass with `max_age_secs=0`).
    // The signature will no longer match (we replaced part of the
    // signing input) but verify_no_replay must reject on the
    // freshness check BEFORE reaching HMAC — that's the contract.
    let stale_ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 3600;
    let parts: Vec<&str> = req.job_nonce.splitn(2, ':').collect();
    req.job_nonce = format!("{}:{}", stale_ts, parts[1]);
    let err = req.verify_no_replay(&key, 300).unwrap_err();
    assert!(
        err.contains("too old"),
        "verify_no_replay must reject stale nonce before HMAC; got: {err}"
    );
}

#[test]
fn job_request_verify_rejects_an_oversized_nonce() {
    let key = test_key();
    let mut req = make_test_request(None);
    req.sign(&key).unwrap();
    let ts = req.job_nonce.split(':').next().unwrap().to_string();
    // Well-formed and fresh, but long enough to be a memory lever once
    // recorded. Refused before the MAC, so it never reaches the cache.
    req.job_nonce = format!("{ts}:{}", "ab".repeat(64));
    let err = req.verify_no_replay(&key, 300).unwrap_err();
    assert!(err.contains("oversized"), "got: {err}");
}

fn make_test_heartbeat() -> WorkerHeartbeat {
    WorkerHeartbeat {
        worker_id: format!("worker-{}", Uuid::new_v4().simple()),
        capabilities: vec!["wasm".to_string()],
        cpu_usage_pct: 25.0,
        build_version: Some("0.1.0+abc1234".to_string()),
        heartbeat_nonce: String::new(),
        signature: vec![],
    }
}

#[test]
fn worker_heartbeat_verify_no_replay_does_not_poison_cache() {
    // Serialized against the tests that wipe/bulk-fill the process-global
    // nonce cache — see NONCE_CACHE_TEST_SERIAL.
    let _serial = crate::NONCE_CACHE_TEST_SERIAL
        .lock()
        .unwrap_or_else(|p| p.into_inner());
    let key = test_key();
    let mut hb = make_test_heartbeat();
    hb.sign(&key).unwrap();
    hb.verify_no_replay(&key, 300)
        .expect("observer call succeeds");
    hb.verify(&key, 300)
        .expect("primary verify must not collide with observer");
    assert!(
        hb.verify(&key, 300).is_err(),
        "second primary verify on the same nonce must fail (replay protection)"
    );
}

#[test]
fn worker_heartbeat_verify_no_replay_rejects_forgery() {
    let key = test_key();
    let mut hb = make_test_heartbeat();
    hb.sign(&key).unwrap();
    hb.signature[0] ^= 0xff;
    assert!(
        hb.verify_no_replay(&key, 300).is_err(),
        "tampered heartbeat signature must fail in verify_no_replay"
    );
}

// ------------------------------------------------------------------
// R2 token ledger: llm_usage wire-format + aggregation tests.
// ------------------------------------------------------------------

fn usage_entries() -> Vec<LlmUsageEntry> {
    vec![
        LlmUsageEntry {
            provider: "anthropic".into(),
            model: "claude-sonnet-4-5".into(),
            prompt_tokens: 1200,
            completion_tokens: 340,
            calls: 2,
        },
        LlmUsageEntry {
            provider: "ollama".into(),
            model: "qwen3:6b".into(),
            prompt_tokens: 900,
            completion_tokens: 210,
            calls: 5,
        },
    ]
}

/// A result signed WITHOUT llm_usage (the pre-R2 shape) must verify
/// unchanged — the empty vec appends nothing to the signing payload,
/// so old messages from old workers keep verifying byte-identically.
#[test]
fn llm_usage_empty_signs_byte_identical_to_pre_r2() {
    let key = test_key();
    let mut result = make_test_result();
    let pre_r2_payload = {
        // Simulate the pre-R2 payload by construction: empty usage.
        assert!(result.llm_usage.is_empty());
        result.sign(&key).unwrap();
        result.clone()
    };
    pre_r2_payload.verify_no_replay(&key, 300).unwrap();

    // Round-trip through the wire (serde) and verify again — the
    // field is skip_serializing_if-omitted, deserializes to empty via
    // serde(default), and the payload bytes still match.
    let wire = serde_json::to_string(&pre_r2_payload).unwrap();
    assert!(
        !wire.contains("llm_usage"),
        "empty llm_usage must be omitted from wire JSON"
    );
    let back: JobResult = serde_json::from_str(&wire).unwrap();
    back.verify_no_replay(&key, 300).unwrap();
}

/// Old-message JSON (captured shape with NO llm_usage key at all)
/// deserializes and verifies against a signature produced before the
/// field existed.
#[test]
fn llm_usage_old_wire_json_still_verifies() {
    let key = test_key();
    let mut result = make_test_result();
    result.sign(&key).unwrap();
    // TEXT round trip, never `to_value`/`from_value`: transcoding a
    // message through `Value` re-derives the payload text and silently
    // drops the signed bytes (pinned by
    // `value_transcoding_loses_signed_bytes_but_text_round_trip_does_not`).
    // Parsing the emitted text into a `Value` is only for the assertion
    // below; the `JobResult` is rebuilt from the ORIGINAL text.
    let wire = serde_json::to_string(&result).unwrap();
    // The key truly isn't on the wire (it's `skip_serializing_if` empty),
    // so the text below IS an old-worker message, byte for byte.
    let as_value: serde_json::Value = serde_json::from_str(&wire).unwrap();
    assert!(as_value.get("llm_usage").is_none());
    let back: JobResult = serde_json::from_str(&wire).unwrap();
    back.verify_no_replay(&key, 300).unwrap();
}

/// A result carrying usage round-trips (field survives serde) and
/// verifies; tampering with any usage number invalidates the signature.
#[test]
fn llm_usage_round_trip_and_tamper_detection() {
    let key = test_key();
    let mut result = make_test_result();
    result.llm_usage = usage_entries();
    result.sign(&key).unwrap();

    let wire = serde_json::to_string(&result).unwrap();
    assert!(wire.contains("llm_usage"));
    let back: JobResult = serde_json::from_str(&wire).unwrap();
    assert_eq!(back.llm_usage, usage_entries());
    back.verify_no_replay(&key, 300).unwrap();

    // Tamper: inflate the completion tokens.
    let mut tampered = back.clone();
    tampered.llm_usage[0].completion_tokens += 1;
    assert!(
        tampered.verify_no_replay(&key, 300).is_err(),
        "tampered token count must invalidate the signature"
    );

    // Tamper: strip the usage entirely (deflation attack).
    let mut stripped = back;
    stripped.llm_usage.clear();
    assert!(
        stripped.verify_no_replay(&key, 300).is_err(),
        "stripping llm_usage from a signed result must fail verification"
    );
}

/// The usage digest is order-independent: same entries in a different
/// vec order produce the same signed bytes.
#[test]
fn llm_usage_signing_is_order_independent() {
    let mut a = make_test_result();
    a.llm_usage = usage_entries();
    let mut b = make_test_result();
    b.job_id = a.job_id;
    let mut rev = usage_entries();
    rev.reverse();
    b.llm_usage = rev;
    assert_eq!(a.signing_payload(), b.signing_payload());
}

// ------------------------------------------------------------------
// Out-of-band fuel (2026-09-29): wire compatibility, binding, and the
// one resolution rule every fuel recorder uses.
// ------------------------------------------------------------------

/// A result without `fuel` signs exactly as before the field existed:
/// nothing is appended, and the key is omitted from the wire.
#[test]
fn fuel_absent_signs_byte_identical_to_pre_field() {
    let key = test_key();
    let mut result = make_test_result();
    assert!(result.fuel.is_none());
    let payload = String::from_utf8(result.signing_payload()).unwrap();
    assert!(!payload.contains(":fuel="), "{payload}");
    result.sign(&key).unwrap();
    let wire = serde_json::to_string(&result).unwrap();
    assert!(
        !wire.contains("\"fuel\""),
        "absent fuel must be omitted: {wire}"
    );
    let back: JobResult = serde_json::from_str(&wire).unwrap();
    back.verify_no_replay(&key, 300).unwrap();
}

/// Present fuel is bound: a tamperer cannot lower it (the budget
/// figure), raise it, or strip it without invalidating the signature.
#[test]
fn fuel_round_trip_and_tamper_detection() {
    let key = test_key();
    let mut result = make_test_result();
    result.fuel = Some(FuelMeasure {
        consumed: 1_234_567,
        limit: 5_000_000,
    });
    result.sign(&key).unwrap();
    let wire = serde_json::to_string(&result).unwrap();
    let back: JobResult = serde_json::from_str(&wire).unwrap();
    assert_eq!(back.fuel, result.fuel);
    back.verify_no_replay(&key, 300).unwrap();

    for tamper in [
        |r: &mut JobResult| r.fuel.as_mut().unwrap().consumed -= 1,
        |r: &mut JobResult| r.fuel.as_mut().unwrap().consumed += 1,
        |r: &mut JobResult| r.fuel.as_mut().unwrap().limit = 1,
        |r: &mut JobResult| r.fuel = None,
    ] {
        let mut t = back.clone();
        tamper(&mut t);
        assert!(
            t.verify_no_replay(&key, 300).is_err(),
            "a changed or stripped fuel figure must fail verification"
        );
    }
}

/// The exact bytes the field adds: the pre-field payload, then
/// `:fuel=<consumed>/<limit>` and nothing else. Append-only at the end is
/// what lets a result without the field keep verifying on either side of
/// a rolling deploy. `worker_id` cannot contain `:` (`validate_worker_id`,
/// re-checked at verify), so the segment cannot be forged from it.
#[test]
fn fuel_signing_segment_is_appended_verbatim_at_the_end() {
    let mut result = make_test_result();
    result.llm_usage = usage_entries();
    let without = String::from_utf8(result.signing_payload()).unwrap();
    result.fuel = Some(FuelMeasure {
        consumed: 1_234_567,
        limit: 5_000_000,
    });
    let with = String::from_utf8(result.signing_payload()).unwrap();
    assert_eq!(with, format!("{without}:fuel=1234567/5000000"));
    assert!(
        without.contains(":llm_usage:"),
        "fuel is appended AFTER llm_usage"
    );
}

/// The resolution rule, case by case.
#[test]
fn spent_fuel_prefers_out_of_band_and_falls_back_to_in_band() {
    let oob = Some(FuelMeasure {
        consumed: 900,
        limit: 1_000,
    });
    let in_band = serde_json::json!({"x": 1, "__fuel_consumed__": 500, "__fuel_limit__": 800});

    // Out-of-band wins, even over an in-band figure: one carrier, never both.
    assert_eq!(
        spent_fuel(oob, &in_band),
        Some(SpentFuel {
            consumed: 900,
            limit: Some(1_000),
            source: FuelSource::OutOfBand
        })
    );
    // An array output has no in-band figure; out-of-band still counts it.
    assert_eq!(
        spent_fuel(oob, &serde_json::json!([1, 2, 3])).map(|f| f.consumed),
        Some(900)
    );
    // A pre-field worker: the in-band figure is read, as before.
    assert_eq!(
        spent_fuel(None, &in_band),
        Some(SpentFuel {
            consumed: 500,
            limit: Some(800),
            source: FuelSource::InBand
        })
    );
    // A pre-field worker's array output: nothing to read.
    assert_eq!(spent_fuel(None, &serde_json::json!([1, 2, 3])), None);
    // Zero is not a measurement worth recording, from either carrier.
    assert_eq!(
        spent_fuel(
            Some(FuelMeasure {
                consumed: 0,
                limit: 1
            }),
            &in_band
        ),
        None
    );
    assert_eq!(
        spent_fuel(None, &serde_json::json!({"__fuel_consumed__": 0})),
        None
    );
}

/// aggregate_llm_usage folds per-call observations per (provider, model),
/// counts calls, saturates, and caps the output length.
#[test]
fn aggregate_llm_usage_merges_counts_and_caps() {
    let raw = vec![
        ("anthropic".to_string(), "m1".to_string(), 100u32, 20u32),
        ("anthropic".to_string(), "m1".to_string(), 50, 10),
        ("ollama".to_string(), "m2".to_string(), 7, 3),
    ];
    let agg = aggregate_llm_usage(raw);
    assert_eq!(agg.len(), 2);
    let a = agg.iter().find(|e| e.model == "m1").unwrap();
    assert_eq!(
        (a.prompt_tokens, a.completion_tokens, a.calls),
        (150, 30, 2)
    );
    let o = agg.iter().find(|e| e.model == "m2").unwrap();
    assert_eq!((o.prompt_tokens, o.completion_tokens, o.calls), (7, 3, 1));

    // Saturating add: near-max counts don't wrap.
    let sat = aggregate_llm_usage(vec![
        ("p".to_string(), "m".to_string(), u32::MAX - 1, u32::MAX - 1),
        ("p".to_string(), "m".to_string(), 100, 100),
    ]);
    assert_eq!(sat[0].prompt_tokens, u32::MAX);
    assert_eq!(sat[0].completion_tokens, u32::MAX);

    // Cap: more than MAX_LLM_USAGE_ENTRIES distinct models truncates.
    let many: Vec<_> = (0..MAX_LLM_USAGE_ENTRIES + 8)
        .map(|i| ("p".to_string(), format!("model-{i:03}"), 1u32, 1u32))
        .collect();
    assert_eq!(aggregate_llm_usage(many).len(), MAX_LLM_USAGE_ENTRIES);
}
