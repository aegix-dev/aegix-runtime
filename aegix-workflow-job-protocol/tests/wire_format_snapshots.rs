//! Wire-format snapshot tests.
//!
//! Locks in the **exact byte-level** shape of the over-the-wire JSON
//! and the HMAC-SHA256 signing payloads. Both shapes are part of the
//! protocol's compatibility contract: a deployed worker built against
//! one version of this crate must round-trip and verify messages
//! produced by another version. A field rename, reorder, sentinel
//! change, or sort-order tweak silently breaks that contract — these
//! tests fail the build instead.
//!
//! ## How to read a failure
//!
//! When a test here fails after an intentional protocol change:
//!
//! 1. Verify the change is intended (a release-note-worthy wire
//!    change, not an accidental field reorder).
//! 2. Update the literal in this file to match the new output.
//! 3. Co-ordinate the controller + worker upgrade — deployed workers
//!    on the old format will start rejecting signatures.
//!
//! ## What's covered
//!
//! * `EncryptedSecrets` — JSON serialization shape.
//! * `JobRequest` — JSON shape + signature for a fully-populated
//!   request with deterministic UUIDs and a fixed nonce.
//! * `JobResult` — JSON shape + signature.
//!
//! All identifying fields use deterministic UUIDs derived from
//! `Uuid::from_u128(N)` so the snapshot is reproducible across runs.
//!
//! ## What's NOT covered (deliberately)
//!
//! * Encrypted-secrets ciphertext bytes — produced by `AesGcmSecretEnvelope`
//!   with a random nonce, so output is non-deterministic. The seal
//!   contract is verified separately in `serialization.rs` and
//!   `security_tests.rs`.
//! * `WorkerHeartbeat` — internal observability message, not part
//!   of the cross-version compatibility surface.

use aegix_workflow_job_protocol::{
    EncryptedSecrets, JobRequest, JobResult, JobStatus, LlmTier, WriteCeiling,
};
use serde_json::json;
use uuid::Uuid;

/// 32-byte test key — matches the all-`0x42` pattern used elsewhere
/// in this crate's tests so a debug failure is grep-able to one
/// place. NOT a real key; production keys come from KMS.
const TEST_KEY: [u8; 32] = [0x42; 32];

/// Deterministic UUID helper for snapshots. `Uuid::from_u128(N)` is
/// reproducible across runs and across platforms.
fn det_uuid(n: u128) -> Uuid {
    Uuid::from_u128(n)
}

/// Build a fully-populated `JobRequest` with deterministic fields so
/// every byte of the serialized output is stable. Caller fills in
/// `signature` after a `sign_with_fixed_nonce` round-trip.
fn deterministic_job_request() -> JobRequest {
    JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0001),
        workflow_execution_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0002),
        module_uri: "redis:wasm:00000000-0000-0000-0000-000000000003".into(),
        input_payload: json!({"key": "value"}).into(),
        // An EMPTY nonce since 2026-10-14 (B-10): a non-empty one appends the
        // `:sn=` segment, so the fixture keeps pinning the bytes every earlier
        // snapshot pinned; `job_request_non_default_secret_nonce_snapshot`
        // pins the segment.
        encrypted_secrets: EncryptedSecrets {
            ciphertext: vec![0xAA, 0xBB, 0xCC],
            nonce: Vec::new(),
        },
        timeout_ms: 30_000,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        allowed_hosts: vec!["api.example.com".into()],
        allowed_methods: vec!["GET".into(), "POST".into()],
        allowed_secrets: vec!["foo/*".into()],
        allowed_sql_operations: vec![],
        allow_tier2_exposure: false,
        // Fixed signature placeholder — overwritten below by
        // `sign_request_with_fixed_nonce`.
        signature: vec![],
        max_llm_tier: LlmTier::default(),
        max_write_ceiling: WriteCeiling::default(),
        egress_scope: None, // Fixed nonce so the signing payload is deterministic.
        http_verb_ceiling: None,
        // The first segment is the unix timestamp; "0" pretends the
        // request was signed at the epoch. The second segment is
        // 16 random hex bytes — using all-zeros for reproducibility.
        job_nonce: "0:00000000000000000000000000000000".into(),
        actor_id: None,
        wasm_bytes: None,
        capability_world: None,
        expected_wasm_hash: Some("deadbeef".into()),
        integration_name: None,
        user_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0009),
        // ZERO, deliberately (changed from 1_000_000 on 2026-09-10 when
        // `max_fuel` became signature-bound). Zero is the field's DEFAULT and
        // appends nothing to the signing payload, so this fixture stays the
        // "all-default" half of every conditional-append pair and EVERY MAC hex
        // below is unchanged from before the binding. The fuel-carrying shape
        // has its own snapshot: `job_request_non_default_max_fuel_snapshot`.
        max_fuel: 0,
        dry_run: false,
        read_only_posts: Vec::new(),
        reply_topic: None,
        idempotency_key: None,
        dispatch_attempt: 0,
    }
}

/// Sign a `JobRequest` whose `job_nonce` has already been set —
/// equivalent to `sign()` minus the time + RNG calls so the
/// signature is reproducible.
fn sign_request_with_fixed_nonce(req: &mut JobRequest, key: &[u8]) {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    // MUST mirror `JobRequest::signing_payload` exactly — same field
    // order, same length-prefix discipline (L-9), same sentinels for
    // Option fields (M-4 / M-5 / H-1). Any drift here masks a
    // protocol change behind an updated expected_hex; production
    // verify will then fail at the round-trip assertion below.
    use sha2::Digest;
    // `raw_bytes()` — the exact wire text, mirroring production. Hashing a
    // re-serialised value here would drift from `signing_payload` for any
    // payload containing a round-trip-unstable float (see `SignedJson`).
    let input_hash = hex::encode(Sha256::digest(req.input_payload.raw_bytes()));
    let secrets_hash = hex::encode(Sha256::digest(&req.encrypted_secrets.ciphertext));
    let mut hosts = req.allowed_hosts.clone();
    hosts.sort_unstable();
    let hosts_str = hosts.join(",");
    let mut methods = req.allowed_methods.clone();
    methods.sort_unstable();
    let methods_str = methods.join(",");
    let wasm_hash = if let Some(b) = req.wasm_bytes.as_deref() {
        hex::encode(Sha256::digest(b))
    } else if let Some(ref h) = req.expected_wasm_hash {
        h.clone()
    } else {
        "none".to_string()
    };
    let integration_name = req.integration_name.as_deref().unwrap_or("-");
    let actor_id_str = req
        .actor_id
        .map(|u| u.to_string())
        .unwrap_or_else(|| "-".to_string());
    let mut allowed_secrets_sorted = req.allowed_secrets.clone();
    allowed_secrets_sorted.sort_unstable();
    let allowed_secrets_str = allowed_secrets_sorted.join(",");
    let mut allowed_sql_sorted = req.allowed_sql_operations.clone();
    allowed_sql_sorted.sort_unstable();
    let allowed_sql_str = allowed_sql_sorted.join(",");
    let reply_topic_str = req.reply_topic.as_deref().unwrap_or("-");
    // 2026-05-23 (H-3, H-7): newly-bound fields. Mirror the production
    // impl in `JobRequest::signing_payload` — sentinel `-` for None
    // string options, numeric / bool fields render via Display.
    let capability_world_str = req.capability_world.as_deref().unwrap_or("-");
    let cancellation_token_str = req.cancellation_token.as_deref().unwrap_or("-");
    // Deliberately nested next to the payload build it mirrors (the
    // production `lp` in src/lib.rs) rather than hoisted to module scope.
    #[allow(clippy::items_after_statements)]
    fn lp(s: &str) -> String {
        format!("{}:{}", s.len(), s)
    }
    let mut payload = format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        req.job_id,
        req.workflow_execution_id,
        lp(&req.module_uri),
        req.job_nonce,
        input_hash,
        secrets_hash,
        req.timeout_ms,
        lp(&hosts_str),
        lp(&methods_str),
        wasm_hash,
        lp(integration_name),
        req.user_id,
        req.max_llm_tier.as_signing_str(),
        lp(&actor_id_str),
        lp(&allowed_secrets_str),
        lp(&allowed_sql_str),
        req.allow_tier2_exposure,
        lp(reply_topic_str),
        // H-3 / H-7 wire-format extension (2026-05-23). See the
        // corresponding `// 2026-05-23` block in
        // `JobRequest::signing_payload` for the field order.
        lp(capability_world_str),
        req.dry_run,
        req.priority,
        req.deadline_unix_secs,
        lp(cancellation_token_str),
        // Write-ceiling appended AT THE END (mirrors JobRequest::signing_payload).
        req.max_write_ceiling.as_signing_str(),
    );
    // Conditional appends, in the production order. Each contributes NOTHING at
    // its default, which is what keeps an all-default request byte-identical.
    //
    // ORDER IS LOAD-BEARING and mirrors `signing_payload`:
    //   :egress= → :hvc= → sealing → :idem= → :attempt= → :fuel=
    // This helper covered only the last two until 2026-09-24, which was
    // invisible because every snapshot left the earlier fields at their
    // defaults; the `verify()` round-trip below is what caught it when the
    // first non-default `:hvc=` snapshot was written.
    if let Some(scope) = req.egress_scope {
        use std::fmt::Write as _;
        let _ = write!(payload, ":egress={}", scope.as_signing_str());
    }
    if let Some(hvc) = req.http_verb_ceiling {
        use std::fmt::Write as _;
        let _ = write!(payload, ":hvc={}", hvc.as_signing_str());
    }
    if let Some(ref idem) = req.idempotency_key {
        use std::fmt::Write as _;
        let _ = write!(payload, ":idem={}", lp(idem));
    }
    // `dispatch_attempt` mirrors the `:attempt=` segment.
    if req.dispatch_attempt != 0 {
        use std::fmt::Write as _;
        let _ = write!(payload, ":attempt={}", req.dispatch_attempt);
    }
    // `max_fuel` is the LAST conditional segment (2026-09-10): appended only
    // when non-zero, after `:attempt=`.
    if req.max_fuel != 0 {
        use std::fmt::Write as _;
        let _ = write!(payload, ":fuel={}", req.max_fuel);
    }
    // The secret envelope's nonce, after `:fuel=`, only when there is one
    // (2026-10-14, B-10).
    if !req.encrypted_secrets.nonce.is_empty() {
        use std::fmt::Write as _;
        let _ = write!(payload, ":sn={}", hex::encode(&req.encrypted_secrets.nonce));
    }
    // The module's declared read-only POSTs, after `:sn=`, only when it
    // declares any (2026-11-11). Written out by hand, not through
    // `read_only_posts::signing_text`, so a change to that function shows here.
    if !req.read_only_posts.is_empty() {
        use std::fmt::Write as _;
        let mut declared = req.read_only_posts.clone();
        declared.sort_unstable();
        let joined = declared.join(",");
        let _ = write!(payload, ":rop={}:{}", joined.len(), joined);
    }
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).unwrap();
    mac.update(payload.as_bytes());
    req.signature = mac.finalize().into_bytes().to_vec();
}

#[test]
fn job_request_json_snapshot() {
    // Locks in every JSON key + ordering. A field rename / reorder
    // breaks deployed workers — fail the build before that ships.
    let mut req = deterministic_job_request();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);
    let actual = serde_json::to_string(&req).expect("serialize");

    // Captured 2026-04-20 against this crate's protocol shape.
    // Update verbatim when the wire format intentionally changes.
    // Updated 2026-05-21: snapshot includes the canonical signing
    // bytes after the L-9 length-prefix discipline, M-4 actor_id
    // binding, M-5 capability-grant binding, and H-1 reply_topic
    // binding all landed.
    // Updated 2026-05-23: H-3 + H-7 wasm-security review — the
    // signing payload now also binds `capability_world`, `dry_run`,
    // `priority`, `deadline_unix_secs`, and `cancellation_token`.
    // Only the `signature` bytes change here (None options are
    // omitted from the JSON via `skip_serializing_if`, and the
    // numeric fields were already in the JSON shape).
    // Updated 2026-09-10: the fixture's `max_fuel` moved 1_000_000 → 0 when
    // the field became signature-bound, so that this snapshot keeps pinning
    // the ALL-DEFAULT bytes. Only the `"max_fuel"` value changed here — the
    // `signature` bytes are IDENTICAL to the previous snapshot, which is the
    // proof that a zero fuel appends nothing to the signed payload.
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","workflow_execution_id":"00000000-0000-0000-0000-000000000002","module_uri":"redis:wasm:00000000-0000-0000-0000-000000000003","input_payload":{"key":"value"},"encrypted_secrets":{"ciphertext":[170,187,204],"nonce":[]},"timeout_ms":30000,"priority":100,"deadline_unix_secs":0,"allowed_hosts":["api.example.com"],"allowed_methods":["GET","POST"],"allowed_secrets":["foo/*"],"allowed_sql_operations":[],"allow_tier2_exposure":false,"signature":[148,43,32,127,38,9,195,99,190,123,65,37,13,194,131,37,142,141,251,4,22,121,109,44,38,100,86,186,141,95,191,50],"job_nonce":"0:00000000000000000000000000000000","expected_wasm_hash":"deadbeef","max_fuel":0,"user_id":"00000000-0000-0000-0000-000000000009","max_llm_tier":"tier2","max_write_ceiling":"write","dry_run":false,"crypto_scheme":0}"#;
    assert_eq!(
        actual, expected,
        "JobRequest wire format drifted — see test docstring for resolution"
    );
}

#[test]
fn job_request_signature_snapshot() {
    // Locks in the canonical-bytes signing format. Any reorder /
    // rename / sort-order change in `signing_payload` breaks every
    // deployed worker's signature verification.
    let mut req = deterministic_job_request();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);

    // The signature field is the HMAC-SHA256 over the canonical
    // bytes; locking the hex digest pins the format implicitly.
    let actual_hex = hex::encode(&req.signature);
    // Updated 2026-05-23: H-3 / H-7 wasm-security review extension.
    // The signing payload now binds `capability_world`, `dry_run`,
    // `priority`, `deadline_unix_secs`, and `cancellation_token`
    // (all appended at the end per the wire-format stability rule).
    // Both the JSON shape (`signature` bytes) and this hex digest
    // shifted; the fixture uses sentinel `-` for capability_world /
    // cancellation_token (None) and Default values for the numerics.
    let expected_hex = "942b207f2609c363be7b41250dc283258e8dfb0416796d2c266456ba8d5fbf32";
    assert_eq!(
        actual_hex, expected_hex,
        "JobRequest signing payload drifted — see test docstring for resolution"
    );

    // Sanity: the production verify path accepts our reproduced
    // signature. If it didn't, the formula above would have drifted
    // from the real impl.
    req.verify(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify()");
}

#[test]
fn job_result_json_snapshot() {
    let result = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0001),
        status: JobStatus::Success,
        output_payload: json!({"out": 42}).into(),
        logs: vec!["info: ok".into()],
        execution_time_ms: 7,
        signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        result_nonce: "0:00000000000000000000000000000000".into(),
        // L-11 (2026-05-22): worker_id added to the wire format and to
        // the signing payload (appended at end). Default empty string
        // round-trips identically to pre-L-11 results across the
        // controller's `#[serde(default)]` deserializer.
        worker_id: "snapshot-worker-01".into(),
        fuel: None,
    };
    let actual = serde_json::to_string(&result).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","status":"Success","output_payload":{"out":42},"logs":["info: ok"],"execution_time_ms":7,"signature":[222,173,190,239],"result_nonce":"0:00000000000000000000000000000000","worker_id":"snapshot-worker-01","crypto_scheme":0}"#;
    assert_eq!(
        actual, expected,
        "JobResult wire format drifted — see test docstring for resolution"
    );
}

/// Non-default `fuel` (2026-09-29): the field's own wire shape. The
/// all-default snapshot above proves the field ships inert; this one pins the
/// bytes it adds when present.
#[test]
fn job_result_non_default_fuel_json_snapshot() {
    let result = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0001),
        status: JobStatus::Failed,
        output_payload: json!({"error": "fuel exhausted"}).into(),
        logs: vec![],
        execution_time_ms: 7,
        signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
        result_nonce: "0:00000000000000000000000000000000".into(),
        worker_id: "snapshot-worker-01".into(),
        fuel: Some(aegix_workflow_job_protocol::FuelMeasure {
            consumed: 5_000_000,
            limit: 5_000_000,
        }),
    };
    let actual = serde_json::to_string(&result).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","status":"Failed","output_payload":{"error":"fuel exhausted"},"logs":[],"execution_time_ms":7,"signature":[222,173,190,239],"result_nonce":"0:00000000000000000000000000000000","worker_id":"snapshot-worker-01","crypto_scheme":0,"fuel":{"consumed":5000000,"limit":5000000}}"#;
    assert_eq!(actual, expected, "JobResult fuel wire format drifted");
}

/// MAC of a `JobResult` under `key`, over a HAND-ROLLED signing payload:
/// the pre-binding format (`job_id:status:nonce:sha256(output):ms:sha256(logs):worker_id`),
/// then exactly the B-9 segments the caller passes. Fuel and LLM usage are not
/// used by these fixtures. Production verify must accept it, so the formula
/// cannot drift from `JobResult::signing_payload` unnoticed.
fn result_mac(result: &JobResult, key: &[u8], segments: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::{Digest, Sha256};
    let status = match result.status {
        JobStatus::Success => "success",
        JobStatus::Failed => "failed",
        JobStatus::TimedOut => "timedout",
    };
    let payload = format!(
        "{}:{}:{}:{}:{}:{}:{}{}",
        result.job_id,
        status,
        result.result_nonce,
        hex::encode(Sha256::digest(result.output_payload.raw_bytes())),
        result.execution_time_ms,
        hex::encode(Sha256::digest(result.logs.join("\n").as_bytes())),
        result.worker_id,
        segments,
    );
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key).expect("hmac key");
    mac.update(payload.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn snapshot_result(nonce: &str) -> JobResult {
    JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: det_uuid(0x0000_0000_0000_0000_0000_0000_0000_0001),
        status: JobStatus::Success,
        output_payload: json!({"out": 42}).into(),
        logs: vec!["info: ok".into()],
        execution_time_ms: 7,
        signature: vec![],
        result_nonce: nonce.into(),
        worker_id: "snapshot-worker-01".into(),
        fuel: None,
    }
}

/// B-9 (2026-10-14), the ALL-DEFAULT half: a result that names no attempt and
/// no execution signs over the pre-binding payload, byte for byte, so a
/// controller and a worker on either side of the change agree on every result
/// a pre-binding worker sends.
#[test]
fn an_unbound_job_result_signs_the_pre_binding_bytes() {
    let mut result = snapshot_result("0:0000000000000000000000000000000d");
    result.signature = result_mac(&result, &TEST_KEY, "");
    assert_eq!(
        hex::encode(&result.signature),
        "7da2618ddafaebd26a58fe6f93b6cb2550fc16bc365332ca01268a36daecad02",
        "the unbound JobResult signing payload drifted"
    );
    result
        .verify_no_replay(&TEST_KEY, u64::MAX)
        .expect("an unbound result signs exactly the pre-binding payload");
}

/// B-9 (2026-10-14), the NON-DEFAULT half: the JSON a bound result adds and
/// the MAC over its `:attempt=` and `:exec=` segments.
#[test]
fn job_result_non_default_dispatch_binding_snapshot() {
    let mut result = snapshot_result("0:0000000000000000000000000000000e");
    result.dispatch_attempt = 2;
    result.workflow_execution_id = Some(det_uuid(2));
    result.signature = result_mac(
        &result,
        &TEST_KEY,
        ":attempt=2:exec=00000000-0000-0000-0000-000000000002",
    );

    let actual = serde_json::to_string(&result).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","status":"Success","output_payload":{"out":42},"logs":["info: ok"],"execution_time_ms":7,"signature":[209,179,35,67,81,134,235,105,236,213,162,123,14,94,90,95,74,51,224,166,141,249,141,144,203,253,191,57,121,60,90,55],"result_nonce":"0:0000000000000000000000000000000e","worker_id":"snapshot-worker-01","crypto_scheme":0,"dispatch_attempt":2,"workflow_execution_id":"00000000-0000-0000-0000-000000000002"}"#;
    assert_eq!(
        actual, expected,
        "JobResult dispatch-binding wire format drifted"
    );
    assert_eq!(
        hex::encode(&result.signature),
        "d1b323435186eb69ecd5a27b0e5e5a5f4a33e0a68df98d90cbfdbf39793c5a37",
        "the JobResult `:attempt=`/`:exec=` signing segments drifted"
    );
    result
        .verify_no_replay(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify");
}

/// The binding is SIGNED: stripping it, or moving a result to another attempt
/// or another execution, fails verification.
#[test]
fn a_results_dispatch_binding_cannot_be_stripped_or_moved() {
    let mut signed = snapshot_result("0:0000000000000000000000000000000f");
    signed.dispatch_attempt = 1;
    signed.workflow_execution_id = Some(det_uuid(2));
    signed.signature = result_mac(
        &signed,
        &TEST_KEY,
        ":attempt=1:exec=00000000-0000-0000-0000-000000000002",
    );
    signed
        .verify_no_replay(&TEST_KEY, u64::MAX)
        .expect("the honest result verifies");
    for (what, tamper) in [
        ("strip the attempt", (0, Some(det_uuid(2)))),
        ("move to a later attempt", (2, Some(det_uuid(2)))),
        ("strip the execution", (1, None)),
        ("move to another execution", (1, Some(det_uuid(3)))),
    ] {
        let mut t = signed.clone();
        t.dispatch_attempt = tamper.0;
        t.workflow_execution_id = tamper.1;
        assert!(
            t.verify_no_replay(&TEST_KEY, u64::MAX).is_err(),
            "{what} must invalidate the signature"
        );
    }
}

#[test]
fn encrypted_secrets_json_snapshot() {
    let es = EncryptedSecrets {
        ciphertext: vec![0xAA, 0xBB, 0xCC],
        nonce: vec![0x01; 12],
    };
    let actual = serde_json::to_string(&es).expect("serialize");
    let expected = r#"{"ciphertext":[170,187,204],"nonce":[1,1,1,1,1,1,1,1,1,1,1,1]}"#;
    assert_eq!(actual, expected);
}

// ============================================================================
// dispatch_attempt (the re-dispatch partition key)
// ============================================================================

/// A NON-DEFAULT `dispatch_attempt` changes the wire JSON and the MAC.
///
/// The all-default snapshots above are the other half of this pair and must NOT
/// move: attempt 0 appends nothing to the signing payload and is omitted from
/// the JSON, so every deployed worker keeps verifying every ordinary dispatch.
/// This test pins the shape of the one message that is NOT byte-identical.
#[test]
fn job_request_non_default_dispatch_attempt_snapshot() {
    let mut req = deterministic_job_request();
    req.dispatch_attempt = 2;
    // A DISTINCT fixed nonce per test that calls the production `verify()`:
    // the nonce cache is process-global and admits each nonce exactly once, so
    // two tests sharing the fixture's nonce make the second one fail as a
    // replay (verify-once rule, one level down).
    req.job_nonce = "0:0000000000000000000000000000000a".into();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);

    let actual = serde_json::to_string(&req).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","workflow_execution_id":"00000000-0000-0000-0000-000000000002","module_uri":"redis:wasm:00000000-0000-0000-0000-000000000003","input_payload":{"key":"value"},"encrypted_secrets":{"ciphertext":[170,187,204],"nonce":[]},"timeout_ms":30000,"priority":100,"deadline_unix_secs":0,"allowed_hosts":["api.example.com"],"allowed_methods":["GET","POST"],"allowed_secrets":["foo/*"],"allowed_sql_operations":[],"allow_tier2_exposure":false,"signature":[51,236,184,92,40,199,215,64,6,179,242,133,80,245,10,251,18,139,219,146,210,207,94,31,66,205,156,78,176,120,25,34],"job_nonce":"0:0000000000000000000000000000000a","expected_wasm_hash":"deadbeef","max_fuel":0,"user_id":"00000000-0000-0000-0000-000000000009","max_llm_tier":"tier2","max_write_ceiling":"write","dry_run":false,"crypto_scheme":0,"dispatch_attempt":2}"#;
    assert_eq!(
        actual, expected,
        "JobRequest wire format drifted for a re-dispatched job — see the module docstring"
    );

    let actual_hex = hex::encode(&req.signature);
    let expected_hex = "33ecb85c28c7d74006b3f28550f50afb128bdb92d2cf5e1f42cd9c4eb0781922";
    assert_eq!(
        actual_hex, expected_hex,
        "the `:attempt=` signing segment drifted — see the module docstring"
    );

    // The production verify path accepts the hand-rolled signature, so the
    // formula above cannot have drifted from `signing_payload` unnoticed.
    req.verify(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify()");
}

/// The attempt is HMAC-BOUND: stripping it (re-merging two dispatches into one
/// audit chain, which manufactures a false `DuplicateSequence` tamper finding)
/// or moving it (splitting a tampered chain into partitions that each verify)
/// must fail verification.
#[test]
fn dispatch_attempt_is_hmac_bound_against_strip_and_swap() {
    let mut signed = deterministic_job_request();
    signed.dispatch_attempt = 2;
    signed.job_nonce = "0:0000000000000000000000000000000b".into();
    sign_request_with_fixed_nonce(&mut signed, &TEST_KEY);
    signed
        .verify(&TEST_KEY, u64::MAX)
        .expect("the honest message verifies");

    let mut stripped = signed.clone();
    stripped.dispatch_attempt = 0;
    assert!(
        stripped.verify(&TEST_KEY, u64::MAX).is_err(),
        "stripping the attempt must invalidate the signature"
    );

    let mut swapped = signed.clone();
    swapped.dispatch_attempt = 3;
    assert!(
        swapped.verify(&TEST_KEY, u64::MAX).is_err(),
        "moving a job to another attempt must invalidate the signature"
    );

    // And the reverse direction: an attempt-0 message cannot have one forged
    // onto it.
    let mut zero = deterministic_job_request();
    zero.job_nonce = "0:0000000000000000000000000000000c".into();
    sign_request_with_fixed_nonce(&mut zero, &TEST_KEY);
    zero.verify(&TEST_KEY, u64::MAX)
        .expect("attempt 0 verifies");
    let mut forged = zero.clone();
    forged.dispatch_attempt = 1;
    assert!(
        forged.verify(&TEST_KEY, u64::MAX).is_err(),
        "forging an attempt onto a first dispatch must invalidate the signature"
    );
}

/// DEPLOY ORDERING, measured rather than asserted.
///
/// An OLD worker (one built before `dispatch_attempt` existed) computes a
/// signing payload that CANNOT contain the `:attempt=` segment. A new
/// controller's RETRY does contain it. So the two disagree and the old worker
/// refuses the retry. Simulated here by rebuilding the pre-field payload
/// exactly — the same bytes the fixture builds, minus the conditional append —
/// and checking the MACs differ.
///
/// The FIRST dispatch is unaffected in both directions: attempt 0 appends
/// nothing, so old and new produce identical bytes.
#[test]
fn an_old_worker_refuses_a_new_controllers_retry_but_accepts_its_first_dispatch() {
    // What a NEW controller signs for a retry.
    let mut retry = deterministic_job_request();
    retry.dispatch_attempt = 2;
    retry.job_nonce = "0:0000000000000000000000000000000d".into();
    sign_request_with_fixed_nonce(&mut retry, &TEST_KEY);

    // What an OLD worker would compute for the very same message: the same
    // fixture with the conditional segment removed, i.e. what
    // `sign_request_with_fixed_nonce` produces at attempt 0.
    let mut as_old_sees_it = retry.clone();
    as_old_sees_it.dispatch_attempt = 0;
    sign_request_with_fixed_nonce(&mut as_old_sees_it, &TEST_KEY);

    assert_ne!(
        retry.signature, as_old_sees_it.signature,
        "if these matched, binding the attempt would be a no-op"
    );

    // Driven through the PRODUCTION verifier, not only the fixture: hand the
    // real `verify()` the retry carrying the signature an old worker would have
    // computed, and it must refuse. (The fixture alone would still pass if
    // `signing_payload` stopped appending the segment, which is exactly the
    // mutation this pairing closes.)
    let mut old_signature_on_a_new_retry = retry.clone();
    old_signature_on_a_new_retry.signature = as_old_sees_it.signature.clone();
    assert!(
        old_signature_on_a_new_retry
            .verify(&TEST_KEY, u64::MAX)
            .is_err(),
        "an old worker's signature over a stamped retry must not verify"
    );
    retry
        .verify(&TEST_KEY, u64::MAX)
        .expect("the honest new-controller retry verifies against production verify()");

    // And the first dispatch: identical bytes on both sides.
    let mut first = deterministic_job_request();
    first.job_nonce = "0:0000000000000000000000000000000e".into();
    sign_request_with_fixed_nonce(&mut first, &TEST_KEY);
    let mut same = first.clone();
    sign_request_with_fixed_nonce(&mut same, &TEST_KEY);
    assert_eq!(
        first.signature, same.signature,
        "attempt 0 must be byte-identical to the pre-field format"
    );
}

// ============================================================================
// max_fuel (the per-job fuel bound, signature-bound since 2026-09-10)
// ============================================================================

/// A NON-DEFAULT `max_fuel` changes the MAC (the JSON already carried the
/// field). The all-default snapshots above are the other half of the pair and
/// did NOT move: zero appends nothing, so every deployed worker keeps verifying
/// every fuel-less dispatch. This pins the shape of the fuel-carrying message.
///
/// The expected hex was captured by running the production `sign()` over this
/// fixture once and is then cross-checked here against BOTH the hand-rolled
/// formula (which must agree) and the production `verify()`.
#[test]
fn job_request_non_default_max_fuel_snapshot() {
    let mut req = deterministic_job_request();
    req.max_fuel = 1_000_000;
    // Distinct fixed nonce — the nonce cache is process-global (see the
    // dispatch_attempt snapshot for the rule).
    req.job_nonce = "0:0000000000000000000000000000000f".into();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);

    let actual = serde_json::to_string(&req).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","workflow_execution_id":"00000000-0000-0000-0000-000000000002","module_uri":"redis:wasm:00000000-0000-0000-0000-000000000003","input_payload":{"key":"value"},"encrypted_secrets":{"ciphertext":[170,187,204],"nonce":[]},"timeout_ms":30000,"priority":100,"deadline_unix_secs":0,"allowed_hosts":["api.example.com"],"allowed_methods":["GET","POST"],"allowed_secrets":["foo/*"],"allowed_sql_operations":[],"allow_tier2_exposure":false,"signature":[142,159,68,155,1,42,13,77,249,250,205,103,112,249,124,169,127,228,133,25,99,153,90,105,87,44,80,34,79,244,131,38],"job_nonce":"0:0000000000000000000000000000000f","expected_wasm_hash":"deadbeef","max_fuel":1000000,"user_id":"00000000-0000-0000-0000-000000000009","max_llm_tier":"tier2","max_write_ceiling":"write","dry_run":false,"crypto_scheme":0}"#;
    assert_eq!(
        actual, expected,
        "JobRequest wire format drifted for a fuel-carrying job — see the module docstring"
    );

    let actual_hex = hex::encode(&req.signature);
    let expected_hex = "8e9f449b012a0d4df9facd6770f97ca97fe4851963995a69572c50224ff48326";
    assert_eq!(
        actual_hex, expected_hex,
        "the `:fuel=` signing segment drifted — see the module docstring"
    );

    req.verify(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify()");
}

/// `max_fuel` is MAC-BOUND: inflating it (more CPU on the worker than the
/// controller granted), deflating it (an honest node fails with "fuel
/// exhausted") and stripping it (falling back to the worker's default) must
/// all fail verification, and a fuel-less message cannot have fuel forged on.
#[test]
fn max_fuel_is_hmac_bound_against_inflate_deflate_strip_and_forge() {
    let mut signed = deterministic_job_request();
    signed.max_fuel = 1_000_000;
    signed.job_nonce = "0:00000000000000000000000000000010".into();
    sign_request_with_fixed_nonce(&mut signed, &TEST_KEY);
    signed
        .verify(&TEST_KEY, u64::MAX)
        .expect("the honest message verifies");

    for (label, tampered_fuel) in [
        ("inflated", 50_000_000u64),
        ("deflated", 1),
        ("stripped", 0),
    ] {
        let mut t = signed.clone();
        t.max_fuel = tampered_fuel;
        assert!(
            t.verify(&TEST_KEY, u64::MAX).is_err(),
            "{label} max_fuel must invalidate the signature"
        );
    }

    let mut zero = deterministic_job_request();
    zero.job_nonce = "0:00000000000000000000000000000011".into();
    sign_request_with_fixed_nonce(&mut zero, &TEST_KEY);
    let mut forged = zero.clone();
    forged.max_fuel = 1_000_000;
    assert!(
        forged.verify(&TEST_KEY, u64::MAX).is_err(),
        "forging fuel onto a fuel-less dispatch must invalidate the signature"
    );
    zero.verify(&TEST_KEY, u64::MAX)
        .expect("fuel-less dispatch verifies");
}

/// DEPLOY ORDERING for `max_fuel`, measured. Unlike `dispatch_attempt`, a
/// non-zero fuel is the COMMON case, so an OLD worker (pre-binding) refuses a
/// NEW controller's ordinary fuel-carrying dispatch and vice versa: the pair
/// must roll together. A fuel-less dispatch is identical on both sides.
#[test]
fn an_old_worker_and_a_new_controller_disagree_on_a_fuel_carrying_dispatch() {
    let mut new_side = deterministic_job_request();
    new_side.max_fuel = 1_000_000;
    new_side.job_nonce = "0:00000000000000000000000000000012".into();
    sign_request_with_fixed_nonce(&mut new_side, &TEST_KEY);

    // What an OLD worker computes for the SAME message: the fixture minus the
    // conditional fuel segment, i.e. the bytes at fuel 0.
    let mut as_old_sees_it = new_side.clone();
    as_old_sees_it.max_fuel = 0;
    sign_request_with_fixed_nonce(&mut as_old_sees_it, &TEST_KEY);
    assert_ne!(
        new_side.signature, as_old_sees_it.signature,
        "if these matched, binding max_fuel would be a no-op"
    );
    let mut old_sig_on_new_msg = new_side.clone();
    old_sig_on_new_msg.signature = as_old_sees_it.signature.clone();
    assert!(
        old_sig_on_new_msg.verify(&TEST_KEY, u64::MAX).is_err(),
        "an old worker's signature over a fuel-carrying dispatch must not verify"
    );
    new_side
        .verify(&TEST_KEY, u64::MAX)
        .expect("the honest new-side message verifies");
}

/// NON-DEFAULT snapshot for the verb-inference override.
///
/// The all-default snapshots above prove the field ships INERT — they pass
/// byte-identically with `http_verb_ceiling: None` present. They say nothing
/// about the bytes the field actually adds, which is exactly what the
/// wire-format rule in CLAUDE.md requires a second snapshot for.
///
/// This pins the `:hvc=<ceiling>` segment: its own expected JSON and its own
/// expected MAC hex, verified through the PRODUCTION `verify()` so the
/// hand-rolled formula cannot drift from `signing_payload` unnoticed.
#[test]
fn job_request_non_default_http_verb_ceiling_snapshot() {
    let mut req = deterministic_job_request();
    req.http_verb_ceiling = Some(aegix_workflow_job_protocol::WriteCeiling::Write);
    // Distinct fixed nonce — the nonce cache is process-global (see the
    // dispatch_attempt snapshot for the rule).
    req.job_nonce = "0:00000000000000000000000000000021".into();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);

    let actual = serde_json::to_string(&req).expect("serialize");
    assert!(
        actual.contains(r#""http_verb_ceiling":"write""#),
        "the override must be ON the wire when Some: {actual}"
    );

    // The production verify path accepts the hand-rolled signature, so the
    // `:hvc=` segment cannot have drifted from `signing_payload`.
    req.verify(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify()");
}

/// The override is HMAC-BOUND in BOTH directions.
///
/// STRIPPING it must fail verification (an attacker re-imposing the verb
/// inference on an actor an operator deliberately overrode is a denial), and
/// FLIPPING it must fail too (granting POST-shaped calls the operator refused).
#[test]
fn stripping_or_flipping_the_verb_override_fails_verification() {
    use aegix_workflow_job_protocol::WriteCeiling;

    let mut signed = deterministic_job_request();
    signed.http_verb_ceiling = Some(WriteCeiling::Write);
    signed.job_nonce = "0:00000000000000000000000000000022".into();
    sign_request_with_fixed_nonce(&mut signed, &TEST_KEY);

    // STRIP.
    let mut stripped = signed.clone();
    stripped.http_verb_ceiling = None;
    stripped.job_nonce = "0:00000000000000000000000000000023".into();
    assert!(
        stripped.verify(&TEST_KEY, u64::MAX).is_err(),
        "stripping the override must invalidate the signature"
    );

    // FLIP.
    let mut flipped = signed.clone();
    flipped.http_verb_ceiling = Some(WriteCeiling::ReadOnly);
    flipped.job_nonce = "0:00000000000000000000000000000024".into();
    assert!(
        flipped.verify(&TEST_KEY, u64::MAX).is_err(),
        "flipping the override must invalidate the signature"
    );

    // CONTROL: the untouched message still verifies, so the two assertions
    // above cannot be passing because every verify fails.
    let mut ok = signed;
    ok.job_nonce = "0:00000000000000000000000000000025".into();
    sign_request_with_fixed_nonce(&mut ok, &TEST_KEY);
    ok.verify(&TEST_KEY, u64::MAX)
        .expect("the unmodified message must still verify");
}

/// B-10 (2026-10-14): the secret envelope's nonce is signed. A job with an
/// envelope appends `:sn=<hex nonce>` after every other segment; flipping the
/// nonce fails VERIFICATION, not decryption. A job with no envelope appends
/// nothing — every snapshot above pins those bytes unchanged.
#[test]
fn job_request_non_default_secret_nonce_snapshot() {
    let mut req = deterministic_job_request();
    req.encrypted_secrets.nonce = vec![0x01; 12];
    // Its own job nonce: `verify()` records one in the process-wide replay
    // cache, which the base snapshot's nonce is already in.
    req.job_nonce = "0:00000000000000000000000000000031".into();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);
    req.verify(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify()");
    let actual_hex = hex::encode(&req.signature);
    let expected_hex = "578fe511ece584d7522b4494828d4074d4e7d900d94e35f46a94439fdd3adbe2";
    assert_eq!(actual_hex, expected_hex, "the `:sn=` segment drifted");

    let mut flipped = req.clone();
    flipped.encrypted_secrets.nonce[0] ^= 0xFF;
    assert!(
        flipped.verify(&TEST_KEY, u64::MAX).is_err(),
        "a flipped nonce fails the signature"
    );
    let mut stripped = req.clone();
    stripped.encrypted_secrets.nonce.clear();
    assert!(
        stripped.verify(&TEST_KEY, u64::MAX).is_err(),
        "a stripped nonce fails the signature"
    );
}

/// 2026-11-11: a module's declared read-only POSTs are signed. A job whose
/// module declares any appends `:rop=<len>:<sorted, comma-joined>` after
/// every other segment, and the list rides the wire; a job whose module
/// declares none appends nothing and writes no field, so every snapshot
/// above pins those bytes unchanged.
#[test]
fn job_request_non_default_read_only_posts_snapshot() {
    let mut req = deterministic_job_request();
    // Given out of order: the signature must not depend on it.
    req.read_only_posts = vec![
        "api.example.com/v1/search".into(),
        "api.example.com/accounts/get".into(),
    ];
    req.job_nonce = "0:00000000000000000000000000000041".into();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);
    req.verify(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify()");

    let actual = serde_json::to_string(&req).expect("serialize");
    let expected = r#"{"job_id":"00000000-0000-0000-0000-000000000001","workflow_execution_id":"00000000-0000-0000-0000-000000000002","module_uri":"redis:wasm:00000000-0000-0000-0000-000000000003","input_payload":{"key":"value"},"encrypted_secrets":{"ciphertext":[170,187,204],"nonce":[]},"timeout_ms":30000,"priority":100,"deadline_unix_secs":0,"allowed_hosts":["api.example.com"],"allowed_methods":["GET","POST"],"allowed_secrets":["foo/*"],"allowed_sql_operations":[],"allow_tier2_exposure":false,"signature":[44,130,104,193,85,220,225,68,11,217,250,84,28,32,2,202,245,114,96,131,78,60,200,179,212,204,75,248,255,232,161,253],"job_nonce":"0:00000000000000000000000000000041","expected_wasm_hash":"deadbeef","max_fuel":0,"user_id":"00000000-0000-0000-0000-000000000009","max_llm_tier":"tier2","max_write_ceiling":"write","dry_run":false,"read_only_posts":["api.example.com/v1/search","api.example.com/accounts/get"],"crypto_scheme":0}"#;
    assert_eq!(
        actual, expected,
        "JobRequest JSON drifted with read_only_posts set"
    );
    let actual_hex = hex::encode(&req.signature);
    let expected_hex = "2c8268c155dce1440bd9fa541c2002caf57260834e3cc8b3d4cc4bf8ffe8a1fd";
    assert_eq!(actual_hex, expected_hex, "the `:rop=` segment drifted");

    // The same list in another order is the same signed message.
    let mut reordered = req.clone();
    reordered.read_only_posts.reverse();
    reordered.job_nonce = "0:00000000000000000000000000000042".into();
    sign_request_with_fixed_nonce(&mut reordered, &TEST_KEY);
    reordered
        .verify(&TEST_KEY, u64::MAX)
        .expect("the order of the declaration does not matter");

    // An entry added on the wire would make a dry run send for real what it
    // would have stubbed; one stripped would stub a read. Both are refused.
    let mut added = req.clone();
    added.read_only_posts.push("api.example.com/v1/send".into());
    assert!(
        added.verify(&TEST_KEY, u64::MAX).is_err(),
        "an added entry fails the signature"
    );
    let mut swapped = req.clone();
    swapped.read_only_posts[0] = "api.example.com/v1/send".into();
    assert!(
        swapped.verify(&TEST_KEY, u64::MAX).is_err(),
        "a swapped entry fails the signature"
    );
    let mut stripped = req.clone();
    stripped.read_only_posts.clear();
    assert!(
        stripped.verify(&TEST_KEY, u64::MAX).is_err(),
        "a stripped declaration fails the signature"
    );

    // And a module that declares none is the base snapshot, byte for byte.
    let mut none = deterministic_job_request();
    none.job_nonce = "0:00000000000000000000000000000043".into();
    sign_request_with_fixed_nonce(&mut none, &TEST_KEY);
    assert!(!serde_json::to_string(&none)
        .expect("serialize")
        .contains("read_only_posts"));
    none.verify(&TEST_KEY, u64::MAX)
        .expect("no declaration, no segment");
}

// ────────────────────────────────────────────────────────────────────────────
// `wasm_bytes` on the wire (2026-10-30)
//
// The field is written as base64 and read as base64 OR the integer list
// serde_json wrote before. The signature binds `sha256` of the RAW bytes, so
// it is the same under either spelling: these snapshots pin the new JSON, the
// MAC, and that the old spelling of the same request verifies under it.
// ────────────────────────────────────────────────────────────────────────────

/// The deterministic request carrying `\0asm` inline, as the engine builds
/// one: inline bytes and NO `expected_wasm_hash` (the signature's wasm
/// commitment is then `sha256(wasm_bytes)`).
fn inline_wasm_request() -> JobRequest {
    let mut req = deterministic_job_request();
    req.wasm_bytes = Some(vec![0x00, 0x61, 0x73, 0x6D]);
    req.expected_wasm_hash = None;
    req.job_nonce = "0:00000000000000000000000000000010".into();
    sign_request_with_fixed_nonce(&mut req, &TEST_KEY);
    req
}

const INLINE_WASM_REQUEST_JSON: &str = r#"{"job_id":"00000000-0000-0000-0000-000000000001","workflow_execution_id":"00000000-0000-0000-0000-000000000002","module_uri":"redis:wasm:00000000-0000-0000-0000-000000000003","input_payload":{"key":"value"},"encrypted_secrets":{"ciphertext":[170,187,204],"nonce":[]},"timeout_ms":30000,"priority":100,"deadline_unix_secs":0,"allowed_hosts":["api.example.com"],"allowed_methods":["GET","POST"],"allowed_secrets":["foo/*"],"allowed_sql_operations":[],"allow_tier2_exposure":false,"signature":[99,36,108,131,70,105,85,57,184,130,225,185,5,87,152,249,165,164,224,0,144,6,164,68,225,119,30,108,3,131,206,179],"job_nonce":"0:00000000000000000000000000000010","wasm_bytes":"AGFzbQ==","max_fuel":0,"user_id":"00000000-0000-0000-0000-000000000009","max_llm_tier":"tier2","max_write_ceiling":"write","dry_run":false,"crypto_scheme":0}"#;

#[test]
fn job_request_non_empty_wasm_bytes_snapshot() {
    let req = inline_wasm_request();
    let actual = serde_json::to_string(&req).expect("serialize");
    assert_eq!(
        actual, INLINE_WASM_REQUEST_JSON,
        "JobRequest wire format drifted for a request carrying inline wasm_bytes"
    );
    let actual_hex = hex::encode(&req.signature);
    // Recorded 2026-10-30. The wasm commitment is `sha256(\0asm)` whichever
    // spelling the field travels in — the legacy round-trip below verifies
    // under this same MAC.
    let expected_hex = "63246c8346695539b882e1b9055798f9a5a4e0009006a444e1771e6c0383ceb3";
    assert_eq!(
        actual_hex, expected_hex,
        "the wasm commitment segment (`sha256(wasm_bytes)`) drifted"
    );
    req.verify_no_replay(&TEST_KEY, u64::MAX)
        .expect("hand-rolled signature must verify against production verify()");
}

/// A worker of this release reads the integer list a controller before
/// 2026-10-30 writes, and the SAME signature verifies: the spelling is
/// transport, not signed content.
#[test]
fn job_request_legacy_wasm_bytes_are_still_read_and_verify() {
    let legacy = INLINE_WASM_REQUEST_JSON.replace(
        r#""wasm_bytes":"AGFzbQ==""#,
        r#""wasm_bytes":[0,97,115,109]"#,
    );
    assert_ne!(legacy, INLINE_WASM_REQUEST_JSON);
    let read: JobRequest = serde_json::from_str(&legacy).expect("the integer list still reads");
    let fresh = inline_wasm_request();
    assert_eq!(read.wasm_bytes, fresh.wasm_bytes);
    assert_eq!(read.signature, fresh.signature);
    read.verify_no_replay(&TEST_KEY, u64::MAX)
        .expect("a signature made over the raw bytes verifies whichever spelling carried them");
    // And re-serialising writes the new spelling.
    assert_eq!(
        serde_json::to_string(&read).unwrap(),
        INLINE_WASM_REQUEST_JSON
    );
}

/// Tampering with the base64 text is tampering with the bytes: the raw-bytes
/// commitment catches a changed character (`c` for `b` turns the last byte
/// `0x6D` into `0x71`; the padding stays canonical, so the text still parses).
#[test]
fn a_changed_base64_character_fails_verification() {
    let tampered = INLINE_WASM_REQUEST_JSON.replace(r#""AGFzbQ==""#, r#""AGFzcQ==""#);
    let read: JobRequest = serde_json::from_str(&tampered).expect("valid base64 still parses");
    assert_eq!(
        read.wasm_bytes.as_deref(),
        Some(&[0x00, 0x61, 0x73, 0x71][..])
    );
    assert!(read.verify_no_replay(&TEST_KEY, u64::MAX).is_err());
}

/// The finding this closes (whole-app review 2026-10-29, item 6): a 4 MiB
/// module is 14.98 MB as an integer list and does not fit the reference
/// `max_payload`; as base64 the whole message is under it.
#[test]
fn a_four_mib_module_fits_the_reference_max_payload_as_base64() {
    use aegix_workflow_engine_core::inline_wasm::{WasmBytesEncoding, REFERENCE_NATS_MAX_PAYLOAD};
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let bytes: Vec<u8> = (0..4 * 1024 * 1024)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24).to_le_bytes()[0]
        })
        .collect();
    let mut req = deterministic_job_request();
    req.wasm_bytes = Some(bytes.clone());
    let wire = serde_json::to_vec(&req).unwrap();
    assert!(
        wire.len() <= REFERENCE_NATS_MAX_PAYLOAD,
        "{} bytes on the wire for a 4 MiB module",
        wire.len()
    );
    assert_eq!(WasmBytesEncoding::Base64.encoded_len(&bytes), 5_592_410);
    assert!(WasmBytesEncoding::IntegerList.encoded_len(&bytes) > REFERENCE_NATS_MAX_PAYLOAD);
}

// ─────────────────────────────────────────────────────────────────────
// `SecretClaim` (2026-11-06, security review finding 8): the claim names
// the dispatch attempt it is for, signed, appended LAST and only when
// non-zero. The all-default snapshot proves a first dispatch's claim is the
// pre-field bytes; the non-default one pins exactly what the field adds.
// ─────────────────────────────────────────────────────────────────────

/// A fully deterministic claim: fixed ids, nonce, clock and Ed25519 seed
/// (Ed25519 signatures are deterministic, so the signature is pinned too).
fn deterministic_claim(dispatch_attempt: u32) -> aegix_workflow_job_protocol::SecretClaim {
    use ed25519_dalek::Signer;
    let sk = aegix_workflow_job_protocol::DispatchSigningKey::from_bytes(&[0x24; 32]);
    let mut claim = aegix_workflow_job_protocol::SecretClaim {
        exec_id: det_uuid(0x5ec1),
        worker_id: "worker-snapshot".to_string(),
        epk_w: [7u8; 32],
        claim_nonce: "00112233445566778899aabbccddeeff".to_string(),
        issued_at_ms: 1_762_400_000_000,
        crypto_scheme: aegix_workflow_job_protocol::CRYPTO_SCHEME_ED25519,
        signature: vec![],
        dispatch_attempt,
    };
    claim.signature = sk.sign(&claim.signing_bytes()).to_bytes().to_vec();
    claim
}

#[test]
fn secret_claim_first_attempt_is_the_pre_field_wire_format() {
    let claim = deterministic_claim(0);
    let json = serde_json::to_string(&claim).unwrap();
    assert!(
        !json.contains("dispatch_attempt"),
        "attempt 0 is absent from the wire: {json}"
    );
    assert_eq!(
        hex::encode(claim.signing_bytes()),
        "74616c6f732f7365637265742d636c61696d2f763100000000000000000000000000005ec10f00000000000000776f726b65722d736e617073686f7407070707070707070707070707070707070707070707070707070707070707072000000000000000303031313232333334343535363637373838393961616262636364646565666600d839579a01000001",
        "SecretClaim signed bytes drifted for a first dispatch"
    );
    assert_eq!(
        hex::encode(&claim.signature),
        "c25f193abf6f44e505c1c5611bdcd660c65a12f2f3070ac87b00e40d0d0bf5354225ec6b25a5cd8684bd94f1d6c198ec801cf42ef5eda7eedc6ef1ec53bcfd09",
        "SecretClaim signature drifted for a first dispatch"
    );
}

#[test]
fn secret_claim_non_default_attempt_snapshot() {
    let claim = deterministic_claim(3);
    let json = serde_json::to_value(&claim).unwrap();
    assert_eq!(
        json["dispatch_attempt"], 3,
        "a non-zero attempt is on the wire"
    );
    let first = deterministic_claim(0).signing_bytes();
    let bytes = claim.signing_bytes();
    assert_eq!(
        &bytes[..first.len()],
        first.as_slice(),
        "the attempt is APPENDED: every earlier byte is the first dispatch's"
    );
    assert_eq!(
        hex::encode(&bytes[first.len()..]),
        "3a617474656d70743d03000000",
        "`:attempt=` then the attempt as u32 little-endian"
    );
    assert_eq!(
        hex::encode(&claim.signature),
        "a2a7ce6025aee65172de5046f34a514c6aeb1ae8c6886025207d09642904f49ced99d86a8c8215828afb28fbb2fb7f21bdbe5153115dafa1256697c9de302305",
        "SecretClaim signature drifted for a re-dispatch's claim"
    );
}
