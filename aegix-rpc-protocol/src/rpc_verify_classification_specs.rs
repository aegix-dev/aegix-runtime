//! Per-protocol pins for the `verify() -> Result<(), VerifyFailure>`
//! taxonomy (#603).
//!
//! Why per-protocol and not "test the enum once": the mapping from gate
//! to variant is written SEVEN times (one `verify()` per request type),
//! so a copy-paste that labels a signature failure `Stale` compiles
//! cleanly and silently poisons the exact diagnosis this work exists to
//! provide. These tests are the only thing standing between a mislabel
//! and an operator chasing a clock-drift theory during a wire-format
//! outage.
//!
//! Harness: the same `ensure_hmac_key` + `wire_hop` shape as
//! `wire_hop_signing_specs`. No nonce-cache state is touched (`verify()`
//! deliberately does not consult it — the subscriber calls
//! `check_and_record_nonce` separately), so no serialisation lock is
//! needed.

use crate::rpc_auth::{self, VerifyFailure};
use uuid::Uuid;

fn ensure_hmac_key() {
    rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x9Cu8; 32]));
}

/// Push a request's timestamp far enough back to leave the 60 s past
/// window without touching any other field.
const WAY_STALE_MS: i64 = 10 * 60 * 1000;

// ── memory_rpc ───────────────────────────────────────────────────────

fn memory_req() -> crate::memory_rpc::MemoryRpcRequest {
    crate::memory_rpc::MemoryRpcRequest::new_signed(
        Uuid::new_v4(),
        crate::memory_rpc::MemoryOp::Get {
            key: "digest/today".to_string(),
        },
    )
    .expect("sign")
}

#[test]
fn memory_classifies_every_gate() {
    ensure_hmac_key();
    assert_eq!(memory_req().verify(), Ok(()));

    let mut stale = memory_req();
    stale.timestamp_ms -= WAY_STALE_MS;
    assert_eq!(stale.verify(), Err(VerifyFailure::Stale));

    let mut tampered = memory_req();
    tampered.signature[0] ^= 0xFF;
    assert_eq!(tampered.verify(), Err(VerifyFailure::BadSignature));

    // Oversized key: a structural cap, which must be reported as such
    // rather than as the signature failure it ALSO is (the re-signed
    // body would differ) — the cheap gate runs first, by design.
    let oversized = crate::memory_rpc::MemoryRpcRequest::new_signed(
        Uuid::new_v4(),
        crate::memory_rpc::MemoryOp::Get {
            key: "k".repeat(crate::MAX_MEMORY_KEY_CHARS + 1),
        },
    );
    assert!(
        oversized.is_none(),
        "sign-time gate rejects it first (MCP-1149)"
    );
    // …so build the over-cap request by mutating a signed one, which is
    // exactly the compromised-worker shape verify() defends against.
    let mut over = memory_req();
    over.op = rpc_auth::RawSigned::from(crate::memory_rpc::MemoryOp::Get {
        key: "k".repeat(crate::MAX_MEMORY_KEY_CHARS + 1),
    });
    assert_eq!(over.verify(), Err(VerifyFailure::OversizedStructure));
}

/// `memory_rpc` is the only protocol carrying bare `f64`s in a signed
/// op, so it is the only one that can produce `NonFinite`.
#[test]
fn memory_classifies_non_finite_before_the_structural_cap() {
    ensure_hmac_key();
    let mut nan = memory_req();
    // NaN ttl AND an over-cap key: finiteness is checked first, so the
    // ordering (not just the mapping) is pinned.
    nan.op = rpc_auth::RawSigned::from(crate::memory_rpc::MemoryOp::Set {
        key: "k".repeat(crate::MAX_MEMORY_KEY_CHARS + 1),
        value: serde_json::json!({}),
        memory_type: "episodic".to_string(),
        ttl_hours: Some(f64::NAN),
        metadata: None,
    });
    assert_eq!(nan.verify(), Err(VerifyFailure::NonFinite));
}

// ── graph_rpc ────────────────────────────────────────────────────────

fn graph_req() -> crate::graph_rpc::GraphSearchRequest {
    crate::graph_rpc::GraphSearchRequest::new_signed(Uuid::new_v4(), "alice".into(), 2, 20)
        .expect("sign")
}

#[test]
fn graph_classifies_every_gate() {
    ensure_hmac_key();
    assert_eq!(graph_req().verify(), Ok(()));

    let mut stale = graph_req();
    stale.timestamp_ms -= WAY_STALE_MS;
    assert_eq!(stale.verify(), Err(VerifyFailure::Stale));

    let mut over = graph_req();
    over.limit = u32::MAX;
    assert_eq!(over.verify(), Err(VerifyFailure::OversizedStructure));

    let mut tampered = graph_req();
    tampered.signature[0] ^= 0xFF;
    assert_eq!(tampered.verify(), Err(VerifyFailure::BadSignature));
}

// ── database_rpc ─────────────────────────────────────────────────────

fn database_req() -> crate::database_rpc::DatabaseRpcRequest {
    crate::database_rpc::DatabaseRpcRequest::new_signed(
        Uuid::new_v4(),
        "SELECT 1".into(),
        vec![],
        true,
    )
    .expect("sign")
}

#[test]
fn database_classifies_every_gate() {
    ensure_hmac_key();
    assert_eq!(database_req().verify(), Ok(()));

    let mut stale = database_req();
    stale.timestamp_ms -= WAY_STALE_MS;
    assert_eq!(stale.verify(), Err(VerifyFailure::Stale));

    let mut tampered = database_req();
    tampered.signature[0] ^= 0xFF;
    assert_eq!(tampered.verify(), Err(VerifyFailure::BadSignature));

    // database_rpc is the one protocol whose structural gate runs BEFORE
    // freshness (MCP-1033). Pin that order explicitly: a request that is
    // both stale AND oversized must report the structural class.
    let mut both = database_req();
    both.timestamp_ms -= WAY_STALE_MS;
    both.sql = "x".repeat(crate::database_rpc::MAX_SQL_BYTES + 1);
    assert_eq!(both.verify(), Err(VerifyFailure::OversizedStructure));
}

// ── state_rpc ────────────────────────────────────────────────────────

fn state_req() -> crate::state_rpc::StateWriteRequest {
    crate::state_rpc::StateWriteRequest::new_signed(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "checkpoint".into(),
        "{}".into(),
        false,
    )
    .expect("sign")
}

#[test]
fn state_classifies_every_gate() {
    ensure_hmac_key();
    assert_eq!(state_req().verify(), Ok(()));

    let mut stale = state_req();
    stale.timestamp_ms -= WAY_STALE_MS;
    assert_eq!(stale.verify(), Err(VerifyFailure::Stale));

    let mut over = state_req();
    over.key = "k".repeat(crate::state_rpc::MAX_STATE_KEY_LEN + 1);
    assert_eq!(over.verify(), Err(VerifyFailure::OversizedStructure));

    let mut tampered = state_req();
    tampered.signature[0] ^= 0xFF;
    assert_eq!(tampered.verify(), Err(VerifyFailure::BadSignature));
}

// ── ml_rpc (predict + few-shot) ──────────────────────────────────────

fn predict_req() -> crate::ml_rpc::MlPredictRequest {
    crate::ml_rpc::MlPredictRequest::new_signed(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "inbox-classifier".into(),
        vec!["Subject: hi".into()],
    )
    .expect("sign")
}

fn fewshot_req() -> crate::ml_rpc::MlFewShotRequest {
    crate::ml_rpc::MlFewShotRequest::new_signed(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "inbox-classifier".into(),
        4,
    )
    .expect("sign")
}

#[test]
fn ml_predict_classifies_every_gate() {
    ensure_hmac_key();
    assert_eq!(predict_req().verify(), Ok(()));

    let mut stale = predict_req();
    stale.timestamp_ms -= WAY_STALE_MS;
    assert_eq!(stale.verify(), Err(VerifyFailure::Stale));

    let mut over = predict_req();
    over.model_name = "m".repeat(crate::ml_rpc::MAX_MODEL_NAME_LEN + 1);
    assert_eq!(over.verify(), Err(VerifyFailure::OversizedStructure));

    let mut tampered = predict_req();
    tampered.signature[0] ^= 0xFF;
    assert_eq!(tampered.verify(), Err(VerifyFailure::BadSignature));
}

#[test]
fn ml_fewshot_classifies_every_gate() {
    ensure_hmac_key();
    assert_eq!(fewshot_req().verify(), Ok(()));

    let mut stale = fewshot_req();
    stale.timestamp_ms -= WAY_STALE_MS;
    assert_eq!(stale.verify(), Err(VerifyFailure::Stale));

    let mut over = fewshot_req();
    over.k = crate::ml_rpc::MAX_FEWSHOT_K + 1;
    assert_eq!(over.verify(), Err(VerifyFailure::OversizedStructure));

    let mut tampered = fewshot_req();
    tampered.signature[0] ^= 0xFF;
    assert_eq!(tampered.verify(), Err(VerifyFailure::BadSignature));
}

// ── integration_state_rpc ────────────────────────────────────────────

fn integration_req() -> crate::integration_state_rpc::IntegrationStateRequest {
    crate::integration_state_rpc::IntegrationStateRequest::new_signed(
        "gmail".into(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        crate::integration_state_rpc::IntegrationOp::Get {
            key: "watch_channel/abc".into(),
        },
    )
    .expect("sign")
}

#[test]
fn integration_state_classifies_every_gate() {
    ensure_hmac_key();
    assert_eq!(integration_req().verify(), Ok(()));

    let mut stale = integration_req();
    stale.timestamp_ms -= WAY_STALE_MS;
    assert_eq!(stale.verify(), Err(VerifyFailure::Stale));

    // integration_name is its own gate; it shares the structural class.
    let mut bad_name = integration_req();
    bad_name.integration_name = "NOT lowercase".into();
    assert_eq!(bad_name.verify(), Err(VerifyFailure::OversizedStructure));

    let mut over = integration_req();
    over.op = rpc_auth::RawSigned::from(crate::integration_state_rpc::IntegrationOp::Get {
        key: "k".repeat(257),
    });
    assert_eq!(over.verify(), Err(VerifyFailure::OversizedStructure));

    let mut tampered = integration_req();
    tampered.signature[0] ^= 0xFF;
    assert_eq!(tampered.verify(), Err(VerifyFailure::BadSignature));
}

// ── UnknownSignerKey vs BadSignature ─────────────────────────────────

/// The split that makes the taxonomy worth having: a signer we hold NO
/// key for is a config/rotation problem ("register the worker"), while a
/// signer we DO hold a key for whose bytes don't check out is a
/// wire-format/deploy problem ("roll the fleet"). Reporting both as one
/// class sends the operator down the wrong path — the failure mode this
/// whole change exists to prevent.
///
/// Exercised across every protocol at once by flipping `crypto_scheme`
/// to Ed25519 with a `worker_id` the (empty) public-key registry has
/// never heard of. This is also the exact shape a real half-migrated
/// fleet produces.
#[test]
fn ed25519_with_an_unregistered_worker_is_unknown_signer_not_bad_signature() {
    ensure_hmac_key();

    let mut m = memory_req();
    m.crypto_scheme = rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
    m.worker_id = "worker-that-was-never-registered".into();
    assert_eq!(m.verify(), Err(VerifyFailure::UnknownSignerKey));

    let mut g = graph_req();
    g.crypto_scheme = rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
    g.worker_id = "worker-that-was-never-registered".into();
    assert_eq!(g.verify(), Err(VerifyFailure::UnknownSignerKey));

    let mut d = database_req();
    d.crypto_scheme = rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
    d.worker_id = "worker-that-was-never-registered".into();
    assert_eq!(d.verify(), Err(VerifyFailure::UnknownSignerKey));

    let mut s = state_req();
    s.crypto_scheme = rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
    s.worker_id = "worker-that-was-never-registered".into();
    assert_eq!(s.verify(), Err(VerifyFailure::UnknownSignerKey));

    let mut p = predict_req();
    p.crypto_scheme = rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
    p.worker_id = "worker-that-was-never-registered".into();
    assert_eq!(p.verify(), Err(VerifyFailure::UnknownSignerKey));

    let mut f = fewshot_req();
    f.crypto_scheme = rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
    f.worker_id = "worker-that-was-never-registered".into();
    assert_eq!(f.verify(), Err(VerifyFailure::UnknownSignerKey));

    let mut i = integration_req();
    i.crypto_scheme = rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
    i.worker_id = "worker-that-was-never-registered".into();
    assert_eq!(i.verify(), Err(VerifyFailure::UnknownSignerKey));
}

/// An Ed25519-declared request with an EMPTY `worker_id` (the shape a
/// worker emits when it fell back to the HMAC signing path but something
/// set the scheme byte anyway) is also unresolvable, not a bad signature.
#[test]
fn ed25519_with_empty_worker_id_is_unknown_signer() {
    ensure_hmac_key();
    let mut m = memory_req();
    m.crypto_scheme = rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
    m.worker_id = String::new();
    assert_eq!(m.verify(), Err(VerifyFailure::UnknownSignerKey));
}

/// An unrecognised `crypto_scheme` classifies as `BadSignature`, not
/// `UnknownSignerKey`: a scheme byte this binary does not implement is
/// most plausibly a NEWER worker talking to an OLDER controller, i.e.
/// version skew — the class the admission gate attaches the build-skew
/// hint to.
#[test]
fn unknown_crypto_scheme_classifies_as_bad_signature() {
    ensure_hmac_key();
    let mut m = memory_req();
    m.crypto_scheme = 99;
    assert_eq!(m.verify(), Err(VerifyFailure::BadSignature));
}

/// The log tokens are a contract with dashboards and greps: stable
/// snake_case, one per variant, all distinct.
#[test]
fn failure_tokens_are_stable_and_distinct() {
    let all = [
        VerifyFailure::Stale,
        VerifyFailure::NonFinite,
        VerifyFailure::OversizedStructure,
        VerifyFailure::UnknownSignerKey,
        VerifyFailure::BadSignature,
    ];
    assert_eq!(
        all.map(VerifyFailure::as_str),
        [
            "stale",
            "non_finite",
            "oversized_structure",
            "unknown_signer_key",
            "bad_signature",
        ]
    );
    for f in all {
        assert_eq!(f.to_string(), f.as_str(), "Display must equal as_str");
    }
    let unique: std::collections::HashSet<_> = all.iter().map(|f| f.as_str()).collect();
    assert_eq!(unique.len(), all.len(), "tokens must be distinct");
}
