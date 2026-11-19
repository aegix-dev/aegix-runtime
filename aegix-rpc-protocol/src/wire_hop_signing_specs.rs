//! Executable specification for the memory-RPC **raw-bytes signing** fix.
//!
//! ## The defect these specs describe
//!
//! The pre-Phase-2 signing path (`rpc_auth::canonical_json_bytes`, since
//! deleted) re-derived a number's TEXT from a *parsed*
//! `serde_json::Value` (`Value::Number(n) => n.to_string()`).
//! serde_json's f64 round trip is
//! **not idempotent**: for a meaningful fraction of ordinary computed
//! values `parse(write(x))` lands one ULP away from `x`, and some values
//! have no fixed point at all (they cycle between two representations
//! forever — see #597). So the sender canonicalises the `Value` it holds
//! in memory, the receiver canonicalises its *re-parse* of the wire JSON,
//! the two byte strings differ, and the signature fails — for an entirely
//! honest sender, on payload content alone.
//!
//! `rpc_auth`'s own module doc states the assumption that makes this
//! safe: "our callers don't feed floating-point edge cases into signed
//! bodies". That assumption is false. `actor_memory` values are ARBITRARY
//! module output; LLM/agent nodes persist computed ratios routinely.
//!
//! The identical defect took down `pa-autonomy-digest` on the
//! job-protocol dispatch surface (#595 → #597 → #598). The fix there was
//! `aegix_workflow_job_protocol::SignedJson`: sign the EXACT wire text,
//! never a form re-derived on each side. The specs below are the contract
//! for the equivalent fix here (`RawSigned<T>` wrapping the whole op).
//!
//! ## How to read this module
//!
//! * The wire-hop specs (memory `Set` value / metadata / ttl,
//!   integration `Set`, and the two seeded property tests) were the
//!   **OPEN** contract: `#[ignore]`d and failing until Phase 2 landed
//!   [`rpc_auth::RawSigned`]. They are now active and MUST pass — a
//!   regression here means the raw-bytes binding was reintroduced-as-
//!   re-derivation somewhere.
//! * The rest pin the confirmed-UNAFFECTED RPC families (they bind only
//!   strings/ints, never a `Value`) and the generator's
//!   anti-vacuousness guard. The two unit-level pins that referenced the
//!   now-deleted `canonical_json_bytes` were removed with it.

use crate::integration_state_rpc::{
    IndexedSlots, IntegrationOp, IntegrationStateRequest, SUBJECT_NAME as INTEGRATION_SUBJECT,
};
use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
use crate::rpc_auth;
use serde_json::json;
use uuid::Uuid;

// The generator and the two float counterexamples come from the SHARED
// harness in `aegix_workflow_job_protocol::test_support` (dev-dependency,
// non-default `test-support` feature). They used to be a local copy —
// taken because the original was `cfg(test)`-private to its crate — and
// the copy drifted immediately: this module never grew the
// size-independence, text-vs-meaning, or transcode assertions the
// dispatch suite had, so the second signed-wire surface was tested
// strictly more weakly while both suites stayed green. Those three
// classes are now present below, on the shared adversary.
//
// * `POISON_2CYCLE` — a float with NO round-trip fixed point (writing,
//   re-parsing and writing again differs from the first write, forever);
//   `…890906e-115` sent vs `…8909045e-115` received, as reproduced by the
//   #598 reviewer. It is what makes "normalise to the fixed point" (the
//   #595 first attempt) provably insufficient and forces raw-bytes
//   signing.
// * `POISON_BITS` — the bit pattern the #597 search surfaced, kept as a
//   second independently-sourced sample so one serde_json version bump
//   cannot silently make this module vacuous.
use aegix_workflow_job_protocol::test_support::{
    arbitrary_json, round_trip_unstable_count, value_transcode_hop, POISON_2CYCLE, POISON_BITS,
};

/// Register the process-global HMAC key. `register_hmac_key` wraps a
/// `OnceLock::set`, so this is idempotent and first-caller-wins — every
/// other test in the crate does exactly this, and because BOTH signing
/// and verification read the same slot, which key wins is irrelevant.
///
/// No serialisation lock is needed here: these tests never touch the
/// nonce cache (`verify()` deliberately does not — the subscriber calls
/// `check_and_record_nonce` separately), which is the only process-global
/// state in `rpc_auth` that tests must serialise on
/// (`rpc_auth::nonce_test_lock`).
fn ensure_hmac_key() {
    rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x9Cu8; 32]));
}

// `wire_hop` (to_vec → from_slice) is the shared helper, imported above.
// It is faithful to production on this surface, not a simplification: the
// worker serialises with `serde_json::to_vec`
// (aegix-wasm-host/src/host/memory.rs) and the single admission
// chokepoint deserialises with `serde_json::from_slice` on the raw NATS
// payload (aegix-rpc-subscribers/src/admission.rs). No intermediate
// `Value` hop exists on either side — and `value_transcode_hop` below
// pins what happens if one is ever introduced.
use aegix_workflow_job_protocol::test_support::wire_hop;

fn memory_set(value: serde_json::Value, metadata: Option<serde_json::Value>) -> MemoryOp {
    MemoryOp::Set {
        key: "digest/ratios".to_string(),
        value,
        memory_type: "episodic".to_string(),
        ttl_hours: None,
        metadata,
    }
}

fn integration_set(value: serde_json::Value) -> IntegrationOp {
    IntegrationOp::Set {
        key: "watch_channel/abc".to_string(),
        value,
        ttl_seconds: None,
        slots: IndexedSlots::default(),
    }
}

// ── OPEN specs: these MUST fail until RawSigned lands ────────────────

/// **OPEN SPEC.** A `MemoryOp::Set` whose value carries a float with no
/// round-trip fixed point must survive the wire and verify.
///
/// This is the production shape that breaks: an agent node computes a
/// ratio, writes it through `agent_memory::set`, the worker signs the
/// canonical form of the `Value` it built, the controller canonicalises
/// its re-parse — and rejects an honest request as `Unauthorized`.
///
/// Un-ignore when `RawSigned<MemoryOp>` binds the exact wire text.
#[test]
fn memory_set_survives_the_wire_with_a_2cycle_float() {
    ensure_hmac_key();
    let actor = Uuid::new_v4();
    let req =
        MemoryRpcRequest::new_signed(actor, memory_set(json!({"ratio": POISON_2CYCLE}), None))
            .expect("sign");
    assert!(
        req.verify().is_ok(),
        "sender-side self-verify must hold — if THIS fails the harness is wrong, not the protocol"
    );
    let received = wire_hop(&req);
    assert!(
        received.verify().is_ok(),
        "an honest Set carrying {POISON_2CYCLE:e} failed verification after the wire hop — \
             the signed form was re-derived from the receiver's re-parse"
    );
}

/// **OPEN SPEC.** Same defect through `metadata` alone.
///
/// `metadata` is canonicalised by the same code path as `value`
/// (`memory_rpc::sign_body_bytes`), so it carries the identical hazard.
/// Covered separately because `metadata` is the field the
/// `__memory_write__` protocol stamps with synthesis provenance —
/// scores, confidences and agreement ratios land here, not in `value`.
///
/// The value is deliberately stable (a plain string) so a failure can
/// only be attributed to the metadata field.
#[test]
fn memory_set_survives_the_wire_with_a_2cycle_float_in_metadata_only() {
    ensure_hmac_key();
    let actor = Uuid::new_v4();
    let req = MemoryRpcRequest::new_signed(
        actor,
        memory_set(
            json!({"note": "stable text payload"}),
            Some(json!({"kind": "daily_brief", "confidence": POISON_2CYCLE})),
        ),
    )
    .expect("sign");
    assert!(req.verify().is_ok(), "sender-side self-verify must hold");
    let received = wire_hop(&req);
    assert!(
        received.verify().is_ok(),
        "an honest Set whose METADATA carries {POISON_2CYCLE:e} failed verification \
             after the wire hop"
    );
}

/// **OPEN SPEC (measured, see the un-ignored `ttl_hours_f64_field_drift_measurement`
/// below for the evidence).** `ttl_hours` is a struct `Option<f64>`, not a
/// `Value`, and is bound as `f64::to_le_bytes`. Its wire text is written by
/// serde's float formatter from the sender's bits and re-parsed into the
/// receiver's bits; if that parse is not bit-exact the LE bytes differ and
/// the signature fails exactly as the `Value` path does.
///
/// Uses the #597 bit pattern plus a seeded search for a drifting value, so
/// the spec is pinned to a measured fact rather than an assumption.
#[test]
fn memory_set_ttl_survives_the_wire_with_drifting_f64() {
    ensure_hmac_key();
    let actor = Uuid::new_v4();
    let ttl = drifting_ttl_f64().expect(
        "no ttl_hours bit pattern drifts through the struct-field hop — \
             see ttl_hours_f64_field_drift_measurement",
    );
    let op = MemoryOp::Set {
        key: "digest/ratios".to_string(),
        value: json!({"note": "stable text payload"}),
        memory_type: "episodic".to_string(),
        ttl_hours: Some(ttl),
        metadata: None,
    };
    let req = MemoryRpcRequest::new_signed(actor, op).expect("sign");
    assert!(req.verify().is_ok(), "sender-side self-verify must hold");
    let received = wire_hop(&req);
    assert!(
        received.verify().is_ok(),
        "an honest Set with ttl_hours = {ttl:e} (bits {:#018x}) failed verification \
             after the wire hop",
        ttl.to_bits()
    );
}

/// **OPEN SPEC.** The integration-state twin of the memory `Set` case.
///
/// `integration_state_rpc::sign_body_bytes` canonicalises
/// `IntegrationOp::Set.value` through the same
/// `rpc_auth::canonical_json_bytes`, so the identical fix applies. Push
/// integrations persist `Value`s that include API-supplied numerics
/// (expiry timestamps, history ids), so this is not a theoretical path.
#[test]
fn integration_set_survives_the_wire_with_a_2cycle_float() {
    ensure_hmac_key();
    let req = IntegrationStateRequest::new_signed(
        "gmail".to_string(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        integration_set(json!({"drift_ratio": POISON_2CYCLE})),
    )
    .expect("sign");
    assert!(req.verify().is_ok(), "sender-side self-verify must hold");
    let received = wire_hop(&req);
    assert!(
        received.verify().is_ok(),
        "an honest IntegrationOp::Set carrying {POISON_2CYCLE:e} failed verification \
             after the wire hop"
    );
}

/// **OPEN SPEC (property).** The defect is payload-DEPENDENT, so every
/// hand-written example is a lottery ticket. This asks the general
/// question the #597 harness asked — "does sign → wire → verify hold for
/// arbitrary JSON?" — which is how the original root cause was found in
/// seconds after six reasoned hypotheses had failed.
///
/// Seeded (never `thread_rng`) so a failure is reproducible from the
/// printed iteration and seed.
#[test]
fn memory_set_survives_the_wire_for_arbitrary_json() {
    ensure_hmac_key();
    let actor = Uuid::new_v4();
    let mut seed = 0x5eed_0dd0_0000_0001_u64;
    for i in 0..2_000 {
        let value = arbitrary_json(&mut seed, 4);
        let req =
            MemoryRpcRequest::new_signed(actor, memory_set(value.clone(), None)).expect("sign");
        let received = wire_hop(&req);
        assert!(
            received.verify().is_ok(),
            "iter {i}: verify failed after the wire hop for value {value}"
        );
    }
}

/// **OPEN SPEC (property).** Integration-state twin of the above.
#[test]
fn integration_set_survives_the_wire_for_arbitrary_json() {
    ensure_hmac_key();
    let mut seed = 0x5eed_0dd0_0000_0002_u64;
    let actor = Uuid::new_v4();
    let user = Uuid::new_v4();
    for i in 0..2_000 {
        let value = arbitrary_json(&mut seed, 4);
        let req = IntegrationStateRequest::new_signed(
            "gmail".to_string(),
            actor,
            user,
            integration_set(value.clone()),
        )
        .expect("sign");
        let received = wire_hop(&req);
        assert!(
            received.verify().is_ok(),
            "iter {i}: verify failed after the wire hop for value {value}"
        );
    }
}

// ── Passing confirmations: the UNAFFECTED RPC families ───────────────
//
// The #598 review claimed only the two `Set` paths bind a `Value`. These
// four tests are the proof rather than the assertion: each runs the same
// sign → wire → verify hop with the most float-hostile content its typed
// fields can carry, and passes today. If a future change threads a
// `Value` into any of them, the family moves from this section to the
// OPEN section above.

/// `graph_rpc` binds `(query: &str, max_depth: u32, limit: u32)` only —
/// no `Value`, no f64. Floats can reach it only as TEXT inside `query`,
/// where they are signed as UTF-8 bytes and are therefore immune.
#[test]
fn graph_rpc_survives_the_wire_including_float_text() {
    ensure_hmac_key();
    let req = crate::graph_rpc::GraphSearchRequest::new_signed(
        Uuid::new_v4(),
        format!("ratio {POISON_2CYCLE} and {}", f64::from_bits(POISON_BITS)),
        3,
        10,
    )
    .expect("sign");
    assert!(
        wire_hop(&req).verify().is_ok(),
        "graph_rpc must be unaffected"
    );
}

/// `database_rpc` binds `(sql: &str, params: &[String], is_fetch: bool)`.
/// Params are length-prefixed UTF-8 — a float-shaped param is text.
#[test]
fn database_rpc_survives_the_wire_including_float_text_params() {
    ensure_hmac_key();
    let req = crate::database_rpc::DatabaseRpcRequest::new_signed(
        Uuid::new_v4(),
        "SELECT * FROM t WHERE ratio = $1".to_string(),
        vec![
            POISON_2CYCLE.to_string(),
            f64::from_bits(POISON_BITS).to_string(),
        ],
        true,
    )
    .expect("sign");
    assert!(
        wire_hop(&req).verify().is_ok(),
        "database_rpc must be unaffected"
    );
}

/// `state_rpc` binds `(execution_id, key: &str, value: &str, is_delete)`.
/// Note `value` is a pre-serialised STRING, not a `Value` — that is
/// precisely why this family is safe, and why the choice must not be
/// "simplified" to a `Value` later.
#[test]
fn state_rpc_survives_the_wire_with_float_bearing_json_text() {
    ensure_hmac_key();
    let req = crate::state_rpc::StateWriteRequest::new_signed(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "session/ratios".to_string(),
        json!({"ratio": POISON_2CYCLE}).to_string(),
        false,
    )
    .expect("sign");
    assert!(
        wire_hop(&req).verify().is_ok(),
        "state_rpc must be unaffected"
    );
}

/// `ml_rpc` binds `(user_id, model_name: &str, inputs: &[String])` for
/// predict and `(user_id, model_name, k: u32)` for few-shot. Strings and
/// ints only.
#[test]
fn ml_rpc_survives_the_wire_including_float_text_inputs() {
    ensure_hmac_key();
    let predict = crate::ml_rpc::MlPredictRequest::new_signed(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "inbox-classifier".to_string(),
        vec![format!("score={POISON_2CYCLE}")],
    )
    .expect("sign predict");
    assert!(
        wire_hop(&predict).verify().is_ok(),
        "ml predict must be unaffected"
    );

    let fewshot = crate::ml_rpc::MlFewShotRequest::new_signed(
        Uuid::new_v4(),
        Uuid::new_v4(),
        "inbox-classifier".to_string(),
        4,
    )
    .expect("sign fewshot");
    assert!(
        wire_hop(&fewshot).verify().is_ok(),
        "ml few-shot must be unaffected"
    );
}

/// The `integration_state_rpc` signing subject is distinct from the
/// memory one — pinned here so the OPEN specs above cannot be "fixed" by
/// accidentally collapsing the two subjects into one.
#[test]
fn integration_and_memory_signing_subjects_are_distinct() {
    assert_ne!(INTEGRATION_SUBJECT, crate::memory_rpc::SUBJECT_NAME);
}

// ── Root-cause pins and the property generator ───────────────────────

// `canonical_bytes_are_not_stable_across_a_json_reparse` was deleted
// in Phase 2 together with `canonical_json_bytes` / `write_canonical`.
// The mechanism it pinned (canonicalising a value vs. canonicalising
// its re-parse yields different bytes) no longer has a subject: nothing
// re-derives anything now that the signature covers the exact wire
// text. The wire-hop specs above are the surviving, higher-level proof.

/// Measurement, not an assumption: does `ttl_hours` — a struct
/// `Option<f64>`, whose wire text is written by serde's float formatter
/// from the sender's bits and re-parsed into the receiver's bits — drift
/// across the serde struct-field hop the way a `Value` number does?
///
/// Answer recorded by this test: YES. `drifting_ttl_f64()` finds a
/// bit pattern within a seeded 20k-sample search, and this test asserts
/// the search succeeds so the OPEN `…ttl_survives_the_wire…` spec can
/// never silently degrade into a no-op that skips on "not found".
#[test]
fn ttl_hours_f64_field_drift_measurement() {
    let found = drifting_ttl_f64();
    assert!(
        found.is_some(),
        "no drifting ttl_hours bit pattern found in {TTL_SEARCH_SAMPLES} seeded samples — \
             if this ever regresses to None, downgrade the ttl OPEN spec to a passing pin \
             documenting that ttl is stable in practice rather than manufacturing a failure"
    );
}

/// Number of seeded samples the ttl drift search draws. Fixed (not
/// time-bounded) so the search is deterministic across machines.
const TTL_SEARCH_SAMPLES: usize = 20_000;

/// Seeded search for an `Option<f64>` value that does NOT survive the
/// serde struct-field wire hop bit-exactly. Returns `None` if no sample
/// drifts, which the measurement test above turns into a loud failure.
///
/// Deliberately probes the REAL hop — a `#[derive(Serialize,
/// Deserialize)]` struct with the same `Option<f64>` shape as
/// `MemoryOp::Set.ttl_hours` — rather than `Value`, because the question
/// is specifically whether the struct-field path differs from the
/// `Value` path.
fn drifting_ttl_f64() -> Option<f64> {
    #[derive(serde::Serialize, serde::Deserialize)]
    struct TtlProbe {
        ttl_hours: Option<f64>,
    }
    let mut seed = 0x7710_0000_0001_u64;
    for _ in 0..TTL_SEARCH_SAMPLES {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let f = f64::from_bits(seed);
        // `validate_finite` rejects NaN/Inf before signing, so a
        // non-finite sample could never reach the wire anyway.
        if !f.is_finite() {
            continue;
        }
        let text =
            serde_json::to_string(&TtlProbe { ttl_hours: Some(f) }).expect("probe serialises");
        let back: TtlProbe = serde_json::from_str(&text).expect("probe re-parses");
        let got = back.ttl_hours.expect("field present");
        if got.to_bits() != f.to_bits() {
            return Some(f);
        }
    }
    None
}

/// Anti-vacuousness guard (ported from #597, now measured by the shared
/// harness). The generator must actually produce round-trip-unstable
/// values, or every property spec above passes for the wrong reason and
/// we would never know.
#[test]
fn generator_actually_produces_round_trip_unstable_values() {
    let mut seed = 0x5eed_0dd0_0000_0003_u64;
    let unstable = round_trip_unstable_count(&mut seed, 20_000, 3);
    assert!(
        unstable > 0,
        "generator produced NO round-trip-unstable value — the wire specs \
             above would be passing (or failing) for reasons unrelated to floats"
    );
}

// ── Assertion classes the copied harness never grew ──────────────────
//
// The three tests below existed only on the job-protocol side. Their
// absence here was invisible: both suites were green, and nothing
// compared their coverage. They are ported now that the generator is
// shared, because each pins a property specific to raw-text binding that
// "sign → wire → verify holds" does NOT imply.

/// CLASS 1 — SIZE INDEPENDENCE. The binding must hold at every payload
/// size, not just the ~50-byte ones every hand-written case uses.
///
/// Worth its own sweep because the signed body is a CONCATENATION
/// (`timestamp_ms` as 8 LE bytes, then `op.raw_bytes()`), and the whole
/// class of defect this file exists for changed the payload's byte LENGTH
/// as well as its content. A length-prefix mistake, an off-by-one at the
/// prefix boundary, or any capacity-based truncation in `sign_body_bytes`
/// would be invisible at one fixed size and fatal at another. Each sample
/// also carries the 2-cycle float so size and content hazards are
/// exercised together.
///
/// Asserts BOTH that verification survives and that the received raw
/// length equals the sent one — a silent truncation that happened to be
/// applied identically on both sides would still verify.
#[test]
fn memory_set_survives_the_wire_across_a_payload_size_sweep() {
    ensure_hmac_key();
    let actor = Uuid::new_v4();
    // Spans the 8-byte prefix boundary, several power-of-two boundaries,
    // and up to the 64 KiB `MAX_VALUE_BYTES` ceiling the persist path
    // enforces — i.e. the whole range a real `agent_memory::set` can put
    // on the wire.
    for filler_len in [
        0usize, 1, 2, 3, 7, 8, 9, 15, 16, 63, 127, 255, 1023, 4096, 16_384, 60_000,
    ] {
        let value = json!({
            "ratio": POISON_2CYCLE,
            "blob": "x".repeat(filler_len),
        });
        let req = MemoryRpcRequest::new_signed(actor, memory_set(value, None))
            .expect("sign at every size");
        let sent_len = req.op.raw_bytes().len();
        let received = wire_hop(&req);
        assert_eq!(
            received.op.raw_bytes().len(),
            sent_len,
            "filler {filler_len}: signed op text changed LENGTH across the wire"
        );
        assert_eq!(
            received.op.raw_bytes(),
            req.op.raw_bytes(),
            "filler {filler_len}: signed op text changed across the wire"
        );
        assert!(
            received.verify().is_ok(),
            "filler {filler_len}: verify failed after the wire hop — the \
                 raw-text binding is size-dependent"
        );
    }
}

/// CLASS 2 — TEXT, NOT MEANING. The signature binds the op's exact TEXT,
/// which is the security consequence of raw-bytes signing and the half
/// that "honest sender verifies" can never demonstrate.
///
/// `RawSigned` can hold text no `MemoryOp` would ever emit: duplicate
/// keys, interior padding, non-shortest number spellings, escaped key
/// characters. Handlers read the deduplicated parse, so the natural worry
/// is a signed/executed split. Both halves are pinned:
///
/// 1. A KEYLESS on-path rewrite cannot exploit it. Every rewrite below is
///    semantics-preserving — each parses to the very op the sender signed,
///    so the pre-#598 `canonical_json_bytes` scheme would have ACCEPTED
///    them — and every one is refused now, because the digest covers the
///    bytes. This is a strict security GAIN of the raw-text binding, not
///    a cost.
/// 2. A KEY HOLDER can of course sign exotic text, and when it does the
///    two halves stay consistent: verification checks the exact bytes and
///    the subscriber acts on the last-wins parse of those same bytes.
///    There is no view of the message that disagrees with the signed one.
#[test]
fn memory_signature_binds_op_text_not_meaning() {
    ensure_hmac_key();
    let actor = Uuid::new_v4();
    let req = MemoryRpcRequest::new_signed(actor, memory_set(json!({"a": 1}), None)).expect("sign");
    let wire = String::from_utf8(serde_json::to_vec(&req).expect("serialise")).expect("utf8");
    let sent = r#""value":{"a":1}"#;
    assert!(wire.contains(sent), "op value text not found on the wire");

    // 1. Keyless rewrites: same meaning, different bytes → all refused.
    for rewrite in [
        r#""value":{"a" : 1}"#,     // interior padding
        r#""value":{"a":0,"a":1}"#, // duplicate key, last-wins
        r#""value":{"a":1.0}"#,     // different number spelling
        r#""value":{"\u0061":1}"#,  // escaped key spelling
    ] {
        let tampered: MemoryRpcRequest = serde_json::from_str(&wire.replace(sent, rewrite))
            .unwrap_or_else(|e| panic!("rewrite {rewrite} must still be valid JSON: {e}"));
        let MemoryOp::Set { value, .. } = tampered.op.get() else {
            panic!("rewrite {rewrite} must still parse as a Set");
        };
        assert_eq!(
            value.get("a").and_then(serde_json::Value::as_f64),
            Some(1.0),
            "precondition: {rewrite} must be semantics-preserving, or the \
                 test proves nothing about text-vs-meaning"
        );
        assert!(
            tampered.verify().is_err(),
            "rewriting the op text to {rewrite} must invalidate the \
                 signature — duplicate-key smuggling requires the signing key"
        );
    }

    // 2. Key holder signs duplicate-key text. `new_signed` cannot express
    //    this (it always re-mints from a `MemoryOp`), so the exotic text
    //    is injected by deserialising it and re-signing over the body the
    //    production formula defines: `timestamp_ms` LE || op.raw_bytes().
    //    Mirroring the formula here is deliberate — it fails loudly if
    //    `memory_rpc::sign_body_bytes` ever changes shape.
    let dup = r#""value":{"a":9,"a":1}"#;
    let mut exotic: MemoryRpcRequest =
        serde_json::from_str(&wire.replace(sent, dup)).expect("exotic text is valid JSON");
    let mut body = exotic.timestamp_ms.to_le_bytes().to_vec();
    body.extend_from_slice(exotic.op.raw_bytes());
    exotic.signature = rpc_auth::sign(
        crate::memory_rpc::SUBJECT_NAME,
        exotic.actor_id,
        &exotic.nonce,
        &body,
    )
    .expect("key registered");
    let received = wire_hop(&exotic);
    assert!(
        String::from_utf8_lossy(received.op.raw_bytes()).contains(r#""a":9,"a":1"#),
        "the exotic text must survive the wire verbatim"
    );
    let MemoryOp::Set { value, .. } = received.op.get() else {
        panic!("expected a Set");
    };
    assert_eq!(
        value,
        &json!({"a": 1}),
        "the parsed view must be the last-wins reading of the SIGNED bytes"
    );
    received
        .verify()
        .expect("text the key holder actually signed must verify");
}

/// CLASS 3 — THE TRANSCODE TRAP. Moving a signed request through
/// `serde_json::Value` (`to_value` → `from_value`) SILENTLY BREAKS ITS
/// SIGNATURE.
///
/// Worth an executable warning because it does not fail loudly anywhere
/// else: the transcode compiles, runs, and produces a structurally
/// identical request — but it re-parses and re-serialises the op, so a
/// round-trip-unstable float lands on different bytes than the ones the
/// sender signed. Serialising to BYTES (what NATS actually carries)
/// preserves them exactly, which is why the production path is safe and
/// the `Value` detour is not.
///
/// Rule for callers: move `MemoryRpcRequest` / `IntegrationStateRequest`
/// over the wire as bytes or a string, never via `serde_json::Value`.
#[test]
fn value_transcoding_loses_signed_memory_bytes_but_text_round_trip_does_not() {
    ensure_hmac_key();
    let actor = Uuid::new_v4();
    let req =
        MemoryRpcRequest::new_signed(actor, memory_set(json!({"ratio": POISON_2CYCLE}), None))
            .expect("sign");
    let signed_bytes = req.op.raw_bytes().to_vec();

    // Byte round trip: byte-preserving, so the signature still verifies.
    let via_bytes = wire_hop(&req);
    assert_eq!(
        via_bytes.op.raw_bytes(),
        signed_bytes.as_slice(),
        "the production wire path MUST preserve the signed bytes"
    );
    via_bytes
        .verify()
        .expect("the production wire path must still verify");

    // Value transcode: re-derives the text, and the float drifts.
    let via_value: MemoryRpcRequest = value_transcode_hop(&req);
    assert_ne!(
        via_value.op.raw_bytes(),
        signed_bytes.as_slice(),
        "if this ever starts preserving bytes, serde_json changed — relax \
             the rule deliberately rather than by accident"
    );
    assert!(
        via_value.verify().is_err(),
        "a Value-transcoded request must FAIL verification — that is the \
             whole reason the rule exists"
    );
}

/// The same trap on the integration-state twin — covered separately
/// because the two surfaces have independent signing formulas and a fix
/// applied to one has historically missed the other.
#[test]
fn value_transcoding_loses_signed_integration_bytes() {
    ensure_hmac_key();
    let req = IntegrationStateRequest::new_signed(
        "gmail".to_string(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        integration_set(json!({"drift_ratio": POISON_2CYCLE})),
    )
    .expect("sign");
    let signed_bytes = req.op.raw_bytes().to_vec();

    let via_bytes = wire_hop(&req);
    assert_eq!(via_bytes.op.raw_bytes(), signed_bytes.as_slice());
    via_bytes
        .verify()
        .expect("the production wire path must still verify");

    let via_value: IntegrationStateRequest = value_transcode_hop(&req);
    assert_ne!(
        via_value.op.raw_bytes(),
        signed_bytes.as_slice(),
        "if this ever starts preserving bytes, serde_json changed"
    );
    assert!(
        via_value.verify().is_err(),
        "a Value-transcoded integration request must FAIL verification"
    );
}

// The second anti-vacuousness guard
// (`generator_produces_values_whose_canonical_bytes_drift`) was deleted
// with `canonical_json_bytes` in Phase 2. Its purpose — proving the
// generator produces values that expose the re-derivation defect — is
// now served, one level higher, by
// `generator_actually_produces_round_trip_unstable_values` above: raw
// text instability across a re-parse is exactly what RawSigned's wire
// hop must survive, and the memory signature is now computed over that
// raw text rather than a canonicalised form.
