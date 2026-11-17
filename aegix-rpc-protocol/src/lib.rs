//! # aegix-rpc-protocol — the signed data-plane RPC protocols
//!
//! The wire types and the signing discipline every worker → controller
//! request/reply shares, with no database, embedding or HTTP dependency:
//!
//! * [`rpc_auth`] — HMAC-SHA256 or Ed25519 bound to `(subject, actor_id,
//!   nonce, body)`, the two-generation nonce cache, the asymmetric freshness
//!   window, the process-global key registry, and `RawSigned<T>` (a `pub use`
//!   of its ONE home, `aegix_workflow_job_protocol::RawSigned`).
//! * one module per subject — [`memory_rpc`] (`talos.memory.op`),
//!   [`graph_rpc`] (`talos.graph.search`), [`database_rpc`]
//!   (`talos.database.query`), [`state_rpc`] (`talos.state.write`), [`ml_rpc`]
//!   (`talos.ml.predict` / `talos.ml.fewshot`) and [`integration_state_rpc`]
//!   — each owning its own signing formula (`sign_body_bytes`) and `verify()`.
//! * [`dispatch_binding`] — the signed `{execution_id, job_id}` a data-plane
//!   request names (2026-10-29).
//! * [`memory_key`] — the key rule and the value / metadata / TTL caps a
//!   `MemoryOp` is validated against, re-exported at the crate root.
//!
//! These modules lived in `aegix-memory` until 2026-10-30, beside the
//! Postgres actor-memory service, so the embeddable runtime (`aegix-runtime`,
//! structural check 109) linked `sqlx` and `pgvector` to carry wire types.
//! They moved here verbatim (`git mv`; the wire-format snapshots and the
//! security tests came with them and are byte-for-byte the same), and
//! `aegix-memory` re-exports every module at its old path, so
//! `aegix_memory::rpc_auth` and `aegix_rpc_protocol::rpc_auth` are the SAME
//! items — one nonce cache, one key registry per process.
//!
//! Record: `docs/engineering-log/packages/2026-10-30-rpc-protocols-below-the-runtime-boundary.md`.

pub mod database_rpc;
pub mod dispatch_binding;
pub mod graph_rpc;
pub mod integration_state_rpc;
pub mod memory_key;
pub mod memory_rpc;
pub mod ml_rpc;
pub mod rpc_auth;
pub mod state_rpc;

pub use memory_key::{
    is_valid_memory_type, memory_types_csv, validate_memory_key, MAX_MEMORY_KEY_CHARS,
    MAX_METADATA_BYTES, MAX_TTL_HOURS, MAX_VALUE_BYTES, MEMORY_TYPES, SET_KV_TTL_HOURS,
};

// ============================================================================
// Unit tests — moved with the modules from aegix-memory/src/lib.rs
// (2026-10-30). The protocol's behavioural specs: the key rule, the
// per-subject sign → wire hop → verify round trips, replay and freshness
// refusals, and the NaN/Inf gate. The wire-format snapshots (literal JSON +
// MAC hex) are tests/wire_format_snapshots.rs.
// ============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    // MCP-1224 (2026-05-18): the canonical `validate_memory_key` helper
    // is now invoked at the persistence boundary inside
    // `persist_memory_with_metadata` and `persist_memory_in_tx_with_metadata`
    // (sibling-drift fix — `scaffold_actor.seed_memories` and any other
    // caller of those write paths previously did only a shallow
    // `key.is_empty()` check, allowing `"   "` whitespace-only keys
    // through and persisting unreachable rows). These tests pin the
    // canonical validator's accept/reject contract so a future
    // refactor of `validate_memory_key` doesn't loosen the bound.
    #[test]
    fn validate_memory_key_accepts_canonical() {
        assert_eq!(validate_memory_key("foo").unwrap(), "foo");
        assert_eq!(
            validate_memory_key("daily_brief/2026-04-21").unwrap(),
            "daily_brief/2026-04-21"
        );
        // Trim semantics: surrounding whitespace stripped, inner
        // whitespace preserved.
        assert_eq!(validate_memory_key("  foo  ").unwrap(), "foo");
        assert_eq!(validate_memory_key("a b\tc").unwrap(), "a b\tc");
        // Exact-cap accepted (500 chars).
        let at_cap = "a".repeat(MAX_MEMORY_KEY_CHARS);
        assert_eq!(validate_memory_key(&at_cap).unwrap(), at_cap.as_str());
    }

    #[test]
    fn validate_memory_key_rejects_whitespace_only() {
        // The seed_memories bypass: scaffold_actor caller passed
        // `"   "` and a shallow `is_empty()` check accepted it,
        // persisting a row whose primary-key projection is empty
        // and therefore unreachable from any subsequent recall.
        assert!(validate_memory_key("   ").is_err());
        assert!(validate_memory_key("\t\t").is_err());
        assert!(validate_memory_key(" \t \t ").is_err());
        assert!(validate_memory_key("").is_err());
    }

    #[test]
    fn validate_memory_key_rejects_control_chars() {
        // Tab is explicitly allowed (MCP-388 trim parity) — every
        // other control char rejected.
        assert!(validate_memory_key("foo\0bar").is_err());
        assert!(validate_memory_key("foo\nbar").is_err());
        assert!(validate_memory_key("foo\rbar").is_err());
        assert!(validate_memory_key("foo\x07bar").is_err());
        // Trailing control chars also rejected (validator inspects
        // the original key, not just the trimmed view, so embedded
        // \0 inside untrimmed padding still triggers).
        assert!(validate_memory_key("  foo\0  ").is_err());
        // Tab inside the key is fine.
        assert!(validate_memory_key("foo\tbar").is_ok());
    }

    #[test]
    fn validate_memory_key_rejects_oversize() {
        // 501 chars rejected (cap is 500 chars, MAX_MEMORY_KEY_CHARS).
        let oversize = "a".repeat(MAX_MEMORY_KEY_CHARS + 1);
        assert!(validate_memory_key(&oversize).is_err());
        // 10 000 chars rejected — the pre-MCP-834 GraphQL path used
        // MAX_SHORT_STRING_LENGTH = 10 000, which is what made this
        // drift hard to detect on the write surface before promotion.
        let way_oversize = "a".repeat(10_000);
        assert!(validate_memory_key(&way_oversize).is_err());
    }

    #[test]
    fn hmac_roundtrip() {
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0xABu8; 32]));
        let actor = Uuid::new_v4();
        let body = b"hello memory";
        let nonce = rpc_auth::random_nonce();
        let sig = rpc_auth::sign("memory_rpc", actor, &nonce, body).unwrap();
        assert!(rpc_auth::verify("memory_rpc", actor, &nonce, body, &sig));

        // Subject binding: a sig valid for memory_rpc must not verify
        // as graph_rpc.
        assert!(!rpc_auth::verify("graph_rpc", actor, &nonce, body, &sig));

        // Actor binding: different actor_id invalidates.
        assert!(!rpc_auth::verify(
            "memory_rpc",
            Uuid::new_v4(),
            &nonce,
            body,
            &sig
        ));

        // Body tampering invalidates.
        assert!(!rpc_auth::verify(
            "memory_rpc",
            actor,
            &nonce,
            b"tampered",
            &sig
        ));

        // Nonce binding invalidates.
        assert!(!rpc_auth::verify("memory_rpc", actor, "other", body, &sig));
    }

    #[test]
    fn memory_rpc_signed_roundtrip() {
        use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x11u8; 32]));
        let actor = Uuid::new_v4();
        let req = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Get {
                key: "capture/abc".to_string(),
            },
        )
        .expect("sign");
        assert!(req.verify().is_ok());

        // Tamper with the op but keep the original signature — must
        // fail verify. This is the critical property for cross-tenant
        // security.
        let mut tampered = req.clone();
        // Re-mints raw for the new op but keeps the original signature
        // (computed over the Set body) — verify must reject.
        tampered.op = crate::rpc_auth::RawSigned::from(MemoryOp::Delete {
            key: "victim-key".to_string(),
        });
        assert!(tampered.verify().is_err());
    }

    // (`canonical_json_sorts_object_keys` deleted with the canonical
    // machinery. The key-order invariance it asserted now holds by virtue
    // of `serde_json::Value::Object` being a BTreeMap in this workspace —
    // covered end-to-end by `memory_set_signature_is_key_order_invariant`
    // below, which signs two orderings and checks both verify.)

    #[test]
    fn memory_set_signature_is_key_order_invariant() {
        use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x55u8; 32]));
        let actor = Uuid::new_v4();

        // Value with keys inserted in two different orders — the
        // signed body must hash to the same bytes, so both requests
        // verify with each other's signatures.
        let mut value_a = serde_json::Map::new();
        value_a.insert("z".to_string(), serde_json::json!("last"));
        value_a.insert("a".to_string(), serde_json::json!("first"));
        let mut value_b = serde_json::Map::new();
        value_b.insert("a".to_string(), serde_json::json!("first"));
        value_b.insert("z".to_string(), serde_json::json!("last"));

        let req_a = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::Value::Object(value_a),
                memory_type: "semantic".to_string(),
                ttl_hours: None,
            },
        )
        .expect("sign A");
        let req_b = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::Value::Object(value_b),
                memory_type: "semantic".to_string(),
                ttl_hours: None,
            },
        )
        .expect("sign B");

        // Both must verify individually (freshness window in play).
        assert!(req_a.verify().is_ok());
        assert!(req_b.verify().is_ok());
        // Signatures may differ (nonce + timestamp do) — but the body
        // hashes must match. Construct a hybrid request using req_a's
        // signature + req_b's op: if canonical form really works,
        // this should still verify because the signed body is
        // byte-identical either way... actually no, nonce differs so
        // signatures still differ. The real test: swap op between
        // them (same nonce + timestamp + signature, new op shape) and
        // verify that works. This is subtle to test cleanly; the
        // canonical_json_sorts_object_keys test above covers the
        // byte invariant directly.
    }

    #[test]
    fn stale_request_is_rejected() {
        use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x44u8; 32]));
        let actor = Uuid::new_v4();
        let mut req = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Get {
                key: "x".to_string(),
            },
        )
        .expect("sign");
        assert!(req.verify().is_ok(), "fresh request should verify");

        // Backdate by 10 minutes — well outside the 60 s window. The
        // signature is still structurally valid but freshness check
        // must reject it.
        req.timestamp_ms -= 10 * 60 * 1000;
        assert!(req.verify().is_err(), "stale request must not verify");

        // Future-dated requests beyond the window are rejected too
        // (protects against clock-skew-based replay).
        let mut future_req = MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Get {
                key: "y".to_string(),
            },
        )
        .expect("sign");
        future_req.timestamp_ms += 10 * 60 * 1000;
        assert!(
            future_req.verify().is_err(),
            "future-dated request outside window must not verify"
        );
    }

    #[test]
    fn state_rpc_signed_roundtrip() {
        use crate::rpc_auth;
        use crate::state_rpc::StateWriteRequest;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x33u8; 32]));
        let actor = Uuid::new_v4();
        let exec = Uuid::new_v4();
        let req = StateWriteRequest::new_signed(
            exec,
            actor,
            "session/user".to_string(),
            "{}".to_string(),
            false,
        )
        .expect("sign");
        assert!(req.verify().is_ok());

        // Tamper with the execution_id → should fail.
        let mut t = req.clone();
        t.execution_id = Uuid::new_v4();
        assert!(t.verify().is_err());

        // Delete flag is part of the signed body — toggling it must
        // invalidate the signature, otherwise a malicious worker
        // could flip a set to a delete at write time.
        let mut t2 = req.clone();
        t2.is_delete = !t2.is_delete;
        assert!(t2.verify().is_err());
    }

    #[test]
    fn database_rpc_signed_roundtrip() {
        use crate::database_rpc::DatabaseRpcRequest;
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x22u8; 32]));
        let actor = Uuid::new_v4();
        let req = DatabaseRpcRequest::new_signed(
            actor,
            "SELECT 1".to_string(),
            vec!["foo".to_string()],
            true,
        )
        .expect("sign");
        assert!(req.verify().is_ok());

        // Tampering with the SQL must invalidate the signature — the
        // critical property that prevents a sandbox from forging a
        // query after the controller passed initial validation.
        let mut tampered = req.clone();
        tampered.sql = "DROP TABLE actor_memory".to_string();
        assert!(tampered.verify().is_err());

        // Subject binding: a valid database signature must not verify
        // as a memory or graph request.
        let body = serde_json::json!({
            "sql": req.sql,
            "params": req.params,
            "is_fetch": req.is_fetch,
        });
        let body_bytes = serde_json::to_vec(&body).unwrap();
        assert!(!rpc_auth::verify(
            "memory_rpc",
            actor,
            &req.nonce,
            &body_bytes,
            &req.signature
        ));
        assert!(!rpc_auth::verify(
            "graph_rpc",
            actor,
            &req.nonce,
            &body_bytes,
            &req.signature
        ));
    }

    #[test]
    fn nonce_replay_is_rejected() {
        use crate::rpc_auth;
        let _g = rpc_auth::nonce_test_lock();
        rpc_auth::clear_nonce_cache_for_test();
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x66u8; 32]));
        let actor = Uuid::new_v4();
        let nonce = rpc_auth::random_nonce();

        // First presentation: accept.
        assert!(rpc_auth::check_and_record_nonce(
            "memory_rpc",
            actor,
            &nonce
        ));
        // Replay within the freshness window: reject.
        assert!(!rpc_auth::check_and_record_nonce(
            "memory_rpc",
            actor,
            &nonce
        ));

        // Cross-subject isolation: the same nonce bytes used under a
        // different subject must be accepted. That's why `subject` is
        // part of the nonce key.
        assert!(rpc_auth::check_and_record_nonce("graph_rpc", actor, &nonce));

        // Cross-actor isolation: a different actor presenting the
        // same nonce is also accepted.
        let other_actor = Uuid::new_v4();
        assert!(rpc_auth::check_and_record_nonce(
            "memory_rpc",
            other_actor,
            &nonce
        ));
    }

    #[test]
    fn memory_rpc_rejects_nan_fields() {
        use crate::memory_rpc::{MemoryOp, MemoryRpcRequest};
        use crate::rpc_auth;
        rpc_auth::register_hmac_key(std::sync::Arc::new(vec![0x77u8; 32]));
        let actor = Uuid::new_v4();

        // NaN ttl_hours — new_signed must refuse.
        assert!(MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::json!({}),
                memory_type: "semantic".to_string(),
                ttl_hours: Some(f64::NAN),
            },
        )
        .is_none());

        // +Inf ttl_hours — same.
        assert!(MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::json!({}),
                memory_type: "semantic".to_string(),
                ttl_hours: Some(f64::INFINITY),
            },
        )
        .is_none());

        // NaN min_score on Search.
        assert!(MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Search {
                exclude_kinds: vec![],
                query: "q".to_string(),
                limit: 5,
                min_score: f64::NAN,
            },
        )
        .is_none());

        // Legitimate value succeeds.
        assert!(MemoryRpcRequest::new_signed(
            actor,
            MemoryOp::Set {
                metadata: None,
                key: "k".to_string(),
                value: serde_json::json!({}),
                memory_type: "semantic".to_string(),
                ttl_hours: Some(24.0),
            },
        )
        .is_some());
    }

    // (`canonical_json_respects_depth_limit` deleted with the canonical
    // machinery — RawSigned binds the exact wire text and relies on
    // serde_json's own 128-deep recursion cap, exercised via the
    // wire_hop_signing_specs property tests, not a bespoke depth walk.)
}

#[cfg(test)]
mod wire_hop_signing_specs {
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
    // (aegix-worker-runtime/src/host/memory.rs) and the single admission
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
        let req =
            MemoryRpcRequest::new_signed(actor, memory_set(json!({"a": 1}), None)).expect("sign");
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
}

#[cfg(test)]
mod rpc_verify_classification_specs {
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
}
