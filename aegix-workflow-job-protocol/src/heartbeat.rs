//! The signed heartbeat a worker publishes, and how a controller verifies
//! it.
//!
//! Moved out of `lib.rs` 2026-11-18, unchanged; every item is re-exported
//! at the crate root, where it was.

#[cfg(test)]
use crate::HmacSha256;
use crate::{validate_worker_id, SignedMessage};
#[cfg(test)]
use hmac::Mac;
use serde::{Deserialize, Serialize};

/// Domain-separation prefix for the worker FLEET HEARTBEAT signing payload.
///
/// DELIBERATELY DISTINCT from every other signed message on the bus, and
/// especially from `WORKER_LIVENESS_POP_DOMAIN` — the two carry very
/// different evidence and must never be interchangeable:
///
/// * A liveness proof (#631) is an **Ed25519 proof of possession**: only the
///   holder of that worker's registered private key can mint one, and it is
///   the credential that keeps a signing key in the controller's trusted
///   verify ring.
/// * A heartbeat is an **HMAC under the fleet-shared `WORKER_SHARED_KEY`**:
///   any process holding that key can mint one for any `worker_id`. It is
///   therefore evidence that *a* process is running and claims to be that
///   worker — a liveness HINT, never a trust signal.
///
/// Because the shared key is fleet-wide, a heartbeat must never be able to
/// stand in for a proof of possession. Separation here is structural on three
/// independent axes (different primitive, different domain tag, different
/// transport), and is asserted in all three directions by
/// `worker_heartbeat_domain_separation_tests`.
pub const WORKER_HEARTBEAT_DOMAIN: &[u8] = b"talos/worker-fleet-heartbeat/v1";

/// Freshness window a heartbeat is verified under, in seconds.
///
/// **This is the replay bound.** Two layers enforce it and neither is
/// sufficient alone:
///  * the signed nonce carries the send timestamp, and
///    `check_freshness_window` rejects anything older than this (or more than
///    `MAX_FUTURE_SKEW_SECS` ahead);
///  * within the window, the process-local `JOB_NONCE_CACHE` refuses a nonce
///    it has already recorded, so a captured heartbeat cannot be re-fired even
///    once inside it.
///
/// So a captured heartbeat is usable for at most 0 replays, and is inert after
/// `WORKER_HEARTBEAT_MAX_AGE_SECS`. It must stay comfortably ABOVE the worker's
/// publish interval (default 30s, see the worker's `heartbeat` module) or
/// legitimate heartbeats would be rejected as stale on a slow bus.
pub const WORKER_HEARTBEAT_MAX_AGE_SECS: u64 = 60;

/// The LARGEST publish interval a worker will actually use, whatever
/// `AEGIX_WORKER_HEARTBEAT_INTERVAL_SECS` is set to.
///
/// The worker clamps its configured interval to this (`worker::heartbeat`), and
/// the clamp is derived rather than written as a literal: an interval at or
/// above [`WORKER_HEARTBEAT_MAX_AGE_SECS`] would let a healthy worker age out
/// of the fleet view between publishes, so the ceiling is three quarters of the
/// window.
///
/// **It lives here, in the protocol crate, because the worker is not its only
/// consumer.** Anything sizing a timeout against "how long can a healthy worker
/// go without being seen" must size against the WORST configuration an operator
/// can produce, not against the default — and it cannot do that from a private
/// const in another binary. The scheduler's fleet-readiness bound
/// (`aegix_scheduler::DEFAULT_SCHEDULER_READINESS_TIMEOUT_SECS`) was derived
/// from the 30 s DEFAULT and came out at exactly 2x the clamped maximum, i.e.
/// with the "full interval of margin" it claimed reduced to zero, and its guard
/// test hardcoded the same 30 s so it could not see that. Deriving both sides
/// from this constant is what makes the guard a guard.
pub const WORKER_HEARTBEAT_MAX_INTERVAL_SECS: u64 = WORKER_HEARTBEAT_MAX_AGE_SECS * 3 / 4;

/// Heartbeat message published by workers so the controller can track fleet health.
///
/// # What this message proves, and what it does NOT
///
/// It proves that a process holding `WORKER_SHARED_KEY` published, within the
/// last [`WORKER_HEARTBEAT_MAX_AGE_SECS`], a message claiming to be
/// `worker_id`. The shared key is FLEET-WIDE, so the `worker_id` is
/// caller-asserted, not authenticated per worker. Consumers must treat the
/// resulting fleet view as an observability hint:
///
/// * It MUST NOT refresh, extend or create trust in any identity. It never
///   touches `worker_identities.last_liveness_at` — that column has exactly
///   one writer, the Ed25519 proof-of-possession endpoint (#631). See
///   `aegix-worker-fleet`'s `heartbeat_never_touches_the_trust_boundary`.
/// * `worker_id` MUST NOT become a metric label (caller-supplied ⇒ unbounded
///   cardinality).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerHeartbeat {
    /// The worker's self-reported identity — the SAME key space as
    /// `worker_identities.worker_id`, `JobResult.worker_id` and the
    /// registration / liveness endpoints (`validate_worker_id` charset).
    ///
    /// It was a `Uuid` until 2026-08, which made the fleet view structurally
    /// unjoinable with the identity registry and is a large part of why two
    /// prior designs nearly intersected the registry against an empty fleet
    /// map. Changing it cost nothing: this message had ZERO producers, so
    /// there was no deployed wire format to stay compatible with.
    pub worker_id: String,
    /// Self-reported capabilities (e.g. ["wasm", "gpu", "network"]).
    pub capabilities: Vec<String>,
    /// Current CPU usage as a percentage (0.0 – 100.0).
    pub cpu_usage_pct: f32,
    /// The worker's self-reported build string, composed exactly like the
    /// controller's own (`{cargo_pkg_version}+{git_sha}[-dirty]`, or
    /// `AEGIX_VERSION` verbatim). `None` = not reported.
    ///
    /// Carried so a live-fleet build-skew detector can work in the deployment
    /// posture where the registry-backed one structurally cannot: a fleet
    /// pinned purely through `AEGIX_WORKER_PUBLIC_KEYS` has no registration
    /// endpoint and no `worker_identities` rows at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build_version: Option<String>,
    /// HMAC-SHA256 signature for tamper detection.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Nonce for replay prevention: `"{unix_secs}:{random_hex}"`.
    #[serde(default)]
    pub heartbeat_nonce: String,
}

impl WorkerHeartbeat {
    /// Canonical signing payload: domain tag followed by every field, each
    /// length-prefixed, in the same construction as
    /// [`worker_liveness_pop_message`].
    ///
    /// The old form was `format!("heartbeat:{id}:{nonce}:{cpu}:{caps}")`, a
    /// delimited string in which two distinct field tuples could collide onto
    /// the same bytes, so one HMAC could verify under two readings. Be exact
    /// about which delimiter carried the hazard: `capabilities` were joined
    /// on `,` and are UNVALIDATED, so `["a,b"]` and `["a", "b"]` genuinely
    /// produced identical bytes. The `:` separators were NOT reachable the
    /// same way — `worker_id` is charset-checked by [`validate_worker_id`],
    /// the nonce is machine-generated and the cpu is a float — and in any
    /// case the whole thing was theoretical rather than exploitable, because
    /// this message had never had a producer. Length prefixes close the
    /// ambiguity outright; the leading domain tag closes cross-type confusion.
    /// Neither change needed a compatibility shim, for the same reason.
    fn signing_payload(&self) -> Vec<u8> {
        fn put(v: &mut Vec<u8>, field: &[u8]) {
            v.extend_from_slice(&(field.len() as u64).to_le_bytes());
            v.extend_from_slice(field);
        }
        let mut v = Vec::with_capacity(WORKER_HEARTBEAT_DOMAIN.len() + 64);
        v.extend_from_slice(WORKER_HEARTBEAT_DOMAIN);
        put(&mut v, self.worker_id.as_bytes());
        put(&mut v, self.heartbeat_nonce.as_bytes());
        // Bit pattern, not `to_string()`: f32 Display is not a canonical
        // encoding (the same class of non-idempotent float round-trip that
        // cost the fleet #598 / structural check 61). `sanitized_cpu` has
        // already collapsed NaN, so the bits are deterministic.
        v.extend_from_slice(&sanitized_cpu(self.cpu_usage_pct).to_bits().to_le_bytes());
        v.extend_from_slice(&(self.capabilities.len() as u64).to_le_bytes());
        for c in &self.capabilities {
            put(&mut v, c.as_bytes());
        }
        // Absent and empty-string are distinguished by the tag byte, so a
        // worker that reports no build cannot be confused with one reporting
        // `""` (which `build_is_verifiable` would reject anyway).
        match self.build_version.as_deref() {
            None => v.push(0u8),
            Some(b) => {
                v.push(1u8);
                put(&mut v, b.as_bytes());
            }
        }
        v
    }

    /// Sign the heartbeat using the pre-shared `key`.
    ///
    /// Rejects a `worker_id` outside the [`validate_worker_id`] charset so a
    /// malformed identity can never reach the fleet view (and, through it, a
    /// log line or a join against the identity registry). Also normalises
    /// `cpu_usage_pct` in place, since a non-finite value serialises to JSON
    /// `null` and would make the message undeliverable.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        validate_worker_id(&self.worker_id)?;
        self.cpu_usage_pct = sanitized_cpu(self.cpu_usage_pct);
        self.sign_core(key)
    }

    /// Verify the HMAC signature and nonce freshness, *and* record
    /// the nonce in the process-local replay cache. See
    /// `JobRequest::verify` for the architectural-mandate rationale
    /// (CLAUDE.md "Verify-once rule"). Pair with
    /// [`verify_no_replay`](Self::verify_no_replay) for passive observers.
    ///
    /// The charset check runs BEFORE the MAC so a malformed identity is
    /// rejected even by a sender that skipped [`sign`](Self::sign) — the
    /// signature covers the id, so a valid MAC over a bad id is still a bad
    /// id.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        validate_worker_id(&self.worker_id)?;
        self.verify_core(key, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Verify HMAC + freshness WITHOUT touching the replay cache.
    /// 2026-05-28 audit F5 sibling of `JobRequest::verify_no_replay`.
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        validate_worker_id(&self.worker_id)?;
        self.verify_no_replay_core(key, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// MAC the current fields WITHOUT minting a fresh nonce, so a test can
    /// pin the send timestamp and exercise the freshness boundary. Test-only:
    /// production signing must always mint a fresh nonce.
    #[cfg(test)]
    fn sign_core_with_fixed_nonce_for_test(&mut self, key: &[u8]) {
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("HMAC key");
        mac.update(&self.signing_payload());
        self.signature = mac.finalize().into_bytes().to_vec();
    }
}

/// Collapse a reported CPU percentage into a canonical, JSON-serialisable
/// value: non-finite (`NaN` / `±inf`) becomes `0.0`, and the rest is clamped
/// to `0.0..=100.0`.
///
/// Two reasons, both load-bearing rather than cosmetic. `serde_json` renders a
/// non-finite float as `null`, which fails to deserialise back into an `f32` —
/// so an un-normalised NaN would produce a heartbeat that signs fine and is
/// undeliverable. And `NaN` has many bit patterns, so hashing its bits would
/// not be deterministic across senders.
#[must_use]
fn sanitized_cpu(v: f32) -> f32 {
    if v.is_finite() {
        v.clamp(0.0, 100.0)
    } else {
        0.0
    }
}

impl SignedMessage for WorkerHeartbeat {
    const NONCE_LABEL: &'static str = "heartbeat_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn nonce(&self) -> &str {
        &self.heartbeat_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.heartbeat_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

/// Non-interchangeability of the fleet heartbeat, in all three directions.
///
/// The heartbeat rides a bus that also carries job results, and it sits beside
/// a #631 liveness proof that means something far stronger. Behavioural
/// "does it verify" tests are necessary but not sufficient here, because they
/// pass just as well when two message types happen to be distinguishable today
/// and would stop being so after an innocent field addition. So each direction
/// is asserted at the BYTE level as well.
#[cfg(test)]
mod worker_heartbeat_domain_separation_tests {
    use super::*;
    use crate::{
        sign_worker_liveness_proof, sign_worker_registration_proof, verify_worker_liveness_proof,
        worker_liveness_pop_message, DispatchSigningKey, JobResult, JobStatus, MAX_WORKER_ID_LEN,
        WORKER_LIVENESS_POP_DOMAIN, WORKER_REGISTRATION_POP_DOMAIN,
    };
    use uuid::Uuid;

    const KEY: [u8; 32] = [0x42; 32];

    fn heartbeat() -> WorkerHeartbeat {
        let mut hb = WorkerHeartbeat {
            worker_id: "dev-worker-fleet".to_string(),
            capabilities: vec!["wasm".to_string()],
            cpu_usage_pct: 12.5,
            build_version: Some("0.1.0+abc1234".to_string()),
            signature: vec![],
            heartbeat_nonce: String::new(),
        };
        hb.sign(&KEY).unwrap();
        hb
    }

    fn job_result() -> JobResult {
        let mut r = JobResult {
            dispatch_attempt: 0,
            workflow_execution_id: None,
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::from_u128(7),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"ok": true}).into(),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: "dev-worker-fleet".to_string(),
            fuel: None,
        };
        r.sign(&KEY).unwrap();
        r
    }

    /// DIRECTION 1 — heartbeat ⇄ job result, the two HMAC message types that
    /// share the fleet key. Same primitive, same key: only the domain tag
    /// separates them, so this is the direction most easily broken by a
    /// careless payload edit.
    #[test]
    fn a_heartbeat_and_a_job_result_never_share_signing_bytes() {
        let hb = heartbeat();
        let jr = job_result();

        assert_ne!(hb.payload_bytes(), jr.payload_bytes());
        assert!(hb.payload_bytes().starts_with(WORKER_HEARTBEAT_DOMAIN));
        assert!(
            !jr.payload_bytes().starts_with(WORKER_HEARTBEAT_DOMAIN),
            "a job result must not be able to open with the heartbeat domain"
        );

        // Lifting one message's signature onto the other fails both ways.
        let mut forged_hb = hb.clone();
        forged_hb.signature = jr.signature.clone();
        forged_hb.heartbeat_nonce = jr.result_nonce.clone();
        assert!(
            forged_hb.verify_no_replay(&KEY, 300).is_err(),
            "a job result's MAC must not authenticate a heartbeat"
        );

        let mut forged_jr = jr.clone();
        forged_jr.signature = hb.signature.clone();
        forged_jr.result_nonce = hb.heartbeat_nonce.clone();
        assert!(
            forged_jr.verify_no_replay(&KEY, 300).is_err(),
            "a heartbeat's MAC must not authenticate a job result"
        );
    }

    /// DIRECTION 2 — heartbeat ⇒ #631 liveness proof. THE SECURITY-CRITICAL
    /// one: the heartbeat is minted under a FLEET-SHARED key, so if it could
    /// stand in for a proof of possession, any worker could keep any other
    /// worker's signing key trusted indefinitely.
    #[test]
    fn a_heartbeat_can_never_stand_in_for_a_liveness_proof() {
        let hb = heartbeat();
        let sk = DispatchSigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();

        // Different domain tag ⇒ different bytes, before any key is involved.
        let pop = worker_liveness_pop_message(&hb.worker_id, &pk, 1_700_000_000_000, "abc");
        assert_ne!(hb.payload_bytes(), pop);
        assert!(!pop.starts_with(WORKER_HEARTBEAT_DOMAIN));
        assert!(!hb.payload_bytes().starts_with(WORKER_LIVENESS_POP_DOMAIN));

        // And the heartbeat's HMAC output is not a valid Ed25519 proof: it is
        // a 32-byte tag against a 64-byte signature, so it fails structurally
        // before the curve maths — belt AND braces with the domain tag.
        assert_eq!(hb.signature.len(), 32);
        assert!(verify_worker_liveness_proof(
            &pk,
            &hb.worker_id,
            1_700_000_000_000,
            "abc",
            &hb.signature
        )
        .is_err());
    }

    /// DIRECTION 3 — #631 liveness proof (and the registration proof) ⇒
    /// heartbeat. The reverse of direction 2: an Ed25519 proof captured off
    /// the liveness endpoint must not be replayable onto the NATS bus as a
    /// fleet heartbeat.
    #[test]
    fn a_liveness_or_registration_proof_can_never_stand_in_for_a_heartbeat() {
        let sk = DispatchSigningKey::from_bytes(&[9u8; 32]);
        let pk = sk.verifying_key().to_bytes();
        let live = sign_worker_liveness_proof(&sk, "dev-worker-fleet", &pk, 1_700_000_000_000, "n");
        let reg = sign_worker_registration_proof(
            &sk,
            "dev-worker-fleet",
            &pk,
            true,
            1_700_000_000_000,
            "n",
        );

        for proof in [&live, &reg] {
            let mut hb = heartbeat();
            hb.signature = proof.clone();
            assert!(
                hb.verify_no_replay(&KEY, 300).is_err(),
                "an Ed25519 worker proof must not authenticate a heartbeat"
            );
        }

        // The three domains are pairwise distinct AND no one is a prefix of
        // another — prefix-freedom is what stops a length-extension-style
        // reinterpretation of one framing as another.
        let domains: [&[u8]; 3] = [
            WORKER_HEARTBEAT_DOMAIN,
            WORKER_LIVENESS_POP_DOMAIN,
            WORKER_REGISTRATION_POP_DOMAIN,
        ];
        for (i, a) in domains.iter().enumerate() {
            for (j, b) in domains.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b), "domain {i} must not extend domain {j}");
                }
            }
        }
    }

    /// A capability containing the old format's delimiters must not be able to
    /// shift a field boundary — the reason the payload is length-prefixed.
    #[test]
    fn delimiters_inside_a_capability_cannot_shift_a_field() {
        let mut a = heartbeat();
        a.capabilities = vec!["wasm,gpu".to_string()];
        a.sign(&KEY).unwrap();
        let mut b = a.clone();
        b.capabilities = vec!["wasm".to_string(), "gpu".to_string()];
        assert_ne!(
            a.payload_bytes(),
            b.payload_bytes(),
            "one cap containing a comma must not encode like two caps"
        );
        assert!(
            b.verify_no_replay(&KEY, 300).is_err(),
            "re-splitting the capability list must invalidate the MAC"
        );
    }

    /// `sign` refuses an identity outside the shared `validate_worker_id`
    /// charset, and `verify` refuses it even if a sender bypassed `sign` —
    /// the fleet view keys on this string.
    #[test]
    fn a_malformed_worker_id_is_refused_on_both_sides() {
        let mut hb = heartbeat();
        hb.worker_id = "evil:id".to_string();
        assert!(hb.sign(&KEY).is_err());

        let mut hb2 = heartbeat();
        hb2.worker_id = "x".repeat(MAX_WORKER_ID_LEN + 1);
        // Sign the oversized id through the raw core, bypassing the guard, to
        // prove `verify` is not merely relying on `sign` having run.
        hb2.sign_core(&KEY).unwrap();
        assert!(hb2.verify_no_replay(&KEY, 300).is_err());
        assert!(hb2.verify(&KEY, 300).is_err());
    }

    /// A non-finite CPU reading is normalised at sign time. Left alone it
    /// serialises to JSON `null`, which does not deserialise back into an
    /// `f32` — a heartbeat that signs cleanly and can never be delivered.
    #[test]
    fn a_non_finite_cpu_reading_is_normalised_and_stays_serialisable() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -5.0, 250.0] {
            let mut hb = heartbeat();
            hb.cpu_usage_pct = bad;
            hb.sign(&KEY).unwrap();
            assert!(hb.cpu_usage_pct.is_finite());
            assert!((0.0..=100.0).contains(&hb.cpu_usage_pct));
            let wire = serde_json::to_vec(&hb).unwrap();
            let back: WorkerHeartbeat = serde_json::from_slice(&wire).unwrap();
            back.verify_no_replay(&KEY, 300)
                .expect("round-trips over the wire and still verifies");
        }
    }

    /// The heartbeat's replay bound, stated as a number and asserted: a
    /// captured heartbeat is good for zero replays inside the window, and is
    /// refused outright once it ages past it.
    #[test]
    fn the_replay_bound_is_the_freshness_window_and_zero_replays_inside_it() {
        let hb = heartbeat();
        hb.verify(&KEY, WORKER_HEARTBEAT_MAX_AGE_SECS)
            .expect("first primary verify succeeds");
        assert!(
            hb.verify(&KEY, WORKER_HEARTBEAT_MAX_AGE_SECS).is_err(),
            "a captured heartbeat must not be replayable inside the window"
        );

        // Aged past the window: refused on freshness alone, no cache involved.
        let mut old = heartbeat();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (WORKER_HEARTBEAT_MAX_AGE_SECS + 5);
        old.heartbeat_nonce = format!("{ts}:{}", hex::encode([1u8; 16]));
        old.sign_core_with_fixed_nonce_for_test(&KEY);
        let err = old
            .verify_no_replay(&KEY, WORKER_HEARTBEAT_MAX_AGE_SECS)
            .unwrap_err();
        assert!(err.contains("too old"), "unexpected error: {err}");
    }

    /// A floor under the freshness window, and NOT the cross-crate pinning it
    /// was originally named for.
    ///
    /// This crate cannot see the worker's publish interval — `worker` depends
    /// on it, not the other way round — so it cannot assert the relationship
    /// "interval < window". The real pinning is worker-side, in
    /// `worker::heartbeat`'s `the_slowest_configurable_interval_still_keeps_a_
    /// worker_visible`, which derives its own clamp ceiling FROM this
    /// constant. What this test contributes is the other half: that shrinking
    /// this constant below a minute — which would silently tighten that
    /// derived ceiling and could push it under the default publish interval —
    /// is a deliberate act rather than a passing edit. Pinned at COMPILE
    /// time (a `const` assertion), so the edit fails the build, not a test.
    const _: () = assert!(
        WORKER_HEARTBEAT_MAX_AGE_SECS >= 60,
        "worker::heartbeat clamps its publish interval to 3/4 of this \
         value; below 60s that ceiling drops under the 30s default"
    );
}
