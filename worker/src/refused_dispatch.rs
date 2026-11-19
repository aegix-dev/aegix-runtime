//! What the worker says to a dispatch it refused: nothing, with one
//! exception. `refused_dispatch_answer` is the one rule, and
//! `signature_failure_payload` words the one answer and the operator's
//! diagnostic line.
//!
//! Moved out of `main.rs` 2026-11-18, unchanged. `refused_dispatch_pin.rs`
//! reads this file for the rule and `main.rs` for the intake that asks it.

use crate::DispatchVerifyConfig;
use aegix_workflow_job_protocol::{
    JobRequest, JobResult, JobStatus, VerifyError, VerifyFailureKind,
};
use serde_json::json;

/// Worker-side gate for the MCP-1212 signature-failure diagnostic (the
/// enriched field dump built in `signature_failure_payload`). OFF by
/// default. Same env var as the controller's dispatch-side diagnostic so one
/// setting lights up both halves during an investigation. Read once at first
/// use; changing the env after boot has no effect.
///
/// Since 2026-11-15 the dump for a dispatch that did not verify is written to
/// this worker's own log (target `signature_diag`, the controller's) and sent
/// nowhere: such a dispatch gets no result at all (`refused_dispatch_answer`).
/// The one refusal that is still answered is of a dispatch the controller
/// signed, and with the gate on its answer carries the dump as before.
pub(crate) static WORKER_SIGNATURE_DIAG_ENABLED: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| {
        aegix_deploy_posture::bool_env_or_default("AEGIX_SIGNATURE_DIAG", false)
    });

/// Coarse, non-sensitive classification of a verify failure.
///
/// Thin alias for [`aegix_workflow_job_protocol::verify_failure_class`], which
/// is where this mapping LIVES as of 2026-09-23. The tokens are unchanged; what
/// moved is the home, because the controller's dispatcher is now a second
/// reader of the token this worker stamps (it re-dispatches a rejection whose
/// class is in `PRE_EXECUTION_REJECTION_CLASSES` instead of handing the prose
/// to the node's module-error retry policy). A second copy here would let the
/// receiver's idea of a class and the sender's retry decision drift apart
/// silently — the same "one home" rule the tokens themselves were rewritten for
/// in 2026-08-25, when this was a `contains()` scan over the verifier's error
/// TEXT rather than a total match over its TYPED reason.
///
/// Kept as a named function rather than inlining the call so the worker's own
/// `signature_failure_payload_tests` keep naming the concept they pin. They
/// drive the SHARED body through it — there is one implementation.
fn classify_verify_failure(kind: VerifyFailureKind) -> &'static str {
    aegix_workflow_job_protocol::verify_failure_class(kind)
}

/// Build the `output_payload` for a signature-verification failure.
///
/// `diag_enabled == false` (production default): a generic error only —
/// no request-derived bytes reach the signed result. `true`: the full
/// MCP-1212 field dump for controller↔worker divergence debugging.
/// Pure function so both shapes are unit-testable (see
/// `signature_failure_payload_tests`).
pub(crate) fn signature_failure_payload(
    diag_enabled: bool,
    req: &JobRequest,
    verify_error: &VerifyError,
) -> serde_json::Value {
    // The headline is the operator's ONLY signal when the diagnostic is off, so
    // it must not say "signature verification failed" for a message that was
    // rejected on AGE before its signature was ever evaluated.
    //
    // `verify_failure_headline`, NOT `describe_verify_failure`: the gated-OFF
    // arm must contain no byte derived from the UNAUTHENTICATED request, and
    // the protocol detail can echo one (the `crypto_scheme` byte, the age the
    // sender chose). The class token carries the actionable part; the full
    // detail is in the worker's own log, which is never signed or republished.
    let headline =
        aegix_workflow_job_protocol::verify_failure_headline("Job dispatch", verify_error.kind());
    if !diag_enabled {
        // Always carry the coarse CLASS of failure. Pre-2026-07-27 this arm
        // returned the bare string, which left a live incident with no signal
        // at all: replay, an unconfigured key, a scheme mismatch and a genuine
        // HMAC divergence are entirely different faults with entirely
        // different fixes, and they were indistinguishable to the operator.
        //
        // The class is derived from OUR OWN verifier's error text, never from
        // request fields — that distinction is the whole security rationale
        // for gating the rich dump, since those fields are attacker-
        // controllable on an UNVERIFIED request and get echoed into a result
        // the worker then signs.
        return json!({
            "error": headline,
            "reason_class": classify_verify_failure(verify_error.kind()),
        });
    }
    let (worker_input_hash, worker_secrets_hash, worker_input_byte_len) = req.diag_hashes();
    json!({
        // Operator opted in: the detail and the observed age are useful here and
        // the echo risk is explicitly accepted (see the gate's doc comment).
        "error": aegix_workflow_job_protocol::describe_verify_failure("Job dispatch", verify_error),
        "reason_class": classify_verify_failure(verify_error.kind()),
        "age_secs": verify_error.age_secs(),
        "diag": {
            "verify_error": verify_error.to_string(),
            "worker_input_hash": worker_input_hash,
            "worker_secrets_hash": worker_secrets_hash,
            "worker_input_byte_len": worker_input_byte_len,
            "signature_byte_len": req.signature.len(),
            "job_nonce": req.job_nonce,
            "module_uri": req.module_uri,
            "actor_id": req.actor_id.map(|u| u.to_string()),
            "user_id": req.user_id.to_string(),
            "allowed_hosts": req.allowed_hosts,
            "allowed_methods": req.allowed_methods,
            "allowed_secrets": req.allowed_secrets,
            "allowed_sql_operations": req.allowed_sql_operations,
            "allow_tier2_exposure": req.allow_tier2_exposure,
            "integration_name": req.integration_name,
            "expected_wasm_hash": req.expected_wasm_hash,
            "timeout_ms": req.timeout_ms,
            "note": "Compare these worker-computed values against the controller's `signature_diag` WARN log entry for the same job_id to identify which signed field diverged (enable it on the controller with AEGIX_SIGNATURE_DIAG=1)."
        }
    })
}

/// What the worker may sign in answer to a dispatch that failed
/// `verify_dispatch`: nothing, with one exception (2026-11-15).
///
/// Nothing in a dispatch that did not verify is authenticated. Its job id,
/// attempt, execution and reply subject are whatever its sender wrote, and for
/// a job that is running all four are readable on the bus. Until this date
/// the worker answered every such dispatch with a `Failed` result, signed with
/// its own key, sent where the dispatch said. That is a genuine worker result
/// for a job its sender chose: it names the attempt and execution the
/// dispatcher is waiting on (`JobResult::answers`) and its signature is this
/// worker's, so a controller took it as the running job's answer. A sender
/// with no key could have any running job recorded as failed, retried while
/// its first attempt still ran, or (with an old timestamp, which is refused
/// before the signature is read) re-dispatched as a job that never started.
/// The oversized and undecodable drops above the decode had already been
/// reasoned this way (`rejected_jobs`); this is the same rule for the third
/// kind of message the worker cannot vouch for.
///
/// The exception is a dispatch refused for the TIME it arrived at
/// (`VerifyError::is_liveness`) whose signature IS the controller's
/// (`verify_signature_only_dispatch`). Its job id, attempt, execution and
/// reply subject are then the controller's own, and the answer is the
/// `stale_timestamp` rejection the dispatcher re-sends on
/// (`PRE_EXECUTION_REJECTION_CLASSES`): the honest case of a job that waited
/// in a busy worker's queue, or crossed a suspended host, for longer than the
/// window. Every other refusal is answered with nothing: a signature that
/// does not hold, a nonce this process has already seen (a replay is never
/// answered; `dispatch_replay`), a scheme or key this worker cannot check.
/// The dispatcher's own wait ends such an attempt.
///
/// Stated limit: bytes the controller really signed, captured and sent again
/// after the window while that same attempt is still running, are answered,
/// and the dispatcher re-sends a job that is in flight. That needs a reader of
/// the bus and an attempt longer than the window; the worker cannot tell it
/// from the honest case, and the package record says what would.
pub(crate) fn refused_dispatch_answer(
    req: &JobRequest,
    refusal: &VerifyError,
    shared_key: &aegix_dispatch_types::WorkerKeyRing,
    dvc: &DispatchVerifyConfig,
    diag_enabled: bool,
) -> Option<JobResult> {
    if !refusal.is_liveness() {
        return None;
    }
    if req
        .verify_signature_only_dispatch(shared_key, &dvc.ed_keys, dvc.accept_legacy_hmac)
        .is_err()
    {
        return None;
    }
    Some(JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: req.job_id,
        status: JobStatus::Failed,
        output_payload: signature_failure_payload(diag_enabled, req, refusal).into(),
        logs: vec![],
        execution_time_ms: 0,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    })
}

#[cfg(test)]
mod signature_failure_payload_tests {
    use super::*;
    use crate::job_result::failed_result;
    use crate::sign_job_result_for;
    use aegix_workflow_job_protocol::{EncryptedSecrets, LlmTier};
    use uuid::Uuid;

    fn err(kind: VerifyFailureKind) -> VerifyError {
        VerifyError::from_parts(kind, "hmac mismatch", None)
    }

    /// Each class implies a DIFFERENT operator action, so they must not
    /// collapse: key_config is a deploy/env fault, scheme_mismatch is
    /// controller/worker version skew, replay is a nonce-cache interaction,
    /// stale_timestamp is a LIVENESS failure, and mismatch is a genuine
    /// signing-payload divergence.
    #[test]
    fn verify_failures_classify_into_distinct_actionable_classes() {
        assert_eq!(classify_verify_failure(VerifyFailureKind::Replay), "replay");
        assert_eq!(
            classify_verify_failure(VerifyFailureKind::SchemeRefused),
            "scheme_mismatch"
        );
        assert_eq!(
            classify_verify_failure(VerifyFailureKind::KeyError),
            "key_config"
        );
        assert_eq!(
            classify_verify_failure(VerifyFailureKind::Stale),
            "stale_timestamp"
        );
        assert_eq!(
            classify_verify_failure(VerifyFailureKind::ClockSkewAhead),
            "stale_timestamp"
        );
        assert_eq!(
            classify_verify_failure(VerifyFailureKind::BadSignature),
            "mismatch"
        );
        assert_eq!(
            classify_verify_failure(VerifyFailureKind::MalformedNonce),
            "mismatch"
        );
    }

    /// The token set and the headline must AGREE: anything the worker labels
    /// `stale_timestamp` must also be reported as a liveness failure, and
    /// nothing else may be. Guards against the two paths drifting apart — the
    /// exact way this bug class returns.
    #[test]
    fn stale_timestamp_class_and_liveness_headline_never_disagree() {
        for &kind in VerifyFailureKind::ALL {
            let e = VerifyError::from_parts(kind, "x", None);
            let headline = aegix_workflow_job_protocol::describe_verify_failure("Job dispatch", &e);
            let says_signature_failed = headline.contains("signature verification failed");
            assert_eq!(
                classify_verify_failure(kind) == "stale_timestamp",
                kind.is_liveness(),
                "class/liveness disagreement for {kind:?}"
            );
            assert!(
                !(kind.is_liveness() && says_signature_failed),
                "a liveness failure must never be headlined as a signature failure: {headline}"
            );
        }
    }

    /// The gated-OFF payload must carry the class but NOTHING derived from the
    /// unverified request — that echo is the security reason the rich dump is
    /// gated in the first place.
    #[test]
    fn ungated_payload_carries_class_but_no_request_fields() {
        let req = unauthenticated_req();
        let v = signature_failure_payload(false, &req, &err(VerifyFailureKind::BadSignature));
        assert_eq!(v["error"], "Job dispatch signature verification failed");
        assert_eq!(v["reason_class"], "mismatch");
        assert!(v.get("diag").is_none(), "no rich dump when gated off");
        // The gated-OFF payload gets SIGNED and published in reply to an
        // UNAUTHENTICATED request, so it must carry no byte derived from that
        // request — not even the verifier's own detail string, which can echo
        // the sender-chosen `crypto_scheme` byte or age.
        assert!(
            !v.to_string().contains("hmac mismatch"),
            "protocol detail must not reach the signed ungated payload: {v}"
        );
        let rendered = v.to_string();
        assert!(
            !rendered.contains("worker_input_hash") && !rendered.contains("module_uri"),
            "must not leak request-derived fields: {rendered}"
        );
    }

    /// Security review 2026-10-14, B-9: a result the worker signs for a
    /// request names that request's attempt and execution, and the binding is
    /// under the signature — the dispatcher takes only an answer to the
    /// attempt it is waiting on.
    #[test]
    fn a_signed_result_answers_the_request_it_was_signed_for() {
        let mut req = unauthenticated_req();
        req.dispatch_attempt = 2;
        let ring = aegix_dispatch_types::WorkerKeyRing::single(
            aegix_dispatch_types::WorkerSharedKey::new(vec![0x24; 32]),
        );
        let mut result = failed_result(req.job_id, &std::time::Instant::now(), "x");
        sign_job_result_for(&mut result, &req, &ring).expect("sign");
        assert_eq!(
            result.answers(&req.dispatch_identity()),
            aegix_workflow_job_protocol::ResultAnswer::ThisDispatch
        );
        result
            .verify_no_replay_dispatch(&ring, &[], 300, true)
            .expect("the bound result verifies");
    }

    pub(super) fn unauthenticated_req() -> JobRequest {
        JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://attacker-chosen/v1".to_string(),
            input_payload: serde_json::json!({"x": 1}).into(),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec!["attacker-chosen-host".to_string()],
            allowed_methods: vec![],
            allowed_secrets: vec!["attacker-chosen-secret".to_string()],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![1, 2, 3],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: aegix_workflow_job_protocol::WriteCeiling::default(),
            egress_scope: None,
            http_verb_ceiling: None,
            job_nonce: "attacker-chosen-nonce".to_string(),
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

    /// Default (diag OFF): no attacker-supplied byte may reach the payload
    /// the worker will sign and publish. Asserted as a PROPERTY rather than
    /// byte-equality — the payload gained a coarse `reason_class` (2026-07-27)
    /// because the bare string left a live incident with no signal at all, and
    /// pinning the exact object would fail on that improvement while proving
    /// nothing extra about the leak this test actually guards.
    #[test]
    fn diag_disabled_emits_generic_error_only() {
        let payload = signature_failure_payload(
            false,
            &unauthenticated_req(),
            &err(VerifyFailureKind::BadSignature),
        );
        assert_eq!(
            payload["error"],
            "Job dispatch signature verification failed"
        );
        // The class is one of OUR tokens, never the verifier's raw text.
        assert!(
            [
                "replay",
                "scheme_mismatch",
                "key_config",
                "stale_timestamp",
                "mismatch"
            ]
            .contains(&payload["reason_class"].as_str().unwrap_or_default()),
            "reason_class must be a known token, got {:?}",
            payload["reason_class"]
        );
        assert!(
            payload.get("diag").is_none(),
            "rich dump must stay gated when diag is off"
        );
        let raw = payload.to_string();
        for tainted in ["attacker-chosen", "hmac mismatch"] {
            assert!(
                !raw.contains(tainted),
                "unauthenticated request bytes leaked into signed result: {tainted}"
            );
        }
    }

    /// A dispatch that aged out must not tell the operator its signature failed
    /// — the worker leg of the same 2026-08-20/24 misattribution.
    #[test]
    fn an_aged_out_dispatch_is_not_reported_as_a_signature_failure() {
        for kind in [VerifyFailureKind::Stale, VerifyFailureKind::ClockSkewAhead] {
            let v = signature_failure_payload(false, &unauthenticated_req(), &err(kind));
            let msg = v["error"].as_str().expect("error is a string");
            assert!(
                !msg.contains("signature verification failed"),
                "{kind:?} headlined as tampering: {msg}"
            );
            assert!(msg.contains(aegix_workflow_job_protocol::LIVENESS_REJECTION_MARKER));
            assert_eq!(v["reason_class"], "stale_timestamp");
        }
    }

    /// Diag ON (explicit operator opt-in): full MCP-1212 field dump.
    #[test]
    fn diag_enabled_carries_divergence_fields() {
        let payload = signature_failure_payload(
            true,
            &unauthenticated_req(),
            &err(VerifyFailureKind::BadSignature),
        );
        let diag = payload.get("diag").expect("diag block present");
        assert_eq!(diag["verify_error"], "hmac mismatch");
        assert_eq!(diag["module_uri"], "wasm://attacker-chosen/v1");
        assert!(diag.get("worker_input_hash").is_some());
    }
}

/// 2026-11-15: a dispatch that does not verify is answered with nothing a
/// controller will take. Each test builds the dispatch a controller really
/// made for a job (`live`), then the message a sender WITHOUT the controller's
/// key puts on the jobs subject for it, drives the worker's own verifier and
/// its one rule for the answer, signs whatever comes back exactly as the
/// intake does, and asks the receiver's two questions of it
/// (`JobResult::answers` for the live dispatch, the worker's signature).
#[cfg(test)]
mod refused_dispatch_tests {
    use super::signature_failure_payload_tests::unauthenticated_req;
    use super::*;
    use crate::job_result::pick_trusted_reply_topic;
    use crate::sign_job_result_for;
    use aegix_workflow_job_protocol::ResultAnswer;

    fn ring() -> aegix_dispatch_types::WorkerKeyRing {
        aegix_dispatch_types::WorkerKeyRing::single(aegix_dispatch_types::WorkerSharedKey::new(
            vec![0x24; 32],
        ))
    }

    /// The worker's verify settings on a fleet-key bus: no controller public
    /// key, legacy HMAC dispatches accepted.
    fn fleet_key_dvc() -> DispatchVerifyConfig {
        DispatchVerifyConfig {
            ed_keys: Vec::new(),
            accept_legacy_hmac: true,
        }
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs()
    }

    /// A dispatch the controller signed for a job that is now running: its
    /// second attempt, with a reply inbox.
    fn live_dispatch(ring: &aegix_dispatch_types::WorkerKeyRing) -> JobRequest {
        let mut live = unauthenticated_req();
        live.module_uri = "wasm://modules/send-report/v3".to_string();
        live.reply_topic = Some("_INBOX.controller.live-job".to_string());
        live.dispatch_attempt = 1;
        live.sign(ring.signing_key().as_bytes())
            .expect("the controller signs");
        live
    }

    /// What a sender with no key can write: everything about the live
    /// dispatch that is readable on the bus, under a signature it made up.
    fn forged_for(live: &JobRequest, nonce_secs: u64) -> JobRequest {
        let mut forged = live.clone();
        forged.job_nonce = format!("{nonce_secs}:{}", hex::encode([0x5a_u8; 16]));
        forged.signature = vec![0xaa; 32];
        forged
    }

    /// What the intake does with the rule's answer, and what a controller
    /// waiting on `live` makes of it: `None` when nothing is sent, otherwise
    /// `(taken as the live job's result, read as a job that never ran)`.
    fn what_a_controller_makes_of(
        answer: Option<JobResult>,
        sent: &JobRequest,
        live: &JobRequest,
        ring: &aegix_dispatch_types::WorkerKeyRing,
    ) -> Option<(bool, bool)> {
        answer.map(|mut result| {
            sign_job_result_for(&mut result, sent, ring).expect("the worker signs");
            let taken = result.answers(&live.dispatch_identity()) == ResultAnswer::ThisDispatch
                && result
                    .verify_no_replay_dispatch(ring, &[], 300, true)
                    .is_ok();
            (taken, result.is_pre_execution_rejection())
        })
    }

    #[test]
    fn a_forged_dispatch_for_a_running_job_is_answered_with_nothing() {
        let ring = ring();
        let dvc = fleet_key_dvc();
        let live = live_dispatch(&ring);
        let forged = forged_for(&live, now_secs());
        assert_eq!(
            pick_trusted_reply_topic(forged.job_id, forged.reply_topic.as_deref(), None).as_deref(),
            live.reply_topic.as_deref(),
            "vacuity guard: an answer would go to the live job's inbox"
        );

        let refusal = forged
            .verify_dispatch(&ring, &dvc.ed_keys, 300, dvc.accept_legacy_hmac)
            .expect_err("a made-up signature does not verify");
        assert_eq!(refusal.kind(), VerifyFailureKind::BadSignature);

        let answer = refused_dispatch_answer(&forged, &refusal, &ring, &dvc, false);
        assert_eq!(
            what_a_controller_makes_of(answer, &forged, &live, &ring),
            None,
            "a worker-signed failure for a forged dispatch is the running job's result \
             to the controller waiting on it: (taken, read as never ran)"
        );
    }

    /// Age is read before the signature, so a forged dispatch with an old
    /// timestamp is refused as `Stale`, the class a dispatcher answers by
    /// sending the job again. It gets nothing either.
    #[test]
    fn a_forged_dispatch_with_an_old_timestamp_is_answered_with_nothing() {
        let ring = ring();
        let dvc = fleet_key_dvc();
        let live = live_dispatch(&ring);
        for nonce_secs in [now_secs() - 900, now_secs() + 900] {
            let forged = forged_for(&live, nonce_secs);
            let refusal = forged
                .verify_dispatch(&ring, &dvc.ed_keys, 300, dvc.accept_legacy_hmac)
                .expect_err("refused on its time");
            assert!(
                refusal.is_liveness(),
                "vacuity guard: refused before its signature was read ({:?})",
                refusal.kind()
            );
            let answer = refused_dispatch_answer(&forged, &refusal, &ring, &dvc, false);
            assert_eq!(
                what_a_controller_makes_of(answer, &forged, &live, &ring),
                None,
                "a signed stale rejection for a forged dispatch has the dispatcher \
                 re-send a job that is still running: (taken, read as never ran)"
            );
        }
    }

    /// The controller's own bytes, sent a second time: refused by the nonce
    /// record, and not answered (the reply subject is the first sending's).
    #[test]
    fn a_replayed_dispatch_is_answered_with_nothing() {
        let ring = ring();
        let dvc = fleet_key_dvc();
        let live = live_dispatch(&ring);
        live.verify_dispatch(&ring, &dvc.ed_keys, 300, dvc.accept_legacy_hmac)
            .expect("the first sending verifies and runs");
        let refusal = live
            .verify_dispatch(&ring, &dvc.ed_keys, 300, dvc.accept_legacy_hmac)
            .expect_err("the second sending is a replay");
        assert_eq!(refusal.kind(), VerifyFailureKind::Replay);
        let answer = refused_dispatch_answer(&live, &refusal, &ring, &dvc, false);
        assert_eq!(
            what_a_controller_makes_of(answer, &live, &live, &ring),
            None
        );
    }

    /// The honest case that is kept: a dispatch the controller signed, refused
    /// for the time it arrived at, is told so, and the dispatcher reads the
    /// answer as a job that never ran. (The refusal is built here; that the
    /// signature check holds on bytes genuinely signed in the past is
    /// `the_signature_alone_tells_an_aged_dispatch_from_a_forged_one` in the
    /// protocol crate, which can back-date a signature.)
    #[test]
    fn the_controllers_own_dispatch_refused_on_its_time_is_still_told_so() {
        let ring = ring();
        let dvc = fleet_key_dvc();
        let live = live_dispatch(&ring);
        for kind in [VerifyFailureKind::Stale, VerifyFailureKind::ClockSkewAhead] {
            let refusal = VerifyError::from_parts(kind, "job_nonce is too old", Some(900));
            let answer = refused_dispatch_answer(&live, &refusal, &ring, &dvc, false);
            let payload = answer
                .as_ref()
                .expect("answered")
                .output_payload
                .value()
                .clone();
            assert_eq!(payload["reason_class"], "stale_timestamp");
            assert_eq!(
                what_a_controller_makes_of(answer, &live, &live, &ring),
                Some((true, true)),
                "{kind:?}: taken, and read as a job that never ran"
            );
        }
    }

    /// The whole table: only a refusal on TIME is ever answered, and only for
    /// a dispatch whose signature this worker can vouch for under its own
    /// scheme rules.
    #[test]
    fn only_a_refusal_on_time_of_a_dispatch_the_controller_signed_is_answered() {
        let ring = ring();
        let dvc = fleet_key_dvc();
        let live = live_dispatch(&ring);
        let forged = forged_for(&live, now_secs());
        // Signed, but under a key this worker does not hold.
        let other_ring = aegix_dispatch_types::WorkerKeyRing::single(
            aegix_dispatch_types::WorkerSharedKey::new(vec![0x99; 32]),
        );
        let other_key = live_dispatch(&other_ring);
        // Ed25519 is required here, so a fleet-key signature vouches for nothing.
        let ed_only = DispatchVerifyConfig {
            ed_keys: Vec::new(),
            accept_legacy_hmac: false,
        };
        for &kind in VerifyFailureKind::ALL {
            let refusal = VerifyError::from_parts(kind, "x", None);
            let answered = |req: &JobRequest, dvc: &DispatchVerifyConfig| {
                refused_dispatch_answer(req, &refusal, &ring, dvc, false).is_some()
            };
            assert_eq!(
                answered(&live, &dvc),
                kind.is_liveness(),
                "{kind:?}, signed"
            );
            assert!(!answered(&forged, &dvc), "{kind:?}, forged");
            assert!(!answered(&other_key, &dvc), "{kind:?}, another key");
            assert!(
                !answered(&live, &ed_only),
                "{kind:?}, a scheme this worker refuses"
            );
            // The field dump an operator can switch on changes nothing here.
            assert!(
                refused_dispatch_answer(&forged, &refusal, &ring, &dvc, true).is_none(),
                "{kind:?}, forged, diagnostic on"
            );
        }
    }
}
