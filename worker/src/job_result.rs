//! What the worker does with a job's result once it has one: the uniform
//! failed result, the timeout's wording, the size cap and its replacement,
//! which reply subject is trusted, and the publish with retry.
//!
//! Moved out of `main.rs` 2026-11-18, unchanged. `fuel_emission_pin.rs`
//! reads this file for the oversize replacement keeping its fuel.

use aegix_workflow_job_protocol::{JobResult, JobStatus};
use serde_json::json;

// ============================================================================
// RELIABILITY: Result Publishing with Retry
// ============================================================================

/// Publish a serialized payload to a NATS topic with exponential backoff retry.
async fn publish_bytes_with_retry(
    nc: &async_nats::Client,
    topic: String,
    payload: bytes::Bytes,
    max_attempts: u32,
) -> Result<(), String> {
    let mut backoff_ms = 100u64;
    for attempt in 0..max_attempts {
        // `publish()` only enqueues into the client's outbound buffer — it returns
        // Ok before the server has seen the message. Every caller of this helper is
        // delivering a signed JobResult / reply, and the controller's reply-inbox
        // await has no independent timeout floor, so a message dropped between the
        // local buffer and the broker (connection blip, buffer discard) is a SILENT
        // loss that hangs the execution until the 30-min stale sweep. `flush()`
        // drains the buffer to the server and awaits acceptance, turning that loss
        // into a retriable error instead of a false success. Cost is one round-trip
        // per job result (infrequent) — acceptable for delivery-critical results.
        let sent = match nc.publish(topic.clone(), payload.clone()).await {
            Ok(()) => nc.flush().await.map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        match sent {
            Ok(()) => {
                if attempt > 0 {
                    ::tracing::info!(topic, attempt, "Published (flushed) after retries");
                }
                return Ok(());
            }
            Err(e) => {
                if attempt < max_attempts - 1 {
                    ::tracing::warn!(
                        topic,
                        attempt = attempt + 1,
                        max_attempts,
                        error = %e,
                        "Failed to publish+flush, retrying"
                    );
                    tokio::time::sleep(tokio::time::Duration::from_millis(backoff_ms)).await;
                    backoff_ms = (backoff_ms * 2).min(5_000);
                } else {
                    return Err(format!(
                        "Failed to publish+flush to {} after {} attempts: {}",
                        topic, max_attempts, e
                    ));
                }
            }
        }
    }
    Err("Unexpected retry loop exit".to_string())
}

/// Publish result to NATS with exponential backoff retry.
///
/// Single-publish architecture (post-r301): the result is published to
/// EXACTLY ONE subject per call:
///
///  * `Some(reply)` (NATS request-reply): publish to the inbox the
///    requester is awaiting on. The requester (engine dispatcher,
///    webhook dispatcher, gmail/gcal handlers, etc.) verifies the
///    result inline and writes durable state through its own path.
///  * `None` (true fire-and-forget): publish to the global
///    `talos.results.{job_id}` topic so the controller's
///    `talos.results.*` audit subscriber can update `module_executions`
///    durably. There is no inline requester to consume the reply.
///
/// Pre-r301 the worker dual-published to BOTH the reply inbox AND
/// `talos.results.{job_id}` "for logging/audit". The controller had
/// two verifiers consuming these (the dispatcher + the audit
/// subscriber) and both ran `JobResult::verify()`, sharing the
/// process-local `JOB_NONCE_CACHE`. Once `WORKER_SHARED_KEY` started
/// loading reliably (post-r294 vault bootstrap fix), the second
/// verifier always hit "result_nonce already seen" and EVERY workflow
/// execution failed (r300 was the protocol-level mitigation;
/// single-publish is the source-level architectural fix).
///
/// Today, every NATS-dispatched path uses request-reply (engine,
/// webhooks, gmail, gcal); `run_sandbox` and `test_module` run WASM
/// in-process and don't hit NATS at all. Audit subscriber-only paths
/// don't currently exist, but the fire-and-forget code path is kept
/// for future use (e.g. async work-queue dispatches that don't await
/// the result inline).
/// H-1: Reconcile the wire-format NATS `msg.reply` (untrusted —
/// flows over an unsigned header an attacker can modify) with the
/// HMAC-bound `JobRequest::reply_topic` (signed, trustworthy when
/// present). Returns the subject the worker SHOULD publish the
/// signed JobResult to, or `None` if no reply path is available.
///
/// Decision matrix:
/// - (Some(signed), Some(wire)) where signed == wire → trust both;
///   return Some(signed). Hot path.
/// - (Some(signed), Some(wire)) where signed != wire → log a
///   SECURITY-level warning AND publish to the SIGNED value. The
///   wire value is attacker-controllable; the signed value is the
///   one the controller committed to.
/// - (Some(signed), None) → publish to the signed value. Indicates
///   the wire header was stripped in transit (rare; treat the
///   signed value as authoritative).
/// - (None, Some(wire)) → IGNORE the wire value and return `None`
///   (2026-09-10). Until then this arm trusted the unsigned header as a
///   backward-compat path; the last controller dispatcher that relied
///   on it (the live webhook path) now signs its inbox, so an unsigned
///   header with no signed twin is treated exactly like no header.
/// - (None, None) → no reply path; the worker publishes to the
///   fire-and-forget `talos.results.{job_id}` topic.
///
/// Pure function so the policy is unit-testable without a NATS
/// broker. The `job_id` parameter is for log correlation only.
pub(crate) fn pick_trusted_reply_topic(
    job_id: uuid::Uuid,
    signed: Option<&str>,
    wire: Option<&str>,
) -> Option<String> {
    match (signed, wire) {
        (Some(s), Some(w)) if s == w => Some(s.to_string()),
        (Some(s), Some(w)) => {
            ::tracing::error!(
                job_id = %job_id,
                signed_reply = %s,
                wire_reply = %w,
                "SECURITY: H-1 reply_topic mismatch — wire msg.reply does not match \
                 HMAC-bound JobRequest.reply_topic. Publishing to the SIGNED value; \
                 wire value is likely attacker-tampered."
            );
            Some(s.to_string())
        }
        (Some(s), None) => {
            ::tracing::warn!(
                job_id = %job_id,
                signed_reply = %s,
                "H-1: msg.reply stripped in transit; publishing to HMAC-bound reply_topic"
            );
            Some(s.to_string())
        }
        (None, Some(w)) => {
            // 2026-09-10 review: this arm used to return `Some(w)` — the one
            // place the worker still honoured an UNSIGNED wire reply header.
            // With the webhook dispatcher now signing its inbox (H-1 parity),
            // no controller path in this workspace sends `reply_topic: None`
            // AND awaits a wire reply; the remaining `None` senders
            // (gmail/gcal/gcp push, DLQ replay) are fire-and-forget and read
            // `talos.results.<job_id>`. A wire header with no signed twin is
            // therefore either a stale controller or a bus participant
            // steering a replayed job's output to itself — the result goes
            // to the audit topic, never to the header.
            ::tracing::debug!(
                job_id = %job_id,
                wire_reply_len = w.len(),
                "reply_topic unsigned (None) but a wire msg.reply was present — \
                 ignoring the wire header; result goes to talos.results.<job_id>"
            );
            None
        }
        (None, None) => {
            // L-12 (2026-05-22): the result will be published to the
            // global `talos.results.{job_id}` topic by the caller
            // (publish_result_with_retry). That path is intended for the
            // controller's audit subscriber — but if neither the
            // signed `reply_topic` NOR the wire `msg.reply` is set AND
            // the operator hasn't configured an audit subscriber, the
            // result effectively disappears (broker delivers to zero
            // subscribers, no error returned). Emit a structured event
            // here so the condition is visible in dashboards and a
            // misconfigured dispatch path doesn't degrade silently.
            //
            // `target: "talos_worker_metrics"` lets operators alert via
            // a single filter; `event_kind` is the stable identifier.
            ::tracing::warn!(
                target: "talos_worker_metrics",
                job_id = %job_id,
                event_kind = "job_result_no_reply",
                "neither signed reply_topic nor wire msg.reply set — result \
                 will publish to the global audit topic only. If no audit \
                 subscriber is configured this result is lost."
            );
            None
        }
    }
}

/// M-7: Hard ceiling on the serialized JobResult bytes the worker
/// will attempt to publish to NATS. Without a pre-publish cap, an
/// oversized `output_payload` (legitimately large or hostile) silently
/// fails at the broker layer (default NATS `max_payload` is 1 MiB)
/// and the controller times out waiting for a reply that will never
/// arrive. The worker has already done the work; the failure is in
/// the last-mile transport with no signal to either side.
///
/// 4 MiB matches the typical `max_payload` we configure on the NATS
/// JetStream servers in production (it can be bumped via NATS config).
/// `WORKER_MAX_JOB_RESULT_BYTES=0` falls back to the default; an
/// explicit positive value overrides.
pub(crate) const DEFAULT_MAX_JOB_RESULT_BYTES: usize = 4 * 1024 * 1024;

pub(crate) fn max_job_result_bytes() -> usize {
    std::env::var("WORKER_MAX_JOB_RESULT_BYTES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|v| *v > 0)
        .unwrap_or(DEFAULT_MAX_JOB_RESULT_BYTES)
}

/// M-7: Replace an oversized `JobResult` with a small "output too
/// large" error result that still signs and publishes successfully.
/// Pure data transform so the policy is unit-testable.
///
/// Preserves `job_id`, `status` (downgraded to `Failed`), and
/// `execution_time_ms` so callers can still correlate; drops the
/// oversized `output_payload` and `logs` (replaces with a single
/// diagnostic line). The new result MUST be re-signed by the caller
/// before publishing — the signature carries `output_hash` so it
/// would be invalid otherwise.
pub(crate) fn truncate_oversized_job_result(
    result: &JobResult,
    serialized_len: usize,
    cap: usize,
) -> JobResult {
    JobResult {
        // B-9: the replacement answers the same dispatch the original did.
        dispatch_attempt: result.dispatch_attempt,
        workflow_execution_id: result.workflow_execution_id,
        // Preserve the token accounting — the usage was real even though
        // the oversized output is dropped, and the entry vec is small
        // (capped at MAX_LLM_USAGE_ENTRIES) so it can't re-breach the cap.
        llm_usage: result.llm_usage.clone(),
        crypto_scheme: 0,
        job_id: result.job_id,
        status: JobStatus::Failed,
        output_payload: serde_json::json!({
            "error": "job_result_too_large",
            "diag": {
                "serialized_bytes": serialized_len,
                "cap_bytes": cap,
                "note": "Worker dropped the original output_payload to keep \
                         under WORKER_MAX_JOB_RESULT_BYTES. Reduce module \
                         output size or raise the cap if this is legitimate."
            }
        })
        .into(),
        logs: vec![format!(
            "[host] dropped {serialized_len}-byte result (cap {cap})"
        )],
        execution_time_ms: result.execution_time_ms,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        // Preserve the fuel for the same reason as the token accounting: the
        // module ran and spent it, and dropping it here would hide exactly
        // the runs large enough to breach the cap from the fuel budget.
        fuel: result.fuel,
    }
}

pub(crate) async fn publish_result_with_retry(
    nc: &async_nats::Client,
    result: &JobResult,
    max_attempts: u32,
    reply_topic: Option<String>,
    shared_key: &aegix_dispatch_types::WorkerKeyRing,
) -> Result<(), String> {
    // Serialize once so we can size-check before deciding how to
    // publish. serde_json::to_vec on a JobResult is cheap (single
    // pass) and we'd serialize anyway downstream.
    let serialized = match serde_json::to_vec(&result) {
        Ok(v) => v,
        Err(e) => {
            return Err(format!("Failed to serialize result: {}", e));
        }
    };

    let cap = max_job_result_bytes();
    let payload = if serialized.len() > cap {
        // M-7: degrade to a "result too large" error message so the
        // controller gets a signed Failed status instead of a silent
        // broker rejection + timeout. Sign the replacement; bail with
        // a Err only if signing itself fails (which would indicate the
        // shared key is mis-configured and is already loud upstream).
        ::tracing::error!(
            job_id = %result.job_id,
            serialized_bytes = serialized.len(),
            cap_bytes = cap,
            "JobResult exceeds NATS publish cap — substituting a small Failed result so the controller doesn't time out"
        );
        let mut replacement = truncate_oversized_job_result(result, serialized.len(), cap);
        // L-11: bind the worker's identity into the signature so the
        // controller's audit log records which pod emitted the
        // truncated-replacement result. RFC 0010 P2: prefer the per-worker
        // Ed25519 key when configured, else legacy HMAC. See `sign_job_result`.
        if let Err(e) = crate::sign_job_result(&mut replacement, shared_key) {
            return Err(format!("Failed to sign oversized-result replacement: {e}"));
        }
        match serde_json::to_vec(&replacement) {
            Ok(v) => bytes::Bytes::from(v),
            Err(e) => return Err(format!("Failed to serialize replacement: {e}")),
        }
    } else {
        bytes::Bytes::from(serialized)
    };

    if let Some(reply) = reply_topic {
        publish_bytes_with_retry(nc, reply, payload, max_attempts).await
    } else {
        let result_topic = aegix_workflow_job_protocol::subjects::results_for(result.job_id);
        publish_bytes_with_retry(nc, result_topic, payload, max_attempts).await
    }
}

/// Build the uniform "failed" `JobResult` shape used by every
/// pre-dispatch rejection path in [`crate::execute_job`] (deadline, secret
/// decryption, module acquisition, hash checks): `status: Failed`,
/// `output_payload: {"error": msg}`, elapsed time from `start`, and
/// empty logs/signature/nonce/worker-id (the publish path signs it).
pub(crate) fn failed_result(
    job_id: uuid::Uuid,
    start: &std::time::Instant,
    msg: &str,
) -> JobResult {
    JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id,
        status: JobStatus::Failed,
        output_payload: json!({ "error": msg }).into(),
        logs: vec![],
        execution_time_ms: start.elapsed().as_millis() as u64,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    }
}

/// Build the operator-facing message for the per-job execution timeout.
///
/// **Takes the same `Duration` that armed `tokio::time::timeout`**, so the
/// reported number cannot disagree with the number that was enforced. That is
/// the point of the function: until 2026-08-25 the timeout arm built the string
/// `"execution timed out after 30 seconds"` as a HARDCODED literal while
/// `job_timeout` was per-node and variable (`req.timeout_ms`, else
/// `WASM_EXECUTION_TIMEOUT_SECS`, default **120**). No node on the reference
/// deployment had ever been given 30 s: fourteen recorded timeouts ran with an
/// enforced 110 s (×4) or 120 s (×10), so the message understated the real
/// budget by ~4× in 14 of 14 cases and led an operator to propose raising a
/// "30 s default" that does not exist.
///
/// `source` names WHERE the limit came from so the operator knows which knob to
/// turn; it is one of two fixed strings, never a request field. The message
/// carries no payload, secret, host or worker id — it reaches
/// `workflow_executions.error_message`.
///
/// **The attribution is deliberately hedged, and that is not sloppiness.** The
/// controller resolves `node_timeouts[node].unwrap_or(*DEFAULT_NODE_TIMEOUT_SECS)`
/// (`engine_dispatch_single.rs`) and sends only the RESULT, so a non-zero
/// `req.timeout_ms` is indistinguishable here between "the node declared
/// `timeout_secs`" and "the node declared nothing and the controller applied its
/// own default". Asserting the former would be a fresh instance of the very
/// defect this function exists to fix: right number, wrong attribution, operator
/// sent to edit a field that is not set.
///
/// Keeps the substring `timed out`, which
/// `aegix_retry_intelligence::classify_error` matches to produce the `timeout`
/// class.
pub(crate) fn timeout_error_message(
    job_timeout: std::time::Duration,
    request_supplied: bool,
) -> String {
    let ms = job_timeout.as_millis();
    let source = if request_supplied {
        "enforced limit from job timeout_ms: node timeout_secs, else controller default"
    } else {
        "enforced limit from worker default WASM_EXECUTION_TIMEOUT_SECS"
    };
    if ms.is_multiple_of(1000) {
        format!(
            "execution timed out after {} seconds ({})",
            ms / 1000,
            source
        )
    } else {
        format!("execution timed out after {ms} ms ({source})")
    }
}

#[cfg(test)]
mod timeout_message_tests {
    use super::timeout_error_message;
    use std::time::Duration;

    /// The headline regression: a node with a NON-30s budget must report its
    /// OWN number. 110 s is not a hypothetical — it is the live
    /// budget of an extract node on the reference deployment, which produced
    /// four of the fourteen recorded timeouts while the message said
    /// "30 seconds".
    #[test]
    fn node_supplied_timeout_reports_its_own_value() {
        let msg = timeout_error_message(Duration::from_secs(110), true);
        assert!(
            msg.contains("110 seconds"),
            "must report the enforced 110s, got: {msg}"
        );
        assert!(
            !msg.contains("30 seconds"),
            "must not report the retired hardcoded literal, got: {msg}"
        );
        assert!(
            msg.contains("job timeout_ms"),
            "must name where the limit arrived from, got: {msg}"
        );
        // Hedged on purpose — see `timeout_error_message`. The worker cannot
        // distinguish a node-declared `timeout_secs` from the controller's own
        // default, so it must not claim either one.
        assert!(
            msg.contains("else controller default"),
            "attribution must stay hedged, got: {msg}"
        );
    }

    /// The worker fallback is 120 s (`WASM_EXECUTION_TIMEOUT_SECS`), which is
    /// what ten of the fourteen recorded timeouts actually enforced.
    #[test]
    fn worker_fallback_timeout_reports_120_and_names_the_env_var() {
        let msg = timeout_error_message(Duration::from_secs(120), false);
        assert!(msg.contains("120 seconds"), "got: {msg}");
        assert!(
            msg.contains("WASM_EXECUTION_TIMEOUT_SECS"),
            "must name the env var an operator would change, got: {msg}"
        );
        assert!(!msg.contains("job timeout_ms"), "got: {msg}");
    }

    /// A 30 s budget still says 30 — the fix is not "never print 30", it is
    /// "print what was enforced". This is the case the old literal got right
    /// by accident, and it must keep working.
    #[test]
    fn thirty_second_budget_still_reports_thirty() {
        let msg = timeout_error_message(Duration::from_secs(30), true);
        assert!(msg.contains("30 seconds"), "got: {msg}");
    }

    /// `req.timeout_ms` is milliseconds, so a sub-second-precision budget must
    /// not be silently truncated to a wrong whole number of seconds (1 500 ms
    /// reported as "1 seconds" would be a smaller instance of the same class).
    #[test]
    fn sub_second_precision_is_reported_in_ms_not_truncated() {
        let msg = timeout_error_message(Duration::from_millis(1_500), true);
        assert!(msg.contains("1500 ms"), "got: {msg}");
        assert!(!msg.contains("1 seconds"), "got: {msg}");
    }

    /// Retry-classification coupling. `aegix_retry_intelligence::classify_error`
    /// buckets this message by the substring `timed out` (it matches BOTH
    /// "timed out" and "timeout"; see CLAUDE.md) and `timeout` is transient, so
    /// a node with `retry_count > 0` retries. Rewording the message without
    /// this substring would silently reclassify every node timeout as
    /// `unknown` (non-transient) — the exact "classification derived from
    /// prose" hazard `classify_verify_failure` was rewritten to escape.
    /// Asserted here rather than in the classifier crate because `worker` does
    /// not depend on `aegix-retry-intelligence`; this guards the token, not the
    /// classifier's own behaviour.
    #[test]
    fn message_keeps_the_token_the_retry_classifier_matches() {
        for (d, node) in [
            (Duration::from_secs(110), true),
            (Duration::from_secs(120), false),
            (Duration::from_millis(1_500), true),
        ] {
            let msg = timeout_error_message(d, node);
            assert!(
                msg.to_lowercase().contains("timed out"),
                "classifier token missing, got: {msg}"
            );
        }
    }
}
