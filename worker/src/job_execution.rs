//! One job, from its dispatch to its result: `execute_job` verifies the
//! dispatch and refuses one that does not verify, and `run_verified_job`
//! opens its secrets, fetches and attests its module, runs it and shapes
//! the result.
//!
//! Moved out of `main.rs` 2026-11-18, unchanged. The textual pins beside
//! this file (`retry_policy_pin`, `fuel_emission_pin`, `inference_wait_pin`,
//! `rehearsal_pin`, `sealing_refusal_pin`, `refused_dispatch_pin`) read it
//! together with `main.rs`. `run_verified_job` stays the last item here and
//! stays private: two of them read a function's body up to the next
//! top-level `fn`.

use crate::job_result::{failed_result, timeout_error_message};
use crate::{
    clamp_job_fuel, dispatch_verify_config, job_world_hint, unattested_wasm_blocked,
    worker_max_job_fuel, worker_result_signing_key, worker_sealing_required, NatsProgressNotifier,
};
use aegix_workflow_job_protocol::{JobRequest, JobResult, JobStatus, VerifyError};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use worker::error_sanitize::sanitize_error_message;
use worker::job_span::JobSpan;
use worker::module_fetcher::{self, FetchedModule};
use worker::runtime::{AegixRuntime, RetryPolicy, SecurityPolicy};
use worker::secret_claim;
use worker::worker_identity;

/// Verify a dispatch and, when it verifies, execute its Wasm module with
/// observability.
///
/// * Verifies the dispatch signature (Ed25519 or legacy HMAC) before executing.
///   A dispatch that does not verify is `Err`: NO result exists for it, and
///   whether anything at all is sent in answer is [`refused_dispatch_answer`]'s
///   to decide, not this function's.
/// * Decrypts secrets from `req.encrypted_secrets` using the shared key.
/// * Passes decrypted secrets to the runtime so WASM modules can access them
///   via the `secrets::get-secret` host function.
#[::tracing::instrument(name = "job-execution", skip_all)]
pub(crate) async fn execute_job(
    cx: &opentelemetry::Context,
    req: JobRequest,
    runtime: Arc<AegixRuntime>,
    shared_key: aegix_dispatch_types::WorkerKeyRing,
    // RFC 0010 P3 (D3b): NATS client for the secret-claim round-trip when a
    // dispatch arrives with `sealing == SEALING_CLAIM_ECIES`.
    nc: &async_nats::Client,
) -> Result<JobResult, VerifyError> {
    let start = std::time::Instant::now();

    // The `#[instrument]` span above is THE job span; wrap it and link it to the
    // propagated controller trace context. All `_span.*` calls below set
    // attributes / events / status on it, exported via the otel bridge layer.
    let mut _span = JobSpan::current_with_parent(cx);
    _span.set_attribute("job_id", &req.job_id.to_string());
    _span.set_attribute("module_uri", &req.module_uri);

    // SECURITY: verify the dispatch signature + nonce freshness (300 s window).
    // RFC 0010 P1: `verify_dispatch` routes on the request's `crypto_scheme` —
    // Ed25519 against the controller public key(s), or legacy HMAC against the
    // WORKER_SHARED_KEY ring (accepted while `accept_legacy_hmac`, refused once
    // AEGIX_DISPATCH_REQUIRE_ED25519 flips it off). Ring-aware on the HMAC side
    // so a rolling WORKER_SHARED_KEY rotation doesn't reject controller-signed
    // jobs.
    let dvc = dispatch_verify_config();
    if let Err(e) = req.verify_dispatch(&shared_key, &dvc.ed_keys, 300, dvc.accept_legacy_hmac) {
        // The stall is symmetric: the SAME host suspend that ages out a result
        // on the controller ages out a dispatch here. Report which it was.
        let headline = aegix_workflow_job_protocol::describe_verify_failure("Job dispatch", &e);
        if e.is_liveness() {
            ::tracing::warn!(
                target: "talos_security",
                job_id = %req.job_id,
                failure_kind = e.kind().label(),
                age_secs = e.age_secs(),
                "{headline}"
            );
        } else {
            ::tracing::error!(
                target: "talos_security",
                job_id = %req.job_id,
                failure_kind = e.kind().label(),
                "{headline}"
            );
        }
        _span.set_attribute("error", e.kind().label());
        _span.end_error(&headline);
        return Err(e);
    }

    Ok(run_verified_job(_span, start, req, runtime, shared_key, nc).await)
}

/// The rest of [`execute_job`]: everything that happens to a dispatch AFTER
/// it verified. Called from there and nowhere else.
async fn run_verified_job(
    mut _span: JobSpan,
    start: std::time::Instant,
    req: JobRequest,
    runtime: Arc<AegixRuntime>,
    shared_key: aegix_dispatch_types::WorkerKeyRing,
    nc: &async_nats::Client,
) -> JobResult {
    let dvc = dispatch_verify_config();

    // DEADLINE CHECK: Reject jobs whose deadline has already passed.
    if req.deadline_unix_secs > 0 {
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now_secs > req.deadline_unix_secs {
            _span.set_attribute("error", "deadline_expired");
            _span.end_error("Job deadline expired before execution started");
            return failed_result(req.job_id, &start, "job deadline expired");
        }
    }

    // RFC 0010 P3 (D3b): downgrade guard. Under `AEGIX_ENVELOPE_SEALING=required`
    // the worker refuses a legacy inline dispatch that would DECRYPT a WSK
    // envelope — the enforcement point that stops an on-wire downgrade from
    // forcing the fleet-wide key back into use. A `sealing == 0` dispatch with an
    // EMPTY `encrypted_secrets` decrypts nothing (a no-secret node), so it is
    // allowed even under `required` — otherwise every secretless node (transforms,
    // routers, …) would break. Only a non-empty WSK ciphertext under `required` is
    // a refused downgrade. Under `off`/`audit` both schemes are handled.
    if worker::secret_claim::inline_envelope_refused(worker_sealing_required(), &req) {
        ::tracing::error!(
            target: "talos_security",
            job_id = %req.job_id,
            "AEGIX_ENVELOPE_SEALING=required but dispatch carries a sealing=0 WSK envelope — refusing"
        );
        _span.end_error("envelope sealing required; inline dispatch refused");
        return failed_result(
            req.job_id,
            &start,
            "envelope sealing required; inline dispatch refused",
        );
    }

    // SECURITY: obtain the job's secrets.
    // - `sealing == 1` (P3): claim them via a signed `SecretClaim` to the
    //   controller's `claim_inbox`; the controller seals to this worker's fresh
    //   ephemeral key and the reply opens under it (forward secrecy). Fail-closed
    //   on any claim/verify/open error — never run secretless.
    // - `sealing == 0` (legacy): decrypt the inline WSK envelope. L-1
    //   (2026-05-22): AAD = workflow_execution_id binds the AES-GCM tag to this
    //   execution (already HMAC-bound in the signing payload), so a transposed
    //   ciphertext fails the tag check here.
    let secrets: aegix_workflow_job_protocol::SecretMap = if req.sealing
        == aegix_workflow_job_protocol::SEALING_CLAIM_ECIES
    {
        let Some(signing_key) = worker_result_signing_key() else {
            ::tracing::error!(
                target: "talos_security",
                job_id = %req.job_id,
                "sealing=1 dispatch requires AEGIX_WORKER_SIGNING_KEY to sign the claim"
            );
            _span.end_error("sealing=1 requires a worker signing key");
            return failed_result(
                req.job_id,
                &start,
                "sealing=1 dispatch requires a worker signing key",
            );
        };
        match secret_claim::claim_secrets(
            nc,
            req.job_id,
            req.dispatch_attempt,
            req.claim_inbox.as_deref(),
            worker_identity(),
            signing_key,
            &dvc.ed_keys,
        )
        .await
        {
            Ok(map) => map,
            Err(e) => {
                ::tracing::error!(
                    target: "talos_security",
                    job_id = %req.job_id,
                    error = %e,
                    "RFC 0010 P3 secret claim failed"
                );
                _span.end_error("secret claim failed");
                return failed_result(req.job_id, &start, "failed to obtain sealed secrets");
            }
        }
    } else if req.encrypted_secrets.is_empty() {
        HashMap::new()
    } else {
        match req
            .encrypted_secrets
            .decrypt_with_ring(&shared_key, req.workflow_execution_id.as_bytes())
        {
            Ok(s) => s,
            Err(e) => {
                ::tracing::error!(job_id = %req.job_id, error = %e, "Failed to decrypt job secrets");
                _span.end_error("Secret decryption failed");

                return failed_result(req.job_id, &start, "failed to decrypt job secrets");
            }
        }
    };

    // Load the Wasm module bytes — acquisition (inline bytes / OCI pull
    // with Sigstore + layer-digest verification / Redis cache /
    // filesystem fallback) lives in `worker::module_fetcher::fetch`,
    // which also documents the attestation model. On failure the
    // FetchError message is byte-for-byte the string the inline code
    // previously placed in the failed result and the span status.
    let FetchedModule {
        bytes: wasm_bytes,
        attested_in_this_run: bytes_attested_in_this_run,
    } = match module_fetcher::fetch(&req, &runtime, &mut _span).await {
        Ok(fetched) => fetched,
        Err(e) => {
            _span.end_error(&e.message);
            return failed_result(req.job_id, &start, &e.message);
        }
    };

    // SECURITY: Verify WASM content hash when inline bytes were not provided.
    // `req.expected_wasm_hash` is set by the controller from `wasm_modules.content_hash`
    // (the SHA-256 recorded at compile time) and covered by the HMAC signing payload,
    // so an attacker who compromises the storage layer (Redis, OCI, filesystem) cannot
    // substitute malicious bytes without the mismatch being detected here.
    //
    // When `wasm_bytes` was provided inline the HMAC already covers sha256(bytes) — no
    // additional check needed.  We only verify when the worker loaded bytes from a URI.
    if req.wasm_bytes.is_none() {
        if let Some(ref expected) = req.expected_wasm_hash {
            use sha2::{Digest, Sha256};
            let actual = hex::encode(Sha256::digest(&wasm_bytes));
            if actual != *expected {
                ::tracing::error!(
                    job_id = %req.job_id,
                    module_uri = %req.module_uri,
                    expected_hash = %expected,
                    actual_hash = %actual,
                    "SECURITY: WASM content hash mismatch — possible storage tampering, refusing execution"
                );
                _span.end_error("wasm_hash_mismatch");
                return failed_result(
                    req.job_id,
                    &start,
                    "WASM integrity check failed: content hash mismatch",
                );
            }
            ::tracing::debug!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                hash = %actual,
                "WASM content hash verified"
            );
        } else if !bytes_attested_in_this_run {
            // No hash commitment from the controller AND the bytes did not
            // pass Sigstore + layer-digest checks in this run — i.e. they
            // came from an OCI cache fallback, `redis:wasm:` fetch, or
            // filesystem load with nothing cryptographically tying them
            // to the controller's recorded `wasm_modules.content_hash`.
            //
            // A Redis-write attacker (compromised pod, shared infra) could
            // substitute arbitrary WASM into the cache — without
            // `expected_wasm_hash` we have no evidence to detect it.
            //
            // M-5: gate this fallback on a POSITIVE opt-in
            // (`AEGIX_ALLOW_UNATTESTED_WASM=1`) instead of "if not
            // production". Pre-fix a dev image accidentally promoted to
            // production, or a container with `RUST_ENV` unset, would
            // silently accept arbitrary cache bytes. The new policy is
            // fail-closed by default: misconfiguration refuses to run.
            // Operators who need the dev shortcut must set the env var
            // explicitly. The profile gate stays as belt-and-braces
            // (2026-10-29: `hardened` never accepts unattested bytes
            // regardless of the override, and refuses the override at boot).
            let allow_unattested =
                aegix_deploy_posture::bool_env_or_default("AEGIX_ALLOW_UNATTESTED_WASM", false);
            let block_unattested = unattested_wasm_blocked(
                aegix_deploy_posture::security_profile::profile(),
                allow_unattested,
            );
            if block_unattested {
                ::tracing::error!(
                    job_id = %req.job_id,
                    module_uri = %req.module_uri,
                    "SECURITY: refusing to execute WASM loaded from unverified storage \
                     (cache/redis/filesystem) without expected_wasm_hash. Either supply \
                     a hash or load from a path that Sigstore-verifies in this run"
                );
                _span.end_error("unattested_wasm_no_hash");
                return failed_result(
                    req.job_id,
                    &start,
                    "WASM integrity check failed: no hash and no in-run attestation",
                );
            }
            ::tracing::warn!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                "WASM loaded from unattested storage without expected_wasm_hash \
                 (AEGIX_ALLOW_UNATTESTED_WASM=1 set — would fail closed without this override). \
                 Always supply expected_wasm_hash or attest in-run via Sigstore in production."
            );
        } else {
            // Bytes were attested in this run via Sigstore + digest checks.
            // No expected_wasm_hash supplied is OK — the in-run attestation
            // is the trust root.
            ::tracing::debug!(
                job_id = %req.job_id,
                module_uri = %req.module_uri,
                "WASM attested via in-run Sigstore + layer-digest verification"
            );
        }
    }

    // Build execution context for automatic logging to database
    _span.add_event("executing_wasm");
    let execution_context = Some((
        req.workflow_execution_id.to_string(), // workflow_id
        req.job_id.to_string(),                // execution_id (for NATS logging)
        req.module_uri.clone(),                // module_id
    ));

    // Build per-module security policy from the job request.
    let security_policy = SecurityPolicy {
        allowed_secrets: req.allowed_secrets.clone(),
        allowed_sql_operations: req.allowed_sql_operations.clone(),
        allow_tier2_exposure: req.allow_tier2_exposure,
        integration_name: req.integration_name.clone(),
        // Opt-in idempotency (Task 3): HMAC-bound on the JobRequest; the HTTP
        // host emits it as an `Idempotency-Key` header on mutating sends.
        idempotency_key: req.idempotency_key.clone(),
        // Signed with the job, and consulted only under `req.dry_run`.
        read_only_posts: req.read_only_posts.clone(),
        // Recorded HTTP answers are a controller-side rehearsal feature
        // (`test_module`). A dispatched job always makes its real requests;
        // nothing on the wire can ask otherwise. Pinned by `rehearsal_pin.rs`.
        http_replay: None,
        http_capture: None,
        fuel_profile: None,
        // A dispatched job's memory calls are the run's own: never a
        // rehearsal (`memory_rehearsal` is set only by `test_module`).
        memory_rehearsal: None,
    };

    // Parse the capability world hint from the controller.  When present and non-Unknown,
    // the runtime uses it instead of re-inspecting the WASM binary.  This is critical for
    // sandbox modules whose Wizer-snapshotted binary may have lost embedded WIT world-name
    // strings that inspect_component relies on.
    //
    // A signed hint naming no world this worker knows is a REFUSAL, not "no
    // hint" (security review 2026-10-15, E2-3): until then it fell back to
    // the binary's inspected world — the pre-G-1 behaviour, wider than the
    // world the controller checked whenever the inspection is wider.
    let capability_world_hint = match job_world_hint(req.capability_world.as_deref()) {
        Ok(hint) => hint,
        Err(()) => {
            ::tracing::warn!(
                target: "talos_security",
                job_id = %req.job_id,
                "capability-world-unrecognised: the job's signed world hint names no world \
                 this worker knows; refused before instantiation"
            );
            return failed_result(
                req.job_id,
                &start,
                "capability-world-unrecognised: the job names a capability world this worker \
                 does not know",
            );
        }
    };

    // Honor the controller-supplied `timeout_ms` from the job request. The
    // controller has already sourced it from the node's `timeout_secs` (or the
    // per-env `WASM_EXECUTION_TIMEOUT_SECS` default). Fallback: use the same
    // `WASM_EXECUTION_TIMEOUT_SECS` env var (120s default) when the request
    // didn't specify. That figure read "60s default" until 2026-08-25, while
    // the lockstep note four lines below this one said 120 and the code says
    // 120 — one comment block contradicting itself. Same
    // stale-literal-beside-a-variable shape as the hardcoded "30 seconds"
    // message that `timeout_error_message` exists to fix, which is why it was
    // corrected in the same change rather than left as a sibling instance.
    // Previously both timeouts were hardcoded 30s, which
    // silently capped agent-node modules calling `llm::complete` even when
    // the author set `timeout_secs: 120` on the node.
    // MCP-642 (2026-05-13): if WASM_EXECUTION_TIMEOUT_SECS=0 AND the
    // caller didn't specify req.timeout_ms, the job timeout below
    // becomes 0ms → every job times out instantly. Same MCP-639 class.
    // 120s default kept in lockstep with DEFAULT_NODE_TIMEOUT_SECS
    // (aegix-workflow-engine) and get_wasm_config so the worker's fallback job
    // timeout matches the controller's reply-wait and the operator-reported value.
    let worker_fallback_secs: u64 =
        worker::runtime::nonzero_env_or_default("WASM_EXECUTION_TIMEOUT_SECS", 120);
    let job_timeout_ms: u64 = if req.timeout_ms > 0 {
        req.timeout_ms
    } else {
        worker_fallback_secs.saturating_mul(1000)
    };
    let job_timeout = std::time::Duration::from_millis(job_timeout_ms);
    // R2 token ledger: worker-owned accumulator shared with the job's
    // AegixContext; drained into the signed JobResult on EVERY branch below
    // (success, failure, timeout) — tokens spent before a trap are spent.
    let llm_usage_acc = worker::context::LlmUsageAcc::default();
    // Out-of-band fuel: the runtime adds every attempt's measured fuel here,
    // success or failure; drained into the signed JobResult below so the
    // controller's hourly fuel budget sees failed, fuel-exhausted and
    // non-object attempts too. A result-cache hit ran nothing and reports none.
    let fuel_acc: worker::context::FuelAcc = std::sync::Arc::new(std::sync::Mutex::new(None));
    // RFC 0014 P2: this job's waiting-for-the-local-inference-slot account.
    // Every deadline below — this outer one, the runtime's inner one and the
    // epoch wall-clock bound — stands still while the job queues for the slot,
    // and the notifier tells the dispatcher so its attempt window does too.
    // Only a job with a SIGNED reply inbox has a dispatcher waiting on it; a
    // fire-and-forget dispatch gets the ledger without a notifier.
    let inference_wait = std::sync::Arc::new(worker::inference_wait::InferenceWaitLedger::new(
        req.reply_topic.as_deref().map(|inbox| {
            std::sync::Arc::new(NatsProgressNotifier {
                nc: nc.clone(),
                subject: aegix_workflow_job_protocol::subjects::job_progress_for(inbox),
                job_id: req.job_id,
                dispatch_attempt: req.dispatch_attempt,
                shared_key: shared_key.clone(),
            }) as std::sync::Arc<dyn worker::inference_wait::WaitNotifier>
        }),
    ));
    match worker::inference_wait::with_pausable_deadline(
        job_timeout,
        Some(&inference_wait),
        runtime.execute_job_with_full_features(aegix_wasm_host::runtime::JobRun {
            wasm_bytes: &wasm_bytes,
            // The guest sees the PARSED payload; the signature (already
            // verified above) covers the raw wire text, which stays with the
            // `SignedJson` on `req`.
            input: req.input_payload.value().clone(),
            allowed_hosts: req.allowed_hosts.clone(),
            allowed_methods: req.allowed_methods.clone(),
            secrets,
            max_memory_mb: 128,
            // Signature-bound (2026-09-10) AND clamped to this worker's own
            // ceiling — see `clamp_job_fuel` for why both.
            max_fuel_override: clamp_job_fuel(req.job_id, req.max_fuel, worker_max_job_fuel()),
            timeout: job_timeout, // per-job timeout — matches the outer tokio::time::timeout
            execution_context,
            // NO in-process retry. The controller that dispatched this job owns
            // its retries and decides them method-aware (resolved `max_retries`,
            // transient classifier, `retry_condition`), re-dispatching with a
            // bumped signed `dispatch_attempt`. A retry here re-ran the WHOLE
            // module on guest-influenced "timeout"/"503" text, blind to
            // `allowed_methods` — a POST node the controller allowed zero
            // retries still ran up to four times. Pinned by
            // `retry_policy_pin.rs`.
            retry_policy: RetryPolicy::controller_dispatched(),
            security_policy,
            capability_world_hint,
            dry_run: req.dry_run,
            actor_id: req.actor_id,
            user_id: req.user_id,
            max_llm_tier: req.max_llm_tier,
            max_write_ceiling: req.max_write_ceiling,
            // The signed override, carried from the wire onto the context.
            // Without this the field arrives and is dropped — which is
            // exactly what #941 shipped, making the whole axis a no-op.
            http_verb_ceiling: req.http_verb_ceiling,
            egress_scope: req.egress_scope,
            // Which controller DISPATCH of this job we are running. Read from
            // the HMAC-bound `JobRequest` field verified above, never inferred:
            // this process is credential-free and cannot look at what a
            // previous dispatch of the same `job_id` wrote, so it is told.
            // It reaches exactly one thing — the audit ledger's partition key —
            // so a re-dispatch's fresh chain is legible as a second attempt
            // rather than as a duplicated sequence in the first.
            dispatch_attempt: req.dispatch_attempt,
            // No result caching for NATS jobs — each execution must be fresh
            // host_diag_out: the worker has a real execution id, so host
            // diagnostics take the NATS route to the log tables. The
            // in-process sink exists only for the id-less MCP surfaces.
            options: aegix_wasm_host::runtime::JobRunOptions {
                llm_usage_out: Some(llm_usage_acc.clone()),
                inference_wait: Some(inference_wait.clone()),
                fuel_out: Some(fuel_acc.clone()),
                ..Default::default()
            },
        }),
    )
    .await
    {
        Ok(Ok(output)) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_success();

            JobResult {
                dispatch_attempt: 0,
                workflow_execution_id: None,
                llm_usage: worker::context::drain_llm_usage_entries(&llm_usage_acc),
                crypto_scheme: 0,
                job_id: req.job_id,
                status: JobStatus::Success,
                // Send-side construction: fixes the result's wire text once,
                // and `sign()` below hashes exactly those bytes.
                output_payload: output.into(),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
                fuel: worker::context::take_fuel(&fuel_acc),
            }
        }
        Ok(Err(e)) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            let error_msg = format!("execution failure: {}", e);
            let sanitized_error = sanitize_error_message(&error_msg);
            _span.set_attribute("error", &sanitized_error);
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_error(&sanitized_error);

            JobResult {
                dispatch_attempt: 0,
                workflow_execution_id: None,
                llm_usage: worker::context::drain_llm_usage_entries(&llm_usage_acc),
                crypto_scheme: 0,
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": sanitized_error}).into(),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
                fuel: worker::context::take_fuel(&fuel_acc),
            }
        }
        Err(_) => {
            let duration_ms = start.elapsed().as_millis() as u64;
            // Report the timeout that was ACTUALLY enforced. `job_timeout` is
            // the exact binding passed to `tokio::time::timeout` above, so the
            // message cannot drift from the enforcement.
            let error_msg = timeout_error_message(job_timeout, req.timeout_ms > 0);
            _span.set_attribute("error", &error_msg);
            _span.set_attribute_int("duration_ms", duration_ms as i64);
            _span.end_error(&error_msg);

            JobResult {
                dispatch_attempt: 0,
                workflow_execution_id: None,
                // Timeout drops the execution future, but usage folded
                // before the deadline is preserved via the shared Arc.
                // A detached in-flight stream reader could in principle
                // fold shortly after this drain — those late tokens are
                // deliberately dropped rather than racing the signature.
                llm_usage: worker::context::drain_llm_usage_entries(&llm_usage_acc),
                crypto_scheme: 0,
                job_id: req.job_id,
                status: JobStatus::Failed,
                output_payload: json!({"error": error_msg}).into(),
                logs: vec![],
                execution_time_ms: duration_ms,
                signature: vec![],
                result_nonce: String::new(),
                worker_id: String::new(),
                fuel: worker::context::take_fuel(&fuel_acc),
            }
        }
    }
}
