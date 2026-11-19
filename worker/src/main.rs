//! Aegix Worker - WASM Execution Engine
//!
//! Production-grade worker with:
//! - OpenTelemetry metrics (Prometheus)
//! - Distributed tracing (Jaeger)
//! - Health checks
//! - Graceful shutdown
//! - NATS-based job queue
//! - HMAC-signed job verification
//! - AES-256-GCM encrypted secrets in transit

use aegix_workflow_job_protocol::{JobRequest, JobResult, JobStatus};
use futures_util::stream::StreamExt;
use std::sync::Arc;
use worker::metrics_server;
use worker::worker_identity;

use worker::runtime::AegixRuntime;

use job_execution::execute_job;
use job_result::{failed_result, pick_trusted_reply_topic, publish_result_with_retry};
// Read by `result_publish_tests` below, which still holds these functions'
// tests beside the concurrency and fuel-clamp ones.
#[cfg(test)]
use job_result::{
    max_job_result_bytes, truncate_oversized_job_result, DEFAULT_MAX_JOB_RESULT_BYTES,
};
use refused_dispatch::{
    refused_dispatch_answer, signature_failure_payload, WORKER_SIGNATURE_DIAG_ENABLED,
};

mod boot_gates;
mod dispatch_replay;
#[cfg(test)]
mod fuel_emission_pin;
#[cfg(test)]
mod inference_wait_pin;
mod job_execution;
mod job_result;
mod nats_connect;
#[cfg(test)]
mod outbound_tls_pin;
#[cfg(test)]
mod redis_acl_contract;
mod refused_dispatch;
#[cfg(test)]
mod refused_dispatch_pin;
#[cfg(test)]
mod rehearsal_pin;
mod rejected_jobs;
#[cfg(test)]
mod retry_policy_pin;
#[cfg(test)]
mod sealing_mode_boot_pin;
#[cfg(test)]
mod sealing_refusal_pin;
mod startup;

/// Default maximum concurrent single-node job executions. Overridable via
/// `AEGIX_MAX_CONCURRENT_JOBS`; see [`max_concurrent_jobs`].
const DEFAULT_MAX_CONCURRENT_JOBS: usize = 100;
/// Maximum concurrent single-node job executions (env `AEGIX_MAX_CONCURRENT_JOBS`).
///
/// Reuses the canonical `nonzero_env_or_default` footgun guard: a
/// non-numeric or `<= 0` value would create a `Semaphore` that permits
/// nothing (silent worker stall), so it is rejected with a WARN and the
/// default is substituted (`>= 1` by construction). Same class as the
/// documented `=0`/negative env-var footgun pattern.
fn max_concurrent_jobs() -> usize {
    worker::runtime::nonzero_env_or_default(
        "AEGIX_MAX_CONCURRENT_JOBS",
        DEFAULT_MAX_CONCURRENT_JOBS,
    )
}

/// Ceiling on the per-job fuel THIS worker will honour from a dispatch's
/// `max_fuel`.
///
/// Default [`aegix_workflow_job_protocol::MAX_JOB_FUEL`] (50 M, the
/// controller's own per-node cap); `AEGIX_WORKER_MAX_JOB_FUEL` lowers or raises
/// it per fleet. Defence in depth behind the signature: since 2026-09-10
/// `JobRequest.max_fuel` is signature-bound, so an on-wire rewrite fails
/// verification — this clamp is for the OTHER sender, a controller that
/// mis-caps (or a future controller whose cap is raised without the fleet's
/// consent). Cached: fixed for the process lifetime.
fn worker_max_job_fuel() -> u64 {
    static CACHE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        worker::runtime::nonzero_env_or_default(
            "AEGIX_WORKER_MAX_JOB_FUEL",
            aegix_workflow_job_protocol::MAX_JOB_FUEL,
        )
    })
}

/// Resolve the fuel override a dispatch asked for against this worker's
/// ceiling. `0` means "use the runtime default" and stays `None`; anything
/// else is `Some(min(requested, ceiling))`. Logs when it actually clamps, so
/// a controller handing out more than the fleet allows is visible rather
/// than silently honoured at the lower number. Pure apart from the log.
fn clamp_job_fuel(job_id: uuid::Uuid, requested: u64, ceiling: u64) -> Option<u64> {
    if requested == 0 {
        return None;
    }
    if requested > ceiling {
        ::tracing::warn!(
            target: "talos_security",
            job_id = %job_id,
            requested_fuel = requested,
            ceiling_fuel = ceiling,
            event_kind = "job_fuel_clamped",
            "dispatch asked for more fuel than this worker's ceiling — clamping"
        );
        return Some(ceiling);
    }
    Some(requested)
}

// L-11 (2026-05-22): The worker's self-reported identity, bound into
// every signed `JobResult` via
// `sign_with_worker_id`, is `worker::worker_identity` — the canonical
// resolver lives in the library so both the binary AND library code
// (e.g. `host_impl::build_signed_agent_envelope`) share the same
// `OnceLock`-cached value. (The binary previously carried a thin
// wrapper fn; now that the binary consumes the library crate directly
// the wrapper is gone and call sites use the imported fn.)

#[cfg(test)]
mod worker_identity_tests {
    use super::worker_identity;

    #[test]
    fn returns_validatable_id() {
        let id = worker_identity();
        // Whatever the resolution branch, the output must satisfy the
        // protocol's validator — that's what the worker is going to
        // pass to `sign_with_worker_id` in production.
        aegix_workflow_job_protocol::validate_worker_id(id)
            .expect("resolved worker_id must satisfy validate_worker_id");
    }

    #[test]
    fn cached_across_calls() {
        // OnceLock semantics: stable address means stable string.
        let a: &'static str = worker_identity();
        let b: &'static str = worker_identity();
        assert_eq!(a.as_ptr(), b.as_ptr(), "worker_identity must be cached");
    }
}

/// The world a job's signed `capability_world` hint names: `Ok(None)` for no
/// hint, `Ok(Some(world))` for a world this worker knows, `Err` for a hint it
/// does not (the parser maps any unknown string to `Unknown`, which the
/// runtime would read as "no hint" — E2-3).
fn job_world_hint(raw: Option<&str>) -> Result<Option<worker::wit_inspector::CapabilityWorld>, ()> {
    use worker::wit_inspector::CapabilityWorld;
    match raw {
        None => Ok(None),
        Some(s) => match s.parse::<CapabilityWorld>() {
            Ok(CapabilityWorld::Unknown) | Err(_) => Err(()),
            Ok(world) => Ok(Some(world)),
        },
    }
}

/// RFC 0010 P1: worker-side dispatch-verify configuration, resolved once from
/// env. The worker holds only the controller's *public* key(s), so it can verify
/// an Ed25519-signed dispatch but cannot forge one — the asymmetric half of the
/// worker-trust boundary.
struct DispatchVerifyConfig {
    /// Controller Ed25519 public key(s). Index 0 is current;
    /// `AEGIX_CONTROLLER_PUBLIC_KEY_PREVIOUS` (comma-separated) adds rotated-out
    /// keys for an overlap window. Empty ⇒ Ed25519 dispatches cannot be verified.
    ed_keys: Vec<aegix_workflow_job_protocol::DispatchVerifyingKey>,
    /// Whether legacy HMAC (scheme 0) dispatches are still accepted. `true` (the
    /// default) is the rollout posture; `AEGIX_DISPATCH_REQUIRE_ED25519=1` flips
    /// it to `false` — the RFC 0010 P4 enforcement flip that refuses HMAC once
    /// the fleet is fully on Ed25519.
    accept_legacy_hmac: bool,
}

/// Whether WASM loaded from unattested storage with no expected hash is
/// refused (2026-10-29). Fail-closed by default; `AEGIX_ALLOW_UNATTESTED_WASM`
/// admits it under `development` and, logged at ERROR on every boot, under
/// `transitional`; `hardened` never admits it (and refuses the override at
/// boot). Until this date the belt-and-braces predicate was `is_production()`,
/// which left a staging worker to the override alone.
fn unattested_wasm_blocked(
    profile: aegix_deploy_posture::security_profile::SecurityProfile,
    allow_unattested: bool,
) -> bool {
    !(allow_unattested && (profile.honours_acknowledgements() || !profile.enforces()))
}

/// RFC 0010 P3 (D3b): whether `AEGIX_ENVELOPE_SEALING=required` — the worker
/// downgrade-guard flag. Under `required` the worker refuses a `sealing == 0`
/// (inline WSK) dispatch. `off`/`audit`/unset → `false` (both schemes handled).
/// Cached; the flag is fixed for the process lifetime.
fn worker_sealing_required() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *CACHE.get_or_init(|| {
        // The one parser. Boot has refused an unrecognised value
        // (`boot_gates::enforce`); read all the same, it is `Required`.
        aegix_deploy_posture::envelope_sealing::from_env_or_strictest()
            == aegix_deploy_posture::envelope_sealing::SealingMode::Required
    })
}

/// Whether a worker under `AEGIX_ENVELOPE_SEALING=required` may boot: only
/// with a usable signing key, the identity it claims each job's secrets
/// with. Pure, so the refusal is tested without an environment.
fn sealing_requires_a_signing_key(
    sealing_required: bool,
    signing_key_usable: bool,
) -> Result<(), &'static str> {
    if sealing_required && !signing_key_usable {
        return Err(
            "AEGIX_ENVELOPE_SEALING=required but this worker has no usable \
             AEGIX_WORKER_SIGNING_KEY (unset or invalid): it could claim no sealed \
             secrets, so every job that carries secrets would fail after dispatch. Set \
             the worker's Ed25519 seed (docs/worker-identity.md) or lower the mode.",
        );
    }
    Ok(())
}

#[cfg(test)]
mod unattested_wasm_tests {
    use super::unattested_wasm_blocked;
    use aegix_deploy_posture::security_profile::SecurityProfile::{
        Development, Hardened, Transitional,
    };

    /// 2026-10-29: fail-closed without the override everywhere; the override
    /// is honoured under development and transitional, never under hardened.
    #[test]
    fn the_override_is_honoured_everywhere_but_hardened() {
        for p in [Hardened, Transitional, Development] {
            assert!(
                unattested_wasm_blocked(p, false),
                "{p:?} without the override"
            );
        }
        assert!(unattested_wasm_blocked(Hardened, true));
        assert!(!unattested_wasm_blocked(Transitional, true));
        assert!(!unattested_wasm_blocked(Development, true));
    }
}

#[cfg(test)]
mod sealing_boot_gate_tests {
    use super::sealing_requires_a_signing_key as gate;

    #[test]
    fn required_without_a_key_refuses_and_names_both_settings() {
        let err = gate(true, false).unwrap_err();
        assert!(err.contains("AEGIX_ENVELOPE_SEALING=required"), "{err}");
        assert!(err.contains("AEGIX_WORKER_SIGNING_KEY"), "{err}");
    }

    #[test]
    fn every_other_combination_boots() {
        assert_eq!(gate(true, true), Ok(()));
        assert_eq!(gate(false, false), Ok(()));
        assert_eq!(gate(false, true), Ok(()));
    }
}

/// Load [`DispatchVerifyConfig`] once. Malformed public keys are skipped with a
/// loud warning (so one bad key can't strand the worker), and enabling
/// enforcement without a usable key is logged as an error — the worker then
/// fails closed per-request (rejecting is safe; admitting a forgery is not).
fn dispatch_verify_config() -> &'static DispatchVerifyConfig {
    static CFG: std::sync::OnceLock<DispatchVerifyConfig> = std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        let mut ed_keys = Vec::new();
        if let Ok(cur) = std::env::var("AEGIX_CONTROLLER_PUBLIC_KEY") {
            match aegix_workflow_job_protocol::parse_ed25519_verifying_key_hex(&cur) {
                Ok(k) => ed_keys.push(k),
                Err(e) => ::tracing::error!(error = %e, "AEGIX_CONTROLLER_PUBLIC_KEY is invalid — Ed25519 dispatch verification disabled"),
            }
        }
        if let Ok(prev) = std::env::var("AEGIX_CONTROLLER_PUBLIC_KEY_PREVIOUS") {
            for (i, part) in prev.split(',').map(str::trim).filter(|s| !s.is_empty()).enumerate() {
                match aegix_workflow_job_protocol::parse_ed25519_verifying_key_hex(part) {
                    Ok(k) => ed_keys.push(k),
                    Err(e) => ::tracing::warn!(index = i, error = %e, "skipping invalid AEGIX_CONTROLLER_PUBLIC_KEY_PREVIOUS entry"),
                }
            }
        }
        let require_ed25519 =
            aegix_deploy_posture::bool_env_or_default("AEGIX_DISPATCH_REQUIRE_ED25519", false);
        if require_ed25519 && ed_keys.is_empty() {
            ::tracing::error!(
                target: "talos_security",
                "AEGIX_DISPATCH_REQUIRE_ED25519 is on but no valid AEGIX_CONTROLLER_PUBLIC_KEY \
                 is configured — the worker will reject ALL dispatches (fail-closed)"
            );
        }
        DispatchVerifyConfig { ed_keys, accept_legacy_hmac: !require_ed25519 }
    })
}

/// Fleet-wide operator-cancel listener.
///
/// # Why a PLAIN subscribe and never a queue subscribe
///
/// Every other worker subscription in this file is a `queue_subscribe`, because
/// a job should be executed once by one member. A cancel is the opposite: the
/// controller does not know which worker holds the execution's in-flight job,
/// so the command has to reach EVERY worker. A queue group would deliver it to
/// one arbitrary member and drop it for the rest — the cancel would appear to
/// work and would silently miss most of the time. Workers that do not hold the
/// execution treat it as a no-op.
///
/// # Verify-once
///
/// This is the SINGLE primary verifier for `CancelCommand` in a worker
/// process. A second `verify_dispatch` against the same command would fail
/// with `"cancel_nonce already seen"` — both would insert into the shared
/// `JOB_NONCE_CACHE` (r300/r301). Observers use `verify_no_replay_dispatch`.
///
/// # Security
///
/// An unsigned or forged command is refused before the registry is touched, so
/// NATS-publish access alone is not a denial-of-service primitive. Nothing
/// secret is logged: the execution id is tenant data and is emitted only at
/// DEBUG on the accepted path, never on the rejected one (an attacker must not
/// be able to write chosen values into the log by publishing garbage).
async fn run_cancel_listener(
    nc: async_nats::Client,
    runtime: Arc<AegixRuntime>,
    shared_key: aegix_dispatch_types::WorkerKeyRing,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let subject = aegix_workflow_job_protocol::subjects::WORKERS_CMD_CANCEL;
    let mut sub = match nc.subscribe(subject).await {
        Ok(s) => s,
        Err(e) => {
            ::tracing::error!(
                error = %e,
                subject,
                "failed to subscribe to the cancel command subject — operator \
                 cancellation will not reach this worker"
            );
            return;
        }
    };
    ::tracing::info!(
        subject,
        "Subscribed to operator-cancel commands (plain, fleet-wide)"
    );

    // A cancel is a 100-byte JSON object. Anything larger is not one, and
    // deserialising it would be work an unauthenticated publisher chose for us.
    const MAX_CANCEL_PAYLOAD_BYTES: usize = 4 * 1024;

    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            msg_opt = sub.next() => {
                let Some(msg) = msg_opt else { break };
                if msg.payload.len() > MAX_CANCEL_PAYLOAD_BYTES {
                    ::tracing::warn!(
                        payload_bytes = msg.payload.len(),
                        "rejecting oversized cancel command"
                    );
                    continue;
                }
                let cmd: aegix_workflow_job_protocol::CancelCommand =
                    match serde_json::from_slice(&msg.payload) {
                        Ok(c) => c,
                        Err(_) => {
                            // No error detail and no payload echo: the sender is
                            // unauthenticated at this point.
                            ::tracing::warn!("failed to decode cancel command");
                            continue;
                        }
                    };

                let dvc = dispatch_verify_config();
                if let Err(e) = cmd.verify_dispatch(
                    &shared_key,
                    &dvc.ed_keys,
                    aegix_workflow_job_protocol::EXECUTION_CANCEL_MAX_AGE_SECS,
                    dvc.accept_legacy_hmac,
                ) {
                    ::tracing::warn!(
                        target: "talos_security",
                        detail = %aegix_workflow_job_protocol::describe_verify_failure(
                            "cancel command", &e
                        ),
                        "refusing unverified cancel command"
                    );
                    continue;
                }

                let flagged = runtime.cancel_execution(cmd.workflow_execution_id);
                if flagged > 0 {
                    ::tracing::info!(
                        execution_id = %cmd.workflow_execution_id,
                        flagged,
                        "operator cancel applied to in-flight job(s)"
                    );
                } else {
                    // The COMMON case across the fleet — every worker that does
                    // not hold this execution lands here. Not an error.
                    ::tracing::debug!(
                        execution_id = %cmd.workflow_execution_id,
                        "cancel command for an execution not in flight here (no-op)"
                    );
                }
            }
        }
    }
    ::tracing::info!("cancel listener stopped");
}

/// RFC 0010 P2: the worker's per-instance Ed25519 **result-signing** key,
/// resolved once from `AEGIX_WORKER_SIGNING_KEY` (a 32-byte hex seed sourced
/// from a Secret / KMS — never a committed plaintext). `None` (the default) ⇒
/// results keep the legacy `WORKER_SHARED_KEY` HMAC path (scheme 0). `Some` ⇒
/// every `JobResult` is signed Ed25519 (scheme 1) under
/// this key; the controller verifies against the matching public key registered
/// for this worker's id in `AEGIX_WORKER_PUBLIC_KEYS`. Because the controller
/// holds only the public half, a compromised worker can forge results as itself
/// but never as another worker — the asymmetric result-path boundary.
///
/// A present-but-malformed seed fails closed to HMAC (loud error) rather than
/// stranding the worker with no way to sign a result at all.
fn worker_result_signing_key() -> Option<&'static aegix_workflow_job_protocol::DispatchSigningKey> {
    static CFG: std::sync::OnceLock<Option<aegix_workflow_job_protocol::DispatchSigningKey>> =
        std::sync::OnceLock::new();
    CFG.get_or_init(|| {
        // An ephemeral identity's key is minted in memory, once per process
        // (2026-11-06, worker::nats_identity); a configured one is read below.
        if aegix_wasm_host::worker_identity::identity_mode()
            == aegix_wasm_host::worker_identity::IdentityMode::Ephemeral
        {
            if std::env::var("AEGIX_WORKER_SIGNING_KEY").is_ok_and(|v| !v.trim().is_empty()) {
                ::tracing::warn!(
                    target: "talos_security",
                    "AEGIX_WORKER_SIGNING_KEY is ignored under AEGIX_WORKER_IDENTITY=ephemeral"
                );
            }
            ::tracing::info!(
                target: "talos_security",
                worker_id = %worker_identity(),
                "minted an ephemeral Ed25519 worker identity (in memory only)"
            );
            return Some(worker::nats_identity::ephemeral_signing_key().clone());
        }
        // Inline, or as a file (AEGIX_WORKER_SIGNING_KEY_FILE, 2026-11-06: the
        // compose production stack hands each replica its key as a compose
        // secret, which `docker inspect` does not show).
        let raw = match worker::nats_identity::value_or_file(
            "AEGIX_WORKER_SIGNING_KEY",
            std::env::var("AEGIX_WORKER_SIGNING_KEY").ok().as_deref(),
            std::env::var("AEGIX_WORKER_SIGNING_KEY_FILE").ok().as_deref(),
            |p| std::fs::read_to_string(p),
        ) {
            Ok(Some(v)) => v,
            Ok(None) => return None,
            Err(e) => {
                ::tracing::error!(target: "talos_security", error = %e,
                    "the worker signing key could not be read — no Ed25519 identity");
                return None;
            }
        };
        match aegix_workflow_job_protocol::parse_ed25519_signing_key_hex(&raw) {
            Ok(sk) => {
                ::tracing::info!(
                    target: "talos_security",
                    "AEGIX_WORKER_SIGNING_KEY loaded — signing job results with per-worker Ed25519 (RFC 0010 P2)"
                );
                Some(sk)
            }
            Err(e) => {
                ::tracing::error!(
                    target: "talos_security",
                    error = %e,
                    "AEGIX_WORKER_SIGNING_KEY is invalid — falling back to legacy HMAC result signing"
                );
                None
            }
        }
    })
    .as_ref()
}

/// B-5 (2026-10-14): register the fleet-wide dispatch replay guard, under the
/// controller's own switch (`AEGIX_DISTRIBUTED_REPLAY`) and fail policy
/// (`AEGIX_REPLAY_FAIL_CLOSED`). With the switch off the process-local nonce
/// cache is the whole defence, as before.
///
/// Whether the Redis user this worker logged in as is the shared one
/// (security review 2026-10-15, E2-6): `default` is the controller's, and with
/// it a compromised worker writes any key the controller reads — a module's
/// cached bytes, the controller's replay nonces, its idempotency records. The
/// worker's own user is `talos-worker` with deploy/redis/worker.acl-rules.
fn redis_user_is_shared(user: &str) -> bool {
    user.trim() == "default"
}

/// Said once at boot, loudly where the deployment faces users. Not a refusal:
/// a managed Redis without ACL users (or a chart install that has not given
/// the worker `WORKER_REDIS_URL`) keeps working, and says so.
async fn report_redis_identity(conn: &mut redis::aio::MultiplexedConnection) {
    let who: redis::RedisResult<String> = redis::cmd("ACL").arg("WHOAMI").query_async(conn).await;
    match who {
        Ok(user) if redis_user_is_shared(&user) => {
            if aegix_auth_types::browser_hardening_required() {
                ::tracing::warn!(
                    target: "talos_security",
                    event_kind = "worker_redis_shared_credential",
                    "the worker connects to Redis as `default`, the controller's user: a \
                     compromised worker can write keys the controller reads. Give it the \
                     `talos-worker` user (deploy/redis/worker.acl-rules, docs/redis-worker-user.md)"
                );
            }
        }
        Ok(user) => ::tracing::info!(target: "talos_security", redis_user = %user, "Redis user"),
        Err(e) => {
            ::tracing::debug!(error = %e, "ACL WHOAMI not answered (Redis without ACL users)")
        }
    }
}

#[cfg(test)]
mod redis_identity_tests {
    #[test]
    fn only_the_default_user_is_the_shared_one() {
        assert!(super::redis_user_is_shared("default"));
        assert!(super::redis_user_is_shared(" default\n"));
        assert!(!super::redis_user_is_shared("talos-worker"));
    }
}

/// B2-2 (2026-10-15): with the switch on, the guard is registered whether or
/// not Redis answers at boot. Until Redis answers, every dispatch is
/// `store_unavailable` — refused when failing closed, the production default —
/// where until then a worker that booted during a Redis outage ran every
/// dispatch unchecked for its lifetime. A worker with no Redis configured at
/// all has no guard, which the same policy refuses when failing closed.
async fn register_dispatch_replay_guard(client: &redis::Client) {
    if !aegix_replay_guard::distributed_replay_from_env() {
        ::tracing::warn!(
            target: "talos_security",
            "AEGIX_DISTRIBUTED_REPLAY is off — a replayed dispatch is refused only by the \
             worker that saw it first"
        );
        return;
    }
    let (guard, connected) = aegix_replay_guard::RedisReplayGuard::registering(client).await;
    let guard = guard.with_prefix(dispatch_replay::KEY_PREFIX);
    let fail_closed = aegix_replay_guard::fail_closed_from_env();
    if let Err(e) = aegix_replay_guard::register_shared_replay_guard(Arc::new(guard)) {
        ::tracing::error!(target: "talos_security", error = %e, "dispatch replay guard not registered");
        return;
    }
    match connected {
        Ok(()) => ::tracing::info!(
            target: "talos_security",
            fail_closed,
            "dispatch replay guard registered (Redis) — a dispatch runs once per fleet"
        ),
        Err(e) => ::tracing::error!(
            target: "talos_security",
            error = %e,
            fail_closed,
            "AEGIX_DISTRIBUTED_REPLAY is on but Redis did not answer at boot — the replay \
             guard is registered and connects when Redis does; until then every dispatch \
             is refused when failing closed, admitted on this worker's cache otherwise"
        ),
    }
}

/// Sign a `JobResult`, preferring the per-worker Ed25519 key when configured
/// (RFC 0010 P2) and falling back to the legacy `WORKER_SHARED_KEY` HMAC. Binds
/// the worker's identity into the signature either way (L-11). Single source of
/// truth for every `JobResult` sign site so the scheme can't diverge between the
/// happy path and the oversized-result replacement path.
fn sign_job_result(
    result: &mut JobResult,
    shared_key: &aegix_dispatch_types::WorkerKeyRing,
) -> Result<(), String> {
    match worker_result_signing_key() {
        Some(sk) => result.sign_ed25519_with_worker_id(sk, worker_identity()),
        None => result.sign_with_worker_id(shared_key.signing_key().as_bytes(), worker_identity()),
    }
}

/// Sign `result` as the answer to `req`: stamp the attempt and execution it
/// answers (security review 2026-10-14, B-9), then [`sign_job_result`]. Every
/// result the worker publishes for a request goes through here; the dispatcher
/// takes only an answer to the attempt it is waiting on.
fn sign_job_result_for(
    result: &mut JobResult,
    req: &aegix_workflow_job_protocol::JobRequest,
    shared_key: &aegix_dispatch_types::WorkerKeyRing,
) -> Result<(), String> {
    result.bind_to_request(req);
    sign_job_result(result, shared_key)
}

/// Ed25519 verifying keys that may vouch for a CACHED result signed by
/// `worker_id` (the idempotency cache's Redis tier re-verifies before it
/// re-publishes). The fleet's registered keys (`AEGIX_WORKER_PUBLIC_KEYS`, a
/// controller-side setting that is usually absent on a worker) plus THIS
/// worker's own key when the result is its own — so a same-identity restart or
/// a same-worker Redis hit re-admits its own Ed25519 result. A sibling's
/// Ed25519 result with no registered key fails re-verification and falls
/// through to re-execution: the safe direction, and no worse than the HMAC-only
/// verifier this replaced, which could re-admit NO Ed25519 result at all.
fn cached_result_verify_keys(
    worker_id: &str,
) -> Vec<aegix_workflow_job_protocol::DispatchVerifyingKey> {
    let mut keys = aegix_workflow_job_protocol::worker_public_keys(worker_id);
    if worker_id == worker_identity() {
        if let Some(sk) = worker_result_signing_key() {
            keys.push(sk.verifying_key());
        }
    }
    keys
}

/// RFC 0014 P2: sign a `JobProgress` exactly as a `JobResult` is signed — the
/// worker's Ed25519 key when configured, the fleet HMAC otherwise — so the
/// dispatcher verifies both with the same key material.
fn sign_job_progress(
    progress: &mut aegix_workflow_job_protocol::JobProgress,
    shared_key: &aegix_dispatch_types::WorkerKeyRing,
) -> Result<(), String> {
    match worker_result_signing_key() {
        Some(sk) => progress.sign_ed25519_with_worker_id(sk, worker_identity()),
        None => {
            progress.sign_with_worker_id(shared_key.signing_key().as_bytes(), worker_identity())
        }
    }
}

/// RFC 0014 P2: tells the dispatcher a job is waiting for (then has) the
/// local-inference slot, so its attempt window stands still while it queues.
///
/// Publishes a signed `JobProgress` to `<reply_inbox>.progress`, derived from
/// the job's SIGNED `reply_topic` — the same controller the result will reach.
/// A controller that predates P2 does not subscribe there and the message is
/// dropped by the broker, so no rollout order is required. A failed publish is
/// logged and otherwise ignored: the worker's own deadlines move regardless,
/// and a controller that never hears about the wait gives up on the attempt
/// exactly as it did before P2.
struct NatsProgressNotifier {
    nc: async_nats::Client,
    subject: String,
    job_id: uuid::Uuid,
    dispatch_attempt: u32,
    shared_key: aegix_dispatch_types::WorkerKeyRing,
}

impl worker::inference_wait::WaitNotifier for NatsProgressNotifier {
    fn notify(
        &self,
        state: aegix_workflow_job_protocol::JobProgressState,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let mut progress = aegix_workflow_job_protocol::JobProgress::new(
                self.job_id,
                self.dispatch_attempt,
                state,
            );
            if let Err(e) = sign_job_progress(&mut progress, &self.shared_key) {
                ::tracing::warn!(job_id = %self.job_id, error = %e, "job progress not signed; not sent");
                return;
            }
            let bytes = match serde_json::to_vec(&progress) {
                Ok(b) => b,
                Err(e) => {
                    ::tracing::warn!(job_id = %self.job_id, error = %e, "job progress not serialized; not sent");
                    return;
                }
            };
            if let Err(e) = self.nc.publish(self.subject.clone(), bytes.into()).await {
                ::tracing::warn!(job_id = %self.job_id, error = %e, "job progress publish failed");
                return;
            }
            ::tracing::info!(
                job_id = %self.job_id,
                dispatch_attempt = self.dispatch_attempt,
                state = state.as_str(),
                "reported local-inference wait to the dispatcher"
            );
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // rustls 0.23 requires an explicit CryptoProvider when the dep graph
    // contains more than one. We pull rustls in via redis (tls-rustls) and
    // reqwest. install_default is idempotent — Err means another caller
    // already installed one, which is fine.
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Before the fleet key or any job's secrets are in memory: no core dump,
    // no same-UID ptrace, root-owned /proc entries. Logged once tracing is up.
    let non_dumpable = aegix_deploy_posture::process_posture::make_process_non_dumpable();

    // Before the first setting is read: a variable left under the former
    // prefix would be ignored and its default used, silently.
    aegix_deploy_posture::legacy_env::refuse_legacy_names().map_err(anyhow::Error::msg)?;

    println!("=== Aegix Worker Starting ===\n");

    // The boot gates: the fleet key, the security profile and every refusal
    // to start that needs no connection (`boot_gates.rs`).
    let shared_key = boot_gates::enforce().await?;

    startup::init_observability(&non_dumpable).await?;

    let startup::Bus {
        nats_url,
        is_production,
        nc,
        single_job_topic,
        mut sub,
    } = startup::connect_bus(&shared_key).await?;

    let runtime = startup::build_runtime(&nc, &shared_key, is_production).await?;

    // ========================================================================
    // METRICS SERVER
    // ========================================================================

    println!("\n[4/5] Starting metrics server...");
    let metrics_port = std::env::var("METRICS_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(9090);

    let _metrics_handle = metrics_server::start_metrics_server(runtime.clone(), metrics_port)
        .expect("Failed to start metrics server — ensure METRICS_AUTH_TOKENS is set");

    println!("      Metrics server running on port {}", metrics_port);
    println!(
        "         - Metrics: http://localhost:{}/metrics",
        metrics_port
    );
    println!(
        "         - Health:  http://localhost:{}/health",
        metrics_port
    );

    // ========================================================================
    // JOB PROCESSING LOOP
    // ========================================================================

    println!("\n[5/5] Starting job processing...");
    println!("\n=== Worker Ready ===");
    println!(
        "Listening for jobs on {} (queue: {})",
        nats_url, single_job_topic
    );

    // Resolve concurrency caps ONCE and bind to locals — the shutdown
    // drain loop below compares `available_permits()` against these same
    // values, so they must not be re-read from env (an operator changing
    // the env mid-process can't happen, but re-reading would also re-emit
    // the WARN and risk drift).
    let max_concurrent_jobs = max_concurrent_jobs();

    // Capacity sanity gate: the single-job semaphore must never hand out
    // more permits than the pooling allocator can instantiate. If
    // `max_concurrent_jobs > TOTAL_COMPONENT_INSTANCES`, a job could
    // acquire a permit, then fail to get a pooling slot at instantiation
    // — turning clean semaphore back-pressure into instantiation errors
    // under saturation. WARN rather
    // than panic so an operator who deliberately raised the allocator's
    // total isn't blocked, but the misconfiguration is loud.
    let total_component_instances = worker::runtime::TOTAL_COMPONENT_INSTANCES as usize;
    if max_concurrent_jobs > total_component_instances {
        ::tracing::warn!(
            max_concurrent_jobs,
            total_component_instances,
            "AEGIX_MAX_CONCURRENT_JOBS exceeds the pooling allocator's total_component_instances — jobs may acquire a concurrency permit but fail to instantiate under saturation; lower the concurrency cap or raise total_component_instances in runtime.rs"
        );
    } else {
        ::tracing::info!(
            max_concurrent_jobs,
            total_component_instances,
            "Job concurrency caps within pooling-allocator capacity"
        );
    }

    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent_jobs));

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── Operator-cancel listener ──────────────────────────────────────────
    // Not semaphore-gated: handling a cancel is a signature check plus a scan
    // of a map bounded by the job concurrency cap, and it must not queue behind
    // the very jobs it is trying to stop.
    //
    // DELIBERATELY NOT joined in the shutdown `select!` below. That select
    // treats any completed arm as "the worker is finished" — correct for the
    // two job loops, whose exit means the bus is gone. This task can also end
    // for a reason that must NOT stop the worker: a failed subscribe. Adding
    // it as an arm would turn a degraded-cancellation condition (logged at
    // ERROR, jobs unaffected) into an immediate shutdown of a worker with jobs
    // in flight. It observes `shutdown_rx` itself, and dropping a tokio
    // `JoinHandle` does not abort the task.
    let _cancel_handle = tokio::spawn(run_cancel_listener(
        nc.clone(),
        runtime.clone(),
        shared_key.clone(),
        shutdown_rx.clone(),
    ));

    // ── Single-node jobs task ─────────────────────────────────────────────
    let single_nc = nc.clone();
    let single_runtime = runtime.clone();
    let single_key = shared_key.clone();
    let single_sem = semaphore.clone();
    let mut single_shutdown = shutdown_rx.clone();

    let single_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = single_shutdown.changed() => break,
                permit_res = single_sem.clone().acquire_owned() => {
                    let permit = match permit_res {
                        Ok(p) => p,
                        Err(_) => break,
                    };

                    tokio::select! {
                        _ = single_shutdown.changed() => break,
                        msg_opt = sub.next() => {
                            let msg = match msg_opt {
                                Some(m) => m,
                                None => break,
                            };

                            let cx = if let Some(ref headers) = msg.headers {
                                worker::trace_nats::extract_trace_context(headers)
                            } else {
                                opentelemetry::Context::new()
                            };

                            // SECURITY: cap payload size before deserialization to prevent
                            // memory exhaustion from oversized NATS messages.
                            const MAX_JOB_PAYLOAD_BYTES: usize = 32 * 1024 * 1024; // 32 MB
                            // Dropped WITHOUT a reply — see `rejected_jobs` for why
                            // no fail-fast result can be sent safely.
                            if msg.payload.len() > MAX_JOB_PAYLOAD_BYTES {
                                rejected_jobs::record(
                                    rejected_jobs::JobKind::Single,
                                    rejected_jobs::RejectReason::Oversized,
                                    msg.payload.len(),
                                );
                                continue;
                            }
                            let req: JobRequest = match serde_json::from_slice(&msg.payload) {
                                Ok(r) => r,
                                Err(_) => {
                                    rejected_jobs::record(
                                        rejected_jobs::JobKind::Single,
                                        rejected_jobs::RejectReason::Undecodable,
                                        msg.payload.len(),
                                    );
                                    continue;
                                }
                            };

                            ::tracing::info!(job_id = %req.job_id, module_uri = %req.module_uri, "Received job");
                            let payload_bytes = msg.payload.len();

                            let nc_clone = single_nc.clone();
                            let runtime_clone = single_runtime.clone();
                            let key_clone = single_key.clone();
                            let wire_reply = msg.reply.map(|r: async_nats::Subject| r.to_string());
                            // H-1: prefer the HMAC-bound `req.reply_topic`
                            // over the unsigned wire `msg.reply`. See
                            // `pick_trusted_reply_topic` for the matrix.
                            let reply_to = pick_trusted_reply_topic(
                                req.job_id,
                                req.reply_topic.as_deref(),
                                wire_reply.as_deref(),
                            );

                            tokio::task::spawn(async move {
                                // FU-2 (R2-5) idempotency: a controller transport-retry re-sends
                                // the same job_id (with a fresh nonce) AFTER the original
                                // executed. Re-publish the cached signed result instead of
                                // re-running the module (which would repeat side effects). The
                                // cached result is still within the 300s JobResult freshness
                                // window, so it's re-published as-is. dry_run jobs are never
                                // cached (no side effects, cheap to re-run).
                                //
                                // SECURITY (self-review fix): the cache must ONLY be consulted
                                // for an AUTHENTICATED request. `execute_job` verifies the
                                // request HMAC, but it runs AFTER this cache check — so without
                                // gating here, an on-NATS attacker could send an unsigned
                                // JobRequest with a known (non-secret) job_id and exfiltrate the
                                // cached signed result to an attacker-chosen reply inbox,
                                // bypassing the "no result leaves the worker without a valid
                                // HMAC" invariant. We pre-verify with the NO-REPLAY variant
                                // (HMAC + freshness, but NOT the nonce cache) so the cache-miss
                                // path's `execute_job` → `verify_dispatch` still records the
                                // nonce exactly once. A forged request fails this pre-check and
                                // falls through to `execute_job`, which refuses it without
                                // running the module; `refused_dispatch_answer` then decides
                                // what is sent in answer (for a forged request, nothing).
                                //
                                // SCHEME-ROUTING (2026-09-10): this pre-check used the HMAC-only
                                // `verify_no_replay_with_ring`, so under an Ed25519 dispatch
                                // (`crypto_scheme = 1`, the dev fleet's posture) it was ALWAYS
                                // false and the idempotency layer was dead. Route on the
                                // scheme exactly as the primary verifier below does.
                                let dvc = dispatch_verify_config();
                                let request_authentic = req
                                    .verify_no_replay_dispatch(
                                        &key_clone,
                                        &dvc.ed_keys,
                                        300,
                                        dvc.accept_legacy_hmac,
                                    )
                                    .is_ok();
                                // B-5 (2026-10-14): once per fleet, not per worker.
                                // B2-2/B2-3 (2026-10-15): the one replay policy decides,
                                // a refusal is counted, and one for want of the store is
                                // answered (a replay never is).
                                if request_authentic {
                                    let verdict = dispatch_replay::fleet_verdict(
                                        aegix_replay_guard::shared_replay_guard().as_deref(),
                                        &dispatch_replay::dispatch_key("job", req.job_id, &req.job_nonce),
                                        aegix_replay_guard::ReplayPolicy::from_env(),
                                    )
                                    .await;
                                    if verdict != aegix_replay_guard::ReplayVerdict::Admit {
                                        dispatch_replay::record_refusal(verdict);
                                        if verdict == aegix_replay_guard::ReplayVerdict::StoreUnavailable {
                                            ::tracing::warn!(
                                                target: "talos_security",
                                                job_id = %req.job_id,
                                                "dispatch refused: the shared replay store could not vouch \
                                                 for its nonce (fail closed); answered Failed, transient"
                                            );
                                            let mut refused = failed_result(
                                                req.job_id,
                                                &std::time::Instant::now(),
                                                dispatch_replay::STORE_UNAVAILABLE_ERROR,
                                            );
                                            if let Err(e) = sign_job_result_for(&mut refused, &req, &key_clone) {
                                                ::tracing::error!(job_id = %req.job_id, error = %e, "CRITICAL: Failed to sign a refusal");
                                            }
                                            if let Err(e) = publish_result_with_retry(
                                                &nc_clone, &refused, 3, reply_to, &key_clone,
                                            )
                                            .await
                                            {
                                                ::tracing::error!(job_id = %req.job_id, error = %e, "Failed to publish a refusal");
                                            }
                                        } else {
                                            ::tracing::warn!(
                                                target: "talos_security",
                                                job_id = %req.job_id,
                                                "dispatch refused: its nonce was already used on this fleet; \
                                                 not run, no reply"
                                            );
                                        }
                                        drop(permit);
                                        return;
                                    }
                                }
                                if request_authentic && !req.dry_run {
                                    // Tier 1: in-process (same-worker retry, free).
                                    // Tier 2: Redis (a retry that reached another
                                    // process of THIS worker identity, or this worker
                                    // after a restart). Redis-sourced bytes are NOT
                                    // trusted blindly: an entry is served only when this
                                    // worker can vouch for it (below), so neither a Redis
                                    // compromise nor a sibling worker can inject a result
                                    // or cross-wire jobs; a refusal falls through to
                                    // normal re-execution.
                                    let cached = match worker::job_idempotency::JOB_RESULT_CACHE
                                        .get(req.job_id)
                                    {
                                        Some(c) => Some(c),
                                        None => worker::job_idempotency::shared_get(
                                            worker::job_idempotency::REDIS_JOB_PREFIX,
                                            req.job_id,
                                        )
                                        .await
                                        .and_then(|bytes| {
                                            // Finding 10 (2026-11-06): only an entry THIS
                                            // worker can vouch for — its own id, verified
                                            // under its own key(s) (never the registry's
                                            // keys for whatever id the entry names), for
                                            // this job and execution at this or an earlier
                                            // attempt. One rule, `vouched_shared_entry`.
                                            let own = worker_identity();
                                            match worker::job_idempotency::vouched_shared_entry(
                                                &bytes,
                                                &req.dispatch_identity(),
                                                own,
                                                |r| {
                                                    r.verify_no_replay_dispatch(
                                                        &key_clone,
                                                        &cached_result_verify_keys(own),
                                                        300,
                                                        aegix_workflow_job_protocol::result_accept_legacy_hmac(),
                                                    )
                                                    .is_ok()
                                                },
                                            ) {
                                                Ok(r) => Some(r),
                                                Err(refusal) => {
                                                    ::tracing::warn!(
                                                        job_id = %req.job_id,
                                                        refusal = ?refusal,
                                                        "idempotency: shared Redis entry is not one \
                                                         this worker can vouch for — ignoring, \
                                                         re-executing"
                                                    );
                                                    None
                                                }
                                            }
                                        }),
                                    };
                                    // A RE-DISPATCH (`dispatch_attempt > 0`) of a job whose
                                    // cached result is NOT a terminal success is the
                                    // controller's application-failure retry asking for a
                                    // fresh run — serving the cached failure would spend the
                                    // whole retry budget re-reading one transient error. The
                                    // put-site below no longer caches such results at all;
                                    // this guard covers an entry a pre-fix worker wrote to
                                    // Redis during a rolling upgrade.
                                    let cached = cached.filter(|c| {
                                        let stale_failure =
                                            req.dispatch_attempt > 0 && !c.is_terminal_success();
                                        if stale_failure {
                                            ::tracing::debug!(
                                                job_id = %req.job_id,
                                                dispatch_attempt = req.dispatch_attempt,
                                                "idempotency: cached result is not a terminal \
                                                 success and this is a re-dispatch — re-executing"
                                            );
                                        }
                                        !stale_failure
                                    });
                                    if let Some(mut cached) = cached {
                                        ::tracing::info!(
                                            job_id = %req.job_id,
                                            "idempotency: re-publishing cached result for re-seen \
                                             job_id (transport retry); skipping re-execution"
                                        );
                                        // B-9 (2026-10-14): the cached result names the
                                        // attempt that produced it; the dispatcher takes
                                        // only an answer to the attempt it is waiting on.
                                        // Re-bind to THIS request and re-sign (a fresh
                                        // nonce). The output and its fuel are the cached
                                        // run's: that run is what this answers with.
                                        if let Err(e) = sign_job_result_for(&mut cached, &req, &key_clone) {
                                            ::tracing::error!(job_id = %req.job_id, error = %e, "CRITICAL: Failed to re-sign cached job result");
                                        }
                                        if let Err(e) = publish_result_with_retry(
                                            &nc_clone, &cached, 3, reply_to, &key_clone,
                                        )
                                        .await
                                        {
                                            ::tracing::error!(job_id = %req.job_id, error = %e, "CRITICAL: Failed to publish cached job result");
                                        }
                                        drop(permit);
                                        return;
                                    }
                                }

                                let mut result = match execute_job(&cx, req.clone(), runtime_clone, key_clone.clone(), &nc_clone).await {
                                    Ok(result) => result,
                                    // The dispatch did not verify. One rule says
                                    // what, if anything, is signed in answer.
                                    Err(refusal) => match refused_dispatch_answer(
                                        &req,
                                        &refusal,
                                        &key_clone,
                                        dispatch_verify_config(),
                                        *WORKER_SIGNATURE_DIAG_ENABLED,
                                    ) {
                                        Some(answer) => answer,
                                        None => {
                                            rejected_jobs::record(
                                                rejected_jobs::JobKind::Single,
                                                rejected_jobs::RejectReason::unverified(refusal.kind()),
                                                payload_bytes,
                                            );
                                            if *WORKER_SIGNATURE_DIAG_ENABLED {
                                                // The field dump an operator asked
                                                // for, in this worker's own log: it
                                                // is no longer sent anywhere.
                                                ::tracing::warn!(
                                                    target: "signature_diag",
                                                    job_id = %req.job_id,
                                                    diag = %signature_failure_payload(true, &req, &refusal),
                                                    "signature_diag: a dispatch that did not verify (AEGIX_SIGNATURE_DIAG)"
                                                );
                                            }
                                            drop(permit);
                                            return;
                                        }
                                    },
                                };

                                // B-9 (2026-10-14): name the dispatch this answers.
                                // L-11: bind worker identity for audit attribution.
                                // RFC 0010 P2: Ed25519 when configured, else HMAC.
                                if let Err(e) = sign_job_result_for(&mut result, &req, &key_clone) {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to sign job result");
                                }

                                // FU-2: cache the SIGNED terminal result BEFORE publishing, so a
                                // retry that arrives because the *reply* (not the execution)
                                // failed still finds it. Keyed on job_id; bounded by TTL + size +
                                // count (see `job_idempotency`). Written to BOTH tiers: the
                                // in-process map (same-worker retry) and Redis (retry landing on
                                // a sibling queue-group worker).
                                //
                                // ONLY a result the controller would NOT retry is cached
                                // (`JobResult::is_terminal_success`, the dispatcher's own
                                // predicate, one home). The dispatcher retries `Failed` and
                                // `success:false` results under the SAME job_id, so caching
                                // those made every engine retry a no-op replay of the first
                                // failure (2026-09-10).
                                if !req.dry_run && !result.is_terminal_success() {
                                    ::tracing::debug!(
                                        job_id = %result.job_id,
                                        status = ?result.status,
                                        "idempotency: not caching a non-success result — the \
                                         controller's retry must re-execute, not replay it"
                                    );
                                }
                                if !req.dry_run && result.is_terminal_success() {
                                    match serde_json::to_vec(&result) {
                                        Ok(bytes) => {
                                            worker::job_idempotency::JOB_RESULT_CACHE.put(
                                                result.job_id,
                                                result.clone(),
                                                bytes.len(),
                                            );
                                            worker::job_idempotency::shared_put(
                                                worker::job_idempotency::REDIS_JOB_PREFIX,
                                                result.job_id,
                                                &bytes,
                                            )
                                            .await;
                                        }
                                        Err(e) => ::tracing::warn!(
                                            job_id = %result.job_id, error = %e,
                                            "idempotency: could not serialize result for cache sizing; not caching"
                                        ),
                                    }
                                }

                                match result.status {
                                    JobStatus::Success => {
                                        ::tracing::info!(job_id = %result.job_id, duration_ms = result.execution_time_ms, "Job completed");
                                    }
                                    JobStatus::Failed => {
                                        ::tracing::warn!(job_id = %result.job_id, duration_ms = result.execution_time_ms, "Job failed");
                                    }
                                    _ => {}
                                }

                                if let Err(e) = publish_result_with_retry(
                                    &nc_clone,
                                    &result,
                                    3,
                                    reply_to,
                                    &key_clone,
                                )
                                .await
                                {
                                    ::tracing::error!(job_id = %result.job_id, error = %e, "CRITICAL: Failed to publish job result");
                                }

                                drop(permit);
                            });
                        }
                    }
                }
            }
        }
    });

    tokio::select! {
        // MCP-667 (2026-05-13): listen for BOTH SIGTERM and SIGINT via
        // the shared `aegix_shutdown::wait_for_shutdown` helper. Pre-fix
        // the worker only handled SIGINT (Ctrl+C); under K8s pod
        // termination the kubelet sends SIGTERM, which was unobserved —
        // in-flight WASM executions, NATS publishes, and result-
        // collector flushes were aborted at SIGKILL after the grace
        // period elapsed instead of draining cleanly. Sibling fix to
        // the controller-side change at `with_graceful_shutdown` —
        // both binaries now route through the same shutdown surface
        // that carries the MCP-501 install-failure handling.
        _ = aegix_shutdown::wait_for_shutdown() => {
            ::tracing::info!("Shutdown signal received, draining in-flight jobs...");
            let _ = shutdown_tx.send(true);
        }
        _ = single_handle => {},
    }

    // ========================================================================
    // GRACEFUL SHUTDOWN
    // ========================================================================

    println!("\n=== Shutting Down ===");

    println!("[1/3] Waiting for in-flight jobs to complete...");
    let shutdown_timeout = tokio::time::Duration::from_secs(30);
    let drain_start = std::time::Instant::now();

    while (semaphore.available_permits() < max_concurrent_jobs || runtime.active_executions() > 0)
        && drain_start.elapsed() < shutdown_timeout
    {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    }

    if runtime.active_executions() > 0 {
        ::tracing::warn!(
            remaining = runtime.active_executions(),
            "Forcing shutdown with jobs still running"
        );
    } else {
        ::tracing::info!("All in-flight jobs drained successfully");
    }
    println!("      All jobs completed");

    println!("[2/3] Flushing traces...");
    worker::tracing::shutdown_tracing();
    println!("      Traces flushed");

    println!("[3/3] Closing connections...");
    drop(nc);
    println!("      Connections closed");

    println!("\nWorker shutdown complete");
    Ok(())
}
#[cfg(test)]
mod result_publish_tests {
    /// E2-3 (2026-10-15): a hint this worker does not know is refused, never
    /// read as "no hint"; a known one in either spelling is that world.
    #[test]
    fn an_unrecognised_world_hint_is_refused_not_dropped() {
        use worker::wit_inspector::CapabilityWorld;
        assert_eq!(super::job_world_hint(None), Ok(None));
        assert_eq!(
            super::job_world_hint(Some("http-node")),
            Ok(Some(CapabilityWorld::Http))
        );
        assert_eq!(
            super::job_world_hint(Some("automation-node")),
            Ok(Some(CapabilityWorld::Trusted))
        );
        for unknown in ["automation-node-v2", "", "llm-node", "unknown"] {
            assert_eq!(super::job_world_hint(Some(unknown)), Err(()), "{unknown:?}");
        }
    }

    use super::*;

    // Serial guard for env-mutating tests in this module. Without it,
    // cargo's parallel test runner can race on the global env.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    // ─── M-7: JobResult publish-size cap ──────────────────────────────────

    /// B-9: the replacement answers the dispatch the original answered.
    #[test]
    fn truncate_oversized_keeps_the_dispatch_the_result_answers() {
        let mut original = failed_result(uuid::Uuid::new_v4(), &std::time::Instant::now(), "x");
        original.dispatch_attempt = 3;
        original.workflow_execution_id = Some(uuid::Uuid::new_v4());
        let replacement = truncate_oversized_job_result(&original, 10_000_000, 4_000_000);
        assert_eq!(replacement.dispatch_attempt, 3);
        assert_eq!(
            replacement.workflow_execution_id,
            original.workflow_execution_id
        );
    }

    #[test]
    fn truncate_oversized_replaces_payload_and_marks_failed() {
        let original = JobResult {
            dispatch_attempt: 0,
            workflow_execution_id: None,
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: uuid::Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"huge": "x".repeat(10_000)}).into(),
            logs: vec!["a".to_string(); 1000],
            execution_time_ms: 42,
            signature: vec![0; 32],
            result_nonce: "1700000000:abc".to_string(),
            worker_id: String::new(),
            fuel: Some(aegix_workflow_job_protocol::FuelMeasure {
                consumed: 3_000_000,
                limit: 4_000_000,
            }),
        };
        let replacement = truncate_oversized_job_result(&original, 10_000_000, 4_000_000);
        // The module ran and spent its fuel; dropping the output must not drop
        // the spend from the actor's fuel budget.
        assert_eq!(replacement.fuel, original.fuel);
        // Identity bound: same job_id so the controller can correlate.
        assert_eq!(replacement.job_id, original.job_id);
        // Status downgraded to Failed — the original Success is no
        // longer accurate because the result didn't reach the
        // controller.
        assert_eq!(replacement.status, JobStatus::Failed);
        // Payload replaced with a small diagnostic blob.
        assert!(replacement.output_payload.value().get("error").is_some());
        assert!(replacement.output_payload.value().get("diag").is_some());
        // Logs and execution time preserved for correlation.
        assert!(!replacement.logs.is_empty());
        assert_eq!(replacement.execution_time_ms, 42);
        // Signature MUST be cleared so the caller can't accidentally
        // publish an unsigned replacement (the caller is expected to
        // re-sign before publishing).
        assert!(replacement.signature.is_empty());
        assert!(replacement.result_nonce.is_empty());
    }

    #[test]
    fn truncate_oversized_replacement_serializes_under_cap() {
        // The replacement itself must fit comfortably under any
        // reasonable cap, otherwise we'd loop forever.
        let original = JobResult {
            dispatch_attempt: 0,
            workflow_execution_id: None,
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: uuid::Uuid::new_v4(),
            status: JobStatus::Success,
            output_payload: serde_json::json!({"huge": "x".repeat(10_000_000)}).into(),
            logs: vec![],
            execution_time_ms: 0,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
            fuel: None,
        };
        let replacement = truncate_oversized_job_result(&original, 10_000_000, 4_000_000);
        let bytes = serde_json::to_vec(&replacement).unwrap();
        // Replacement is small — well under any realistic cap.
        assert!(
            bytes.len() < 4096,
            "replacement should serialize to a small payload; got {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn max_job_result_bytes_uses_default_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("WORKER_MAX_JOB_RESULT_BYTES");
        assert_eq!(max_job_result_bytes(), DEFAULT_MAX_JOB_RESULT_BYTES);
    }

    #[test]
    fn max_job_result_bytes_respects_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("WORKER_MAX_JOB_RESULT_BYTES", "8388608"); // 8 MiB
        assert_eq!(max_job_result_bytes(), 8_388_608);
        std::env::remove_var("WORKER_MAX_JOB_RESULT_BYTES");
    }

    // ─── B2: env-tunable concurrency caps ─────────────────────────────────

    #[test]
    fn concurrency_caps_use_defaults_when_unset() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::remove_var("AEGIX_MAX_CONCURRENT_JOBS");
        assert_eq!(max_concurrent_jobs(), DEFAULT_MAX_CONCURRENT_JOBS);
    }

    #[test]
    fn concurrency_caps_respect_positive_override() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("AEGIX_MAX_CONCURRENT_JOBS", "42");
        assert_eq!(max_concurrent_jobs(), 42);
        std::env::remove_var("AEGIX_MAX_CONCURRENT_JOBS");
    }

    #[test]
    fn concurrency_cap_zero_falls_back_to_default() {
        // =0/negative footgun guard: a 0 Semaphore permits nothing and
        // would silently stall the worker. `nonzero_env_or_default`
        // substitutes the default (>= 1) with a WARN.
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("AEGIX_MAX_CONCURRENT_JOBS", "0");
        assert_eq!(max_concurrent_jobs(), DEFAULT_MAX_CONCURRENT_JOBS);
        std::env::remove_var("AEGIX_MAX_CONCURRENT_JOBS");
    }

    #[test]
    fn concurrency_cap_negative_falls_back_to_default() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("AEGIX_MAX_CONCURRENT_JOBS", "-5");
        assert_eq!(max_concurrent_jobs(), DEFAULT_MAX_CONCURRENT_JOBS);
        std::env::remove_var("AEGIX_MAX_CONCURRENT_JOBS");
    }

    #[test]
    fn concurrency_cap_non_numeric_falls_back_to_default() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("AEGIX_MAX_CONCURRENT_JOBS", "lots");
        assert_eq!(max_concurrent_jobs(), DEFAULT_MAX_CONCURRENT_JOBS);
        std::env::remove_var("AEGIX_MAX_CONCURRENT_JOBS");
    }

    #[test]
    fn default_concurrency_within_pooling_capacity() {
        // The startup capacity gate in `main()` WARNs when
        // max_concurrent_jobs > TOTAL_COMPONENT_INSTANCES. Pin the
        // shipped defaults so a future bump that would silently exceed
        // the pooling allocator's instance ceiling trips here first.
        let total = worker::runtime::TOTAL_COMPONENT_INSTANCES as usize;
        assert!(
            DEFAULT_MAX_CONCURRENT_JOBS <= total,
            "default single-job concurrency {DEFAULT_MAX_CONCURRENT_JOBS} exceeds pooling total_component_instances {total}"
        );
    }

    // ─── D3 (2026-09-10): per-job fuel clamp ──────────────────────────────

    #[test]
    fn clamp_job_fuel_zero_means_runtime_default() {
        assert_eq!(clamp_job_fuel(uuid::Uuid::nil(), 0, 50_000_000), None);
    }

    #[test]
    fn clamp_job_fuel_honours_a_request_within_the_ceiling() {
        assert_eq!(
            clamp_job_fuel(uuid::Uuid::nil(), 5_000_000, 50_000_000),
            Some(5_000_000)
        );
        assert_eq!(
            clamp_job_fuel(uuid::Uuid::nil(), 50_000_000, 50_000_000),
            Some(50_000_000),
            "exactly the ceiling is not a clamp"
        );
    }

    #[test]
    fn clamp_job_fuel_caps_an_oversized_request() {
        assert_eq!(
            clamp_job_fuel(uuid::Uuid::nil(), u64::MAX, 50_000_000),
            Some(50_000_000)
        );
        assert_eq!(
            clamp_job_fuel(uuid::Uuid::nil(), 50_000_001, 50_000_000),
            Some(50_000_000)
        );
    }

    #[test]
    fn worker_fuel_ceiling_default_is_the_protocol_constant() {
        // Unless an operator set the env var in this test process, the ceiling
        // is the shared constant — the same number the controller caps at.
        // Check 73: an EMPTY value is "unset" everywhere in this workspace, so
        // the guard must read the value, not merely its presence.
        if std::env::var("AEGIX_WORKER_MAX_JOB_FUEL")
            .ok()
            .filter(|v| !v.is_empty())
            .is_none()
        {
            assert_eq!(
                worker_max_job_fuel(),
                aegix_workflow_job_protocol::MAX_JOB_FUEL
            );
        }
    }

    // ─── H-1: pick_trusted_reply_topic decision matrix ────────────────────
    //
    // The whole point of H-1 is that a NATS-channel attacker who
    // substitutes `msg.reply` cannot redirect the worker's signed
    // JobResult to an attacker-controlled subject. These tests pin
    // the policy at the function boundary so a future "simplification"
    // can't silently re-introduce the regression.

    #[test]
    fn pick_reply_signed_and_wire_match() {
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.abc"), Some("_INBOX.abc"));
        assert_eq!(r.as_deref(), Some("_INBOX.abc"));
    }

    #[test]
    fn pick_reply_signed_and_wire_mismatch_returns_signed() {
        // SECURITY: an attacker substituted `msg.reply` — the worker
        // MUST publish to the signed value, not the wire value.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.legit"), Some("talos.admin.commands"));
        assert_eq!(
            r.as_deref(),
            Some("_INBOX.legit"),
            "wire taking priority would be the security regression"
        );
    }

    #[test]
    fn pick_reply_signed_only() {
        // msg.reply stripped in transit; signed value is authoritative.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, Some("_INBOX.signed"), None);
        assert_eq!(r.as_deref(), Some("_INBOX.signed"));
    }

    #[test]
    fn pick_reply_wire_only_is_ignored() {
        // 2026-09-10: an unsigned wire header with no signed twin is NOT a
        // reply path. Pre-fix this returned `Some("_INBOX.legacy")` — the
        // one arm through which a replayed job's signed output could be
        // steered to an attacker-chosen inbox.
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, None, Some("_INBOX.legacy"));
        assert_eq!(r, None);
    }

    #[test]
    fn pick_reply_neither_present() {
        let jid = uuid::Uuid::new_v4();
        let r = pick_trusted_reply_topic(jid, None, None);
        assert_eq!(r, None);
    }

    #[test]
    fn pick_reply_mismatch_does_not_publish_to_attacker_subject() {
        // Specific regression guard: an attacker substituting a
        // sensitive admin subject MUST NOT result in the worker
        // publishing there. This is the whole point of H-1.
        let jid = uuid::Uuid::new_v4();
        let bad_subjects = [
            "talos.admin.commands",
            "talos.jobs",          // would create a NATS loop
            "$SYS.REQ.ACCOUNT",    // NATS system subject
            "_INBOX.attacker.xyz", // inbox-prefix but not the signed one
        ];
        for bad in bad_subjects {
            let r = pick_trusted_reply_topic(jid, Some("_INBOX.legit"), Some(bad));
            assert_eq!(
                r.as_deref(),
                Some("_INBOX.legit"),
                "H-1 regression: wire subject {bad:?} leaked through"
            );
        }
    }
}
