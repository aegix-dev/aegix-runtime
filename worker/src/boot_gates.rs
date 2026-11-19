//! What the worker checks before it connects to anything: the fleet key,
//! the security profile, the module-signature policy and cosign pin, the
//! replay guard, the fleet-identity and sealing requirements, and the
//! egress and SQL switches.
//!
//! This is the first section of `main()`, moved out 2026-11-18 as one
//! function with its statements in the order they had. `main()` calls it
//! after the process is made non-dumpable and former setting names are
//! refused, and before observability starts. It returns the one thing the
//! rest of `main()` uses from it, the key ring.

use crate::{sealing_requires_a_signing_key, worker_result_signing_key, worker_sealing_required};
use aegix_workflow_job_protocol::load_worker_key_ring;
use std::sync::Arc;
use worker::module_fetcher::{
    cosign_pin_under_profile, enforce_production_sigstore_policy_explicit, parse_cosign_version,
    parse_semver_triple, resolve_and_hash_cosign_binary,
    validate_sigstore_identity_regexp_for_policy, SigstorePolicy,
};
use worker::sql_validator;
use worker::worker_identity;

/// Run every boot gate, in order. `Err` is a refusal to start.
pub(crate) async fn enforce() -> anyhow::Result<aegix_dispatch_types::WorkerKeyRing> {
    // ========================================================================
    // SECURITY: Load and validate the shared key at startup.
    // Fail-fast if the key is absent or malformed — never start with no auth.
    // ========================================================================

    // Load the full verify/decrypt-ring (current + WORKER_SHARED_KEY_PREVIOUS).
    // The worker SIGNS results + RPC with the current key only; it VERIFIES
    // controller-signed jobs and DECRYPTS secrets against the whole ring, so a
    // rolling WORKER_SHARED_KEY rotation doesn't break either side mid-roll.
    let shared_key =
        load_worker_key_ring().map_err(|e| anyhow::anyhow!("WORKER_SHARED_KEY error: {}", e))?;
    // M-3 (partial): log a SHA-256 fingerprint of the shared key at
    // startup so config drift between controller and worker is visible
    // without exposing the key material. Operators can grep both
    // process logs for `worker_shared_key_fp=` and confirm they match
    // — if they don't, all signed RPCs will fail verification and the
    // error surfaces here instead of as opaque "signature verification
    // failed" later. We log only the first 8 hex chars (32 bits) which
    // is enough to detect mismatch with negligible info leak.
    {
        let fp_short = aegix_workflow_job_protocol::worker_key_fingerprint(
            shared_key.signing_key().as_bytes(),
        );
        let verify_count = shared_key.verify_keys().len();
        println!(
            "[0/5] Loaded WORKER_SHARED_KEY (32 bytes, fp={fp_short}, verify_keys={verify_count})"
        );
        ::tracing::info!(
            worker_shared_key_fp = %fp_short,
            verify_key_count = verify_count,
            "WORKER_SHARED_KEY loaded; compare this fingerprint against the controller's log line for drift detection"
        );
        for prev in shared_key.verify_keys().iter().skip(1) {
            ::tracing::info!(
                previous_worker_shared_key_fp =
                    %aegix_workflow_job_protocol::worker_key_fingerprint(prev.as_bytes()),
                "WORKER_SHARED_KEY_PREVIOUS accepted for verify/decrypt (rotation in progress)"
            );
        }
    }

    // The security profile (2026-10-29, AEGIX_SECURITY_PROFILE), resolved
    // FIRST: an unrecognised spelling refuses the boot in every environment,
    // `hardened` (the default wherever the deployment faces users) refuses
    // every acknowledgement the gates below would otherwise read
    // (AEGIX_ALLOW_LEGACY_FLEET_HMAC, AEGIX_WORKER_ALLOW_ENV_PROVIDER_KEYS,
    // AEGIX_ALLOW_UNATTESTED_WASM, an explicit AEGIX_WRITE_CEILING_ENFORCED=
    // false), and `transitional` logs each one at ERROR. Every gate below
    // asks the profile where it used to ask `is_production()` or
    // `browser_hardening_required()`.
    let security_profile = aegix_deploy_posture::security_profile::enforce_at_boot(
        aegix_deploy_posture::security_profile::Process::Worker,
    )
    .map_err(|e| anyhow::anyhow!(e))?
    .profile;
    let security_enforces = security_profile.enforces();

    // Wasm-security review 2026-05-22 (MEDIUM-4): production gate. Where the
    // profile enforces we refuse to boot unless the operator has made an
    // explicit Sigstore choice (required / audit / disabled; `audit` only
    // under `transitional`). Pre-fix,
    // `from_env` silently fell through to `Disabled` when the env var
    // was unset — the operator's monitoring saw a clean startup and
    // had no signal that signature verification was off. Mirrors the
    // `AEGIX_AOT_HMAC_KEY` boot discipline so production failures are
    // loud and immediate. Dev/test hosts (`is_production() == false`)
    // continue to see the silent default. An UNRECOGNISED value is refused
    // here in every environment (E-7, 2026-10-14), so the two startup checks
    // below read the policy this gate resolved.
    let sigstore_policy_at_boot = enforce_production_sigstore_policy_explicit()?;

    // Operator decision D2-B (2026-10-15): a worker in a deployment that faces
    // users (production, and staging as `docker-compose.prod.yml` runs it)
    // does not boot without the distributed replay guard, so a dispatch runs
    // once per fleet. No acknowledgement waives it.
    aegix_replay_guard::boot_requirement_from_env(security_enforces)
        .map_err(|e| anyhow::anyhow!(e))?;

    // An unrecognised AEGIX_ENVELOPE_SEALING refuses boot in every profile
    // (2026-11-18): it was read as `off`, and the gate below asks the mode.
    aegix_deploy_posture::envelope_sealing::from_env().map_err(|e| anyhow::anyhow!(e))?;

    // Security review 2026-10-14 (B-2): where the profile enforces, a worker
    // does not accept a dispatch signed with the fleet-shared
    // WORKER_SHARED_KEY unless AEGIX_ALLOW_LEGACY_FLEET_HMAC names `dispatch`
    // (read only under `transitional`). The controller gates results and RPC
    // at its own boot.
    aegix_deploy_posture::fleet_identity::enforce_production_fleet_identity(
        security_enforces,
        &[
            aegix_deploy_posture::fleet_identity::SurfaceSwitch {
                surface: aegix_deploy_posture::fleet_identity::LegacyFleetSurface::Dispatch,
                switch: "AEGIX_DISPATCH_REQUIRE_ED25519",
                required: aegix_deploy_posture::bool_env_or_default(
                    "AEGIX_DISPATCH_REQUIRE_ED25519",
                    false,
                ),
            },
            // The envelope (2026-10-29): under `off`/`audit` this worker
            // still OPENS an inline envelope sealed under the fleet key, so
            // a dispatch meant for a sibling is readable here too.
            aegix_deploy_posture::fleet_identity::SurfaceSwitch {
                surface: aegix_deploy_posture::fleet_identity::LegacyFleetSurface::Envelope,
                switch: "AEGIX_ENVELOPE_SEALING",
                required: worker_sealing_required(),
            },
        ],
        security_profile
            .honours_acknowledgements()
            .then(|| std::env::var("AEGIX_ALLOW_LEGACY_FLEET_HMAC").ok())
            .flatten()
            .as_deref(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    // A worker that requires sealing claims every secret-carrying job with
    // its Ed25519 identity; with no usable AEGIX_WORKER_SIGNING_KEY it could
    // claim nothing, and would fail every such job one at a time after the
    // controller had already handed the job to it. Refused at boot instead,
    // in every environment: there is no fallback to fall to.
    sealing_requires_a_signing_key(
        worker_sealing_required(),
        worker_result_signing_key().is_some(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    // L-4: Sigstore startup sanity — verify `cosign` is actually
    // executable when policy is non-Disabled. Pre-fix the missing
    // binary surfaced as a per-pull "cosign_unavailable" error;
    // production deploys that THOUGHT verification was running
    // discovered the gap only when an unsigned artifact slipped
    // through (or, in Required mode, when every pull failed).
    // Failing at boot in Required mode is loud, immediate, and
    // points at the right config knob.
    {
        let sigstore_policy = sigstore_policy_at_boot;
        if sigstore_policy != SigstorePolicy::Disabled {
            match tokio::process::Command::new("cosign")
                .arg("version")
                .output()
                .await
            {
                Ok(out) if out.status.success() => {
                    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
                    let version_line = stdout.lines().next().unwrap_or("(unknown)").to_string();

                    // M5 (2026-05-22): version-pin cosign so a swapped-in
                    // older binary (predating critical CVE fixes) or a
                    // replaced binary doesn't silently pass through.
                    // `AEGIX_COSIGN_MIN_VERSION` is the minimum
                    // semver-ish version accepted; default `2.0.0`
                    // matches the cosign 2.x line which is the
                    // long-supported branch with hardened defaults.
                    //
                    // Parse rule: pull the first dotted `X.Y.Z` token
                    // out of stdout (cosign output format has shifted
                    // across versions; the version triple is the only
                    // stable shape). Fail-closed in Required mode if
                    // we can't parse anything; warn-and-continue under
                    // Audit. This is operator-tunable via the env so
                    // a future cosign 3.x bump doesn't require code
                    // changes.
                    let min_version = std::env::var("AEGIX_COSIGN_MIN_VERSION")
                        .ok()
                        .filter(|v| !v.is_empty())
                        .unwrap_or_else(|| "2.0.0".to_string());
                    match parse_cosign_version(&stdout) {
                        Some((maj, min, patch)) => {
                            let parsed_observed = (maj, min, patch);
                            let parsed_min = parse_semver_triple(&min_version).unwrap_or((2, 0, 0));
                            if parsed_observed < parsed_min {
                                let msg = format!(
                                    "cosign version {}.{}.{} is below required minimum {} \
                                     (set AEGIX_COSIGN_MIN_VERSION to override)",
                                    parsed_observed.0,
                                    parsed_observed.1,
                                    parsed_observed.2,
                                    min_version,
                                );
                                if sigstore_policy == SigstorePolicy::Required {
                                    return Err(anyhow::anyhow!(
                                        "Sigstore startup sanity check failed: {msg}"
                                    ));
                                }
                                ::tracing::warn!(
                                    cosign_version = %version_line,
                                    min_version = %min_version,
                                    "{msg} (Audit mode: continuing)"
                                );
                            }
                        }
                        None => {
                            if sigstore_policy == SigstorePolicy::Required {
                                return Err(anyhow::anyhow!(
                                    "Could not parse cosign version from stdout: {version_line:?}. \
                                     Required policy refuses to boot without a verified version pin."
                                ));
                            }
                            ::tracing::warn!(
                                stdout = %stdout,
                                "Could not parse cosign version — version-pin check skipped (Audit mode)"
                            );
                        }
                    }

                    // M5 part B: optional SHA-256 pin of the cosign
                    // binary itself. When set, the worker hashes the
                    // resolved cosign executable and refuses to boot
                    // if the hash doesn't match. This closes the
                    // "swap cosign with a wrapper that always exits 0"
                    // attack path. Most operators won't set this;
                    // sigstore-enforcement clusters that want defense
                    // in depth absolutely should.
                    //
                    // L-3 (2026-05-22): under Required policy, advise
                    // operators who run WITHOUT a hash pin that an
                    // attacker with worker-pod write access (sidecar
                    // exploit, init-container compromise) can swap the
                    // cosign binary for a wrapper that always exits 0 —
                    // bypassing every other Sigstore gate. Loud WARN at
                    // startup so the gap is visible in production logs;
                    // not fail-closed because Required-without-pin is a
                    // legitimate (if weaker) deployment posture and the
                    // pin requires per-image hash bookkeeping operators
                    // may roll out separately from this code change.
                    //
                    // 2026-11-04: the bookkeeping is gone — the worker
                    // image bakes the pin (worker/Dockerfile, the sum its
                    // cosign download was verified against), so every
                    // deployment of the image is pinned and this WARN no
                    // longer fires there. A `required` worker with NO pin
                    // is now running outside the image, and under
                    // AEGIX_SECURITY_PROFILE=hardened that refuses the boot
                    // (`cosign_pin_under_profile`, the shape of the `audit`
                    // refusal); `transitional` and `development` keep the
                    // WARN below.
                    // docs/engineering-log/packages/2026-11-04-worker-cosign-pin-baked-in.md
                    let cosign_pin = std::env::var("AEGIX_COSIGN_SHA256")
                        .ok()
                        .filter(|v| !v.is_empty());
                    cosign_pin_under_profile(
                        security_profile,
                        sigstore_policy,
                        cosign_pin.is_some(),
                    )
                    .map_err(|e| anyhow::anyhow!(e))?;
                    if cosign_pin.is_none() && sigstore_policy == SigstorePolicy::Required {
                        ::tracing::warn!(
                            policy = ?sigstore_policy,
                            "AEGIX_COSIGN_SHA256 not set under Required Sigstore policy — \
                             cosign binary will not be hash-verified at startup. Set \
                             AEGIX_COSIGN_SHA256 to the sha256 of the bundled cosign \
                             binary for defense-in-depth against binary-swap attacks."
                        );
                    }
                    if let Some(expected_sha256) = cosign_pin {
                        match resolve_and_hash_cosign_binary().await {
                            Ok(actual) => {
                                use subtle::ConstantTimeEq as _;
                                let actual_lower = actual.to_lowercase();
                                let expected_lower = expected_sha256.trim().to_lowercase();
                                let eq: bool = actual_lower
                                    .as_bytes()
                                    .ct_eq(expected_lower.as_bytes())
                                    .into();
                                if !eq {
                                    if sigstore_policy == SigstorePolicy::Required {
                                        return Err(anyhow::anyhow!(
                                            "cosign binary sha256 mismatch: expected {expected_lower}, \
                                             got {actual_lower}. Required policy refuses to boot."
                                        ));
                                    }
                                    ::tracing::warn!(
                                        expected = %expected_lower,
                                        actual = %actual_lower,
                                        "cosign binary sha256 mismatch (Audit mode: continuing)"
                                    );
                                } else {
                                    ::tracing::info!(
                                        sha256 = %actual_lower,
                                        "cosign binary sha256 pin verified"
                                    );
                                }
                            }
                            Err(e) => {
                                if sigstore_policy == SigstorePolicy::Required {
                                    return Err(anyhow::anyhow!(
                                        "Could not hash cosign binary for SHA-256 pin: {e}. \
                                         Required policy refuses to boot."
                                    ));
                                }
                                ::tracing::warn!(
                                    error = %e,
                                    "Could not hash cosign binary — sha256 pin check skipped (Audit mode)"
                                );
                            }
                        }
                    }

                    ::tracing::info!(
                        cosign_version = %version_line,
                        policy = ?sigstore_policy,
                        "Sigstore startup sanity check: cosign binary OK"
                    );
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
                    if sigstore_policy == SigstorePolicy::Required {
                        return Err(anyhow::anyhow!(
                            "cosign binary present but `cosign version` exited non-zero (stderr: {stderr}). \
                             Required policy refuses to boot."
                        ));
                    }
                    ::tracing::warn!(
                        stderr = %stderr,
                        "Sigstore startup sanity check: cosign returned non-zero — verifications will fail"
                    );
                }
                Err(e) => {
                    if sigstore_policy == SigstorePolicy::Required {
                        return Err(anyhow::anyhow!(
                            "cosign binary not executable ({e}) and Sigstore policy is Required. \
                             Install cosign in the worker image or set AEGIX_SIGSTORE_REQUIRED=audit \
                             during migration."
                        ));
                    }
                    ::tracing::warn!(
                        error = %e,
                        "Sigstore startup sanity check: cosign not executable — Audit mode will warn-and-continue on every pull"
                    );
                }
            }
        }
    }

    // M-1: validate Sigstore identity regexp at startup so an operator
    // who set `AEGIX_SIGSTORE_REQUIRED=true` with a permissive pattern
    // discovers the policy is broken HERE — not silently per-pull when
    // every malicious-signature artifact passes verification. In
    // `Required` mode any rejection is fatal; in `Audit` mode we WARN
    // and continue (audit is the migration window). `Disabled` mode
    // skips this entirely.
    {
        let sigstore_policy_at_startup = sigstore_policy_at_boot;
        if sigstore_policy_at_startup != SigstorePolicy::Disabled {
            let regexp = std::env::var("AEGIX_SIGSTORE_IDENTITY_REGEXP").unwrap_or_default();
            // The policy-aware validator also refuses, under Required, a
            // workflow pin that does not pin the git ref (`…\.yml@` alone
            // admits a signature from any branch); Audit gets the warning.
            match validate_sigstore_identity_regexp_for_policy(&regexp, sigstore_policy_at_startup)
            {
                Ok(None) => {
                    ::tracing::info!(
                        policy = ?sigstore_policy_at_startup,
                        "Sigstore identity regexp validated at startup"
                    );
                }
                Ok(Some(warning)) => {
                    ::tracing::warn!(
                        policy = ?sigstore_policy_at_startup,
                        rejection = ?warning,
                        reason = %warning.human_reason(),
                        "AEGIX_SIGSTORE_IDENTITY_REGEXP accepted with a warning — \
                         would fail closed under Required"
                    );
                }
                Err(rejection) => match sigstore_policy_at_startup {
                    SigstorePolicy::Required => {
                        return Err(anyhow::anyhow!(
                            "AEGIX_SIGSTORE_IDENTITY_REGEXP rejected at startup ({:?}): {}. \
                             Fix the env var and restart — \
                             refusing to run under Required policy with broken config.",
                            rejection,
                            rejection.human_reason()
                        ));
                    }
                    SigstorePolicy::Audit => {
                        ::tracing::warn!(
                            rejection = ?rejection,
                            reason = %rejection.human_reason(),
                            "AEGIX_SIGSTORE_IDENTITY_REGEXP rejected under Audit policy — \
                             would fail closed under Required"
                        );
                    }
                    SigstorePolicy::Disabled => unreachable!(),
                },
            }
        }
    }

    // Install the same key into aegix-memory's RPC auth slot so the
    // WIT `agent_memory::*` and `graph_memory::*` host functions can
    // sign their NATS requests. The controller registers the same
    // key on its side for verification (see controller/src/main.rs).
    // Worker only SIGNS its outbound RPC (controller verifies), so the
    // current/signing key is all rpc_auth needs here.
    aegix_rpc_protocol::rpc_auth::register_hmac_key(Arc::new(
        shared_key.signing_key().as_bytes().to_vec(),
    ));

    // RFC 0010 P2 inc.3: when a per-worker Ed25519 key is provisioned
    // (AEGIX_WORKER_SIGNING_KEY — the SAME key used to sign job results),
    // also register it as the RPC signing identity so memory/graph/database/
    // state/integration-state requests are signed Ed25519 under this worker's
    // id. The controller resolves the matching public key by worker_id and
    // verifies asymmetrically; the HMAC key above stays registered so the
    // controller's dual-verify accepts either scheme during rollout. Absent
    // the key, RPC signing stays on the legacy HMAC path unchanged.
    if let Some(rpc_signing_key) = worker_result_signing_key() {
        aegix_rpc_protocol::rpc_auth::register_ed25519_signing_key(
            worker_identity().to_string(),
            Arc::new(rpc_signing_key.clone()),
        );
        ::tracing::info!(
            target: "talos_security",
            worker_id = %worker_identity(),
            "Registered per-worker Ed25519 RPC signing identity (RFC 0010 P2 inc.3)"
        );

        // RFC 0010 P2 inc.4d: self-register this worker's public key with the
        // controller (if AEGIX_CONTROLLER_URL + AEGIX_WORKER_REGISTRATION_TOKEN
        // are set). Best-effort and detached so it never blocks boot or job
        // processing; the signing key is `&'static` (OnceLock), so it moves into
        // the task cleanly.
        tokio::spawn(worker::self_register::register_worker_identity_at_boot(
            rpc_signing_key,
        ));

        // Periodic liveness ping. Registration alone told the controller this
        // key EXISTS; nothing told it the process was still running, so a
        // departed worker's public key stayed in the trusted verify ring
        // forever. This is the refresh that lets the controller bound that.
        // Detached and best-effort like the registration above — a failed ping
        // never touches job processing, and the controller's window is many
        // multiples of the interval so only sustained silence reaps a key.
        tokio::spawn(worker::liveness::run_liveness_pinger(rpc_signing_key));
    }

    // M-3 (2026-05-22): log the SQL empty-allowlist policy at startup
    // so operators can confirm the mode they're running. Default is
    // `DenyMutations` (least-privilege); `AllowAllNonDdl` is the
    // legacy permissive mode reachable via
    // `AEGIX_SQL_PERMISSIVE_EMPTY_ALLOWLIST=1`. Logged at INFO so it
    // appears once at boot without spamming normal traffic.
    {
        let sql_policy = sql_validator::EmptyAllowlistPolicy::from_env();
        match sql_policy {
            sql_validator::EmptyAllowlistPolicy::DenyMutations => {
                ::tracing::info!(
                    policy = "DenyMutations",
                    "SQL validator: empty allowlist permits SELECT/EXPLAIN only (default)"
                );
            }
            sql_validator::EmptyAllowlistPolicy::AllowAllNonDdl => {
                ::tracing::warn!(
                    policy = "AllowAllNonDdl",
                    "SQL validator: legacy permissive mode is enabled via \
                     AEGIX_SQL_PERMISSIVE_EMPTY_ALLOWLIST — JobRequests with empty \
                     allowed_sql_operations admit every non-DDL non-AlwaysBlocked \
                     statement type. Prefer setting allowed_sql_operations explicitly."
                );
            }
        }
    }

    Ok(shared_key)
}
