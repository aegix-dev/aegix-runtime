//! How the worker starts, after its boot gates and before its job loop:
//! observability, the connection and subscription to the message bus, and
//! the runtime with its Redis tiers.
//!
//! These are three sections of `main()`, moved out 2026-11-18 as three
//! functions with their statements in the order they had. What each takes
//! and returns is exactly what the rest of `main()` gave it and read from
//! it.

use crate::nats_connect::{connect_nats_with_identity, worker_connect_options};
use crate::{
    dispatch_replay, register_dispatch_replay_guard, rejected_jobs, report_redis_identity,
};
use async_nats::{Client, Subscriber};
use std::sync::Arc;
use worker::runtime::AegixRuntime;
use worker::{circuit_breaker, metrics};

/// Metrics, tracing, the panic hook, the seeded counters and the periodic
/// sweeps. Nothing it builds is read by the rest of `main()`.
pub(crate) async fn init_observability(non_dumpable: &Result<(), String>) -> anyhow::Result<()> {
    // ========================================================================
    // OBSERVABILITY INITIALIZATION
    // ========================================================================

    println!("[1/5] Initializing observability...");

    if let Err(e) = metrics::init_telemetry() {
        eprintln!("Warning: Failed to initialize metrics: {}", e);
        eprintln!("    Continuing without metrics...");
    } else {
        println!("      Metrics initialized");
    }

    // Initialise OTel tracing FIRST — `init_tracing` installs the SDK provider
    // (+ the W3C propagator used by `extract_trace_context`). The otel bridge
    // layer in the subscriber below pulls a tracer from that provider, so the
    // provider must exist before the subscriber is built.
    //
    // UNCONFIGURED MUST MEAN DISABLED — the controller carried the byte-identical
    // defect and both are fixed together; repairing one of two sites is how a
    // uniform bug becomes a per-binary one that survives far longer. This used to
    // be `env::var("JAEGER_ENDPOINT").ok().or_else(|| Some("http://localhost:4317"))`,
    // whose `or_else` made `init_tracing`'s `None` ⇒ disabled path unreachable, so
    // an unconfigured worker exported spans to itself and logged an export ERROR
    // per flush forever. `endpoint_from_env` is the shared chokepoint.
    let trace_endpoint = worker::tracing::endpoint_from_env();

    // Called UNCONDITIONALLY, including with `None`, so "tracing is off" is
    // stated in the log rather than being indistinguishable from silence.
    match worker::tracing::init_tracing("talos-worker", trace_endpoint.as_deref()) {
        Ok(()) => match trace_endpoint.as_deref() {
            Some(endpoint) => println!(
                "      Tracing enabled (endpoint: {})",
                worker::tracing::redact_endpoint(endpoint)
            ),
            None => println!(
                "      Tracing DISABLED (no endpoint configured; set one of {})",
                worker::tracing::TRACE_ENDPOINT_ENV_VARS.join(", ")
            ),
        },
        Err(e) => {
            eprintln!("Warning: Failed to initialize tracing: {}", e);
            eprintln!("    Continuing without tracing...");
        }
    }
    aegix_deploy_posture::process_posture::log_non_dumpable_outcome(non_dumpable);

    // Install the tracing subscriber. The fmt layer keeps host_impl.rs
    // `tracing::warn!`/`info!` (security checks, vault allowlist, SSRF blocks,
    // rate limits) in `docker logs` (RUST_LOG, default: worker=info,warn). The
    // optional OTel bridge layer — present only when `init_tracing` installed a
    // provider above (OTLP endpoint configured) — exports the worker's `tracing`
    // spans to OTLP so each `job-execution` span (and the host-function spans
    // nested under it) appears in the trace backend, linked to the controller's
    // `workflow` span via the propagated context.
    //
    // PERF: the worker is the hot WASM-execution path. Span volume is bounded by
    // the global EnvFilter (info/warn) AND the otel sampler: the SDK default is
    // ParentBased(AlwaysOn), so jobs that carry a sampled controller context
    // inherit its decision; root jobs (e.g. module-bound gmail/gcal dispatch with
    // no controller span) sample at AlwaysOn. High-throughput deployments should
    // configure a ratio sampler on the controller (the parent) to bound export.
    {
        use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};
        let filter = EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| EnvFilter::new("worker=info,warn"));
        // SECURITY CHOKEPOINT — `otel_bridge_layer` is the ONE constructor for
        // this layer in the workspace; the controller builds its own from the
        // same function. Built inline, `tracing_opentelemetry::layer()`
        // promotes every in-span `tracing` EVENT into an exported span event
        // named with the formatted message — which in this binary includes
        // un-redacted guest WASM log lines (`[WASM] {msg}`) plus ~418 other
        // event callsites that interpolate upstream error text. The shared
        // constructor filters promoted events out; deliberate span writes
        // (`JobSpan`, `ExecutionSpan`) are unaffected and stay redacted. See
        // `aegix_trace::otel_bridge_layer_with_tracer`.
        let otel_layer = worker::tracing::otel_bridge_layer("talos-worker");
        tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true).with_thread_ids(false))
            .with(otel_layer)
            .init();
    }

    // Process-wide panic hook, installed immediately after the subscriber
    // (its whole output is one structured `tracing` line) and before the
    // job loop can spawn anything. Its collectors go into
    // `prometheus::default_registry()`, which is the registry
    // `metrics::get_prometheus_metrics()` gathers for `/metrics` — the
    // same one `seed_circuit_breaker_series` seeds into — so
    // `aegix_task_panics_total{process="worker"}` is exported by a worker
    // even when the OTEL exporter build failed. Only THIS process's label
    // value is seeded: a `{process="controller"}` series on a worker's
    // `/metrics` would imply a signal nothing here can increment.
    aegix_task_supervision::install_panic_hook("worker");
    // The worker supervises NO `BackgroundTask`, so it seeds NO
    // `aegix_background_task_exits_total` series. Until 2026-09-08 it
    // passed the whole table implicitly and its `/metrics` carried all
    // 126 controller-only `(task, outcome)` pairs at 0 — measured live —
    // i.e. seeded combinations nothing in this process can ever
    // increment, which is check 58's own rule and the very claim the
    // comment above makes about the `process` label. If a worker loop is
    // ever supervised, name it here.
    if let Err(e) = aegix_task_supervision::register_metrics(prometheus::default_registry(), &[]) {
        eprintln!("Warning: failed to register panic metrics: {e}");
    }
    rejected_jobs::seed();
    dispatch_replay::seed();

    // MCP-580: spawn the circuit-breaker periodic cleanup task so the
    // per-host `records` DashMap doesn't grow monotonically with
    // distinct hosts seen across the worker's lifetime. Idempotent at
    // the breaker level (only Closed stale entries get evicted; Open /
    // HalfOpen are preserved). Pre-fix the cleanup() method existed
    // but had zero callers.
    circuit_breaker::spawn_periodic_cleanup();

    // FU-2 (R2-5): periodically sweep the job-idempotency cache so expired
    // completed-result entries don't linger on a worker that goes idle.
    // Read-path eviction handles active job_ids; this is the companion sweep
    // (CLAUDE.md cache rule: TTL cache = read-path eviction + periodic sweep).
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(
            worker::job_idempotency::SWEEP_INTERVAL_SECS,
        ));
        tick.tick().await; // skip the immediate first tick
        loop {
            tick.tick().await;
            worker::job_idempotency::JOB_RESULT_CACHE.sweep();
        }
    });

    Ok(())
}

/// What [`connect_bus`] hands back to `main()`.
pub(crate) struct Bus {
    /// The bus address as configured, for the job loop's log line.
    pub(crate) nats_url: String,
    /// Read once here; the runtime's Redis posture asks the same answer.
    pub(crate) is_production: bool,
    pub(crate) nc: Client,
    pub(crate) single_job_topic: String,
    pub(crate) sub: Subscriber,
}

/// Connect to the bus under the configured credential, subscribe to the job
/// subject as a queue group, and start the fleet heartbeat.
pub(crate) async fn connect_bus(
    shared_key: &aegix_dispatch_types::WorkerKeyRing,
) -> anyhow::Result<Bus> {
    // ========================================================================
    // NATS CONNECTION
    // ========================================================================

    println!("\n[2/5] Connecting to NATS...");
    // MCP-631: empty-env hardening — `NATS_URL=""` (Helm placeholder)
    // would otherwise produce an empty URL and NATS connect fails with
    // a confusing parse error rather than using the default.
    let nats_url = std::env::var("NATS_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "nats://127.0.0.1:4222".to_string());

    // Sanitize the URL for logging — strip embedded credentials (nats://user:pass@host).
    let nats_url_safe = {
        let mut u = nats_url.clone();
        if let Some(at) = u.find('@') {
            let scheme_end = u.find("://").map(|i| i + 3).unwrap_or(0);
            u.replace_range(scheme_end..at + 1, "[credentials]@");
        }
        u
    };

    // SECURITY: Use authenticated connection when NATS_USER + NATS_PASSWORD are set.
    // MCP-631: empty-env hardening — pre-fix, `NATS_USER=""` +
    // `NATS_PASSWORD=""` (Helm placeholder) produced
    // `(Some(""), Some(""))` which matched the authenticated branch
    // BELOW, BYPASSING the production-mode auth gate. The worker
    // would then attempt to authenticate with empty credentials; if
    // the NATS server happened to allow anonymous connections (no
    // auth file), the worker would silently connect anonymously
    // despite the operator's intent. Treating empty as unset routes
    // the request through the unauthenticated branch where the
    // production gate refuses it. Sibling to MCP-590/591/592 family.
    let nats_user = std::env::var("NATS_USER").ok().filter(|v| !v.is_empty());
    let nats_password = std::env::var("NATS_PASSWORD")
        .ok()
        .filter(|v| !v.is_empty());
    // MCP-668 (2026-05-13): route through `aegix_deploy_posture::is_production()` so
    // a helm-rendered empty `RUST_ENV=""` doesn't bypass this gate. Raw
    // `unwrap_or_default()` produced `""` which !== `"production"`, allowing
    // the worker to fall through to unauthenticated NATS even in prod.
    // Same empty-env-var family as MCP-590/591/592/630/631 and the
    // MCP-653 RUST_ENV long-tail closure.
    let is_production = aegix_deploy_posture::is_production();

    // SECURITY (2026-07-19, L5): in production, REFUSE to start on a plaintext
    // NATS URL — same fail-closed posture the controller enforces
    // (tls-prod-gate-nats). The worker sends HMAC-signed job RESULTS and
    // receives decrypted secrets over this bus; cleartext on the wire is a
    // transmission-security violation (HIPAA §164.312(e) / SOC2 CC6.7). Before
    // this gate the worker only required NATS *auth* in prod and relied on
    // NATS_CA_FILE being set to force TLS — an operator with a plaintext
    // `nats://` URL and no CA file transmitted credentials + payloads in the
    // clear where the controller would have refused to boot.
    // tls-prod-gate-nats
    if is_production && !nats_url.starts_with("tls://") && !nats_url.starts_with("nats+tls://") {
        return Err(anyhow::anyhow!(
            "NATS_URL must use TLS (tls:// or nats+tls://) in production — refusing to \
             start. Got scheme: '{}'.",
            nats_url.split("://").next().unwrap_or("<unknown>")
        ));
    }

    // How the worker authenticates (2026-11-06, worker::nats_identity). Both
    // settings are checked before anything connects: a wrong spelling, or an
    // ephemeral identity with no way to register, refuses boot.
    let nats_auth = worker::nats_identity::parse_nats_auth(
        std::env::var("AEGIX_WORKER_NATS_AUTH").ok().as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    let identity_mode = aegix_wasm_host::worker_identity::parse_identity_mode(
        std::env::var("AEGIX_WORKER_IDENTITY").ok().as_deref(),
    )
    .map_err(anyhow::Error::msg)?;
    let registration_token = worker::nats_identity::registration_credential(
        std::env::var("AEGIX_WORKER_REGISTRATION_TOKEN")
            .ok()
            .as_deref(),
        std::env::var("AEGIX_WORKER_REGISTRATION_TOKEN_FILE")
            .ok()
            .as_deref(),
        |p| std::fs::read_to_string(p),
    )
    .map_err(anyhow::Error::msg)?;
    worker::nats_identity::check_identity_settings(
        nats_auth,
        identity_mode,
        registration_token.is_some(),
    )
    .map_err(anyhow::Error::msg)?;

    let nc: Client = match (nats_auth, nats_user, nats_password) {
        (worker::nats_identity::NatsAuth::Identity, _, _) => {
            connect_nats_with_identity(&nats_url, &nats_url_safe, identity_mode, registration_token)
                .await?
        }
        (_, Some(user), Some(pass)) => {
            // apply_nats_ca adds the in-cluster NATS CA + requires TLS when
            // NATS_CA_FILE is set (tls:// URL); no-op otherwise.
            let opts = worker_connect_options().user_and_password(user, pass);
            match aegix_nats_tls::apply_nats_ca(opts).connect(&nats_url).await {
                Ok(c) => {
                    println!(
                        "      Connected to NATS (authenticated) at {}",
                        nats_url_safe
                    );
                    c
                }
                Err(e) => {
                    eprintln!("Failed to connect to NATS at {}: {}", nats_url_safe, e);
                    eprintln!("   Check NATS_USER/NATS_PASSWORD credentials.");
                    return Err(anyhow::anyhow!(e));
                }
            }
        }
        _ => {
            // SECURITY: In production, require NATS authentication to prevent
            // unauthorized job submission and message interception.
            if is_production {
                eprintln!("CRITICAL SECURITY ERROR: NATS_USER and NATS_PASSWORD must be set in production.");
                eprintln!(
                    "   Unauthenticated NATS connections are not allowed in production mode."
                );
                return Err(anyhow::anyhow!(
                    "NATS authentication required in production (set NATS_USER and NATS_PASSWORD)"
                ));
            }
            ::tracing::warn!(
                "NATS_USER/NATS_PASSWORD not set — connecting without authentication. \
                 This is acceptable for development but MUST NOT be used in production."
            );
            let opts = aegix_nats_tls::apply_nats_ca(worker_connect_options());
            match opts.connect(&nats_url).await {
                Ok(c) => {
                    println!(
                        "      Connected to NATS (unauthenticated) at {}",
                        nats_url_safe
                    );
                    c
                }
                Err(e) => {
                    eprintln!("Failed to connect to NATS at {}: {}", nats_url_safe, e);
                    eprintln!("   Make sure a NATS server is running.");
                    return Err(anyhow::anyhow!(e));
                }
            }
        }
    };

    // Retrieve configurable NATS queue topics or use defaults.
    // This enables per-customer VPC "Edge Node" routing.
    // MCP-631: empty-env hardening — empty NATS topic would silently
    // subscribe to "" which behaves as an unsubscribed topic and the
    // worker would receive no jobs without a loud error.
    let single_job_topic = std::env::var("NATS_JOB_TOPIC")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| aegix_workflow_job_protocol::subjects::JOBS.to_string());
    // Use the topic names as the queue groups so multiple edge nodes on the same topic load-balance
    let queue_group = single_job_topic.clone();

    let sub: Subscriber = nc
        .queue_subscribe(single_job_topic.clone(), queue_group.clone())
        .await?;
    println!(
        "      Subscribed to '{}' queue (group: {})",
        single_job_topic, queue_group
    );

    // ---------- Fleet heartbeat ----------
    // Publish a signed heartbeat on `talos.workers.heartbeat.<worker_id>` so
    // the controller has a live view of which worker PROCESSES are running.
    //
    // TWO THINGS THIS IS NOT, both easy to over-read. It is not the liveness
    // ping spawned above: that is an Ed25519 proof of possession of THIS
    // worker's own registered key, and it is the only thing that may keep a
    // signing key trusted. This heartbeat is an HMAC under the FLEET-SHARED
    // `WORKER_SHARED_KEY`, so any process holding that key can mint one naming
    // any worker_id — observability, never trust. And it is not a dispatch
    // input: nothing routes jobs on the fleet view.
    //
    // Detached and best-effort like the two registrations above; ceasing to
    // heartbeat costs visibility only, never trust.
    tokio::spawn(worker::heartbeat::run_heartbeat_publisher(
        nc.clone(),
        shared_key.signing_key().as_bytes().to_vec(),
    ));

    Ok(Bus {
        nats_url,
        is_production,
        nc,
        single_job_topic,
        sub,
    })
}

/// Connect Redis when it is configured, register the replay guard and the
/// local-inference fleet, and build the runtime.
pub(crate) async fn build_runtime(
    nc: &Client,
    shared_key: &aegix_dispatch_types::WorkerKeyRing,
    is_production: bool,
) -> anyhow::Result<Arc<AegixRuntime>> {
    // ========================================================================
    // RUNTIME INITIALIZATION (with NATS client for logging)
    // ========================================================================

    // ========================================================================
    // REDIS CONNECTION (Phase 1: Decoupled Read Path)
    // ========================================================================

    println!("\n[2.5/5] Connecting to Redis...");
    let redis_client = if let Ok(redis_url) = std::env::var("REDIS_URL") {
        // SECURITY: Require TLS (rediss://) in production to prevent credential
        // and data interception on the network.
        if is_production && !redis_url.starts_with("rediss://") {
            eprintln!("FATAL: REDIS_URL must use rediss:// (TLS) in production");
            std::process::exit(1);
        }
        match aegix_redis::client(redis_url.as_str()) {
            Ok(client) => {
                // Test connection
                match aegix_redis::multiplexed(&client).await {
                    Ok(mut conn) => {
                        println!(
                            "      Connected to Redis at {}",
                            redis_url.split('@').next_back().unwrap_or("redis")
                        );
                        report_redis_identity(&mut conn).await;
                        Some(Arc::new(client))
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to connect to Redis: {}. WASM cache interface will be unavailable.", e);
                        None
                    }
                }
            }
            Err(e) => {
                eprintln!("Warning: Failed to create Redis client: {}. WASM cache interface will be unavailable.", e);
                None
            }
        }
    } else {
        println!("      REDIS_URL not configured. WASM cache interface will be unavailable.");
        None
    };

    // Fleet-wide job idempotency tier (2026-07-01): jobs arrive via a NATS
    // queue group, so a controller transport-retry can land on a DIFFERENT
    // worker whose in-process result cache is cold — re-executing side
    // effects. Backing the cache with the same Redis makes dedup fleet-wide;
    // absent/unreachable Redis degrades to same-worker-only (the old
    // behavior), never an error.
    // RFC 0014 P4a: count local LLM timeouts by which deadline fired.
    worker::local_llm_fleet::install_timeout_series();
    if let Some(ref client) = redis_client {
        worker::job_idempotency::init_redis(client.as_ref().clone()).await;
        register_dispatch_replay_guard(client.as_ref()).await;
        // RFC 0014 P3b: queue local LLM calls with the controller and the
        // other workers, not only within this process. Never fatal.
        worker::local_llm_fleet::install(client.as_ref().clone()).await;
    } else if aegix_replay_guard::distributed_replay_from_env() {
        // B2-2: the switch asks for a shared guard and there is no Redis to
        // hold one; the replay policy refuses every dispatch when failing
        // closed. Said once, loudly, at boot.
        ::tracing::error!(
            target: "talos_security",
            fail_closed = aegix_replay_guard::fail_closed_from_env(),
            "AEGIX_DISTRIBUTED_REPLAY is on but REDIS_URL is unset — no replay guard; every \
             dispatch is refused when failing closed"
        );
    }

    // PostgreSQL connection block removed Phase 2.10. Worker is now
    // credential-free: the WIT `database::execute_query` host
    // function dispatches via signed NATS-RPC to the controller
    // (Phase 2.3). DATABASE_URL is intentionally not read here.

    println!("\n[3/5] Creating WASM runtime...");
    // The Redis tier of the module result cache is sealed under a key derived
    // from WORKER_SHARED_KEY (E-4, 2026-10-14): every worker of the fleet
    // opens what another sealed, and a value written by anyone without the
    // key is a miss. See aegix_wasm_host::result_cache_seal.
    let runtime = Arc::new(
        AegixRuntime::with_resources(
            redis_client.clone(),       // Redis client for WASM fetching and caching
            Some(Arc::new(nc.clone())), // NATS client for WASM log publishing
            None,                       // No file system sandbox for now
        )?
        .with_result_cache_seal_key(
            worker::result_cache_seal::ResultCacheSealKey::derive(
                shared_key.signing_key().as_bytes(),
            ),
        ),
    );
    println!("      Runtime created with NATS logging enabled (worker is credential-free; database access via NATS-RPC)");

    // The epoch-interruption ticker (the third kill switch alongside fuel +
    // wall-clock timeout) is started by `AegixRuntime::with_resources`
    // itself since 2026-09-25 — on a dedicated OS thread, so compute-bound
    // guests cannot starve it — and must NOT be started again here: a second
    // ticker would advance the epoch twice per interval and halve every
    // job's wall-clock budget.
    println!("      Epoch-interruption ticker started by the runtime (third kill switch alongside fuel + wall-clock timeout)");

    Ok(runtime)
}
