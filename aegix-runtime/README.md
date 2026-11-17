# aegix-runtime

The Aegix runtime as one embeddable unit, apart from the platform built on it.

The **runtime** is a wasmtime host that runs untrusted WebAssembly components
under capability gating, a signed job protocol between a controller and a
pool of workers that hold no secret store, and a signed data plane for
everything a module reads or writes. It is developed inside a larger
workflow platform, and until 2026-10-29 it had no boundary of its own:
nothing could be built or embedded without that platform around it. This
crate is that boundary. It implements nothing; every item is a `pub use` of a crate below the line, and
a lint in the repository this crate is developed in (structural check 109,
its `check-runtime-boundary` target) refuses a platform crate anywhere in its
dependency closure.

```text
aegix-runtime            ← you depend on this, at RUNTIME_API_VERSION
├── aegix-worker-runtime      the wasmtime host: AegixRuntime, AegixContext, host functions
├── aegix-workflow-job-protocol  JobRequest / JobResult, signing, the secrets envelope
├── aegix-rpc-protocol        the signed-RPC client side (rpc_auth) and the per-subject protocols
├── aegix-capability-world    the capability lattice
├── aegix-wit-inspector       which world a binary fits
└── aegix-replay-guard        the distributed replay guard a hardened worker needs
```

## What it guarantees

- **One name, one version.** `RUNTIME_API_VERSION` is the crate's version and
  is bumped with it. A change to any re-exported surface is a change to this
  crate's version, not something an embedder discovers from a transitive crate.
- **No platform in the closure.** `cargo tree -p aegix-runtime -e normal`
  contains no MCP handler, no GraphQL schema, no controller binary, no
  `aegix-*-repository`, no `aegix-*-service`, no integration and no engine.
  Check 109 holds this on every lint run in the development repository; its
  one home for the names is that repository's `lint-runtime-boundary.py`.
- **The WIT ships with it.** `aegix_runtime::WIT` is `wit/aegix.wit` byte for
  byte, the host API a component is compiled against, with the capability
  worlds that bundle its interfaces. `tests/embed.rs` builds a component from
  it and runs it.
- **The production configuration.** `AegixRuntime::new()` is what the deployed
  worker constructs: fuel metering, the epoch-deadline ticker that preempts a
  loop no timeout can, the pooling allocator, per-execution ephemeral
  sandboxes, the SSRF resolver in front of every outbound host call.

## What it does not guarantee

- **Stability before 1.0.** The re-exported types keep their shapes and wire
  formats from the crates below; the facade adds no compatibility layer. A
  bump of this crate's minor version may change them.
- **A controller.** The runtime is one half of a two-process design. The
  controller (the thing that holds every secret, signs dispatches, answers
  the signed RPCs and seals secret envelopes) is not in this crate. The
  platform's is built on Postgres; `aegix-reference-controller` is the
  smallest one, with its record in memory. `examples/embed_worker.rs` runs a component with no
  controller at all; a host call that needs one (`agent-memory`, `secrets`,
  `database`) is then refused, exactly as it is refused in production.
- **A small closure, and no database.** Check 109 names platform crates AND
  refuses `sqlx` and `pgvector` anywhere in the closure (since 2026-10-30,
  when the signed-RPC protocols moved out of `aegix-memory` into
  `aegix-rpc-protocol`, a leaf with no database, embedding or HTTP
  dependency); since the same day, `axum` / `axum-*` (the HTTP middleware
  of `aegix-idempotency` is behind its `axum` feature, off by default; the
  runtime uses that crate's dedup store only); and, since 2026-11-01,
  `opentelemetry-otlp`, `opentelemetry-proto`, `tonic` / `tonic-*` and
  `prost` / `prost-*` (the OTLP span exporter of `aegix-trace` is behind its
  `otlp` feature, off by default; the runtime keeps the span types, the
  `tracing`→OTel bridge layer and the redaction sink, and exports nothing);
  and, since 2026-11-02, `oci-client` / `oci-spec` (the `oci://` registry
  pull of `module_fetcher` is `aegix-worker-runtime`'s `oci` feature, off by
  default: an embedder runs modules from bytes) and `prometheus` /
  `opentelemetry-prometheus` (the Prometheus default registry and the
  OTel→Prometheus reader are its `prometheus` feature, off by default; the
  OTel instruments stay and record into the no-op global meter).
  The closure is 346 crates. An embedder that does export traces turns on
  this crate's own `otlp` feature, which passes through to `aegix-trace`;
  without it, `init_tracing` refuses a configured endpoint with a log line
  (`NoExporterInThisBuild`) rather than exporting nothing in silence. The
  same shape for the other two: `oci` passes through to the registry client,
  and without it an `oci://` dispatch is refused by `fetch` with
  `NoRegistryClientInThisBuild` (a boot line names a configured Sigstore
  policy or registry credential the build cannot use); `prometheus` passes
  through to the exposition, and without it `metrics::init_telemetry`
  refuses with `NoMetricsExporterInThisBuild`. `HAS_OTLP_EXPORTER`,
  `HAS_OCI_REGISTRY_CLIENT` and `HAS_PROMETHEUS_EXPORTER` say which build
  you have. What stays, by decision: `reqwest` (the HTTP host functions),
  `redis` (the sealed result cache, the dedup reservation, the replay guard)
  and `async-nats` (the signed data plane itself — every data-plane RPC a
  host call makes is a NATS request).
- **The controller side of sealing.** `envelope_seal` here is the worker's
  half: the ephemeral key, the signed claim, the sealed reply it opens. The
  in-flight seal store and the claim responder are `aegix-envelope-seal`.

## The five security properties, and where they are here

These are the "Core architectural decisions" of the development
repository's README, as an embedder meets them.

1. **Credential-free worker.** A module receives an opaque handle to a secret,
   never the string; the worker holds no master key and decrypts a per-job
   envelope only. `worker_runtime::host_impl::check_secret_allowlist` enforces
   both the module's `allowed_secrets` grant and the host-reserved deny-list;
   `job_protocol::EncryptedSecrets` is the AES-256-GCM envelope; a resolved
   map is a `SecretMap` of zeroizing values from the moment it opens.
2. **Signed cross-process data plane.** Every RPC the worker makes is bound to
   `(subject, actor_id, nonce, body)` by HMAC-SHA256 or Ed25519
   (`rpc_auth::sign_rpc` / `verify_rpc`), with a two-generation nonce cache
   and an asymmetric freshness window (60 s past, 5 s future); a
   `JobRequest` is verified once per process (`verify`), and a passive
   observer uses `verify_no_replay`. `RawSigned<T>` binds the exact wire
   text of a JSON body so signer and verifier cannot disagree on a float.
3. **Capability lattice.** `CapabilityWorld::is_subset_of` is a partial order,
   not a ladder: `Filesystem ⊄ Secrets`, `Database ⊄ Agent`. A module is
   linked into the world it was checked at and no other; `inspect_component`
   reads which one a binary fits from its import section, and
   `wit_inspector::imports_outside_world` says what it would need beyond a
   given world.
4. **Per-actor LLM tier ceiling.** `LlmTier::Tier1` means local inference
   only. The tier travels HMAC-bound in the job and is enforced at five host
   surfaces in `worker_runtime::host_impl` (key resolution, `vault://` header
   substitution, HTTP, GraphQL, webhook and stream egress to
   `job_protocol::EXTERNAL_LLM_HOSTS`); `EgressScope` is the separate axis
   that lets a tier-1 module reach a declared public API without an external
   model.
5. **Sigstore-verified module supply chain.** A module pulled from a registry
   is digest-checked and, under `SigstorePolicy::Required`, `cosign`-verified
   against a pinned certificate identity and OIDC issuer before it is
   instantiated or cached (`worker_runtime::module_fetcher`, with this
   crate's `oci` feature on); a cached result is sealed under a key the cache
   key is bound to.

## How to embed

```toml
[dependencies]
aegix-runtime = { git = "https://github.com/aegix-dev/aegix-runtime" }   # or `path = …` to a checkout
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use aegix_runtime::{inspect_component, AegixRuntime};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bytes = std::fs::read("echo_debug.wasm")?;
    let inspection = inspect_component(&bytes);
    anyhow::ensure!(inspection.is_aegix_node, "not an Aegix node");

    let runtime = AegixRuntime::new()?;
    let output = runtime
        .execute_module_string(&bytes, r#"{"message":"hello"}"#)
        .await?;
    println!("{output}");
    Ok(())
}
```

`cargo run -p aegix-runtime --example embed_worker -- <component.wasm>` is
the same thing as a program. A component is a `aegix:core` node compiled
against `aegix_runtime::WIT`: a Rust module compiled with `cargo component`
against `wit/aegix.wit` (`module-templates/echo-debug/template.rs` is the
smallest), or, as `tests/embed.rs` does, a core module with `run` and
`cabi_realloc` exported, encoded into a world with `wit-component`.

To build that component yourself, the host needs the `wasm32-wasip2` target
and `cargo-component` (0.21.1 is the version the builder images pin);
neither comes with a Rust install. The `compile_module` example of
`aegix-compilation` takes one source file through the compile path a
controller uses, which writes the module's Cargo project and bindings for
it:

```bash
rustup target add wasm32-wasip2
cargo install cargo-component@0.21.1 --locked
cargo run -p aegix-compilation --example compile_module -- \
    module-templates/echo-debug/template.rs minimal-node echo_debug.wasm
cargo run -p aegix-runtime --example embed_worker -- echo_debug.wasm '{"message":"hello"}'
```

The component is written to the path the last argument names (99 KB), and
the checkout is left as it was: the module's Cargo project and bindings are
made in a build directory outside it. The run answers with the module's
output stamped with the fuel it spent (`__fuel_consumed__`,
`__fuel_limit__`) beside its own fields. Measured 2026-11-01 on an Apple
Silicon laptop with a cold target directory and no compile cache (recorded
in the development repository's engineering log,
`2026-11-01-outside-reader-first-hour.md`): the example builds in 49 s (375
crates by name, 405 by name and version, a 3.5 GB `target/`), `cargo test -p
aegix-runtime` takes 8 s more, and the run answers in 4 s. (The crate count
was 375 when that was measured; it is 346 since the 2026-11-02 cut. The
`compile_module` step was not part of that measurement: it builds
`aegix-compilation` as well.)

For more than one module at a time use `execute_job_with_full_features`,
which takes the module's grants (`allowed_hosts`, `allowed_secrets`, the
method allowlist), its fuel and wall-clock budgets, the actor's ceilings and
the `SecretMap` the controller sealed for it; `AegixRuntime::with_resources`
adds Redis (the sealed result cache, the OCI pull cache), NATS (the signed
RPCs) and a sandboxed directory.

## How to talk to a controller

A deployed worker is `worker/src/main.rs` in the repository; it is the
reference for the sequence, which this crate carries all the types for:

1. **Identity.** The worker holds an Ed25519 signing key
   (`job_protocol::DispatchSigningKey`) and registers its public half with a
   proof of possession (`sign_worker_registration_proof`), renewed by a
   liveness proof (`sign_worker_liveness_proof`) that bounds how long its key
   stays in the controller's verify ring after the process departs.
2. **Dispatch.** A `JobRequest` arrives signed
   (`DispatchSigner`; the worker verifies with `Verifier`). `verify()` is
   called exactly once per message per process; a dispatch that fails on age
   is refused before its signature is evaluated.
3. **Secrets.** The request carries an `EncryptedSecrets` envelope, or, under
   claim-based sealing, the worker generates an `envelope_seal::WorkerEphemeral`,
   sends a signed `SecretClaim` to the dispatch's claim inbox and opens the
   `SealedSecrets` reply into a `SecretMap`. There is one claim per dispatch.
4. **Data plane.** The module's host calls that need the controller go out as
   signed RPCs on the subjects in `job_protocol::subjects` with the request
   types in `rpc` (`memory_rpc::MemoryOp`, `graph_rpc::GraphSearchRequest`,
   `database_rpc::DatabaseRpcRequest`, `state_rpc::StateWriteRequest`,
   `ml_rpc::MlPredictRequest`), each signed by `rpc_auth::sign_rpc`.
5. **Result.** The worker stamps the result with the dispatch it answers
   (`JobResult::bind_to_request`), signs it, and publishes it to ONE subject:
   the reply inbox when the request names one, otherwise the global results
   subject. Fuel is read by the receiver from the signed result
   (`job_protocol::spent_fuel`), never from the module's output.
6. **Replay.** Where the deployment faces users, `replay_guard::boot_requirement`
   refuses to boot without the distributed replay store (`AEGIX_DISTRIBUTED_REPLAY`
   and `REDIS_URL`); the process-local nonce caches alone do not survive a
   restart inside the freshness window.

## Versioning

- `RUNTIME_API_VERSION` and `Cargo.toml`'s `version` are held equal by a test.
- The WIT package line, `package aegix:core;`, is **not** versioned, by
  decision: a version there renames every `aegix:core/<interface>` import, so
  no component compiled before the change would link, and every installed
  binary in a deployment would stop at dispatch. A WIT change is a change to
  this crate's version; the WIT text itself is `aegix_runtime::WIT`.

## Record

In the development repository's engineering log,
`2026-10-29-talos-runtime-boundary.md`: the measured closure of each runtime crate, the edges considered and left, and
what was deliberately not moved. The cuts since, each with its measured
closure: `2026-10-30-rpc-protocols-below-the-runtime-boundary.md` (sqlx,
pgvector), `2026-10-30-axum-below-the-runtime-boundary.md`,
`2026-11-01-otlp-below-the-runtime-boundary.md`, and
`2026-11-02-oci-and-prometheus-below-the-runtime-boundary.md`, which also
records why `async-nats`, `aegix-local-inference` and `aegix-dlp-provider`
stay.
