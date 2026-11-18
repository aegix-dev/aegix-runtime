# Embedding the runtime

This tree is a runtime to build on, with a reference controller to read. It
is not a service to deploy as it stands ([limits.md](limits.md), "The
reference controller"). There are three ways to use it, smallest first.

Nothing here is on crates.io. Depend on the repository, held to a release's
tag, and copy this tree's `Cargo.lock` beside your manifest to build with
the versions its tests ran on:

```toml
[dependencies]
aegix-runtime = { git = "https://github.com/aegix-dev/aegix-runtime", tag = "v0.1.1" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
anyhow = "1"
```

Build with the Rust release `rust-toolchain.toml` names, or a newer one;
copying that file too is the simple way. An older compiler is refused by
the WebAssembly engine's crates, by name. The crate has a version of its
own (`aegix-runtime/src/lib.rs`, `RUNTIME_API_VERSION`), apart from the
release's. Before 1.0 either may change what it re-exports.

## 1. Run one module, with no controller

A module is a WebAssembly component compiled against `wit/aegix.wit`.
Building one needs the `wasm32-wasip2` target and `cargo-component`; neither
comes with a Rust install.

```bash
rustup target add wasm32-wasip2
cargo install cargo-component@0.21.1 --locked
cargo run -p aegix-compilation --example compile_module -- \
    module-templates/echo-debug/template.rs minimal-node echo_debug.wasm
cargo run -p aegix-runtime --example embed_worker -- echo_debug.wasm '{"message":"hello"}'
```

The second command prints the module's output, with the fuel it spent
beside its own fields. The program is
`aegix-runtime/examples/embed_worker.rs`, and it is four steps: read which
world the binary fits, build the host, run the module, shut down.

```rust
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

With no controller there is no actor, no secret and nobody to sign a data
call. A module that asks for one is refused, as it would be in a deployment
that did not grant it. `aegix-runtime/tests/embed.rs` is the same run as a
test, with a component built from text, so it needs no toolchain.

## 2. Run a job with grants

`aegix-worker-runtime/src/runtime.rs`, `execute_job_with_full_features`,
is what a worker calls for each job. It takes the module's grants (hosts,
verbs, secrets), its fuel, memory and time limits, the actor's ceilings and
the secrets the controller sealed for the job. Your program is then a
worker: it decides nothing about what a module may do, and must be handed
all of it by something it can verify. `worker/src/main.rs`, `execute_job`,
is that sequence: verify the job, claim its secrets, run, sign the result.
[aegix-runtime/README.md](../aegix-runtime/README.md), "How to talk to a
controller", lists the types for each step.

## 3. Write a controller

A controller holds the secrets and the record of which job runs for which
actor. The rules it applies to a worker's requests are not yours to write
again. They are three functions, and the platform this tree comes from
calls the same three:

| Step | Decided in |
|---|---|
| a signed request is admitted: size, signature, age, replay | `aegix-rpc-gates/src/admission.rs`, `admit_from_bytes` |
| the request names a job this controller is running, for that actor | `aegix-rpc-gates/src/dispatch_binding.rs`, `gate` |
| a write is within the actor's ceiling | `aegix-rpc-gates/src/write_ceiling.rs`, `gate` |

What you supply is the record: `aegix-rpc-gates/src/ledger.rs`,
`GateLedger`. Its two methods look a job and an actor up by the id the
signature binds, and return what is recorded. They filter on nothing, and
they return an error, never "no such job", when the record could not be
read; the gates refuse on an error.

`aegix-reference-controller` is the worked example, with its record in
memory: `aegix-reference-controller/src/ledger.rs` is the record,
`aegix-reference-controller/src/data_plane.rs`, `memory_op`, is a data call
passing all three functions, and
`aegix-reference-controller/src/serve.rs`, `await_result`, is a job from
dispatch to its recorded end. [reference-controller.md](reference-controller.md)
says what it leaves out, which is the list of what a controller for real
use adds: a record that outlives a restart, more than one process, a login
per worker on the broker, and TLS.

Run `make demo` against your changes: it is nine cases a controller must
get right, and each prints the file that decided.
