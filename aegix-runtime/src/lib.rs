#![doc = include_str!("../README.md")]
// A facade (2026-10-29, docs/engineering-log/packages/2026-10-29-talos-runtime-boundary.md):
// nothing is implemented here. Every item is a `pub use` of a crate below the
// runtime boundary, so an embedder names ONE crate and ONE version, and
// structural check 109 holds that crate's dependency closure free of the
// platform (aegix-mcp-handlers, aegix-api, controller, the repositories, the
// integrations). A type the runtime needs lives below this line; adding a
// dependency to any crate re-exported here is a boundary change.

/// The version of the embeddable runtime API: the version of this crate.
///
/// Bumped with `version` in `Cargo.toml` (a test holds the two equal). The
/// WIT package line in `wit/aegix.wit` is NOT versioned: a version there
/// renames every `aegix:core/<interface>` import, so no component compiled
/// before the change would link. This constant is where the runtime's
/// version is read.
pub const RUNTIME_API_VERSION: &str = "0.2.0";

/// The WIT package every Aegix component imports from.
///
/// Unversioned by decision (see [`RUNTIME_API_VERSION`]): a component's
/// import names are `aegix:core/<interface>`, exactly as
/// `aegix_wit_inspector` lists them.
pub const WIT_PACKAGE: &str = "aegix:core";

/// The WIT that defines the host API, byte for byte the repository's
/// `wit/aegix.wit`: every interface, and the capability worlds
/// (`minimal-node` … `automation-node`) that bundle them.
///
/// An embedder compiles components against this text; the test in
/// `tests/embed.rs` builds one from it and runs it.
pub const WIT: &str = include_str!("../../wit/aegix.wit");

// ── The WASM host ──────────────────────────────────────────────────────────

/// The wasmtime host: [`AegixRuntime`], [`AegixContext`], the host functions
/// behind every `aegix:core/*` interface, the module fetcher, the SQL
/// validator and the result cache. The whole crate, for an embedder that
/// needs a module the short paths below do not name.
pub use aegix_wasm_host as wasm_host;

/// The former name of [`wasm_host`], from when the host crate was
/// `aegix-worker-runtime`. The same items; kept so an embedder's paths go on
/// compiling, with a warning that names the new one.
#[deprecated(note = "renamed: use `aegix_runtime::wasm_host`")]
pub mod worker_runtime {
    pub use aegix_wasm_host::*;
}

/// The runtime proper: construction, the execute entry points, the security
/// and retry policies and health.
pub mod runtime {
    pub use aegix_wasm_host::runtime::*;
}

/// Per-execution context: the capability ceilings, egress scope, secret slots
/// and the development opt-ins a test states on the context, never in the
/// environment.
pub mod context {
    pub use aegix_wasm_host::context::*;
}

pub use aegix_wasm_host::context::{AegixContext, DevEgressOptIns};
pub use aegix_wasm_host::runtime::{
    AegixRuntime, RetryPolicy, RuntimeHealthStatus, SecurityPolicy,
};

// ── Talking to a controller ────────────────────────────────────────────────

/// The signed job protocol: `JobRequest` / `JobResult`,
/// the Ed25519 dispatch and HMAC result signing, the encrypted-secrets
/// envelope, the worker heartbeat and registration proofs, the vault-path
/// and HTTP-method grant matchers, and the LLM-provider host and path lists.
pub use aegix_workflow_job_protocol as job_protocol;

pub use aegix_workflow_job_protocol::{
    EgressScope, EncryptedSecrets, JobRequest, JobResult, JobStatus, LlmTier, SecretMap,
    WriteCeiling,
};

/// The client side of per-execution secret-envelope sealing (RFC 0010 P3):
/// the worker's ephemeral key, the signed claim it sends, and the sealed
/// reply it opens. The controller side (the in-flight seal store and the
/// claim responder) is `aegix-envelope-seal` and is deliberately not here.
pub mod envelope_seal {
    pub use aegix_workflow_job_protocol::envelope_seal::*;
}

/// Signing and verifying the signed NATS RPCs the worker makes for its
/// data-plane reads and writes: HMAC-SHA256 or Ed25519 bound to
/// `(subject, actor_id, nonce, body)`, the two-generation nonce cache, the
/// asymmetric freshness window, and `RawSigned<T>` for exact-wire-bytes
/// bodies.
pub mod rpc_auth {
    pub use aegix_rpc_protocol::rpc_auth::*;
}

/// The per-subject RPC request and reply types the worker sends over
/// `talos.memory.op`, `talos.graph.search`, `talos.database.query`,
/// `talos.state.write`, `talos.ml.predict` / `talos.ml.fewshot` and the
/// integration-state subject. Protocol only: the controller-side handlers
/// are not part of the runtime.
pub mod rpc {
    pub use aegix_rpc_protocol::database_rpc;
    pub use aegix_rpc_protocol::graph_rpc;
    pub use aegix_rpc_protocol::integration_state_rpc;
    pub use aegix_rpc_protocol::memory_rpc;
    pub use aegix_rpc_protocol::ml_rpc;
    pub use aegix_rpc_protocol::state_rpc;
}

/// The distributed dispatch-replay guard a worker that faces users must
/// run with (`aegix_replay_guard::boot_requirement`).
pub use aegix_replay_guard as replay_guard;

// ── What a module may do ───────────────────────────────────────────────────

/// The capability worlds and their partial order (`is_subset_of`): a
/// lattice, not tiers.
pub use aegix_capability_world as capability_world;
pub use aegix_capability_world::CapabilityWorld;

/// Reads a component's import section: which world it fits, whether it is an
/// Aegix node, and `imports_outside_world` against a world's WIT imports.
pub use aegix_wit_inspector as wit_inspector;
pub use aegix_wit_inspector::{inspect_component, ComponentInspection};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_api_version_is_the_crate_version() {
        assert_eq!(RUNTIME_API_VERSION, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn the_wit_package_line_is_unversioned() {
        // The decision in the package record: a version on the package line
        // renames every import. This pins the line until that decision is
        // revisited with every installed binary in view.
        let first = WIT
            .lines()
            .map(str::trim)
            .find(|l| !l.is_empty() && !l.starts_with("//"))
            .expect("the WIT has a package line");
        assert_eq!(first, format!("package {WIT_PACKAGE};"));
    }

    #[test]
    fn the_wit_declares_every_capability_world() {
        // The worlds the runtime links a component into, by name; a component
        // is classified into one of them by `inspect_component`.
        for world in [
            "minimal-node",
            "http-node",
            "secrets-node",
            "database-node",
            "agent-node",
            "automation-node",
        ] {
            assert!(
                WIT.contains(&format!("world {world} ")),
                "{world} is not declared in wit/aegix.wit"
            );
        }
    }

    #[test]
    fn the_facade_resolves_the_surfaces_it_promises() {
        // Compile-time proof that each re-export names a real item; the
        // values are not used.
        let _: fn() -> anyhow::Result<AegixRuntime> = AegixRuntime::new;
        let _: fn(&[u8]) -> ComponentInspection = inspect_component;
        let _ = rpc_auth::PAST_WINDOW_MS;
        let _ = job_protocol::MAX_JOB_FUEL;
        let _ = CapabilityWorld::Minimal;
        let _ = envelope_seal::WorkerEphemeral::generate;
        let _ = replay_guard::boot_requirement;
    }
}
