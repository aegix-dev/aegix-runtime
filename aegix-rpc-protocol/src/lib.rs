//! # aegix-rpc-protocol — the signed data-plane RPC protocols
//!
//! The wire types and the signing discipline every worker → controller
//! request/reply shares, with no database, embedding or HTTP dependency:
//!
//! * [`rpc_auth`] — HMAC-SHA256 or Ed25519 bound to `(subject, actor_id,
//!   nonce, body)`, the two-generation nonce cache, the asymmetric freshness
//!   window, the process-global key registry, and `RawSigned<T>` (a `pub use`
//!   of its ONE home, `aegix_workflow_job_protocol::RawSigned`).
//! * one module per subject — [`memory_rpc`] (`talos.memory.op`),
//!   [`graph_rpc`] (`talos.graph.search`), [`database_rpc`]
//!   (`talos.database.query`), [`state_rpc`] (`talos.state.write`), [`ml_rpc`]
//!   (`talos.ml.predict` / `talos.ml.fewshot`) and [`integration_state_rpc`]
//!   — each owning its own signing formula (`sign_body_bytes`) and `verify()`.
//! * [`dispatch_binding`] — the signed `{execution_id, job_id}` a data-plane
//!   request names (2026-10-29).
//! * [`memory_key`] — the key rule and the value / metadata / TTL caps a
//!   `MemoryOp` is validated against, re-exported at the crate root.
//!
//! These modules lived in `aegix-memory` until 2026-10-30, beside the
//! Postgres actor-memory service, so the embeddable runtime (`aegix-runtime`,
//! structural check 109) linked `sqlx` and `pgvector` to carry wire types.
//! They moved here verbatim (`git mv`; the wire-format snapshots and the
//! security tests came with them and are byte-for-byte the same), and
//! `aegix-memory` re-exports every module at its old path, so
//! `aegix_memory::rpc_auth` and `aegix_rpc_protocol::rpc_auth` are the SAME
//! items — one nonce cache, one key registry per process.
//!
//! Record: `docs/engineering-log/packages/2026-10-30-rpc-protocols-below-the-runtime-boundary.md`.

pub mod database_rpc;
pub mod dispatch_binding;
pub mod graph_rpc;
pub mod integration_state_rpc;
pub mod memory_key;
pub mod memory_rpc;
pub mod ml_rpc;
pub mod rpc_auth;
pub mod state_rpc;

pub use memory_key::{
    is_valid_memory_type, memory_types_csv, validate_memory_key, MAX_MEMORY_KEY_CHARS,
    MAX_METADATA_BYTES, MAX_TTL_HOURS, MAX_VALUE_BYTES, MEMORY_TYPES, SET_KV_TTL_HOURS,
};

// ============================================================================
// Unit tests — moved with the modules from aegix-memory/src/lib.rs
// (2026-10-30). The protocol's behavioural specs: the key rule, the
// per-subject sign → wire hop → verify round trips, replay and freshness
// refusals, and the NaN/Inf gate. The wire-format snapshots (literal JSON +
// MAC hex) are tests/wire_format_snapshots.rs.
// ============================================================================
#[cfg(test)]
mod tests;

#[cfg(test)]
mod wire_hop_signing_specs;

#[cfg(test)]
mod rpc_verify_classification_specs;
