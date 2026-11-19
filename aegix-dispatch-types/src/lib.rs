//! The data model a runtime and whatever dispatches to it share.
//!
//! A worker and its controller agree on a small set of things before either
//! can do its part: the key a dispatch is signed and its secrets sealed
//! under, the shape a resolved secret travels in, the three ceilings a job
//! carries and the worker enforces (the model tier, the egress scope, the
//! write ceiling), how a module's bytes ride a message and the key they are
//! cached under, how time spent
//! queueing for local inference is credited, and the names a fuel reading is
//! stamped under. This crate is those things and nothing else: **types and
//! pure functions only**, with no async runtime, no I/O and no engine.
//!
//! It was cut out of `aegix-workflow-engine-core` on 2026-11-18. That crate
//! is the workflow engine's data model (graphs, edges, system nodes, retry,
//! the trait boundaries an executor plugs into) and re-exports every item
//! here at the path it had, so the engine and everything above it name them
//! as before. A crate below the runtime boundary (the worker, the worker
//! runtime, the job protocol, the gates, the reference controller) depends
//! on this crate and never on the engine's.

mod actor_ceilings;
mod egress_scope;
pub mod fuel;
pub mod inference_wait;
pub mod inline_wasm;
mod llm_tier;
mod secret_envelope;
mod secrets;
mod shared_key;
mod wasm_cache;
mod write_ceiling;

pub use actor_ceilings::ActorCeilings;
pub use egress_scope::EgressScope;
pub use fuel::HIGH_FUEL_UTILISATION;
pub use inference_wait::{RunWaitClock, WaitAccounting, LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS};
pub use llm_tier::LlmTier;
pub use secret_envelope::{
    validate_seal_output, SealValidationError, SecretEnvelope, MIN_SEAL_NONCE_LEN,
};
pub use secrets::{BoxError, SecretMap};
pub use shared_key::{WorkerKeyRing, WorkerSharedKey};
pub use wasm_cache::{scoped_wasm_cache_key, scoped_wasm_redis_uri};
pub use write_ceiling::{
    effective_write_ceiling, http_verb_ceiling_from_db, write_ceiling_denies,
    write_ceiling_denies_axis, CeilingAxis, WriteCeiling, AGENT_MEMORY_SET_OP,
    WRITE_CEILING_POLICY,
};
