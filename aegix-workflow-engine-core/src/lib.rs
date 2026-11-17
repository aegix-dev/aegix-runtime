//! Core data model + trait boundaries for a portable workflow
//! execution engine.
//!
//! This crate is **types + traits only**. It deliberately carries no
//! async runtime, no I/O, and no expression-evaluator dependency. An
//! executor crate layers the scheduling loop on top of these types
//! and plugs in consumer-supplied impls for each trait boundary.
//!
//! # What the executor does with these types
//!
//! The executor (see the sibling `aegix-workflow-engine` crate for the
//! reference DAG scheduler + dispatch loop) owns the scheduling
//! loop. Given a graph of [`SystemNodeKind`]-typed nodes connected
//! by [`EdgeLogic`], it:
//!
//! * **Topologically orders** the graph.
//! * **Fans out** ready nodes via [`NodeDispatcher::dispatch`] on
//!   `tokio::spawn` with a configurable concurrency cap, and joins
//!   siblings via [`JoinMode`] (All / Any / Majority / N).
//! * **Speculatively prefetches** module artifacts for a node's
//!   downstream successors (via the [`ModuleFetcher`] trait) while
//!   the parent still runs — hiding fetch latency behind execution.
//! * **Supports sub-workflow primitives**: every one of
//!   [`SystemNodeKind`]'s variants (`SubWorkflow`, `Judge`,
//!   `Ensemble`, `AgentLoop`, `ReActLoop`, `ReflectiveRetry`,
//!   `LlmDispatch`, `DynamicDispatch`, `CapabilityDispatch`,
//!   `ConfidenceGate`, `Verify`, `Synthesize`, `Collect`,
//!   `FanIn`, `WhileLoop`, `RepeatLoop`, `Wait`, `ErrorHandler`) is
//!   dispatched through a matching handler that composes
//!   [`NodeDispatcher`] with engine-local state. Sub-workflow graphs
//!   are batch-prefetched at run start (one `WHERE id = ANY($1)`
//!   query via [`WorkflowGraphStore`]) to eliminate N+1 lookups.
//! * **Persists and resumes paused runs** via [`CheckpointStore`] —
//!   `Wait` / cancelled runs snapshot per-node outputs through
//!   [`CheckpointStore::save`]; a subsequent resume hydrates them
//!   through [`CheckpointStore::load`].
//! * **Enforces security invariants** at every dispatch:
//!   [`SecretsResolver`] resolves per-node secrets; the executor
//!   refreshes short-lived credentials via
//!   [`SecretsResolver::refresh_vault_paths`] before handing them
//!   opaque-encrypted to the dispatcher; signed HMAC wire formats and
//!   topic-scoped queues are the dispatcher's concern.
//! * **Observes lifecycle events** via [`NodeLifecycleHook`] for
//!   per-node post-completion side effects (cost attribution, audit
//!   hooks, custom persistence).
//!
//! # Trait boundaries
//!
//! Every external-I/O concern the executor needs is behind exactly
//! one trait:
//!
//! * [`SecretsResolver`] — resolve module / vault / LLM-provider
//!   secrets; optional OAuth-style refresh hook.
//! * [`CheckpointStore`] — load a paused run's per-node outputs.
//! * [`WorkflowGraphStore`] — resolve sub-workflow graphs by id.
//! * [`NodeLifecycleHook`] — observe node completion for cross-cutting
//!   concerns.
//! * [`JobTransport`] — raw "send bytes, get bytes" channel to the
//!   worker pool (caller-owned timeout).
//! * [`NodeDispatcher`] — high-level "run this node" primitive. Owns
//!   wire-format construction, signing, retry, and result parsing.
//!
//! Every trait the executor talks to for external I/O lives in this
//! crate. A production controller typically ships adapters that wire
//! real infrastructure behind each trait (for example: Postgres for
//! graph + events + checkpoint storage, a signed-NATS job protocol
//! for dispatch, and `rhai` + DLP scrubbing + retry classification
//! for the policy hooks).
//!
//! # What's in this crate, what's not
//!
//! This crate is **types + trait boundaries** — it is the API the
//! executor commits to, nothing more. See the crate README for
//! non-goals. The executor implementation itself lives in the
//! downstream crate that uses these traits.

#![cfg_attr(docsrs, feature(doc_cfg))]
// Every public item in this crate is part of the trait surface that
// the rest of the family depends on. `deny(missing_docs)` makes any
// undocumented `pub` item a compile error, preventing future
// regressions on the API contract. The crate is already fully
// documented as of 2026-04 — the deny gates new additions, not
// existing code.
#![deny(missing_docs)]

/// Compile-time witness for the `llm-primitives` feature on this crate.
///
/// Sibling crates that depend on `aegix-workflow-engine-core` and also
/// expose an `llm-primitives` feature use this constant to assert
/// feature-flag coherence at compile time:
///
/// ```ignore
/// // In aegix-workflow-engine/src/lib.rs:
/// const _: () = assert!(
///     aegix_workflow_engine_core::HAS_LLM_PRIMITIVES
///         == cfg!(feature = "llm-primitives"),
///     "feature mismatch — see docs",
/// );
/// ```
///
/// `true` when the feature is enabled on **this** crate, `false`
/// otherwise. Cargo unifies features across the dependency graph, so
/// the only mismatch this catches is the one a misconfigured
/// `Cargo.toml` can actually produce: enabling `llm-primitives` on
/// `aegix-workflow-engine-core` while disabling it on the engine.
pub const HAS_LLM_PRIMITIVES: bool = cfg!(feature = "llm-primitives");

/// The share of its fuel limit above which a node has too little headroom:
/// a larger payload than the one measured is likely to exhaust it.
///
/// ONE line, drawn in four places that must agree: the fleet gauge
/// (`aegix_fuel_high_utilisation_nodes`), the `get_fuel_usage_report`
/// headroom section, the catalog's recorded-run gate
/// (`aegix-catalog-tests/tests/fuel_fixtures.rs`) and the validator's
/// `fuel-headroom` warning. `aegix_compilation::scaffold::HIGH_FUEL_UTILISATION`
/// is this constant. The controller's background task documents how 0.80 was
/// chosen against the fleet's distribution.
pub const HIGH_FUEL_UTILISATION: f64 = 0.80;

/// The fuel a module is taken to spend per byte of input it reads into an
/// untyped JSON value. Measured on the node this was written for
/// (2026-11-13): `pa-model-catchup/late` spent 6.8M fuel on a 132 KB input it
/// never used, about 51 fuel a byte. Stepping over input a module does not
/// read costs ~5 a byte (`2026-10-30-accumulated-envelope-capped.md`) and a
/// typed parse ~11 (`2026-10-01-fuel-budget-per-byte-rate.md`), so this is
/// the expensive reading, the one that ran out.
pub const INPUT_PARSE_FUEL_PER_BYTE: u64 = 50;

/// The share of its fuel limit above which a node's input counts as large:
/// reading it at [`INPUT_PARSE_FUEL_PER_BYTE`] would take this much of the
/// limit before the module does any work. One home, read by the daily fuel
/// headroom check and `get_fuel_usage_report`. Chosen against the
/// production fleet on 2026-11-13 (`2026-11-13-fuel-headroom-reaches-the-digest.md`):
/// against the ceilings last enforced, 2 of ~350 (workflow, node) pairs are at
/// or above it; against the limits configured since, none.
pub const LARGE_INPUT_SHARE: f64 = 0.40;

/// The share of `limit` that reading `input_bytes` at
/// [`INPUT_PARSE_FUEL_PER_BYTE`] would take. `0.0` for a limit of zero.
#[must_use]
// A share for a threshold comparison: a byte count or a fuel limit past 2^52
// losing precision changes no answer.
#[allow(clippy::cast_precision_loss)]
pub fn input_fuel_share(input_bytes: u64, limit: u64) -> f64 {
    if limit == 0 {
        return 0.0;
    }
    (input_bytes as f64 * INPUT_PARSE_FUEL_PER_BYTE as f64) / limit as f64
}

pub mod action_links;
mod actor_ceilings;
mod approval_gate;
mod assistant_report_reader;
pub mod attempt_window;
mod checkpoint;
mod child_run_admission;
mod child_run_recorder;
pub mod child_workflow_refs;
pub mod config_from_input;
pub mod connections_reader;
mod context;
pub mod delivery_verdict;
pub mod dispatch_targets;
mod dispatcher;
mod edge;
mod egress_scope;
mod event_sink;
mod expression;
pub mod graph_limits;
mod graph_store;
pub mod inference_wait;
pub mod inline_wasm;
pub mod input_preview;
mod judge_score_recorder;
mod llm_tier;
mod memory_freshness;
mod module_artifact;
mod module_execution_store;
mod module_fetcher;
mod node_hook;
mod node_identity;
mod operator_digest_reader;
mod ops_alerts_reader;
mod pending_approvals_reader;
mod rate_limit;
pub mod registry_reference;
pub mod reserved_keys;
mod retry;
mod retry_classifier;
mod sanitizer;
mod secret_envelope;
mod secrets;
mod shared_key;
mod started_by;
mod sub_actor_context;
mod system_node;
mod transport;
mod wasm_cache;
mod write_ceiling;

pub use action_links::ActionLinkMinter;
pub use actor_ceilings::ActorCeilings;
pub use approval_gate::{ApprovalGate, ApprovalStatus};
pub use assistant_report_reader::AssistantReportReader;
pub use attempt_window::{
    attempt_window_for_remaining, clamp_attempt_timeout, clamp_cause, dispatch_allowance_secs,
    simulate_attempt_sequence, AttemptFit, AttemptSequence, AttemptWindow, ClampCause,
    SimulatedAttempt, BUDGET_RESERVE_SECS, MAX_SIMULATED_ATTEMPTS, MIN_REMAINING_FOR_ATTEMPT_SECS,
    TOKIO_WRAP_GRACE_SECS,
};
pub use checkpoint::CheckpointStore;
pub use child_run_admission::ChildRunAdmission;
pub use child_run_recorder::{
    ChildDispatchKind, ChildRunOrigin, ChildRunRecord, ChildRunRecorder, ChildRunSite,
    ChildRunStatus, MAX_ERROR_CLASS_CHARS, MAX_NODE_PATH_LEN, MAX_PARENT_NODE_ID_CHARS,
};
pub use child_workflow_refs::{
    child_workflow_ids, child_workflow_ids_checked, collect_child_workflow_references,
    CHILD_WORKFLOW_ID_MAP_KEYS, CHILD_WORKFLOW_ID_SUFFIX,
};
pub use connections_reader::ConnectionsReader;
pub use context::WorkflowContext;
pub use dispatcher::{
    DispatchJob, DispatchJobBuilder, DispatchResult, NodeDispatcher, DEFAULT_DISPATCH_TIMEOUT_SECS,
};
pub use edge::EdgeLogic;
pub use egress_scope::EgressScope;
pub use event_sink::{EventSink, NodeEventWrite};
pub use expression::ExpressionEvaluator;
pub use graph_store::{GraphLookup, WorkflowGraphStore};
pub use inference_wait::{RunWaitClock, WaitAccounting, LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS};
pub use judge_score_recorder::JudgeScoreRecorder;
pub use llm_tier::LlmTier;
pub use memory_freshness::MemoryFreshnessResolver;
pub use module_artifact::{read_only_posts_for_dispatch, WasmModuleArtifact};
pub use module_execution_store::{ExecutionStartedContext, ModuleExecutionStore, StartedRow};
pub use module_fetcher::ModuleFetcher;
pub use node_hook::{NodeCompletionContext, NodeLifecycleHook};
pub use node_identity::{engine_node_uuid, node_module_id};
pub use operator_digest_reader::OperatorDigestReader;
pub use ops_alerts_reader::{
    parse_alert_sources, usable_alert_source, OpsAlertsReader, MAX_ALERT_SOURCES,
};
pub use pending_approvals_reader::PendingApprovalsReader;
pub use rate_limit::RateLimitStore;
pub use retry::{
    default_max_retries_for_module, default_node_timeout_secs, effective_retries_with_idempotency,
    methods_are_read_only, world_enables_idempotent_retry, RetryPolicy, DEFAULT_BACKOFF_MS,
    DEFAULT_NODE_TIMEOUT_SECS_FALLBACK, DEFAULT_TRANSIENT_RETRIES,
    DEFAULT_WORKFLOW_EXECUTION_TIMEOUT_SECS, MAX_RETRIES_UNBUDGETED,
};
pub use retry_classifier::RetryClassifier;
pub use sanitizer::{ExecutionSanitizer, OutputSanitizer};
pub use secret_envelope::{
    validate_seal_output, SealValidationError, SecretEnvelope, MIN_SEAL_NONCE_LEN,
};
pub use secrets::{
    BoxError, ForcedRefresh, GcpImpersonationTokenProvider, GithubInstallationTokenProvider,
    MintReadiness, SecretMap, SecretsResolver,
};
pub use shared_key::{WorkerKeyRing, WorkerSharedKey};
pub use started_by::StartedByResolver;
pub use sub_actor_context::{SubworkflowActorContextResolver, SubworkflowBinding};
pub use system_node::{JoinMode, SystemNodeKind};
pub use transport::JobTransport;
pub use wasm_cache::{scoped_wasm_cache_key, scoped_wasm_redis_uri};
pub use write_ceiling::{
    effective_write_ceiling, http_verb_ceiling_from_db, write_ceiling_denies,
    write_ceiling_denies_axis, CeilingAxis, WriteCeiling, AGENT_MEMORY_SET_OP,
    WRITE_CEILING_POLICY,
};

#[cfg(test)]
mod input_fuel_share_tests {
    use super::{input_fuel_share, LARGE_INPUT_SHARE};

    /// The two nodes the threshold was chosen on: the motivating case, which
    /// ran out of fuel, is large; the busiest ordinary compose node is not.
    #[test]
    fn the_measured_cases_fall_on_their_sides() {
        // pa-model-catchup/late before the fix: 130 569 bytes, 4M limit.
        assert!(input_fuel_share(130_569, 4_000_000) >= LARGE_INPUT_SHARE);
        // talos-alerts-to-phone/compose: 15 395 bytes, 3.5M limit (22%).
        assert!(input_fuel_share(15_395, 3_500_000) < LARGE_INPUT_SHARE);
        assert_eq!(input_fuel_share(1, 0), 0.0);
        assert!((input_fuel_share(20_000, 1_000_000) - 1.0).abs() < 1e-9);
    }
}
