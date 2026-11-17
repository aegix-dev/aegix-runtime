//! The dispatch-binding gate: a data-plane RPC from a worker key is served
//! only for the live dispatch it names (2026-10-29).
//!
//! # Why this exists
//!
//! Every request/reply subject a controller serves (`talos.memory.op`,
//! `talos.graph.search`, `talos.database.query`, `talos.ml.predict`,
//! `talos.ml.fewshot`, `talos.integration_state.op`) executed for the
//! `actor_id` the request named, bound to nothing but the signature. The
//! signature proves possession of a key the whole worker fleet holds
//! (`WORKER_SHARED_KEY`) or of one worker's Ed25519 key; it does not prove
//! that any module of that actor is running, or that the signer was given a
//! job for it. So one leaked key, or one compromised worker, read and wrote
//! every actor's memory and ran guest SQL as every tenant. This closed it for
//! those six. `talos.state.write` was taken not to have the gap, because since
//! 2026-10-14 a durable state write lands only for a live execution
//! (`execution_state_write`); but that statement never asked WHOSE run, and
//! any worker key wrote into any tenant's live run. Since 2026-11-09 it calls
//! this gate too, and `aegix-rpc-subscribers`' `state_write_binding` behind it.
//!
//! # The rule
//!
//! A worker stamps every request with the signed
//! [`DispatchBinding`] its execution context holds: the job's run
//! (`workflow_execution_id`) and the job's own `module_executions` row. The
//! controller admits the request only when that row exists, is this actor's,
//! and is still being dispatched (`pending` or `running`), and — for a node of
//! a run — only while the run itself is live (the same statuses the state
//! write honours, [`STATE_WRITABLE_STATUSES`]). A module-bound dispatch (a
//! webhook or push notification firing one module with no run) names itself in
//! both ids and has no run to be live.
//!
//! A node of a CHILD run (2026-11-11,
//! `docs/engineering-log/packages/2026-11-11-child-run-nodes-name-a-live-dispatch.md`).
//! A sub-workflow, a judge, an ensemble candidate, a loop body and every
//! other child-run kind runs in-process under a SYNTHETIC execution id that
//! names no `workflow_executions` row (RFC 0012). Its jobs carry that id, its
//! `module_executions` rows hold it, and the worker stamps it into the
//! binding, so "the run is live" read by that id was never true and every
//! data-plane call of every child-run node was refused from the day this gate
//! shipped. The run such a job belongs to is the one its ROW records in
//! `module_executions.root_execution_id`: the top-level run, written by the
//! controller's engine in the INSERT that creates the row
//! (`ExecutionStartedContext::root_execution_id`), never updated and never
//! taken from the request. The binding's execution id must still equal the
//! row's `workflow_execution_id` (the child's id), so the rule admits
//! exactly the jobs it did plus a child-run job whose recorded root is live:
//! a job id under a root that has ended, a job that has ended, another
//! actor's job and a job another worker claimed are refused as before. There
//! is no arm that admits "any job under a live run", and none that trusts a
//! root the worker names.
//!
//! The actor itself must still be dispatchable, [`DISPATCHABLE_ACTOR_STATUS`]
//! (2026-11-06, the data-plane re-evaluation's finding 11). Suspending,
//! terminating or archiving an actor ends none of its in-flight rows, so until
//! then a stopped actor's running jobs kept data-plane access until their rows
//! ended; now the next uncached read refuses them.
//!
//! A job whose secrets a worker has claimed is served only for that worker
//! (2026-11-06, `docs/engineering-log/packages/2026-11-06-the-binding-names-its-claimant.md`).
//! The claim responder records the claimant on the job's row before it hands
//! the secrets out (`module_executions.claimed_by_worker_id`,
//! `aegix_module_executions::record_secret_claimant`); from then on a request
//! naming that job is admitted only when it is Ed25519-signed under the same
//! worker id ([`signer_identity`]). The fleet HMAC key proves no worker id, so
//! it is never the claimant. A job with no recorded claimant (one that
//! carried no secrets, so made no claim; or one not claimed YET) is admitted
//! on the rest of the rule: the controller cannot tell those two apart from
//! the row, and the first is most of the fleet's dispatches.
//!
//! A request with NO binding is one of two things: the controller's own
//! in-process rehearsal runtime (`run_sandbox`, `test_module`, a scratch
//! session, a replay), which has no dispatch and signs under
//! [`CONTROLLER_RPC_IDENTITY`], or a worker built before the field. The first
//! is admitted on its identity; the second is refused unless the operator
//! waived it for the upgrade window (`AEGIX_RPC_REQUIRE_DISPATCH_BINDING=false`,
//! `aegix_config::dispatch_binding`). A binding that IS present is checked
//! whatever the switch says.
//!
//! # Shape
//!
//! [`decide`] is pure — the requirement, the signer and the three-valued
//! [`DispatchRead`] are parameters — so the rule is testable with no process
//! env and no database, and the two states that mean *unknown* cannot collapse
//! into the one that means *permitted*. The same shape as
//! [`crate::write_ceiling`].
//!
//! Whether a dispatch is live is pure too: [`dispatch_is_live`] decides it
//! from the [`DispatchFacts`] a [`GateLedger`] read for the job (since
//! 2026-11-13; until then the rule was the `WHERE` clause of one Postgres
//! statement). A ledger looks a job up and returns what is recorded; it does
//! not filter, so every controller, whatever it keeps its record in, is held
//! to this one rule. The requirement is an argument of [`gate`]: this crate
//! reads no environment and counts no metric. The platform's entry point,
//! which supplies the Postgres ledger, the process's requirement and the
//! refusal counter, is `aegix_rpc_subscribers::dispatch_binding::gate`.
//!
//! # Cost
//!
//! One ledger read per DISTINCT `(run, job, actor, signer)` per [`CACHE_TTL`], not
//! per call: a module's data-plane calls cluster inside one attempt, and a
//! positive answer is held for two seconds. The cache is positive-only (a
//! refusal is never remembered, so a row that becomes live is seen at once),
//! bounded ([`CACHE_CAP`] entries; past it, expired entries are dropped and
//! nothing new is remembered until there is room), and keyed on all three
//! ids AND the signer's identity, so a hit for one actor never answers for
//! another, and a hit for one worker never answers for another worker or for
//! the fleet key. What the TTL costs:
//! a run cancelled while its module is mid-call, or an actor suspended,
//! terminated or archived while its module is mid-call, is served for at most
//! two more seconds; and a job claimed in the two seconds after another
//! worker's positive answer for it was cached is served to that worker for at
//! most the rest of the TTL (in practice nothing: a worker claims before its
//! module runs, so no honest call precedes the claim). A controller-signed
//! request pays nothing: it is admitted before any read.

use crate::ledger::{DispatchFacts, GateLedger};
use aegix_config::dispatch_binding::Requirement;
use aegix_rpc_protocol::dispatch_binding::DispatchBinding;
use aegix_rpc_protocol::rpc_auth::RPC_CRYPTO_SCHEME_ED25519;
use aegix_rpc_protocol::state_rpc::STATE_WRITABLE_STATUSES;
use aegix_workflow_job_protocol::CONTROLLER_RPC_IDENTITY;
use dashmap::DashMap;
use std::sync::LazyLock;
use std::time::{Duration, Instant};
use uuid::Uuid;

/// Who signed the request, as far as this gate distinguishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Signer {
    /// The controller's own RPC identity: an Ed25519 signature under
    /// [`CONTROLLER_RPC_IDENTITY`]. Sound because the request has already
    /// verified, and the key registry resolves that id ONLY to the key the
    /// controller installed (`register_controller_rpc_verifying_key`): a
    /// worker cannot register under it, and the env ring and the DB overlay
    /// never carry it.
    Controller,
    /// Anything else that verified: a worker's Ed25519 key, or the fleet HMAC
    /// key. The holder may be any worker, or anything that has the key.
    WorkerKey,
}

/// Classify a VERIFIED request's signer. Must not be called on a request that
/// has not passed its protocol's `verify()`: an unverified `worker_id` is a
/// claim.
pub fn classify_signer(crypto_scheme: u8, worker_id: &str) -> Signer {
    if crypto_scheme == RPC_CRYPTO_SCHEME_ED25519 && worker_id == CONTROLLER_RPC_IDENTITY {
        Signer::Controller
    } else {
        Signer::WorkerKey
    }
}

/// The worker identity a VERIFIED request proves, for the claimant
/// comparison: its `worker_id` when it is Ed25519-signed (the controller
/// resolved the verifying key BY that id, so the id is proven), and nothing
/// under the fleet HMAC key, whose `worker_id` is empty and proves no worker.
/// A request that proves no worker is never a job's claimant.
pub fn signer_identity(crypto_scheme: u8, worker_id: &str) -> Option<&str> {
    (crypto_scheme == RPC_CRYPTO_SCHEME_ED25519 && !worker_id.is_empty()).then_some(worker_id)
}

/// The answer to "is the named dispatch live and this actor's?", kept
/// three-valued so a caller must say what an unreadable answer means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchRead {
    /// The row exists, belongs to the actor, is `pending`/`running`, its
    /// run (if it has one) is live, the actor is still dispatchable, and
    /// the job is unclaimed or claimed by the signer.
    Live,
    /// No such row, another actor's, ended, a run that has ended, an actor
    /// suspended, terminated or archived, or a job another worker (or a
    /// signer that proves no worker) claimed.
    NotLive,
    /// The lookup failed. Carries no detail: the cause is an operator concern.
    Unreadable,
}

/// Why a request was refused. **Operator-facing only**: the reply is the
/// protocol's reason-blind `Unauthorized`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// A worker key signed a request that names no dispatch, and the
    /// requirement stands.
    Unbound,
    /// The named dispatch is not live for this actor.
    NotLive,
    /// The dispatch could not be read, so the gate failed CLOSED.
    Unreadable,
}

impl RefusalReason {
    /// Stable snake_case token for the audit log. Append, never rename.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unbound => "dispatch_unbound",
            Self::NotLive => "dispatch_not_live",
            Self::Unreadable => "dispatch_unreadable",
        }
    }

    /// The `reason` label of `aegix_rpc_dispatch_binding_refusals_total`:
    /// the metric's own name already says "dispatch binding", so the label
    /// carries only what distinguishes the arms. The exhaustive `match` means
    /// a fourth variant cannot be added without deciding its spelling, and
    /// `refusal_reason_spellings_stay_paired` pins the three.
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Unbound => "unbound",
            Self::NotLive => "not_live",
            Self::Unreadable => "unreadable",
        }
    }
}

/// The gate's verdict. `#[must_use]`: a gate whose answer is computed and
/// dropped is worse than no gate, because the code then LOOKS gated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum BindingDecision {
    Permit,
    Refuse(RefusalReason),
}

/// The rule, with nothing else in it.
///
/// * The controller's own identity is admitted without a read: it holds the
///   database credentials this gate protects, and its rehearsals have no
///   dispatch to name.
/// * A worker key with no binding is admitted only under a waiver.
/// * A worker key with a binding is admitted only for a dispatch that was
///   READ as live. Both unknown states refuse: a gate that cannot read its
///   rule and permits has, during the database incident that matters most,
///   the behaviour of no gate, and leaves logs implying one ran.
pub fn decide(
    requirement: Requirement,
    signer: Signer,
    bound: Option<DispatchRead>,
) -> BindingDecision {
    match (signer, bound) {
        (Signer::Controller, _) => BindingDecision::Permit,
        (Signer::WorkerKey, None) => match requirement {
            Requirement::Required => BindingDecision::Refuse(RefusalReason::Unbound),
            Requirement::Waived => BindingDecision::Permit,
        },
        (Signer::WorkerKey, Some(DispatchRead::Live)) => BindingDecision::Permit,
        (Signer::WorkerKey, Some(DispatchRead::NotLive)) => {
            BindingDecision::Refuse(RefusalReason::NotLive)
        }
        (Signer::WorkerKey, Some(DispatchRead::Unreadable)) => {
            BindingDecision::Refuse(RefusalReason::Unreadable)
        }
    }
}

/// The one `actors.status` a dispatch's data-plane calls are served for.
///
/// Not a set of its own: it is what the trigger path already admits. Of the
/// four statuses `actors_status_check` allows (`active`, `suspended`,
/// `terminated`, `archived`), `aegix_workflow_authorization::
/// classify_actor_dispatch_status` refuses `archived` and `terminated`, and
/// the execution precheck it runs next (`aegix_actor_repository::
/// budget_precheck::check_actor_status`) refuses `suspended` and
/// `terminated`; only `active` passes both. A fifth status added to the CHECK
/// is refused here until it is named.
///
/// Public since 2026-11-09: the gate admits the controller's own signer
/// before it reads the actor, so an in-process run (`test_module`,
/// `run_sandbox`) asks this constant at its own surface before it binds an
/// actor (`docs/engineering-log/packages/2026-11-09-in-process-runs-honour-the-actor.md`).
pub const DISPATCHABLE_ACTOR_STATUS: &str = "active";

/// How long a positive answer is held. See the module docs for what it costs.
pub const CACHE_TTL: Duration = Duration::from_secs(2);
/// The most `(run, job, actor, signer)` entries held at once: a fleet's concurrent
/// dispatches, with headroom. Past it nothing new is remembered, so the gate
/// degrades to one read per call, never to an unbounded map.
pub const CACHE_CAP: usize = 8192;

/// `(run, job, actor, signer identity)`. The identity is the one
/// [`signer_identity`] returns, `None` for the fleet key, so an answer read
/// for one worker (or for the fleet key) is never an answer for another. One
/// `String` per lookup: a few bytes against an RPC round trip.
type CacheKey = (Uuid, Uuid, Uuid, Option<String>);

static LIVE_CACHE: LazyLock<DashMap<CacheKey, Instant>> = LazyLock::new(DashMap::new);

fn cache_key(binding: &DispatchBinding, actor_id: Uuid, signer: Option<&str>) -> CacheKey {
    (
        binding.execution_id,
        binding.job_id,
        actor_id,
        signer.map(str::to_owned),
    )
}

fn cache_hit(key: &CacheKey, now: Instant) -> bool {
    LIVE_CACHE.get(key).is_some_and(|expires| *expires > now)
}

fn cache_remember(key: CacheKey, now: Instant) {
    if LIVE_CACHE.len() >= CACHE_CAP {
        LIVE_CACHE.retain(|_, expires| *expires > now);
        if LIVE_CACHE.len() >= CACHE_CAP {
            return;
        }
    }
    LIVE_CACHE.insert(key, now + CACHE_TTL);
}

/// Test-only: forget every held answer, so a test that ends a run sees the
/// database and not the cache.
#[cfg(test)]
pub(crate) fn clear_cache() {
    LIVE_CACHE.clear();
}

/// The two `module_executions` statuses in which a job is being dispatched:
/// created and not yet picked up, and running. Every other status is a job
/// that has ended. (The push integrations leave a module-bound row `pending`
/// until its result arrives, so `pending` is live.)
pub const JOB_DISPATCHING_STATUSES: &[&str] = &["pending", "running"];

/// THE rule: is the dispatch `binding` names live for `actor_id` and
/// `signer`, given what the ledger recorded for the job?
///
/// Every clause must hold.
///
/// * The job is the signed actor's. A job with no actor is nobody's.
/// * The job is being dispatched ([`JOB_DISPATCHING_STATUSES`]).
/// * The actor is [`DISPATCHABLE_ACTOR_STATUS`]. An actor the ledger does not
///   hold is not.
/// * The job is unclaimed, or claimed by the signer. `signer` is
///   [`signer_identity`]'s answer: `None` (the fleet key) proves no worker,
///   so a claimed job is never live for it.
/// * A module-bound dispatch (the job has no run) names itself in both ids.
///   A node of a run names the run its record holds (for a node of a CHILD
///   run, the child's synthetic id), and the run that must be live, the one
///   the ledger read as [`DispatchFacts::live_run_status`], is live: one of
///   [`STATE_WRITABLE_STATUSES`], the statuses a state write honours. A run
///   the ledger does not hold is not live.
///
/// There is no arm that admits "any job under a live run", and none that
/// takes a root run from the request: see the module docs.
pub fn dispatch_is_live(
    facts: &DispatchFacts,
    binding: &DispatchBinding,
    actor_id: Uuid,
    signer: Option<&str>,
) -> bool {
    let the_actors_job = facts.actor_id == Some(actor_id);
    let being_dispatched = JOB_DISPATCHING_STATUSES.contains(&facts.job_status.as_str());
    let actor_dispatchable = facts.actor_status.as_deref() == Some(DISPATCHABLE_ACTOR_STATUS);
    let signers_to_act_for = match facts.claimed_by.as_deref() {
        None => true,
        Some(claimant) => signer == Some(claimant),
    };
    let names_its_live_run = match facts.run_id {
        None => binding.execution_id == binding.job_id,
        Some(run) => {
            run == binding.execution_id
                && facts
                    .live_run_status
                    .as_deref()
                    .is_some_and(|status| STATE_WRITABLE_STATUSES.contains(&status))
        }
    };
    the_actors_job
        && being_dispatched
        && actor_dispatchable
        && signers_to_act_for
        && names_its_live_run
}

/// Read whether the named dispatch is live for `actor_id` and `signer`: one
/// ledger lookup of the job the binding names, then [`dispatch_is_live`]. A
/// job the ledger does not hold is not live.
///
/// The `Err` arm is logged here (controller-side only) and collapsed to
/// [`DispatchRead::Unreadable`]: a ledger's error text may name relations and
/// must not travel to a caller.
pub async fn read_dispatch<L: GateLedger + Sync>(
    ledger: &L,
    binding: &DispatchBinding,
    actor_id: Uuid,
    signer: Option<&str>,
) -> DispatchRead {
    match ledger.dispatch_facts(binding.job_id).await {
        Ok(Some(facts)) if dispatch_is_live(&facts, binding, actor_id, signer) => {
            DispatchRead::Live
        }
        Ok(_) => DispatchRead::NotLive,
        Err(e) => {
            tracing::error!(
                target: "talos_rpc",
                event_kind = "dispatch_binding_read_failed",
                %actor_id,
                execution_id = %binding.execution_id,
                job_id = %binding.job_id,
                error = %e,
                "dispatch-binding lookup failed — failing CLOSED, the request is refused"
            );
            DispatchRead::Unreadable
        }
    }
}

/// [`read_dispatch`] behind the positive cache.
async fn read_dispatch_cached<L: GateLedger + Sync>(
    ledger: &L,
    binding: &DispatchBinding,
    actor_id: Uuid,
    signer: Option<&str>,
) -> DispatchRead {
    let key = cache_key(binding, actor_id, signer);
    let now = Instant::now();
    if cache_hit(&key, now) {
        return DispatchRead::Live;
    }
    let read = read_dispatch(ledger, binding, actor_id, signer).await;
    if read == DispatchRead::Live {
        cache_remember(key, now);
    }
    read
}

/// The gate, on a VERIFIED request: classify the signer, read the binding
/// (if any) and decide; on a refusal, write the operator-facing record.
/// Called after admission and before any work.
///
/// `requirement` is what the calling process runs under (a process whose
/// switch is unreadable is held to [`Requirement::Required`] by its caller).
/// `subject` is the NATS subject the request arrived on, for the record.
/// The refusal is returned as well as logged: the caller counts it.
pub async fn gate<L: GateLedger + Sync>(
    ledger: &L,
    requirement: Requirement,
    subject: &'static str,
    actor_id: Uuid,
    crypto_scheme: u8,
    worker_id: &str,
    binding: Option<&DispatchBinding>,
) -> BindingDecision {
    let signer = classify_signer(crypto_scheme, worker_id);
    let bound = match (signer, binding) {
        (Signer::Controller, _) | (Signer::WorkerKey, None) => None,
        (Signer::WorkerKey, Some(b)) => Some(
            read_dispatch_cached(
                ledger,
                b,
                actor_id,
                signer_identity(crypto_scheme, worker_id),
            )
            .await,
        ),
    };
    let decision = decide(requirement, signer, bound);
    if let BindingDecision::Refuse(reason) = decision {
        log_refusal(subject, actor_id, worker_id, binding, reason);
    }
    decision
}

/// Write the operator-facing record of a refusal to the `talos_audit` log
/// target (a log line, not a hash-chained ledger: a controller has no
/// `ExecutionLedger` producer, the limit `write_ceiling` records too). The
/// counter, `aegix_rpc_dispatch_binding_refusals_total{subject,reason}` on
/// the platform, is the caller's: it has the decision.
fn log_refusal(
    subject: &'static str,
    actor_id: Uuid,
    worker_id: &str,
    binding: Option<&DispatchBinding>,
    reason: RefusalReason,
) {
    tracing::warn!(
        target: "talos_audit",
        event_kind = "rpc_dispatch_binding_refused",
        subject,
        %actor_id,
        signer = if worker_id.is_empty() { "<fleet hmac>" } else { worker_id },
        execution_id = binding.map(|b| b.execution_id.to_string()).as_deref().unwrap_or("-"),
        job_id = binding.map(|b| b.job_id.to_string()).as_deref().unwrap_or("-"),
        reason = reason.as_str(),
        "dispatch binding: signed-RPC request refused at the controller — the signer named \
         no live dispatch of this actor that it may act for"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::testing::MemoryLedger;
    use aegix_rpc_protocol::rpc_auth::RPC_CRYPTO_SCHEME_HMAC;

    fn binding() -> DispatchBinding {
        DispatchBinding {
            execution_id: Uuid::new_v4(),
            job_id: Uuid::new_v4(),
        }
    }

    #[test]
    fn the_controller_is_admitted_whatever_it_sends() {
        for requirement in [Requirement::Required, Requirement::Waived] {
            for bound in [
                None,
                Some(DispatchRead::Live),
                Some(DispatchRead::NotLive),
                Some(DispatchRead::Unreadable),
            ] {
                assert_eq!(
                    decide(requirement, Signer::Controller, bound),
                    BindingDecision::Permit
                );
            }
        }
    }

    #[test]
    fn a_worker_key_with_no_binding_is_refused_unless_waived() {
        assert_eq!(
            decide(Requirement::Required, Signer::WorkerKey, None),
            BindingDecision::Refuse(RefusalReason::Unbound)
        );
        assert_eq!(
            decide(Requirement::Waived, Signer::WorkerKey, None),
            BindingDecision::Permit
        );
    }

    /// A waiver tolerates absence, never a false statement.
    #[test]
    fn a_binding_that_is_present_is_checked_under_a_waiver_too() {
        for requirement in [Requirement::Required, Requirement::Waived] {
            assert_eq!(
                decide(requirement, Signer::WorkerKey, Some(DispatchRead::Live)),
                BindingDecision::Permit
            );
            assert_eq!(
                decide(requirement, Signer::WorkerKey, Some(DispatchRead::NotLive)),
                BindingDecision::Refuse(RefusalReason::NotLive)
            );
            assert_eq!(
                decide(
                    requirement,
                    Signer::WorkerKey,
                    Some(DispatchRead::Unreadable)
                ),
                BindingDecision::Refuse(RefusalReason::Unreadable),
                "an unreadable dispatch fails CLOSED"
            );
        }
    }

    /// Only an Ed25519 signature under the reserved id is the controller: the
    /// fleet HMAC key cannot claim the id (its `worker_id` is empty on the
    /// wire), and the id under any other scheme is a claim, not a proof.
    #[test]
    fn only_an_ed25519_signature_under_the_reserved_id_is_the_controller() {
        assert_eq!(
            classify_signer(RPC_CRYPTO_SCHEME_ED25519, CONTROLLER_RPC_IDENTITY),
            Signer::Controller
        );
        assert_eq!(
            classify_signer(RPC_CRYPTO_SCHEME_HMAC, CONTROLLER_RPC_IDENTITY),
            Signer::WorkerKey
        );
        assert_eq!(
            classify_signer(RPC_CRYPTO_SCHEME_HMAC, ""),
            Signer::WorkerKey
        );
        assert_eq!(
            classify_signer(RPC_CRYPTO_SCHEME_ED25519, "worker-7"),
            Signer::WorkerKey
        );
        assert_eq!(
            classify_signer(RPC_CRYPTO_SCHEME_ED25519, "talos-controller "),
            Signer::WorkerKey,
            "the id is compared whole"
        );
    }

    /// Only an Ed25519 signature proves a worker id; the fleet key proves none.
    #[test]
    fn only_an_ed25519_signature_proves_a_worker_identity() {
        assert_eq!(
            signer_identity(RPC_CRYPTO_SCHEME_ED25519, "worker-7"),
            Some("worker-7")
        );
        assert_eq!(signer_identity(RPC_CRYPTO_SCHEME_ED25519, ""), None);
        assert_eq!(signer_identity(RPC_CRYPTO_SCHEME_HMAC, ""), None);
        assert_eq!(
            signer_identity(RPC_CRYPTO_SCHEME_HMAC, "worker-7"),
            None,
            "a worker id beside an HMAC signature is a claim, not a proof"
        );
    }

    #[test]
    fn refusal_reason_spellings_stay_paired() {
        let pairs = [
            (RefusalReason::Unbound, "dispatch_unbound", "unbound"),
            (RefusalReason::NotLive, "dispatch_not_live", "not_live"),
            (
                RefusalReason::Unreadable,
                "dispatch_unreadable",
                "unreadable",
            ),
        ];
        for (reason, log, metric) in pairs {
            assert_eq!(reason.as_str(), log);
            assert_eq!(reason.metric_label(), metric);
        }
        // That every metric spelling is one the platform's registry seeds is
        // pinned where the registry is linked:
        // `aegix_rpc_subscribers::dispatch_binding`'s tests.
    }

    /// Every test that reads or fills the process-wide cache takes a turn:
    /// under libtest's default threading one test's `clear_cache` otherwise
    /// lands in the middle of another's fill, and a gate test's live answer
    /// lands in the bounded test's exact count.
    static CACHE_TEST_TURN: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn take_cache_turn() -> std::sync::MutexGuard<'static, ()> {
        CACHE_TEST_TURN
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The cache answers only for the exact `(run, job, actor, signer)` it was told
    /// about, and only until its entry expires.
    #[test]
    fn the_cache_is_keyed_on_all_ids_and_the_signer_and_expires() {
        let _turn = take_cache_turn();
        clear_cache();
        let b = binding();
        let actor = Uuid::new_v4();
        let now = Instant::now();
        let key = cache_key(&b, actor, Some("worker-a"));
        assert!(!cache_hit(&key, now));
        cache_remember(key.clone(), now);
        assert!(cache_hit(&key, now));
        assert!(cache_hit(&key, now + CACHE_TTL - Duration::from_millis(1)));
        assert!(!cache_hit(&key, now + CACHE_TTL), "expired at the TTL");
        assert!(
            !cache_hit(&cache_key(&b, Uuid::new_v4(), Some("worker-a")), now),
            "another actor is not answered"
        );
        assert!(
            !cache_hit(&cache_key(&b, actor, Some("worker-b")), now),
            "another worker is not answered"
        );
        assert!(
            !cache_hit(&cache_key(&b, actor, None), now),
            "the fleet key is not answered by a worker's entry"
        );
        assert!(
            !cache_hit(
                &cache_key(
                    &DispatchBinding {
                        execution_id: b.execution_id,
                        job_id: Uuid::new_v4(),
                    },
                    actor,
                    Some("worker-a")
                ),
                now
            ),
            "another job is not answered"
        );
        clear_cache();
    }

    #[test]
    fn the_cache_is_bounded() {
        let _turn = take_cache_turn();
        clear_cache();
        let now = Instant::now();
        for _ in 0..CACHE_CAP {
            cache_remember((Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), None), now);
        }
        assert_eq!(LIVE_CACHE.len(), CACHE_CAP);
        // Full of live entries: nothing new is remembered.
        let extra = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), None);
        cache_remember(extra.clone(), now);
        assert!(!cache_hit(&extra, now));
        assert_eq!(LIVE_CACHE.len(), CACHE_CAP);
        // Once the held entries have expired, there is room again.
        let later = now + CACHE_TTL;
        cache_remember(extra.clone(), later);
        assert!(cache_hit(&extra, later));
        assert!(LIVE_CACHE.len() <= CACHE_CAP);
        clear_cache();
    }

    // ── the rule over facts ────────────────────────────────────────────────

    const WORKER: &str = "worker-a";

    /// A node of a run, live in every clause: the job is the actor's and
    /// running, the actor is active, nobody has claimed it, and the run its
    /// record names is running.
    fn live_node(actor: Uuid, run: Uuid) -> DispatchFacts {
        DispatchFacts {
            actor_id: Some(actor),
            job_status: "running".to_owned(),
            actor_status: Some(DISPATCHABLE_ACTOR_STATUS.to_owned()),
            claimed_by: None,
            run_id: Some(run),
            live_run_status: Some("running".to_owned()),
        }
    }

    /// A module-bound dispatch, live in every clause: no run, so no run
    /// status.
    fn live_module_bound(actor: Uuid) -> DispatchFacts {
        DispatchFacts {
            run_id: None,
            live_run_status: None,
            ..live_node(actor, Uuid::nil())
        }
    }

    #[test]
    fn a_node_of_a_live_run_is_live_for_its_actor() {
        let (actor, b) = (Uuid::new_v4(), binding());
        let facts = live_node(actor, b.execution_id);
        assert!(dispatch_is_live(&facts, &b, actor, None));
        assert!(dispatch_is_live(&facts, &b, actor, Some(WORKER)));
        // A job not picked up yet is being dispatched too.
        let pending = DispatchFacts {
            job_status: "pending".to_owned(),
            ..facts
        };
        assert!(dispatch_is_live(&pending, &b, actor, None));
    }

    /// One clause false at a time, every other clause true: each alone
    /// refuses. A rule that dropped a clause passes every other test here.
    #[test]
    fn each_clause_alone_makes_a_dispatch_not_live() {
        let (actor, b) = (Uuid::new_v4(), binding());
        let live = live_node(actor, b.execution_id);
        assert!(dispatch_is_live(&live, &b, actor, Some(WORKER)));

        // Another actor's job, asked for by this one; and this actor's job,
        // asked for by another.
        let another = DispatchFacts {
            actor_id: Some(Uuid::new_v4()),
            ..live.clone()
        };
        assert!(!dispatch_is_live(&another, &b, actor, Some(WORKER)));
        assert!(!dispatch_is_live(&live, &b, Uuid::new_v4(), Some(WORKER)));
        // A job with no actor is nobody's.
        let nobody = DispatchFacts {
            actor_id: None,
            ..live.clone()
        };
        assert!(!dispatch_is_live(&nobody, &b, actor, Some(WORKER)));

        // A job that has ended, however it ended; and a status this rule
        // does not name.
        for status in [
            "completed",
            "failed",
            "cancelled",
            "timeout",
            "",
            "Running",
            "running ",
        ] {
            let ended = DispatchFacts {
                job_status: status.to_owned(),
                ..live.clone()
            };
            assert!(
                !dispatch_is_live(&ended, &b, actor, Some(WORKER)),
                "{status:?}"
            );
        }

        // An actor that was stopped, one this rule does not name, and one the
        // ledger does not hold.
        for status in [
            Some("suspended"),
            Some("terminated"),
            Some("archived"),
            Some("Active"),
            Some(""),
            None,
        ] {
            let stopped = DispatchFacts {
                actor_status: status.map(str::to_owned),
                ..live.clone()
            };
            assert!(
                !dispatch_is_live(&stopped, &b, actor, Some(WORKER)),
                "{status:?}"
            );
        }

        // A run that has ended, one this rule does not name, and one the
        // ledger does not hold.
        for status in [
            Some("completed"),
            Some("failed"),
            Some("cancelled"),
            Some("queued"),
            Some("pending"),
            Some(""),
            None,
        ] {
            let ended = DispatchFacts {
                live_run_status: status.map(str::to_owned),
                ..live.clone()
            };
            assert!(
                !dispatch_is_live(&ended, &b, actor, Some(WORKER)),
                "{status:?}"
            );
        }

        // The job's record names another run than the request does.
        let other_run = DispatchFacts {
            run_id: Some(Uuid::new_v4()),
            ..live.clone()
        };
        assert!(!dispatch_is_live(&other_run, &b, actor, Some(WORKER)));
    }

    /// The run statuses that serve are the state write's list, by name, so a
    /// status added there is served here and one removed is not.
    #[test]
    fn the_live_run_statuses_are_the_state_writes() {
        let (actor, b) = (Uuid::new_v4(), binding());
        for status in STATE_WRITABLE_STATUSES {
            let facts = DispatchFacts {
                live_run_status: Some((*status).to_owned()),
                ..live_node(actor, b.execution_id)
            };
            assert!(dispatch_is_live(&facts, &b, actor, None), "{status}");
        }
        assert_eq!(STATE_WRITABLE_STATUSES, ["running", "resuming", "waiting"]);
    }

    /// A claimed job is the claimant's alone: not another worker's, and not
    /// the fleet key's, which proves no worker.
    #[test]
    fn a_claimed_job_is_live_only_for_its_claimant() {
        let (actor, b) = (Uuid::new_v4(), binding());
        let claimed = DispatchFacts {
            claimed_by: Some(WORKER.to_owned()),
            ..live_node(actor, b.execution_id)
        };
        assert!(dispatch_is_live(&claimed, &b, actor, Some(WORKER)));
        assert!(!dispatch_is_live(&claimed, &b, actor, Some("worker-b")));
        assert!(!dispatch_is_live(&claimed, &b, actor, None));
        assert!(
            !dispatch_is_live(&claimed, &b, actor, Some("worker-a ")),
            "the id is compared whole"
        );
        // A claimant recorded as the empty string is still a claimant: the
        // fleet key, which proves no worker, is not it.
        let claimed_by_nobody = DispatchFacts {
            claimed_by: Some(String::new()),
            ..claimed
        };
        assert!(!dispatch_is_live(&claimed_by_nobody, &b, actor, None));
    }

    /// A module-bound dispatch has no run and names itself in both ids. A
    /// request that names a run for it is not served, and neither is a
    /// request that names a job of a run as if it were module-bound.
    #[test]
    fn a_module_bound_dispatch_names_itself_in_both_ids() {
        let actor = Uuid::new_v4();
        let job = Uuid::new_v4();
        let itself = DispatchBinding {
            execution_id: job,
            job_id: job,
        };
        let facts = live_module_bound(actor);
        assert!(dispatch_is_live(&facts, &itself, actor, None));
        let names_a_run = DispatchBinding {
            execution_id: Uuid::new_v4(),
            job_id: job,
        };
        assert!(!dispatch_is_live(&facts, &names_a_run, actor, None));
        // A run status the ledger happened to return for a job with no run
        // serves nothing: the job has no run to be live.
        let stray = DispatchFacts {
            live_run_status: Some("running".to_owned()),
            ..facts
        };
        assert!(!dispatch_is_live(&stray, &names_a_run, actor, None));
        // A node of a run, asked for as if it were module-bound.
        let node = live_node(actor, Uuid::new_v4());
        assert!(!dispatch_is_live(&node, &itself, actor, None));
    }

    // ── the gate over a ledger ─────────────────────────────────────────────

    const SUBJECT: &str = "talos.memory.op";

    /// Drive a gate call to its end on a runtime of this test's own. The
    /// tests here are plain functions so the cache's turn (a `std` mutex
    /// guard) is held around the future, never across an await inside it.
    fn block_on<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a current-thread runtime")
            .block_on(future)
    }

    async fn ask(
        ledger: &MemoryLedger,
        actor: Uuid,
        scheme: u8,
        worker_id: &str,
        binding: Option<&DispatchBinding>,
    ) -> BindingDecision {
        gate(
            ledger,
            Requirement::Required,
            SUBJECT,
            actor,
            scheme,
            worker_id,
            binding,
        )
        .await
    }

    /// The whole life of one job, asked for with the fleet key: unknown to
    /// the ledger, live, ended. A refusal is never remembered (the job is
    /// served the moment it is recorded), and a live answer is held for the
    /// TTL and no longer.
    #[test]
    fn a_job_is_served_while_it_is_live_and_refused_before_and_after() {
        let _turn = take_cache_turn();
        clear_cache();
        block_on(async {
            let ledger = MemoryLedger::default();
            let (actor, b) = (Uuid::new_v4(), binding());
            let not_live = BindingDecision::Refuse(RefusalReason::NotLive);

            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", Some(&b)).await,
                not_live,
                "a job the ledger does not hold"
            );
            ledger.put_job(b.job_id, live_node(actor, b.execution_id));
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", Some(&b)).await,
                BindingDecision::Permit,
                "a refusal was remembered"
            );
            // Another actor naming the same job is refused while it is live.
            assert_eq!(
                ask(
                    &ledger,
                    Uuid::new_v4(),
                    RPC_CRYPTO_SCHEME_HMAC,
                    "",
                    Some(&b)
                )
                .await,
                not_live
            );

            ledger.update_job(b.job_id, |job| job.job_status = "completed".to_owned());
            // Within the TTL the held answer still serves: the stated cost.
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", Some(&b)).await,
                BindingDecision::Permit
            );
            // Past it (here: forgotten), the ledger is asked and the job has ended.
            clear_cache();
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", Some(&b)).await,
                not_live
            );
            // And that refusal is not held either: asked again, it is refused
            // again, by a second read.
            let reads = ledger.reads();
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", Some(&b)).await,
                not_live,
                "a refusal was served from the cache as live"
            );
            assert_eq!(ledger.reads(), reads + 1);
        });
        clear_cache();
    }

    /// A job a worker claimed is served to that worker's own signature and to
    /// nobody else's, the fleet key included, and one worker's held answer is
    /// not another's.
    #[test]
    fn a_claimed_job_is_served_only_to_its_claimants_signature() {
        let _turn = take_cache_turn();
        clear_cache();
        block_on(async {
            let ledger = MemoryLedger::default();
            let (actor, b) = (Uuid::new_v4(), binding());
            ledger.put_job(
                b.job_id,
                DispatchFacts {
                    claimed_by: Some(WORKER.to_owned()),
                    ..live_node(actor, b.execution_id)
                },
            );
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_ED25519, WORKER, Some(&b)).await,
                BindingDecision::Permit
            );
            let not_live = BindingDecision::Refuse(RefusalReason::NotLive);
            assert_eq!(
                ask(
                    &ledger,
                    actor,
                    RPC_CRYPTO_SCHEME_ED25519,
                    "worker-b",
                    Some(&b)
                )
                .await,
                not_live
            );
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", Some(&b)).await,
                not_live
            );
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, WORKER, Some(&b)).await,
                not_live,
                "a worker id beside an HMAC signature is a claim, not a proof"
            );
        });
        clear_cache();
    }

    /// A ledger that cannot be read refuses, with its own reason, and the
    /// refusal is not remembered either.
    #[test]
    fn a_ledger_that_cannot_be_read_fails_closed() {
        let _turn = take_cache_turn();
        clear_cache();
        block_on(async {
            let ledger = MemoryLedger::default();
            let (actor, b) = (Uuid::new_v4(), binding());
            ledger.put_job(b.job_id, live_node(actor, b.execution_id));
            ledger.break_reads();
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", Some(&b)).await,
                BindingDecision::Refuse(RefusalReason::Unreadable)
            );
            assert_eq!(
                read_dispatch(&ledger, &b, actor, None).await,
                DispatchRead::Unreadable
            );
        });
        clear_cache();
    }

    /// The controller's own signature and an unbound worker key are decided
    /// without a read; a waiver admits the second and still checks a binding
    /// that is present.
    #[test]
    fn the_gate_reads_the_ledger_only_for_a_worker_key_that_names_a_dispatch() {
        let _turn = take_cache_turn();
        clear_cache();
        block_on(async {
            let ledger = MemoryLedger::default();
            let (actor, b) = (Uuid::new_v4(), binding());
            ledger.break_reads();
            assert_eq!(
                ask(
                    &ledger,
                    actor,
                    RPC_CRYPTO_SCHEME_ED25519,
                    CONTROLLER_RPC_IDENTITY,
                    Some(&b)
                )
                .await,
                BindingDecision::Permit
            );
            assert_eq!(
                ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", None).await,
                BindingDecision::Refuse(RefusalReason::Unbound)
            );
            let waived = |binding| {
                gate(
                    &ledger,
                    Requirement::Waived,
                    SUBJECT,
                    actor,
                    RPC_CRYPTO_SCHEME_HMAC,
                    "",
                    binding,
                )
            };
            assert_eq!(waived(None).await, BindingDecision::Permit);
            assert_eq!(ledger.reads(), 0, "none of these may read the ledger");
            assert_eq!(
                waived(Some(&b)).await,
                BindingDecision::Refuse(RefusalReason::Unreadable),
                "a waiver tolerates absence, never a binding it cannot check"
            );
            assert_eq!(ledger.reads(), 1);
        });
        clear_cache();
    }

    /// One read per distinct dispatch per TTL, not per call.
    #[test]
    fn a_live_answer_costs_one_read_per_ttl() {
        let _turn = take_cache_turn();
        clear_cache();
        block_on(async {
            let ledger = MemoryLedger::default();
            let (actor, b) = (Uuid::new_v4(), binding());
            ledger.put_job(b.job_id, live_node(actor, b.execution_id));
            for _ in 0..5 {
                assert_eq!(
                    ask(&ledger, actor, RPC_CRYPTO_SCHEME_HMAC, "", Some(&b)).await,
                    BindingDecision::Permit
                );
            }
            assert_eq!(ledger.reads(), 1);
        });
        clear_cache();
    }
}
