//! Controller-side write-ceiling gate for the signed-RPC mutation routes.
//!
//! # Why this exists
//!
//! `actors.max_write_ceiling` is ONE control. #750 established that it must be
//! checked on EVERY route to a mutation rather than on the routes that
//! happened to be built first; it closed the controller's `__memory_write__`
//! envelope route and RECORDED, without fixing, the next one — "the
//! memory-RPC `MemoryOp::Set` handler (`aegix-rpc-subscribers`) still TRUSTS
//! the worker's gate".
//!
//! That trust rests on an assumption the transport does not support. The
//! request is HMAC-signed under `WORKER_SHARED_KEY`, which is **fleet-shared**
//! (`rpc_auth`'s own module docs say a compromised worker leaking it "can
//! forge requests for ANY actor"). So the signature proves the sender holds
//! the fleet key — it does not prove the sender ran a write-ceiling gate. Three
//! realistic senders do not:
//!
//! * a worker booted without `AEGIX_WRITE_CEILING_ENFORCED`, which is exactly
//!   the mixed-fleet state `get_platform_info.fleet.write_ceiling.enforced_by
//!   = "some"` reports and #752 calls "the dangerous one";
//! * a worker running an older build, from before the gate existed;
//! * any process at all that has the key.
//!
//! Measured on pristine `main` (2026-09-05,
//! `controller/tests/rpc_write_ceiling_tests.rs`): with enforcement ON at the
//! controller, a signed `MemoryOp::Set` naming an actor whose
//! `max_write_ceiling = 'readonly'` landed a row in `actor_memory` and the
//! reply said `Ok`.
//!
//! # Shape
//!
//! [`decide`] is **pure** — `enforced` is a parameter, not an env read, and
//! the database answer arrives as a three-valued [`CeilingRead`] — so the rule
//! is testable with no process env and no Postgres, and so the two states that
//! mean *unknown* cannot be collapsed into the state that means *permitted*.
//! The DECISION itself is [`aegix_workflow_job_protocol::write_ceiling_denies`]
//! (a re-export of `aegix_dispatch_types`'s), shared with the worker and
//! with #750's envelope gate rather than re-derived here: two paths answering
//! one question differently IS the defect.
//!
//! # What this deliberately does NOT do
//!
//! It does not read the env. Whether the ceiling is enforced is [`gate`]'s
//! `enforced` argument: the platform's caller
//! (`aegix_rpc_subscribers::write_ceiling::gate`) passes
//! `aegix_workflow_engine::write_ceiling_gate::controller_write_ceiling_enforced`
//! — the controller process's ONE reader of `AEGIX_WRITE_CEILING_ENFORCED`,
//! already cached in a `OnceLock` and already consulted by the envelope gate.
//! A second reader here would be a second answer to "is this control live",
//! which is check 69's class.
//!
//! It does not read Postgres. The ceiling arrives through
//! [`crate::ledger::GateLedger::actor_write_ceiling`], so a controller with no
//! database decides by this same code.
//!
//! It does not count. A refusal is returned to the caller, which owns the
//! metrics registry, and is written here once to the `talos_audit` log target.
//!
//! It does not gate `talos.state.write`. See [`CONTROLLER_SERVED_WRITE_OPS`].

use crate::ledger::GateLedger;
use aegix_dispatch_types::{write_ceiling_denies, WriteCeiling};
use aegix_rpc_protocol::{database_rpc, integration_state_rpc, memory_rpc};

/// The answer to "what is this actor's ceiling?", kept three-valued so a
/// caller must say what an unreadable answer means at its own site.
///
/// Same shape and same reasoning as `ExecutionLookup` (#748) and
/// `classify_input_schema_read` (#730): a determinate value, a determinate
/// absence, and *we could not look* are three different facts, and folding the
/// third into either of the others is how a gate silently stops gating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CeilingRead {
    /// The row was read and carried a (fail-closed parsed) ceiling.
    Found(WriteCeiling),
    /// No `actors` row with this id. Reachable legitimately — an actor
    /// deleted while one of its jobs was still in flight — and illegitimately,
    /// since the caller supplies the id under a FLEET-SHARED signature.
    NoSuchActor,
    /// The lookup itself failed (pool exhaustion, Postgres restart, column
    /// drift). Carries no detail: nothing downstream may act on the cause,
    /// and the raw error must not reach a caller.
    Unreadable,
}

/// Why a mutation was refused. **Operator-facing only** — see
/// [`CeilingDecision`] for why this does not reach the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalReason {
    /// The actor exists, enforcement is on, and its ceiling is `readonly`.
    Policy,
    /// The rule could not be read (absent actor, or a failed lookup), so the
    /// gate failed CLOSED. Distinct from [`Self::Policy`] because it names an
    /// operator problem — a dangling actor id, or a database the enforcement
    /// path cannot reach — rather than a policy working as configured.
    Unreadable,
}

impl RefusalReason {
    /// Stable snake_case token for logs and the `talos_rpc` outcome tag.
    /// Append, never rename — dashboards key on these.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Policy => "write_ceiling",
            Self::Unreadable => "write_ceiling_unreadable",
        }
    }

    /// The same two-valued fact, spelled for the `reason` label of
    /// `aegix_rpc_write_ceiling_refusals_total`.
    ///
    /// A SECOND spelling of one fact is the drift this file's own tests are
    /// about, so it is justified rather than assumed: the metric is already
    /// named `..._write_ceiling_refusals_total`, so a label reading
    /// `reason="write_ceiling"` says the metric's own name back and carries no
    /// information, while `reason="write_ceiling_unreadable"` is the only value
    /// that distinguishes anything. The short pair is what a dashboard legend
    /// can render. `refusal_reason_spellings_stay_paired` pins the mapping, and
    /// the `match` is exhaustive, so a third variant cannot be added without
    /// deciding its metric spelling.
    ///
    /// The LOG keeps [`Self::as_str`] — those tokens are the worker's, and
    /// renaming them would break the `mutation_profile` ↔ audit-event
    /// correlation `get_module_info` promises.
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Policy => "policy",
            Self::Unreadable => "unreadable",
        }
    }
}

/// The gate's verdict.
///
/// `#[must_use]`: a gate whose answer is computed and dropped is worse than no
/// gate, because the code then LOOKS gated. (#736's shape — a classifier that
/// runs and whose result is thrown away — was measured as the survivor of
/// every other instrument in that change.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum CeilingDecision {
    Permit,
    Refuse(RefusalReason),
}

impl CeilingDecision {
    pub fn is_refused(self) -> bool {
        matches!(self, Self::Refuse(_))
    }
}

/// The rule, with nothing else in it.
///
/// * Enforcement off (the staged-rollout default) ⇒ `Permit`, unconditionally
///   and without consulting the read at all. This is byte-identical to
///   pre-change behaviour and is why the async wrapper never touches the
///   database on a default-configured deployment.
/// * Enforcement on ⇒ the shared `write_ceiling_denies` decides for a ceiling
///   that was actually read; every other read outcome refuses.
///
/// **Fail closed is not a preference here, it is the only defensible answer.**
/// A gate that cannot read its rule and PERMITS has, in the moment that
/// matters most (a database incident), exactly the behaviour of no gate — and
/// unlike no gate, it leaves logs implying one ran.
pub fn decide(enforced: bool, read: CeilingRead) -> CeilingDecision {
    if !enforced {
        return CeilingDecision::Permit;
    }
    match read {
        CeilingRead::Found(ceiling) => {
            if write_ceiling_denies(true, ceiling) {
                CeilingDecision::Refuse(RefusalReason::Policy)
            } else {
                CeilingDecision::Permit
            }
        }
        CeilingRead::NoSuchActor | CeilingRead::Unreadable => {
            CeilingDecision::Refuse(RefusalReason::Unreadable)
        }
    }
}

/// Read the actor's ceiling and CLASSIFY the read.
///
/// The `Err` arm is logged here (with the ledger's own words, controller-side
/// only) and collapsed to [`CeilingRead::Unreadable`]: the cause is an
/// operator concern and must never travel to a caller, per the checklist's §3
/// rule that raw Postgres text leaks schema.
pub async fn read_ceiling<L: GateLedger + Sync>(ledger: &L, actor_id: uuid::Uuid) -> CeilingRead {
    match ledger.actor_write_ceiling(actor_id).await {
        Ok(Some(c)) => CeilingRead::Found(c),
        Ok(None) => CeilingRead::NoSuchActor,
        Err(e) => {
            tracing::error!(
                target: "talos_rpc",
                event_kind = "write_ceiling_read_failed",
                %actor_id,
                error = %e,
                "write-ceiling lookup failed — failing CLOSED, the mutation is refused"
            );
            CeilingRead::Unreadable
        }
    }
}

/// The gate: resolve the ceiling, decide, and — on a refusal — write the
/// operator-facing record. The caller counts the refusal it is handed.
///
/// `enforced` is the calling process's answer to "is the ceiling enforced
/// here" (see the module docs for why it is an argument).
///
/// `op` MUST be one of the worker's own audit tokens (see
/// [`CONTROLLER_SERVED_WRITE_OPS`]), because `get_module_info`'s
/// `mutation_profile` promises operators that its labels correlate one-to-one
/// with refusal events.
///
/// ## Cost
///
/// Zero when enforcement is off: the ledger is not read. With enforcement ON,
/// one read of the actor's ceiling — over Postgres a primary-key read of
/// `actors`, measured 2026-09-05 at **1.1 µs** server-side and **0.43 ms**
/// including the host round trip, against a memory `Set` that already performs
/// an embedding attempt, an AEAD encrypt and an upsert. A per-actor cache was
/// rejected rather than merely deferred: a TTL on a security rule is a window
/// in which a revoked grant is still honoured, and this path is measured at
/// ~1 write/week on the dev fleet.
pub async fn gate<L: GateLedger + Sync>(
    ledger: &L,
    enforced: bool,
    actor_id: uuid::Uuid,
    op: &'static str,
    subject: &'static str,
    target: &str,
) -> CeilingDecision {
    if !enforced {
        return CeilingDecision::Permit;
    }
    let read = read_ceiling(ledger, actor_id).await;
    let decision = decide(true, read);
    if let CeilingDecision::Refuse(reason) = decision {
        log_refusal(actor_id, op, subject, target, reason, read);
    }
    decision
}

/// Write the operator-facing record of a refusal.
///
/// **Audit parity, and its stated limit.** `op` and `policy` are the EXACT
/// tokens the worker stamps on its `wasi:capability_denied` rows and the exact
/// tokens #750's envelope refusal uses, because the three are the same control
/// refusing the same thing by three transports. The parity is in the
/// VOCABULARY, not the transport: the worker's refusals also enter the
/// hash-chained WORM ledger and the controller has no `ExecutionLedger`
/// producer, so this reaches the `talos_audit` tracing target, and the
/// caller's counters, only — the same limit #750 recorded.
///
/// **`event_kind` is distinct on purpose.** A refusal HERE is a different
/// operational fact from a refusal at the envelope gate. The envelope route
/// has no worker-side gate at all, so refusing there is routine. This route
/// does: reaching it means a worker sent a mutation its OWN gate should have
/// refused, i.e. a FLEET-CONFIGURATION defect (an un-flagged or stale worker),
/// which is worth alerting on where the envelope refusal is not.
fn log_refusal(
    actor_id: uuid::Uuid,
    op: &'static str,
    subject: &'static str,
    target: &str,
    reason: RefusalReason,
    read: CeilingRead,
) {
    let ceiling = match read {
        CeilingRead::Found(c) => c.as_signing_str(),
        // Not "readonly": we did not read a ceiling, and reporting one we did
        // not read is the misleading-report class (#730/#736/#748) one level
        // down. The refusal stands; the field says why it is unknown.
        CeilingRead::NoSuchActor => "<no such actor>",
        CeilingRead::Unreadable => "<unreadable>",
    };
    tracing::warn!(
        target: "talos_audit",
        event_kind = "rpc_write_ceiling_refused",
        op,
        policy = aegix_dispatch_types::WRITE_CEILING_POLICY,
        subject,
        %actor_id,
        reason = reason.as_str(),
        ceiling,
        target_preview = %target,
        "write-ceiling: signed-RPC mutation refused at the controller — the \
         sending worker did not refuse it itself, which means its \
         AEGIX_WRITE_CEILING_ENFORCED is unset or its build predates the gate"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// Audit probe
// ───────────────────────────────────────────────────────────────────────────

/// Exercise THIS gate — the signed-RPC mutation route — and inspect the result.
///
/// The twin of `aegix_workflow_engine::write_ceiling_gate::probe_envelope_gate`,
/// and together they are what lets `security_audit` claim `round_trip` for the
/// controller half of the write ceiling instead of repeating the sentence "the
/// controller cannot exercise it from here", which stopped being true when
/// #750 and #757 landed.
///
/// # What it asserts, and why each arm
///
/// * `readonly` REFUSES, with `RefusalReason::Policy` — the rule working as
///   configured.
/// * `write` PERMITS. A gate that refuses everything is an outage, not a gate.
/// * **Both** unknown reads — `CeilingRead::NoSuchActor` and
///   `CeilingRead::Unreadable` — REFUSE, with `RefusalReason::Unreadable`.
///   This is the arm that matters most and the one no configuration check can
///   reach: a gate that cannot read its rule and permits has, during a database
///   incident, exactly the behaviour of no gate, while leaving logs implying one
///   ran. The reason must also be DISTINCT from the policy refusal, because "this
///   actor is readonly" and "I could not find out" send an operator to two
///   different places.
/// * With enforcement OFF every read PERMITS — the staged-rollout default,
///   byte-identical to pre-#757 behaviour.
///
/// # Cost
///
/// Pure and in-process: `decide` takes `enforced` as a parameter and the
/// ledger's answer as a value, so this touches neither the env nor a ledger.
/// The DB-backed `CeilingRead` path is deliberately NOT probed — resolving a
/// real actor row would mean either writing a probe actor (a side effect in an
/// audit documented as side-effect free) or depending on one existing (a probe
/// that reports "broken" when the fixture is missing). What a live read adds
/// over this is coverage of `read_actor_write_ceiling`'s own SQL, which is
/// covered by the controller's `rpc_write_ceiling_tests`.
///
/// # Errors
///
/// `Err(arm)` names the FIRST arm that behaved wrongly. No partial-success
/// shape: a gate that refuses correctly and permits wrongly is broken.
pub fn probe_rpc_gate() -> Result<(), &'static str> {
    if decide(true, CeilingRead::Found(WriteCeiling::ReadOnly))
        != CeilingDecision::Refuse(RefusalReason::Policy)
    {
        return Err("signed-RPC route: a readonly actor's mutation was PERMITTED");
    }
    if decide(true, CeilingRead::Found(WriteCeiling::Write)) != CeilingDecision::Permit {
        return Err("signed-RPC route: a write-capable actor's mutation was REFUSED");
    }
    for read in [CeilingRead::NoSuchActor, CeilingRead::Unreadable] {
        if decide(true, read) != CeilingDecision::Refuse(RefusalReason::Unreadable) {
            return Err(
                "signed-RPC route: an unreadable ceiling rule did NOT fail closed — during a \
                 database incident this gate permits every mutation",
            );
        }
    }
    for read in [
        CeilingRead::Found(WriteCeiling::ReadOnly),
        CeilingRead::Found(WriteCeiling::Write),
        CeilingRead::NoSuchActor,
        CeilingRead::Unreadable,
    ] {
        if decide(false, read) != CeilingDecision::Permit {
            return Err("signed-RPC route: enforcement is OFF but a mutation was refused anyway");
        }
    }
    Ok(())
}

// ── The op vocabulary, and the parity contract ──────────────────────────────

/// Worker audit token for an actor-memory delete. `aegix_workflow_job_protocol`
/// exports only the `set` token (#750 needed only that one); these two are
/// spelled here rather than re-derived, and
/// `controller_ops_are_worker_ops` pins all of them against
/// `aegix_capability_world::write_gated_ops` so a rename on the worker side
/// fails this crate's tests.
pub const AGENT_MEMORY_DELETE_OP: &str = "agent-memory-delete";
pub const AGENT_MEMORY_STORE_WITH_EMBEDDING_OP: &str = "agent-memory-store-with-embedding";
pub const INTEGRATION_STATE_SET_OP: &str = "integration-state-set";
pub const INTEGRATION_STATE_DELETE_OP: &str = "integration-state-delete";
pub const DATABASE_QUERY_OP: &str = "database-query";

/// Every ceiling-gated WORKER op whose mutation is actually PERFORMED BY THE
/// CONTROLLER, over a signed RPC subject — i.e. exactly the set a controller
/// must refuse when the worker did not.
///
/// The worker's full ceiling-gated set (`aegix_capability_world::write_gated_ops`)
/// is larger, and the remainder is deliberately NOT here: `http-fetch`,
/// `http-fetch-all`, `webhook-send`, `email-send`, `graphql-execute`,
/// `messaging-publish`, `messaging-request`, `object-storage-put` and
/// `object-storage-delete` all egress from the WORKER process and never reach
/// a controller RPC subscriber, so the controller has no place to stand.
/// `complement_is_worker_local` pins that split, so a NEW ceiling-gated worker
/// op forces a decision here instead of silently landing in the ungated half.
///
/// `talos.state.write` is absent for a different and stronger reason: the
/// worker deliberately does NOT ceiling-gate execution `state` (it is
/// engine-internal durability, not the actor's data — `write_gated_ops`' own
/// docs say so), and `talos.graph.search`, `talos.ml.predict` and
/// `talos.ml.fewshot` are reads. Gating any of them here would make the
/// controller STRICTER than the worker, which is the same class of defect as
/// being laxer: one control, two answers.
pub const CONTROLLER_SERVED_WRITE_OPS: &[(&str, &str)] = &[
    (
        aegix_dispatch_types::AGENT_MEMORY_SET_OP,
        memory_rpc::SUBJECT_MEMORY_OP,
    ),
    (
        AGENT_MEMORY_STORE_WITH_EMBEDDING_OP,
        memory_rpc::SUBJECT_MEMORY_OP,
    ),
    (AGENT_MEMORY_DELETE_OP, memory_rpc::SUBJECT_MEMORY_OP),
    (
        INTEGRATION_STATE_SET_OP,
        integration_state_rpc::SUBJECT_INTEGRATION_STATE_OP,
    ),
    (
        INTEGRATION_STATE_DELETE_OP,
        integration_state_rpc::SUBJECT_INTEGRATION_STATE_OP,
    ),
    (DATABASE_QUERY_OP, database_rpc::SUBJECT_DATABASE_QUERY),
];

#[cfg(test)]
mod write_ceiling_tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn enforcement_off_permits_every_read_outcome() {
        // The staged-rollout default. Byte-identical to pre-change behaviour,
        // including for the failure reads — a deployment that has not opted in
        // must not start refusing because Postgres hiccuped.
        for read in [
            CeilingRead::Found(WriteCeiling::Write),
            CeilingRead::Found(WriteCeiling::ReadOnly),
            CeilingRead::NoSuchActor,
            CeilingRead::Unreadable,
        ] {
            assert_eq!(decide(false, read), CeilingDecision::Permit, "{read:?}");
        }
    }

    #[test]
    fn enforcement_on_refuses_readonly_and_permits_write() {
        assert_eq!(
            decide(true, CeilingRead::Found(WriteCeiling::ReadOnly)),
            CeilingDecision::Refuse(RefusalReason::Policy)
        );
        assert_eq!(
            decide(true, CeilingRead::Found(WriteCeiling::Write)),
            CeilingDecision::Permit
        );
    }

    #[test]
    fn an_unreadable_rule_fails_closed_with_its_own_reason() {
        // SECURITY: neither of these may PERMIT. And they must be
        // distinguishable from a policy refusal in the operator's logs —
        // "this actor is readonly" and "I could not find out" send an
        // operator to two different places.
        for read in [CeilingRead::NoSuchActor, CeilingRead::Unreadable] {
            assert_eq!(
                decide(true, read),
                CeilingDecision::Refuse(RefusalReason::Unreadable),
                "{read:?} must fail closed"
            );
        }
        assert_ne!(
            RefusalReason::Policy.as_str(),
            RefusalReason::Unreadable.as_str()
        );
    }

    #[test]
    fn the_decision_is_the_shared_predicate_not_a_local_copy() {
        // If `write_ceiling_denies` ever changes, this must change with it.
        // Pinning the agreement here is what stops a local re-derivation from
        // drifting — the defect #750 exists because of.
        for (enforced, ceiling) in [
            (true, WriteCeiling::ReadOnly),
            (true, WriteCeiling::Write),
            (false, WriteCeiling::ReadOnly),
            (false, WriteCeiling::Write),
        ] {
            let shared = write_ceiling_denies(enforced, ceiling);
            let ours = decide(enforced, CeilingRead::Found(ceiling)).is_refused();
            assert_eq!(shared, ours, "enforced={enforced} ceiling={ceiling:?}");
        }
    }

    /// Every op the controller gates must be an op the WORKER gates, spelled
    /// identically. A rename on either side fails here rather than silently
    /// breaking the `mutation_profile` ↔ audit-event correlation
    /// `get_module_info` promises operators.
    #[test]
    fn controller_ops_are_worker_ops() {
        let worker: HashSet<&str> = aegix_capability_world::write_gated_ops(
            &aegix_capability_world::CapabilityWorld::Trusted,
        )
        .into_iter()
        .collect();
        for (op, _subject) in CONTROLLER_SERVED_WRITE_OPS {
            assert!(
                worker.contains(op),
                "`{op}` is gated by the controller but is not in the worker's \
                 write_gated_ops — one control, two vocabularies"
            );
        }
    }

    /// The complement. Every worker-gated op the controller does NOT gate must
    /// be one the controller structurally CANNOT gate, because the mutation
    /// happens inside the worker process and never reaches a subscriber.
    ///
    /// This is the half that keeps the list honest: without it, a NEW
    /// ceiling-gated worker op would land in the ungated remainder and nothing
    /// would say so. Adding one now fails this test until someone decides
    /// which half it belongs in.
    #[test]
    fn complement_is_worker_local() {
        const WORKER_LOCAL_EGRESS_OPS: &[&str] = &[
            "http-fetch",
            "http-fetch-all",
            "webhook-send",
            "email-send",
            "graphql-execute",
            "messaging-publish",
            "messaging-request",
            "object-storage-put",
            "object-storage-delete",
        ];
        let controller: HashSet<&str> = CONTROLLER_SERVED_WRITE_OPS
            .iter()
            .map(|(op, _)| *op)
            .collect();
        let worker_local: HashSet<&str> = WORKER_LOCAL_EGRESS_OPS.iter().copied().collect();
        let worker: HashSet<&str> = aegix_capability_world::write_gated_ops(
            &aegix_capability_world::CapabilityWorld::Trusted,
        )
        .into_iter()
        .collect();

        let unaccounted: Vec<&str> = worker
            .iter()
            .copied()
            .filter(|op| !controller.contains(op) && !worker_local.contains(op))
            .collect();
        assert!(
            unaccounted.is_empty(),
            "these worker ceiling-gated ops are in neither half — decide \
             whether the controller serves them over RPC (add to \
             CONTROLLER_SERVED_WRITE_OPS and gate it) or whether they are \
             worker-local egress (add to WORKER_LOCAL_EGRESS_OPS): \
             {unaccounted:?}"
        );
        // And nothing may be claimed worker-local that the worker does not
        // actually gate — a stale entry here would silently excuse a real op.
        for op in WORKER_LOCAL_EGRESS_OPS {
            assert!(
                worker.contains(op),
                "`{op}` is listed as worker-local egress but the worker does \
                 not ceiling-gate it — stale entry"
            );
        }
    }

    /// The audit's `round_trip` claim for the signed-RPC half rests entirely
    /// on this returning `Ok`. A REGRESSION guard, not a restatement of the
    /// `decide` tests above: those call `decide` directly, so all of them
    /// could pass while the probe — the thing a running controller executes —
    /// was wired wrong.
    #[test]
    fn the_audit_probe_finds_this_gate_healthy() {
        assert_eq!(probe_rpc_gate(), Ok(()));
    }

    /// Two spellings of one fact must not drift. The log token is the
    /// worker's vocabulary; the metric label is the dashboard's. An operator
    /// correlating a `aegix_rpc_write_ceiling_refusals_total{reason="policy"}`
    /// bump against `event_kind=rpc_write_ceiling_refused reason=write_ceiling`
    /// needs the pairing to be stable, and both come from exhaustive matches
    /// so a third variant cannot skip either.
    #[test]
    fn refusal_reason_spellings_stay_paired() {
        for (r, log, metric) in [
            (RefusalReason::Policy, "write_ceiling", "policy"),
            (
                RefusalReason::Unreadable,
                "write_ceiling_unreadable",
                "unreadable",
            ),
        ] {
            assert_eq!(r.as_str(), log);
            assert_eq!(r.metric_label(), metric);
        }
        assert_ne!(
            RefusalReason::Policy.metric_label(),
            RefusalReason::Unreadable.metric_label()
        );
    }

    // That a refusal moves the platform's counters, and that every gated
    // subject is one its registry seeds, are pinned where the registry is
    // linked: `aegix_rpc_subscribers::write_ceiling`'s tests.

    #[test]
    fn every_gated_op_names_a_real_subject() {
        for (op, subject) in CONTROLLER_SERVED_WRITE_OPS {
            assert!(
                subject.starts_with("talos."),
                "`{op}` names `{subject}`, which is not a talos NATS subject"
            );
        }
    }

    // ── the gate over a ledger ─────────────────────────────────────────────

    use crate::ledger::testing::MemoryLedger;
    use uuid::Uuid;

    async fn ask(ledger: &MemoryLedger, enforced: bool, actor: Uuid) -> CeilingDecision {
        gate(
            ledger,
            enforced,
            actor,
            aegix_dispatch_types::AGENT_MEMORY_SET_OP,
            memory_rpc::SUBJECT_MEMORY_OP,
            "probe/key",
        )
        .await
    }

    #[tokio::test]
    async fn a_readonly_actor_is_refused_and_a_writable_one_permitted() {
        let ledger = MemoryLedger::default();
        let (readonly, writable) = (Uuid::new_v4(), Uuid::new_v4());
        ledger.put_ceiling(readonly, WriteCeiling::ReadOnly);
        ledger.put_ceiling(writable, WriteCeiling::Write);
        assert_eq!(
            ask(&ledger, true, readonly).await,
            CeilingDecision::Refuse(RefusalReason::Policy)
        );
        assert_eq!(ask(&ledger, true, writable).await, CeilingDecision::Permit);
        // The ceiling is read on every call: a ceiling lowered between two
        // mutations refuses the second.
        ledger.put_ceiling(writable, WriteCeiling::ReadOnly);
        assert_eq!(
            ask(&ledger, true, writable).await,
            CeilingDecision::Refuse(RefusalReason::Policy)
        );
        assert_eq!(ledger.reads(), 3, "one read per call, none remembered");
    }

    /// SECURITY: an actor the ledger does not hold, and a ledger that cannot
    /// be read, both refuse, with the reason that is not the policy's.
    #[tokio::test]
    async fn a_ceiling_that_cannot_be_read_fails_closed() {
        let ledger = MemoryLedger::default();
        let actor = Uuid::new_v4();
        assert_eq!(
            ask(&ledger, true, actor).await,
            CeilingDecision::Refuse(RefusalReason::Unreadable),
            "no such actor"
        );
        ledger.put_ceiling(actor, WriteCeiling::Write);
        assert_eq!(ask(&ledger, true, actor).await, CeilingDecision::Permit);
        ledger.break_reads();
        assert_eq!(
            ask(&ledger, true, actor).await,
            CeilingDecision::Refuse(RefusalReason::Unreadable),
            "a writable actor whose ceiling cannot be read"
        );
        assert_eq!(read_ceiling(&ledger, actor).await, CeilingRead::Unreadable);
    }

    /// The staged-rollout default: enforcement off permits everything and
    /// does not look, so a ledger that is down refuses nothing.
    #[tokio::test]
    async fn enforcement_off_permits_without_reading_the_ledger() {
        let ledger = MemoryLedger::default();
        let readonly = Uuid::new_v4();
        ledger.put_ceiling(readonly, WriteCeiling::ReadOnly);
        ledger.break_reads();
        assert_eq!(ask(&ledger, false, readonly).await, CeilingDecision::Permit);
        assert_eq!(
            ask(&ledger, false, Uuid::new_v4()).await,
            CeilingDecision::Permit
        );
        assert_eq!(ledger.reads(), 0);
    }
}
