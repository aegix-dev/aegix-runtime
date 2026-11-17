//! This controller's record of its actors and its dispatches, held in memory.
//!
//! It is the [`GateLedger`] the two gates read. Per that trait's contract it
//! answers with what is recorded and decides nothing: whether a job is live
//! and whether a ceiling refuses are `aegix-rpc-gates`' to say.
//!
//! A job is recorded `running` BEFORE its dispatch is published and is moved
//! to an ended state BEFORE its outcome is shown to anyone, so the record is
//! never behind what a worker or an operator can observe. Ended jobs are kept
//! up to [`MAX_ENDED_JOBS`]; one that has been dropped is a job the ledger
//! does not know, which the dispatch-binding gate refuses.

use aegix_rpc_gates::{DispatchFacts, GateLedger};
use aegix_workflow_engine_core::{EgressScope, LlmTier, WriteCeiling};
use std::collections::{HashMap, VecDeque};
use std::convert::Infallible;
use std::sync::Mutex;
use uuid::Uuid;

/// Dispatches in flight at once. A dispatch above it is refused.
pub const MAX_RUNNING_JOBS: usize = 64;

/// Ended jobs kept for `job` and `wait`. The oldest is dropped first.
pub const MAX_ENDED_JOBS: usize = 1024;

/// Whether an actor may be dispatched for and served.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorStatus {
    Active,
    Suspended,
}

impl ActorStatus {
    /// The string the dispatch-binding gate compares
    /// (`dispatch_binding::DISPATCHABLE_ACTOR_STATUS` is `"active"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Suspended => "suspended",
        }
    }
}

/// An actor: an identity a module runs as, and the ceilings on what a run as
/// it may do.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Actor {
    pub id: Uuid,
    pub name: String,
    pub status: ActorStatus,
    pub max_llm_tier: LlmTier,
    pub egress_scope: Option<EgressScope>,
    pub max_write_ceiling: WriteCeiling,
}

/// Where a dispatch is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum JobState {
    /// Published, and no accepted result yet.
    Running,
    /// The worker's verified result reported success.
    Completed,
    /// The worker's verified result reported failure, or the dispatch could
    /// not be published.
    Failed,
    /// No accepted result arrived inside the dispatch's window, or the
    /// worker's verified result reported a timeout.
    #[serde(rename = "timeout")]
    TimedOut,
}

impl JobState {
    /// The status string the gate reads. `running` is one of
    /// `dispatch_binding::JOB_DISPATCHING_STATUSES`; the ended three are not.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::TimedOut => "timeout",
        }
    }

    #[must_use]
    pub fn is_ended(self) -> bool {
        !matches!(self, Self::Running)
    }
}

/// What a dispatch came to.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct Outcome {
    /// The module's output, or the worker's error object.
    pub output: serde_json::Value,
    /// Why the job ended as it did, when it did not complete.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// The id the worker signed its result under. Empty when no result was
    /// accepted.
    pub worker_id: String,
    pub execution_time_ms: u64,
    /// The log lines the worker published for this job while it ran,
    /// capped.
    pub log_lines: Vec<String>,
}

/// One dispatch.
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub struct JobRecord {
    pub job_id: Uuid,
    pub actor_id: Uuid,
    pub module: String,
    pub state: JobState,
    /// The worker whose signed claim was answered with this job's sealed
    /// secrets. `None`: nobody claimed (no secrets, or the inline envelope).
    pub claimed_by: Option<String>,
    pub dispatched_unix: u64,
    /// The last second a worker may start this job
    /// (`JobRequest::deadline_unix_secs`).
    pub start_cutoff_unix: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
}

/// Why a dispatch could not be recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// [`MAX_RUNNING_JOBS`] dispatches are already in flight.
    TooManyRunning,
    /// The id is already recorded. Ids are fresh random UUIDs, so this is a
    /// defect in the caller, never a normal outcome.
    DuplicateJob,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooManyRunning => write!(
                f,
                "{MAX_RUNNING_JOBS} dispatches are already in flight; wait for one to end"
            ),
            Self::DuplicateJob => write!(f, "the job id is already recorded"),
        }
    }
}

#[derive(Debug, Default)]
struct Inner {
    actors: HashMap<Uuid, Actor>,
    jobs: HashMap<Uuid, JobRecord>,
    /// Ended jobs, oldest first, for eviction.
    ended: VecDeque<Uuid>,
    running: usize,
}

/// The record. Every method takes one short lock and awaits nothing while
/// holding it.
#[derive(Debug, Default)]
pub struct Ledger {
    inner: Mutex<Inner>,
    /// Woken whenever a job ends.
    ended: tokio::sync::Notify,
}

impl Ledger {
    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        // A panic while the lock was held leaves plain data behind, never a
        // half-applied transition (each method writes its fields in one
        // step), so the record is still the record.
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Add or replace an actor.
    pub fn put_actor(&self, actor: Actor) {
        self.lock().actors.insert(actor.id, actor);
    }

    #[must_use]
    pub fn actor(&self, id: Uuid) -> Option<Actor> {
        self.lock().actors.get(&id).cloned()
    }

    /// An actor by its configured name, or by its id written out.
    #[must_use]
    pub fn find_actor(&self, name_or_id: &str) -> Option<Actor> {
        let inner = self.lock();
        if let Ok(id) = name_or_id.parse::<Uuid>() {
            if let Some(actor) = inner.actors.get(&id) {
                return Some(actor.clone());
            }
        }
        inner
            .actors
            .values()
            .find(|a| a.name == name_or_id)
            .cloned()
    }

    #[must_use]
    pub fn actors(&self) -> Vec<Actor> {
        let mut actors: Vec<Actor> = self.lock().actors.values().cloned().collect();
        actors.sort_by(|a, b| a.name.cmp(&b.name));
        actors
    }

    /// Change an actor's status. `false`: there is no such actor.
    pub fn set_actor_status(&self, id: Uuid, status: ActorStatus) -> bool {
        match self.lock().actors.get_mut(&id) {
            Some(actor) => {
                actor.status = status;
                true
            }
            None => false,
        }
    }

    /// Record a dispatch as `running`. Called before the dispatch is
    /// published.
    pub fn record_dispatch(
        &self,
        job_id: Uuid,
        actor_id: Uuid,
        module: &str,
        dispatched_unix: u64,
        start_cutoff_unix: u64,
    ) -> Result<(), RecordError> {
        let mut inner = self.lock();
        if inner.running >= MAX_RUNNING_JOBS {
            return Err(RecordError::TooManyRunning);
        }
        if inner.jobs.contains_key(&job_id) {
            return Err(RecordError::DuplicateJob);
        }
        inner.running += 1;
        inner.jobs.insert(
            job_id,
            JobRecord {
                job_id,
                actor_id,
                module: module.to_string(),
                state: JobState::Running,
                claimed_by: None,
                dispatched_unix,
                start_cutoff_unix,
                outcome: None,
            },
        );
        Ok(())
    }

    /// Record the worker whose claim was answered with the job's sealed
    /// secrets. `false`: the job is not running (it ended, or was never
    /// recorded), or another worker already claimed it, and the claim must
    /// not be answered.
    ///
    /// The first claim is the job's claimant for good. A job's secrets are
    /// sealed for one claim, so a second is not expected; if one arrived it
    /// must not move the job's data to another worker.
    pub fn record_claimant(&self, job_id: Uuid, worker_id: &str) -> bool {
        match self.lock().jobs.get_mut(&job_id) {
            Some(job) if job.state == JobState::Running => match &job.claimed_by {
                Some(first) => first == worker_id,
                None => {
                    job.claimed_by = Some(worker_id.to_string());
                    true
                }
            },
            _ => false,
        }
    }

    /// End a running job. `false`: it was not running, and nothing changed
    /// (a job ends once).
    pub fn finish(&self, job_id: Uuid, state: JobState, outcome: Outcome) -> bool {
        debug_assert!(state.is_ended(), "a job is finished into an ended state");
        let finished = {
            let mut inner = self.lock();
            let Some(job) = inner.jobs.get_mut(&job_id) else {
                return false;
            };
            if job.state != JobState::Running || !state.is_ended() {
                return false;
            }
            job.state = state;
            job.outcome = Some(outcome);
            inner.running = inner.running.saturating_sub(1);
            inner.ended.push_back(job_id);
            while inner.ended.len() > MAX_ENDED_JOBS {
                if let Some(oldest) = inner.ended.pop_front() {
                    inner.jobs.remove(&oldest);
                }
            }
            true
        };
        if finished {
            self.ended.notify_waiters();
        }
        finished
    }

    #[must_use]
    pub fn job(&self, job_id: Uuid) -> Option<JobRecord> {
        self.lock().jobs.get(&job_id).cloned()
    }

    /// (running, ended and kept).
    #[must_use]
    pub fn job_counts(&self) -> (usize, usize) {
        let inner = self.lock();
        (inner.running, inner.ended.len())
    }

    /// The job's record once it has ended, or `None` when it is still running
    /// at `timeout`, or is not recorded.
    pub async fn wait_ended(
        &self,
        job_id: Uuid,
        timeout: std::time::Duration,
    ) -> Option<JobRecord> {
        let wait = async {
            loop {
                // Registered before the check, so an end between the check
                // and the await is not missed.
                let woken = self.ended.notified();
                match self.job(job_id) {
                    Some(job) if job.state.is_ended() => return Some(job),
                    Some(_) => {}
                    None => return None,
                }
                woken.await;
            }
        };
        tokio::time::timeout(timeout, wait).await.ok().flatten()
    }
}

impl GateLedger for Ledger {
    type Error = Infallible;

    async fn dispatch_facts(&self, job_id: Uuid) -> Result<Option<DispatchFacts>, Self::Error> {
        let inner = self.lock();
        Ok(inner.jobs.get(&job_id).map(|job| DispatchFacts {
            actor_id: Some(job.actor_id),
            job_status: job.state.as_str().to_string(),
            actor_status: inner
                .actors
                .get(&job.actor_id)
                .map(|actor| actor.status.as_str().to_string()),
            claimed_by: job.claimed_by.clone(),
            // Every dispatch this controller makes is one module run with no
            // workflow run around it: the job is its own execution.
            run_id: None,
            live_run_status: None,
        }))
    }

    async fn actor_write_ceiling(
        &self,
        actor_id: Uuid,
    ) -> Result<Option<WriteCeiling>, Self::Error> {
        Ok(self
            .lock()
            .actors
            .get(&actor_id)
            .map(|actor| actor.max_write_ceiling))
    }
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    pub(crate) fn actor(name: &str, ceiling: WriteCeiling) -> Actor {
        Actor {
            id: Uuid::new_v4(),
            name: name.to_string(),
            status: ActorStatus::Active,
            max_llm_tier: LlmTier::Tier1,
            egress_scope: None,
            max_write_ceiling: ceiling,
        }
    }

    pub(crate) fn outcome() -> Outcome {
        Outcome {
            output: serde_json::json!({"ok": true}),
            error: None,
            worker_id: "worker-a".to_string(),
            execution_time_ms: 7,
            log_lines: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{actor, outcome};
    use super::*;
    use aegix_rpc_gates::dispatch_binding::{
        dispatch_is_live, DISPATCHABLE_ACTOR_STATUS, JOB_DISPATCHING_STATUSES,
    };
    use aegix_rpc_protocol::dispatch_binding::DispatchBinding;

    fn module_bound(job_id: Uuid) -> DispatchBinding {
        DispatchBinding {
            execution_id: job_id,
            job_id,
        }
    }

    #[test]
    fn the_strings_the_ledger_records_are_the_strings_the_gate_compares() {
        assert_eq!(ActorStatus::Active.as_str(), DISPATCHABLE_ACTOR_STATUS);
        assert_ne!(ActorStatus::Suspended.as_str(), DISPATCHABLE_ACTOR_STATUS);
        assert!(JOB_DISPATCHING_STATUSES.contains(&JobState::Running.as_str()));
        for ended in [JobState::Completed, JobState::Failed, JobState::TimedOut] {
            assert!(
                !JOB_DISPATCHING_STATUSES.contains(&ended.as_str()),
                "{ended:?} must not read as a live job"
            );
            assert!(ended.is_ended());
        }
        assert!(!JobState::Running.is_ended());
    }

    #[tokio::test]
    async fn a_recorded_job_is_live_until_it_ends_and_never_again() {
        let ledger = Ledger::default();
        let a = actor("demo", WriteCeiling::ReadOnly);
        ledger.put_actor(a.clone());
        let job = Uuid::new_v4();
        ledger
            .record_dispatch(job, a.id, "m", 100, 130)
            .expect("recorded");

        let facts = ledger.dispatch_facts(job).await.unwrap().expect("facts");
        assert_eq!(facts.actor_id, Some(a.id));
        assert_eq!(facts.job_status, "running");
        assert_eq!(facts.actor_status.as_deref(), Some("active"));
        assert_eq!(facts.run_id, None);
        assert!(dispatch_is_live(&facts, &module_bound(job), a.id, None));

        assert!(ledger.finish(job, JobState::Completed, outcome()));
        let facts = ledger.dispatch_facts(job).await.unwrap().expect("facts");
        assert_eq!(facts.job_status, "completed");
        assert!(!dispatch_is_live(&facts, &module_bound(job), a.id, None));

        // A job ends once: a second finish changes nothing.
        assert!(!ledger.finish(job, JobState::Failed, outcome()));
        assert_eq!(ledger.job(job).unwrap().state, JobState::Completed);
    }

    #[tokio::test]
    async fn a_job_the_ledger_does_not_hold_has_no_facts() {
        let ledger = Ledger::default();
        assert_eq!(ledger.dispatch_facts(Uuid::new_v4()).await.unwrap(), None);
    }

    #[tokio::test]
    async fn a_suspended_actors_running_job_is_not_live() {
        let ledger = Ledger::default();
        let a = actor("demo", WriteCeiling::Write);
        ledger.put_actor(a.clone());
        let job = Uuid::new_v4();
        ledger.record_dispatch(job, a.id, "m", 0, 30).unwrap();
        assert!(ledger.set_actor_status(a.id, ActorStatus::Suspended));
        let facts = ledger.dispatch_facts(job).await.unwrap().unwrap();
        assert_eq!(facts.actor_status.as_deref(), Some("suspended"));
        assert!(!dispatch_is_live(&facts, &module_bound(job), a.id, None));
        assert!(!ledger.set_actor_status(Uuid::new_v4(), ActorStatus::Active));
    }

    #[tokio::test]
    async fn a_claimant_is_recorded_only_on_a_running_job() {
        let ledger = Ledger::default();
        let a = actor("demo", WriteCeiling::Write);
        ledger.put_actor(a.clone());
        let job = Uuid::new_v4();
        ledger.record_dispatch(job, a.id, "m", 0, 30).unwrap();
        assert!(ledger.record_claimant(job, "worker-a"));
        let facts = ledger.dispatch_facts(job).await.unwrap().unwrap();
        assert_eq!(facts.claimed_by.as_deref(), Some("worker-a"));
        // The claimant may ask; another worker's key may not.
        assert!(dispatch_is_live(
            &facts,
            &module_bound(job),
            a.id,
            Some("worker-a")
        ));
        assert!(!dispatch_is_live(
            &facts,
            &module_bound(job),
            a.id,
            Some("worker-b")
        ));

        // The first claim stands: a second worker's is refused and changes
        // nothing; the claimant's own again is the same record.
        assert!(!ledger.record_claimant(job, "worker-b"));
        assert!(ledger.record_claimant(job, "worker-a"));
        let facts = ledger.dispatch_facts(job).await.unwrap().unwrap();
        assert_eq!(facts.claimed_by.as_deref(), Some("worker-a"));

        ledger.finish(job, JobState::Completed, outcome());
        assert!(
            !ledger.record_claimant(job, "worker-b"),
            "an ended job is not claimed"
        );
        assert!(!ledger.record_claimant(Uuid::new_v4(), "worker-a"));
    }

    #[tokio::test]
    async fn the_write_ceiling_is_the_actors_and_an_unknown_actor_has_none() {
        let ledger = Ledger::default();
        let ro = actor("ro", WriteCeiling::ReadOnly);
        let rw = actor("rw", WriteCeiling::Write);
        ledger.put_actor(ro.clone());
        ledger.put_actor(rw.clone());
        assert_eq!(
            ledger.actor_write_ceiling(ro.id).await.unwrap(),
            Some(WriteCeiling::ReadOnly)
        );
        assert_eq!(
            ledger.actor_write_ceiling(rw.id).await.unwrap(),
            Some(WriteCeiling::Write)
        );
        assert_eq!(
            ledger.actor_write_ceiling(Uuid::new_v4()).await.unwrap(),
            None
        );
    }

    #[test]
    fn running_jobs_are_capped_and_ended_jobs_are_dropped_oldest_first() {
        let ledger = Ledger::default();
        let a = actor("demo", WriteCeiling::Write);
        ledger.put_actor(a.clone());
        let mut running = Vec::new();
        for _ in 0..MAX_RUNNING_JOBS {
            let job = Uuid::new_v4();
            ledger.record_dispatch(job, a.id, "m", 0, 30).unwrap();
            running.push(job);
        }
        assert_eq!(
            ledger.record_dispatch(Uuid::new_v4(), a.id, "m", 0, 30),
            Err(RecordError::TooManyRunning)
        );
        assert_eq!(
            ledger.record_dispatch(running[0], a.id, "m", 0, 30),
            Err(RecordError::TooManyRunning),
            "the cap is checked first"
        );
        // Ending one frees a slot, and a recorded id is refused.
        assert!(ledger.finish(running[0], JobState::Completed, outcome()));
        assert_eq!(
            ledger.record_dispatch(running[1], a.id, "m", 0, 30),
            Err(RecordError::DuplicateJob)
        );
        let first_ended = running[0];

        // Fill the ended list past its cap: the first to end is dropped.
        for job in running.drain(1..) {
            ledger.finish(job, JobState::Completed, outcome());
        }
        for _ in 0..(MAX_ENDED_JOBS - MAX_RUNNING_JOBS + 1) {
            let job = Uuid::new_v4();
            ledger.record_dispatch(job, a.id, "m", 0, 30).unwrap();
            ledger.finish(job, JobState::Failed, outcome());
        }
        assert_eq!(ledger.job_counts(), (0, MAX_ENDED_JOBS));
        assert!(
            ledger.job(first_ended).is_none(),
            "the oldest ended job is dropped"
        );
    }

    #[tokio::test]
    async fn waiting_returns_when_the_job_ends_and_gives_up_at_its_timeout() {
        let ledger = std::sync::Arc::new(Ledger::default());
        let a = actor("demo", WriteCeiling::Write);
        ledger.put_actor(a.clone());
        let job = Uuid::new_v4();
        ledger.record_dispatch(job, a.id, "m", 0, 30).unwrap();

        assert!(ledger
            .wait_ended(job, std::time::Duration::from_millis(20))
            .await
            .is_none());
        assert!(ledger
            .wait_ended(Uuid::new_v4(), std::time::Duration::from_secs(5))
            .await
            .is_none());

        let waiter = {
            let ledger = ledger.clone();
            tokio::spawn(async move {
                ledger
                    .wait_ended(job, std::time::Duration::from_secs(10))
                    .await
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        ledger.finish(job, JobState::TimedOut, outcome());
        let ended = waiter.await.unwrap().expect("the waiter saw the end");
        assert_eq!(ended.state, JobState::TimedOut);
    }
}
