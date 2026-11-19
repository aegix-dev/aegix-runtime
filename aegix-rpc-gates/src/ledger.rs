//! What the gates ask of a controller's record of its dispatches and actors.
//!
//! A ledger answers with FACTS, never with a verdict. Whether a dispatch is
//! live ([`crate::dispatch_binding::dispatch_is_live`]) and whether a ceiling
//! refuses ([`crate::write_ceiling::decide`]) are decided in this crate, from
//! what the ledger read, so a controller that keeps its record in Postgres and
//! one that keeps it in memory cannot come to hold two rules. An
//! implementation is a lookup and nothing else: it must not filter on status,
//! actor, claimant or run, and it must not turn "I could not read" into
//! `Ok(None)`.

use aegix_dispatch_types::WriteCeiling;
use std::fmt::Display;
use std::future::Future;
use uuid::Uuid;

/// What the ledger records about one job, read in ONE snapshot: the gate
/// compares several of these with each other, and a job that ended between
/// two reads must not be seen as live by the first and claimed by the second.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchFacts {
    /// The actor the job's record names. `None`: the job has no actor.
    pub actor_id: Option<Uuid>,
    /// The job's status, exactly as recorded.
    pub job_status: String,
    /// The status of that actor, exactly as recorded. `None`: the job has no
    /// actor, or the ledger holds no such actor.
    pub actor_status: Option<String>,
    /// The worker that claimed the job's secrets. `None`: nobody has.
    pub claimed_by: Option<String>,
    /// The run the job is a node of, as the job's record names it (for a node
    /// of a child run, the child's own id). `None`: a module-bound dispatch,
    /// which has no run.
    pub run_id: Option<Uuid>,
    /// The status, exactly as recorded, of the run that must be live for this
    /// job to be served: the ROOT run the job's record names when it names
    /// one, and otherwise `run_id`'s. Always read from the job's record,
    /// never from anything a request carries. `None`: the job has no run, or
    /// the ledger holds no such run.
    pub live_run_status: Option<String>,
}

/// A controller's record of its dispatches and its actors' write ceilings.
///
/// Both reads are keyed by an id the request's signature binds, and return
/// only what the gates compare: no tenant data crosses this trait.
pub trait GateLedger {
    /// Why a read failed. The gates log it controller-side and refuse; it
    /// never reaches a caller.
    type Error: Display;

    /// The facts recorded for `job_id`. `Ok(None)`: there is no such job.
    /// `Err`: the ledger could not be read (the gate fails closed).
    fn dispatch_facts(
        &self,
        job_id: Uuid,
    ) -> impl Future<Output = Result<Option<DispatchFacts>, Self::Error>> + Send;

    /// The write ceiling recorded for `actor_id`. `Ok(None)`: there is no
    /// such actor. `Err`: the ledger could not be read (the gate fails
    /// closed).
    fn actor_write_ceiling(
        &self,
        actor_id: Uuid,
    ) -> impl Future<Output = Result<Option<WriteCeiling>, Self::Error>> + Send;
}

/// A ledger held in memory, for this crate's tests: jobs and ceilings in two
/// maps, a switch that makes every read fail, and a count of reads so a test
/// can say that a gate did not look.
#[cfg(test)]
pub(crate) mod testing {
    use super::{DispatchFacts, GateLedger, Uuid, WriteCeiling};
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct MemoryLedger {
        jobs: Mutex<HashMap<Uuid, DispatchFacts>>,
        ceilings: Mutex<HashMap<Uuid, WriteCeiling>>,
        broken: AtomicBool,
        reads: AtomicUsize,
    }

    impl MemoryLedger {
        pub(crate) fn put_job(&self, job_id: Uuid, facts: DispatchFacts) {
            self.jobs.lock().expect("jobs").insert(job_id, facts);
        }

        /// Change one recorded job in place, as a controller does when a job
        /// ends or is claimed.
        pub(crate) fn update_job(&self, job_id: Uuid, change: impl FnOnce(&mut DispatchFacts)) {
            change(
                self.jobs
                    .lock()
                    .expect("jobs")
                    .get_mut(&job_id)
                    .expect("the job is recorded"),
            );
        }

        pub(crate) fn put_ceiling(&self, actor_id: Uuid, ceiling: WriteCeiling) {
            self.ceilings
                .lock()
                .expect("ceilings")
                .insert(actor_id, ceiling);
        }

        /// From now on every read fails, as a ledger that is down does.
        pub(crate) fn break_reads(&self) {
            self.broken.store(true, Ordering::SeqCst);
        }

        pub(crate) fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }

        fn read(&self) -> Result<(), &'static str> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if self.broken.load(Ordering::SeqCst) {
                Err("the ledger is down")
            } else {
                Ok(())
            }
        }
    }

    impl GateLedger for MemoryLedger {
        type Error = &'static str;

        async fn dispatch_facts(&self, job_id: Uuid) -> Result<Option<DispatchFacts>, Self::Error> {
            self.read()?;
            Ok(self.jobs.lock().expect("jobs").get(&job_id).cloned())
        }

        async fn actor_write_ceiling(
            &self,
            actor_id: Uuid,
        ) -> Result<Option<WriteCeiling>, Self::Error> {
            self.read()?;
            Ok(self
                .ceilings
                .lock()
                .expect("ceilings")
                .get(&actor_id)
                .copied())
        }
    }
}
