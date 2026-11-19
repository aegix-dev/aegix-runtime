//! The running controller: one NATS connection, the record, and the tasks
//! that send a job and wait for it.
//!
//! The decisions are elsewhere and have no network in them
//! ([`crate::dispatch`], [`crate::data_plane`], [`crate::memory`]). This
//! module is the order things happen in:
//!
//! 1. the job is prepared and signed;
//! 2. the controller subscribes to the job's reply subject and its log
//!    subject, so nothing a worker sends can arrive before there is a
//!    listener;
//! 3. the job is recorded as running, so a data call that names it can be
//!    served from the moment a worker has it, and never before;
//! 4. under worker identity, the job's secrets are registered for one claim;
//! 5. the request is published;
//! 6. the controller waits for a result it believes, until the job's wait
//!    ends. Then it tells every worker to stop the job and records it as
//!    timed out.
//!
//! The job is recorded as ended BEFORE its outcome can be read, so a job
//! that is shown as finished is already refused by the dispatch-binding
//! gate.

use crate::config::{Config, SEED_MEMORY_TYPE};
use crate::counters::{Decision, Refusals};
use crate::data_plane::{self, DataPlane};
use crate::dispatch::{self, Module, Plan, PrepareError, SecretStore, MAX_LOG_LINES};
use crate::keys::{Keys, Posture};
use crate::ledger::{JobState, Ledger, RecordError};
use crate::memory::{self, MemoryStore};
use aegix_dispatch_types::inline_wasm::refuse_over_max_payload;
use aegix_envelope_seal::{ClaimRecord, ClaimRecorder, InFlightSeals};
use aegix_workflow_job_protocol::subjects;
use aegix_workflow_job_protocol::{CancelCommand, JobRequest};
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

/// How old a worker's claim for a job's secrets may be.
pub const CLAIM_MAX_AGE_SECS: u64 = 300;

/// The reason a refused result is counted under, by subject.
const RESULT_SUBJECT: &str = "job.result";

/// How long after a result the controller keeps reading the job's log
/// subject, for lines a worker published just before it.
const LOG_DRAIN: std::time::Duration = std::time::Duration::from_millis(100);

/// The longest the reading of late lines may last in all. The job is still
/// `running` in the ledger while it does, so its data calls are still
/// served: without this bound, a worker that published a line more often
/// than every [`LOG_DRAIN`] held its job open past the controller's wait for
/// as long as it kept publishing.
const LOG_DRAIN_LIMIT: std::time::Duration = std::time::Duration::from_millis(500);

/// Why a dispatch was not sent.
#[derive(Debug)]
pub enum DispatchError {
    NoSuchModule(String),
    NoSuchActor(String),
    Prepare(PrepareError),
    Ledger(RecordError),
    /// The message is larger than the NATS server accepts.
    TooLarge(String),
    Nats(String),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoSuchModule(name) => write!(f, "no module named {name:?} is configured"),
            Self::NoSuchActor(name) => write!(f, "no actor named {name:?} is configured"),
            Self::Prepare(e) => e.fmt(f),
            Self::Ledger(e) => e.fmt(f),
            Self::TooLarge(why) => f.write_str(why),
            Self::Nats(why) => write!(f, "the message bus refused: {why}"),
        }
    }
}

/// The running controller.
pub struct Controller {
    nats: async_nats::Client,
    keys: Keys,
    pub ledger: Arc<Ledger>,
    pub memory: Arc<MemoryStore>,
    pub refusals: Arc<Refusals>,
    secrets: SecretStore,
    modules: HashMap<String, Module>,
    seals: Arc<InFlightSeals>,
    claim_subject: String,
    job_subject: String,
    pickup_window_secs: u64,
}

impl Controller {
    /// Start serving: install the posture's keys, load the record from the
    /// configuration, serve the data plane, and (under worker identity)
    /// answer claims.
    pub async fn start(
        config: Config,
        keys: Keys,
        nats: async_nats::Client,
    ) -> Result<Arc<Self>, String> {
        keys.install();

        let ledger = Arc::new(Ledger::default());
        let memory = Arc::new(MemoryStore::default());
        let refusals = Arc::new(Refusals::default());
        for actor in config.actors {
            ledger.put_actor(actor);
        }
        let now = memory::now_unix();
        for seed in config.seeds {
            memory
                .put(
                    seed.actor_id,
                    &seed.key,
                    seed.value,
                    SEED_MEMORY_TYPE,
                    None,
                    None,
                    now,
                )
                .map_err(|e| format!("memory {:?} in the configuration: {e}", seed.key))?;
        }

        let seals = Arc::new(InFlightSeals::new());
        let claim_subject = nats.new_inbox();
        if let Some(controller_key) = keys.controller_key() {
            let recorder = claim_recorder(ledger.clone());
            let responder = aegix_envelope_seal::run_claim_responder(
                Arc::new(nats.clone()),
                claim_subject.clone(),
                seals.clone(),
                controller_key.clone(),
                CLAIM_MAX_AGE_SECS,
                Some(recorder),
                // No registry in this controller: a dropped claim is logged.
                aegix_envelope_seal::claim_drops_uncounted,
            );
            tokio::spawn(async move {
                if let Err(e) = responder.await {
                    tracing::error!(error = %e, "the claim responder stopped");
                }
            });
        }

        let plane = DataPlane {
            ledger: ledger.clone(),
            memory: memory.clone(),
            refusals: refusals.clone(),
        };
        let plane_nats = nats.clone();
        tokio::spawn(async move {
            if let Err(e) = data_plane::serve(plane_nats, plane).await {
                tracing::error!(error = %e, "the data plane stopped");
            }
        });

        let job_subject = std::env::var("NATS_JOB_TOPIC")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| subjects::JOBS.to_string());

        Ok(Arc::new(Self {
            nats,
            keys,
            ledger,
            memory,
            refusals,
            secrets: config.secrets,
            modules: config.modules,
            seals,
            claim_subject,
            job_subject,
            pickup_window_secs: config.pickup_window_secs,
        }))
    }

    #[must_use]
    pub fn posture(&self) -> Posture {
        self.keys.posture()
    }

    /// The configured modules' names, sorted.
    #[must_use]
    pub fn module_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.modules.keys().cloned().collect();
        names.sort();
        names
    }

    /// The stored secrets' paths, sorted. Paths only.
    #[must_use]
    pub fn secret_paths(&self) -> Vec<String> {
        self.secrets.paths()
    }

    /// Send `module` to a worker for `actor` (a name or an id) with `input`.
    /// Returns the job's id as soon as the request is published; the job's
    /// end is read from the ledger.
    pub async fn dispatch(
        self: &Arc<Self>,
        module: &str,
        actor: &str,
        input: serde_json::Value,
    ) -> Result<Uuid, DispatchError> {
        let module_entry = self
            .modules
            .get(module)
            .ok_or_else(|| DispatchError::NoSuchModule(module.to_string()))?;
        let actor_entry = self
            .ledger
            .find_actor(actor)
            .ok_or_else(|| DispatchError::NoSuchActor(actor.to_string()))?;

        let job_id = Uuid::new_v4();
        let reply_inbox = self.nats.new_inbox();
        let now = memory::now_unix();
        let prepared = dispatch::prepare(Plan {
            keys: &self.keys,
            actor: &actor_entry,
            module: module_entry,
            secrets: &self.secrets,
            input,
            job_id,
            reply_inbox: reply_inbox.clone(),
            claim_subject: &self.claim_subject,
            now_unix: now,
            pickup_window_secs: self.pickup_window_secs,
        })
        .map_err(DispatchError::Prepare)?;

        let payload = serde_json::to_vec(&prepared.request)
            .map_err(|e| DispatchError::Nats(e.to_string()))?;
        refuse_over_max_payload(
            payload.len(),
            self.nats.server_info().max_payload,
            &prepared.request.module_uri,
            prepared.request.wasm_bytes.as_deref(),
        )
        .map_err(|e| DispatchError::TooLarge(e.to_string()))?;

        // Listeners first: a worker answers on the signed reply subject, and
        // a result published before the subscription exists is lost.
        let replies = self
            .nats
            .subscribe(reply_inbox.clone())
            .await
            .map_err(|e| DispatchError::Nats(e.to_string()))?;
        let logs = self
            .nats
            .subscribe(format!("wasm.log.{job_id}"))
            .await
            .map_err(|e| DispatchError::Nats(e.to_string()))?;

        // Recorded before it is published: from here a data call that names
        // this job is served, and there is no moment at which a worker holds
        // a job the ledger does not.
        self.ledger
            .record_dispatch(
                job_id,
                actor_entry.id,
                &module_entry.name,
                now,
                prepared.start_cutoff_unix,
            )
            .map_err(DispatchError::Ledger)?;

        if let Some(seal) = prepared.seal {
            self.seals.register(job_id, 0, seal);
        }

        if let Err(e) = self
            .nats
            .publish_with_reply(self.job_subject.clone(), reply_inbox, payload.into())
            .await
        {
            self.seals.discard(job_id);
            let why = e.to_string();
            self.ledger
                .finish(job_id, JobState::Failed, dispatch::not_sent(&why));
            return Err(DispatchError::Nats(why));
        }

        let controller = self.clone();
        let request = prepared.request;
        let wait = prepared.wait;
        tokio::spawn(async move {
            controller.await_result(request, wait, replies, logs).await;
        });
        Ok(job_id)
    }

    /// Wait for the job's result until `wait` ends, then record how it ended.
    async fn await_result(
        &self,
        request: JobRequest,
        wait: std::time::Duration,
        mut replies: async_nats::Subscriber,
        mut logs: async_nats::Subscriber,
    ) {
        let job_id = request.job_id;
        let deadline = tokio::time::Instant::now() + wait;
        let mut lines: Vec<String> = Vec::new();
        let accepted = loop {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => break None,
                line = logs.next() => {
                    if let Some(msg) = line {
                        push_line(&mut lines, &msg.payload);
                    }
                }
                reply = replies.next() => {
                    let Some(msg) = reply else { break None };
                    let worker = self.seals.claimant(job_id);
                    let claimant = worker
                        .as_deref()
                        .zip(self.seals.claimed_attempt(job_id));
                    match dispatch::accept_result(&self.keys, &request, claimant, &msg.payload) {
                        Ok(result) => break Some(result),
                        Err(refusal) => {
                            // Not this job's result. Keep waiting: the real
                            // one may still come.
                            self.refusals
                                .count(Decision::Result, RESULT_SUBJECT, refusal.as_str());
                            tracing::warn!(
                                target: "talos_audit",
                                job_id = %job_id,
                                reason = refusal.as_str(),
                                "a message on a job's reply subject was not taken as its result"
                            );
                        }
                    }
                }
            }
        };

        // Lines a worker published just before the result.
        drain_late_lines(&mut logs.map(|msg| msg.payload), &mut lines).await;

        self.seals.discard(job_id);
        match accepted {
            Some(result) => {
                let (state, outcome) = dispatch::settle(result, lines);
                self.ledger.finish(job_id, state, outcome);
            }
            None => {
                // Ended in the ledger first, so the job's data calls stop
                // being served before the workers are told.
                self.ledger
                    .finish(job_id, JobState::TimedOut, dispatch::timed_out(wait, lines));
                self.cancel(job_id).await;
            }
        }
    }

    /// Tell every worker to stop `job_id`. A worker that still holds it sets
    /// the job's cancelled flag, which its outbound calls read.
    async fn cancel(&self, job_id: Uuid) {
        let mut command = CancelCommand::new(job_id);
        if let Err(e) = self.keys.signer().sign_cancel(&mut command) {
            tracing::error!(job_id = %job_id, error = %e, "the cancel could not be signed");
            return;
        }
        match serde_json::to_vec(&command) {
            Ok(bytes) => {
                if let Err(e) = self
                    .nats
                    .publish(subjects::WORKERS_CMD_CANCEL, bytes.into())
                    .await
                {
                    tracing::error!(job_id = %job_id, error = %e, "the cancel was not published");
                }
            }
            Err(e) => tracing::error!(job_id = %job_id, error = %e, "the cancel did not serialise"),
        }
    }
}

/// Read the lines already on their way: until [`LOG_DRAIN`] passes with
/// none, and never for longer than [`LOG_DRAIN_LIMIT`] however many arrive.
async fn drain_late_lines<S, B>(payloads: &mut S, lines: &mut Vec<String>)
where
    S: futures::Stream<Item = B> + Unpin,
    B: AsRef<[u8]>,
{
    let limit = tokio::time::Instant::now() + LOG_DRAIN_LIMIT;
    loop {
        let wait = (tokio::time::Instant::now() + LOG_DRAIN).min(limit);
        match tokio::time::timeout_at(wait, payloads.next()).await {
            Ok(Some(payload)) => push_line(lines, payload.as_ref()),
            Ok(None) | Err(_) => return,
        }
        if tokio::time::Instant::now() >= limit {
            return;
        }
    }
}

fn push_line(lines: &mut Vec<String>, payload: &[u8]) {
    if lines.len() < MAX_LOG_LINES {
        if let Some(line) = dispatch::log_message(payload) {
            lines.push(line);
        }
    }
}

/// What the claim responder asks before it hands a job's secrets to a
/// worker: that the job is still running, for its one attempt. The worker
/// is then recorded as the job's claimant. A claim for a job this
/// controller has ended, or never sent, is refused, so a late worker is
/// given nothing.
#[must_use]
pub fn claim_recorder(ledger: Arc<Ledger>) -> ClaimRecorder {
    Arc::new(move |record: ClaimRecord| {
        let ledger = ledger.clone();
        Box::pin(async move {
            if record.dispatch_attempt == 0
                && ledger.record_claimant(record.exec_id, &record.worker_id)
            {
                Ok(())
            } else {
                Err("the job is not running".to_string())
            }
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::testing::{actor, outcome};
    use aegix_dispatch_types::WriteCeiling;

    fn claim(job: Uuid, attempt: u32) -> ClaimRecord {
        ClaimRecord {
            exec_id: job,
            dispatch_attempt: attempt,
            worker_id: "worker-a".to_string(),
        }
    }

    #[tokio::test]
    async fn a_claim_is_recorded_only_for_a_running_job_and_its_one_attempt() {
        let ledger = Arc::new(Ledger::default());
        let a = actor("a", WriteCeiling::Write);
        ledger.put_actor(a.clone());
        let job = Uuid::new_v4();
        ledger
            .record_dispatch(job, a.id, "m", 100, 130)
            .expect("recorded");
        let recorder = claim_recorder(ledger.clone());

        assert!(
            recorder(claim(Uuid::new_v4(), 0)).await.is_err(),
            "unknown job"
        );
        assert!(recorder(claim(job, 1)).await.is_err(), "another attempt");
        assert!(ledger.job(job).expect("held").claimed_by.is_none());

        assert!(recorder(claim(job, 0)).await.is_ok());
        assert_eq!(
            ledger.job(job).expect("held").claimed_by.as_deref(),
            Some("worker-a")
        );

        assert!(ledger.finish(job, JobState::TimedOut, outcome()));
        assert!(
            recorder(claim(job, 0)).await.is_err(),
            "a job the controller ended hands out nothing"
        );
    }

    #[test]
    fn only_log_messages_are_kept_and_only_so_many() {
        let mut lines = Vec::new();
        push_line(&mut lines, br#"{"message":"one"}"#);
        push_line(&mut lines, b"not a log line");
        assert_eq!(lines, ["one"]);
        for _ in 0..MAX_LOG_LINES * 2 {
            push_line(&mut lines, br#"{"message":"more"}"#);
        }
        assert_eq!(lines.len(), MAX_LOG_LINES);
    }

    /// One line every `every`, for ever.
    fn a_line_every(
        every: std::time::Duration,
    ) -> impl futures::Stream<Item = &'static [u8]> + Unpin {
        Box::pin(futures::stream::unfold((), move |()| async move {
            tokio::time::sleep(every).await;
            Some((&br#"{"message":"still here"}"#[..], ()))
        }))
    }

    #[tokio::test(start_paused = true)]
    async fn a_sender_that_never_stops_does_not_hold_the_drain_open() {
        // Faster than LOG_DRAIN, so the wait for a quiet moment never ends.
        let mut busy = a_line_every(LOG_DRAIN / 4);
        let mut lines = Vec::new();
        let started = tokio::time::Instant::now();
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            drain_late_lines(&mut busy, &mut lines),
        )
        .await
        .expect("the drain ends although lines keep arriving");
        assert!(
            started.elapsed() <= LOG_DRAIN_LIMIT + LOG_DRAIN,
            "the job stayed open for {:?}",
            started.elapsed()
        );
        assert!(!lines.is_empty(), "the lines that did arrive are kept");
    }

    #[tokio::test(start_paused = true)]
    async fn a_quiet_subject_ends_the_drain_after_one_wait() {
        let mut lines = Vec::new();
        let started = tokio::time::Instant::now();
        // One line at once, then nothing for longer than the drain waits.
        let mut late = Box::pin(
            futures::stream::iter([&br#"{"message":"last"}"#[..]])
                .chain(a_line_every(std::time::Duration::from_secs(3600))),
        );
        drain_late_lines(&mut late, &mut lines).await;
        assert_eq!(lines, ["last"]);
        assert!(started.elapsed() <= LOG_DRAIN + std::time::Duration::from_millis(1));
    }
}
