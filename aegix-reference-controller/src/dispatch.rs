//! One dispatch: what is signed and sent to a worker, and what is believed
//! when an answer comes back.
//!
//! Both halves are functions of their arguments, with no network in them:
//! [`prepare`] builds and signs the request, [`accept_result`] decides whether
//! a message on the reply subject is this job's result. [`crate::serve`] does
//! the sending and the waiting around them.
//!
//! # The deadline
//!
//! A worker accepts a signed dispatch for up to five minutes after it was
//! signed, so a job that sat on the bus could start long after its controller
//! gave up on it. Every request built here therefore carries
//! `deadline_unix_secs`: the last second at which a worker may START the job,
//! the pickup window ([`PICKUP_WINDOW_SECS`] unless the configuration names
//! another) after it was signed. The controller waits that
//! long, plus the job's own time limit, plus [`RESULT_GRACE_SECS`]; when the
//! wait ends it tells every worker to stop the job and records it as timed
//! out. From then on the job is not live, so a data call that names it is
//! refused by the dispatch-binding gate, and a claim for its secrets is
//! refused by the claim recorder.

use crate::keys::Keys;
use crate::ledger::{Actor, ActorStatus, JobState, Outcome};
use aegix_dispatch_types::SecretMap;
use aegix_envelope_seal::SealContext;
use aegix_workflow_job_protocol::{
    sealed_result_refused, vault_path_permitted, EncryptedSecrets, JobRequest, JobResult,
    JobStatus, RecordedClaimant, ResultAnswer, SEALING_CLAIM_ECIES,
};
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// How long after signing a worker may still start the job, unless the
/// configuration names another window.
pub const PICKUP_WINDOW_SECS: u64 = 30;

/// The longest pickup window a configuration may name. A worker refuses a
/// dispatch whose signature is older than this whatever the deadline says,
/// so a longer window would promise a start no worker will make.
pub const MAX_PICKUP_WINDOW_SECS: u64 = 300;

/// How long past the job's own time limit the controller waits for the
/// result to arrive.
pub const RESULT_GRACE_SECS: u64 = 10;

/// How old a result's signature may be. A result is signed when the job
/// ends, so this bounds its transit, not the job.
pub const RESULT_MAX_AGE_SECS: u64 = 300;

/// The largest message read as a result.
pub const MAX_RESULT_BYTES: usize = 8 * 1024 * 1024;

/// The largest input a dispatch carries, as JSON text.
pub const MAX_INPUT_BYTES: usize = 64 * 1024;

/// The longest time limit a module may be given.
pub const MAX_TIMEOUT_SECS: u64 = 900;

/// Log lines kept for one job, and the longest one kept whole.
pub const MAX_LOG_LINES: usize = 200;
pub const MAX_LOG_LINE_BYTES: usize = 2048;

/// A module the configuration names: its bytes and its grants.
#[derive(Clone)]
pub struct Module {
    pub name: String,
    pub wasm: Arc<Vec<u8>>,
    pub capability_world: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_methods: Vec<String>,
    pub allowed_secrets: Vec<String>,
    pub max_fuel: u64,
    pub timeout_secs: u64,
}

impl std::fmt::Debug for Module {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Module")
            .field("name", &self.name)
            .field("wasm_bytes", &self.wasm.len())
            .field("capability_world", &self.capability_world)
            .finish_non_exhaustive()
    }
}

/// The secrets this controller holds, by path. Values are wiped when
/// dropped and never rendered.
#[derive(Default)]
pub struct SecretStore {
    by_path: SecretMap,
}

impl std::fmt::Debug for SecretStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStore")
            .field("paths", &self.by_path.len())
            .finish()
    }
}

impl SecretStore {
    #[must_use]
    pub fn new(by_path: SecretMap) -> Self {
        Self { by_path }
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.by_path.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_path.is_empty()
    }

    /// The stored paths, sorted. Paths only.
    #[must_use]
    pub fn paths(&self) -> Vec<String> {
        let mut paths: Vec<String> = self.by_path.keys().cloned().collect();
        paths.sort();
        paths
    }

    /// The secrets a dispatch of a module with this grant is handed: a stored
    /// path the grant admits, by the matcher the worker enforces the same
    /// grant with. A path the worker reserves for its host (a model
    /// provider's key) is never handed over, whatever the grant says: this
    /// controller delivers no model keys.
    #[must_use]
    pub fn granted(&self, allowed_secrets: &[String]) -> SecretMap {
        self.by_path
            .iter()
            .filter(|(path, _)| {
                vault_path_permitted(allowed_secrets, path)
                    && !aegix_workflow_job_protocol::is_controller_internal_vault_path(path)
            })
            .map(|(path, value)| (path.clone(), value.clone()))
            .collect()
    }
}

/// Why a dispatch was not sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareError {
    /// The actor is suspended.
    ActorNotActive,
    /// The input is larger than [`MAX_INPUT_BYTES`].
    InputTooLarge(usize),
    /// The secrets could not be encrypted or sealed, or the request could
    /// not be signed. Carries the library's reason, which names no value.
    Crypto(String),
}

impl std::fmt::Display for PrepareError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ActorNotActive => f.write_str("the actor is suspended"),
            Self::InputTooLarge(n) => write!(
                f,
                "the input is {n} bytes as JSON; the most a dispatch carries is {MAX_INPUT_BYTES}"
            ),
            Self::Crypto(e) => write!(f, "the dispatch could not be secured: {e}"),
        }
    }
}

/// What [`prepare`] is given.
pub struct Plan<'a> {
    pub keys: &'a Keys,
    pub actor: &'a Actor,
    pub module: &'a Module,
    pub secrets: &'a SecretStore,
    pub input: serde_json::Value,
    pub job_id: Uuid,
    /// The subject the worker must answer on. It is signed into the request,
    /// and a worker publishes its result to the signed value.
    pub reply_inbox: String,
    /// The subject a worker claims this job's secrets on.
    pub claim_subject: &'a str,
    pub now_unix: u64,
    /// How long after `now_unix` a worker may still start the job.
    pub pickup_window_secs: u64,
}

/// A signed request and what the sender must do around it.
pub struct Prepared {
    pub request: JobRequest,
    /// The job's secrets, to be registered for the one claim BEFORE the
    /// request is published. `None` when the dispatch carries its secrets
    /// itself, or has none.
    pub seal: Option<SealContext>,
    /// `request.deadline_unix_secs`.
    pub start_cutoff_unix: u64,
    /// How long the sender waits for the result before it stops the job.
    pub wait: Duration,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("job_id", &self.request.job_id)
            .field("sealed", &self.seal.is_some())
            .field("start_cutoff_unix", &self.start_cutoff_unix)
            .field("wait", &self.wait)
            .finish_non_exhaustive()
    }
}

/// How long the sender waits for a job with this time limit: the window in
/// which it may start, its own time limit, and the result's transit.
#[must_use]
pub fn wait_for(pickup_window_secs: u64, timeout_secs: u64) -> Duration {
    Duration::from_secs(pickup_window_secs + timeout_secs + RESULT_GRACE_SECS)
}

/// Build and sign the request for one dispatch.
///
/// Every dispatch is a job of its own, not a node of a run: its execution id
/// is its job id, which is what a data call must name to be served.
///
/// The actor's ceilings are copied from the actor's record. The module's
/// grants are copied from the module's entry. Nothing in the request comes
/// from the input.
pub fn prepare(plan: Plan<'_>) -> Result<Prepared, PrepareError> {
    let Plan {
        keys,
        actor,
        module,
        secrets,
        input,
        job_id,
        reply_inbox,
        claim_subject,
        now_unix,
        pickup_window_secs,
    } = plan;

    if actor.status != ActorStatus::Active {
        return Err(PrepareError::ActorNotActive);
    }
    let input_len = serde_json::to_vec(&input).map_or(usize::MAX, |b| b.len());
    if input_len > MAX_INPUT_BYTES {
        return Err(PrepareError::InputTooLarge(input_len));
    }

    let granted = secrets.granted(&module.allowed_secrets);
    let start_cutoff_unix = now_unix + pickup_window_secs;

    let mut request = JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id,
        workflow_execution_id: job_id,
        module_uri: format!("inline:{}", module.name),
        input_payload: input.into(),
        encrypted_secrets: EncryptedSecrets::empty(),
        timeout_ms: module.timeout_secs.saturating_mul(1000),
        priority: 100,
        deadline_unix_secs: start_cutoff_unix,
        cancellation_token: None,
        allowed_hosts: module.allowed_hosts.clone(),
        allowed_methods: module.allowed_methods.clone(),
        allowed_secrets: module.allowed_secrets.clone(),
        allowed_sql_operations: Vec::new(),
        allow_tier2_exposure: false,
        signature: Vec::new(),
        job_nonce: String::new(),
        actor_id: Some(actor.id),
        wasm_bytes: Some(module.wasm.as_ref().clone()),
        capability_world: Some(module.capability_world.clone()),
        integration_name: None,
        expected_wasm_hash: None,
        max_fuel: module.max_fuel,
        user_id: Uuid::nil(),
        max_llm_tier: actor.max_llm_tier,
        max_write_ceiling: actor.max_write_ceiling,
        egress_scope: actor.egress_scope,
        http_verb_ceiling: None,
        dry_run: false,
        read_only_posts: Vec::new(),
        reply_topic: Some(reply_inbox),
        idempotency_key: None,
        dispatch_attempt: 0,
    };

    // The secrets are placed before the request is signed: the envelope, or
    // the fact that there is a claim to make and where, is part of what the
    // signature covers.
    let mut seal = None;
    if !granted.is_empty() {
        match keys.inline_envelope_key() {
            Some(key) => {
                request.encrypted_secrets =
                    EncryptedSecrets::encrypt_with_aad(&granted, key, job_id.as_bytes())
                        .map_err(PrepareError::Crypto)?;
            }
            None => {
                seal = Some(SealContext::new(&granted).map_err(PrepareError::Crypto)?);
                request.sealing = SEALING_CLAIM_ECIES;
                request.claim_inbox = Some(claim_subject.to_string());
                let mut paths: Vec<String> = granted.keys().cloned().collect();
                paths.sort();
                request.secret_paths = paths;
            }
        }
    }

    keys.signer()
        .sign_job(&mut request)
        .map_err(PrepareError::Crypto)?;

    Ok(Prepared {
        request,
        seal,
        start_cutoff_unix,
        wait: wait_for(pickup_window_secs, module.timeout_secs),
    })
}

/// Why a message on a job's reply subject was not taken as its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultRefusal {
    TooLarge,
    Malformed,
    /// It names another job, another attempt, or no dispatch at all.
    NotThisDispatch,
    /// Its signature, its freshness or its nonce. Carries the class.
    Unverified(&'static str),
    /// It is signed by a worker other than the one this job's secrets were
    /// sealed to.
    NotTheClaimant,
}

impl ResultRefusal {
    /// The reason a refusal is counted under.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TooLarge => "too_large",
            Self::Malformed => "malformed",
            Self::NotThisDispatch => "not_this_dispatch",
            Self::Unverified(class) => class,
            Self::NotTheClaimant => "not_the_claimant",
        }
    }
}

/// Decide whether `payload` is the result of `request`.
///
/// In order: its length; its parse; that it names this job, this attempt and
/// this execution; its signature, by a key this posture believes, with its
/// nonce recorded so the same result is never taken twice; and, when the
/// job's secrets were sealed to a worker, that this worker signed it.
///
/// `claimant` is who claimed the job's secrets and for which attempt, or
/// `None` when nothing was handed out.
///
/// This is the one place in the process that verifies a result, which the
/// nonce record requires: a second verifier would see every result as a
/// replay.
pub fn accept_result(
    keys: &Keys,
    request: &JobRequest,
    claimant: Option<(&str, u32)>,
    payload: &[u8],
) -> Result<JobResult, ResultRefusal> {
    if payload.len() > MAX_RESULT_BYTES {
        return Err(ResultRefusal::TooLarge);
    }
    let result: JobResult =
        serde_json::from_slice(payload).map_err(|_| ResultRefusal::Malformed)?;
    // A result that names no execution comes from a worker older than the
    // binding. The platform takes it during a rollout; there is no rollout
    // here, and it is refused.
    if result.answers(&request.dispatch_identity()) != ResultAnswer::ThisDispatch {
        return Err(ResultRefusal::NotThisDispatch);
    }
    result
        .verify_dispatch(
            keys.result_ring(),
            &aegix_workflow_job_protocol::worker_public_keys(&result.worker_id),
            RESULT_MAX_AGE_SECS,
            keys.accepts_fleet_key_results(),
        )
        .map_err(|e| ResultRefusal::Unverified(e.kind().label()))?;
    let claimant = claimant.map(|(worker_id, attempt)| RecordedClaimant { worker_id, attempt });
    if sealed_result_refused(claimant, &result.worker_id, result.dispatch_attempt) {
        return Err(ResultRefusal::NotTheClaimant);
    }
    Ok(result)
}

/// One line of a job's log, cut to [`MAX_LOG_LINE_BYTES`] on a character
/// boundary.
#[must_use]
pub fn clip_log_line(line: &str) -> String {
    if line.len() <= MAX_LOG_LINE_BYTES {
        return line.to_string();
    }
    let mut end = MAX_LOG_LINE_BYTES;
    while !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &line[..end])
}

/// The `message` of one `wasm.log.<job>` payload, if it is one.
#[must_use]
pub fn log_message(payload: &[u8]) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Line {
        message: String,
    }
    serde_json::from_slice::<Line>(payload)
        .ok()
        .map(|l| clip_log_line(&l.message))
}

/// The state and outcome an accepted result is recorded as. `stream_lines`
/// are the lines the worker published while the job ran; the result's own
/// lines follow, without repeats, up to [`MAX_LOG_LINES`] in all.
#[must_use]
pub fn settle(result: JobResult, stream_lines: Vec<String>) -> (JobState, Outcome) {
    let state = match result.status {
        JobStatus::Success => JobState::Completed,
        JobStatus::Failed => JobState::Failed,
        JobStatus::TimedOut => JobState::TimedOut,
    };
    let output = result.output_payload.value().clone();
    let error = (state != JobState::Completed).then(|| {
        output
            .get("error")
            .and_then(serde_json::Value::as_str)
            .map_or_else(
                || format!("the worker reported {}", state.as_str()),
                str::to_string,
            )
    });
    let mut log_lines = stream_lines;
    for line in &result.logs {
        let line = clip_log_line(line);
        if !log_lines.contains(&line) {
            log_lines.push(line);
        }
    }
    log_lines.truncate(MAX_LOG_LINES);
    (
        state,
        Outcome {
            output,
            error,
            worker_id: result.worker_id,
            execution_time_ms: result.execution_time_ms,
            log_lines,
        },
    )
}

/// The outcome recorded for a job no result arrived for.
#[must_use]
pub fn timed_out(wait: Duration, stream_lines: Vec<String>) -> Outcome {
    Outcome {
        output: serde_json::Value::Null,
        error: Some(format!(
            "no result within {} s; every worker was told to stop the job",
            wait.as_secs()
        )),
        worker_id: String::new(),
        execution_time_ms: 0,
        log_lines: stream_lines,
    }
}

/// The outcome recorded for a job whose request never left.
#[must_use]
pub fn not_sent(why: &str) -> Outcome {
    Outcome {
        output: serde_json::Value::Null,
        error: Some(format!("the request was not published: {why}")),
        worker_id: String::new(),
        execution_time_ms: 0,
        log_lines: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::testing::{fleet_keys, identity_keys, FLEET_KEY};
    use crate::ledger::testing::actor;
    use aegix_dispatch_types::{EgressScope, LlmTier, WriteCeiling};
    use aegix_workflow_job_protocol::DispatchSigningKey;
    use zeroize::Zeroizing;

    fn module(allowed_secrets: &[&str]) -> Module {
        Module {
            name: "probe".to_string(),
            wasm: Arc::new(b"\0asm-not-really".to_vec()),
            capability_world: "agent-node".to_string(),
            allowed_hosts: vec!["api.example.test".to_string()],
            allowed_methods: vec!["GET".to_string()],
            allowed_secrets: allowed_secrets.iter().map(|s| (*s).to_string()).collect(),
            max_fuel: 3_000_000,
            timeout_secs: 20,
        }
    }

    fn store(paths: &[&str]) -> SecretStore {
        SecretStore::new(
            paths
                .iter()
                .map(|p| ((*p).to_string(), Zeroizing::new(format!("value-of-{p}"))))
                .collect(),
        )
    }

    const NOW: u64 = 1_800_000_000;
    const CLAIMS: &str = "_INBOX.claims.test";

    fn plan<'a>(
        keys: &'a Keys,
        actor: &'a Actor,
        module: &'a Module,
        secrets: &'a SecretStore,
    ) -> Plan<'a> {
        Plan {
            keys,
            actor,
            module,
            secrets,
            input: serde_json::json!({"config": {"HOLD_SECS": 0}}),
            job_id: Uuid::new_v4(),
            reply_inbox: "_INBOX.reply.test".to_string(),
            claim_subject: CLAIMS,
            now_unix: NOW,
            pickup_window_secs: PICKUP_WINDOW_SECS,
        }
    }

    #[test]
    fn a_dispatch_carries_a_start_deadline_and_the_sender_waits_past_the_time_limit() {
        let keys = fleet_keys();
        let a = actor("a", WriteCeiling::Write);
        let m = module(&[]);
        let prepared = prepare(plan(&keys, &a, &m, &store(&[]))).expect("prepared");
        assert_eq!(
            prepared.request.deadline_unix_secs,
            NOW + PICKUP_WINDOW_SECS
        );
        assert_eq!(prepared.start_cutoff_unix, NOW + PICKUP_WINDOW_SECS);
        assert!(
            prepared.request.deadline_unix_secs > 0,
            "a deadline of 0 is the worker's word for none"
        );
        assert_eq!(prepared.request.timeout_ms, 20_000);
        assert_eq!(
            prepared.wait,
            Duration::from_secs(PICKUP_WINDOW_SECS + 20 + RESULT_GRACE_SECS)
        );
    }

    #[test]
    fn the_pickup_window_moves_the_deadline_and_the_wait_together() {
        let keys = fleet_keys();
        let a = actor("a", WriteCeiling::Write);
        let m = module(&[]);
        let secrets = store(&[]);
        let mut short = plan(&keys, &a, &m, &secrets);
        short.pickup_window_secs = 5;
        let prepared = prepare(short).expect("prepared");
        assert_eq!(prepared.request.deadline_unix_secs, NOW + 5);
        assert_eq!(
            prepared.wait,
            Duration::from_secs(5 + 20 + RESULT_GRACE_SECS),
            "the sender must not give up before the last moment a worker may start, \
             plus the job's own limit"
        );
    }

    #[test]
    fn the_deadline_is_signed() {
        let keys = fleet_keys();
        let a = actor("a", WriteCeiling::Write);
        let m = module(&[]);
        let mut request = prepare(plan(&keys, &a, &m, &store(&[])))
            .expect("prepared")
            .request;
        assert!(request.verify_no_replay(&FLEET_KEY, 60).is_ok());
        request.deadline_unix_secs += 3600;
        assert!(
            request.verify_no_replay(&FLEET_KEY, 60).is_err(),
            "a later deadline must not verify"
        );
        request.deadline_unix_secs = 0;
        assert!(
            request.verify_no_replay(&FLEET_KEY, 60).is_err(),
            "a removed deadline must not verify"
        );
    }

    #[test]
    fn a_dispatch_is_a_job_of_its_own_for_the_actor_with_the_actors_ceilings() {
        let keys = fleet_keys();
        let mut a = actor("a", WriteCeiling::ReadOnly);
        a.max_llm_tier = LlmTier::Tier1;
        a.egress_scope = Some(EgressScope::Local);
        let m = module(&[]);
        let s = store(&[]);
        let p = plan(&keys, &a, &m, &s);
        let job_id = p.job_id;
        let request = prepare(p).expect("prepared").request;
        assert_eq!(request.job_id, job_id);
        assert_eq!(request.workflow_execution_id, job_id);
        assert_eq!(request.actor_id, Some(a.id));
        assert_eq!(request.max_write_ceiling, WriteCeiling::ReadOnly);
        assert_eq!(request.max_llm_tier, LlmTier::Tier1);
        assert_eq!(request.egress_scope, Some(EgressScope::Local));
        assert_eq!(request.reply_topic.as_deref(), Some("_INBOX.reply.test"));
        assert_eq!(request.capability_world.as_deref(), Some("agent-node"));
        assert_eq!(request.allowed_hosts, m.allowed_hosts);
        assert_eq!(request.allowed_methods, m.allowed_methods);
        assert!(!request.allow_tier2_exposure);
        assert!(!request.dry_run);
        assert_eq!(request.wasm_bytes.as_deref(), Some(m.wasm.as_slice()));
    }

    #[test]
    fn a_suspended_actor_and_an_oversized_input_are_not_dispatched() {
        let keys = fleet_keys();
        let mut a = actor("a", WriteCeiling::Write);
        let m = module(&[]);
        let s = store(&[]);
        let mut p = plan(&keys, &a, &m, &s);
        p.input = serde_json::json!({"blob": "x".repeat(MAX_INPUT_BYTES)});
        assert!(matches!(prepare(p), Err(PrepareError::InputTooLarge(_))));
        a.status = ActorStatus::Suspended;
        assert_eq!(
            prepare(plan(&keys, &a, &m, &s)).expect_err("suspended"),
            PrepareError::ActorNotActive
        );
    }

    #[test]
    fn only_a_stored_secret_the_grant_admits_leaves_and_a_model_key_never_does() {
        let s = store(&[
            "demo/granted",
            "demo/ungranted",
            "team/a/token",
            "team/b/token",
            "anthropic/api_key",
        ]);
        let granted = |allowed: &[&str]| {
            let allowed: Vec<String> = allowed.iter().map(|s| (*s).to_string()).collect();
            let mut paths: Vec<String> = s.granted(&allowed).into_keys().collect();
            paths.sort();
            paths
        };
        assert!(granted(&[]).is_empty(), "no grant, no secret");
        assert_eq!(granted(&["demo/granted"]), ["demo/granted"]);
        assert_eq!(granted(&["team/a/*"]), ["team/a/token"]);
        assert!(granted(&["*"]).is_empty(), "a bare * grants nothing");
        assert!(
            granted(&["anthropic/api_key", "anthropic/*"]).is_empty(),
            "a model provider's key is not delivered"
        );
        assert!(granted(&["demo/missing"]).is_empty());
    }

    #[test]
    fn under_the_fleet_key_the_granted_secrets_travel_encrypted_to_this_job() {
        let keys = fleet_keys();
        let a = actor("a", WriteCeiling::Write);
        let m = module(&["demo/granted"]);
        let s = store(&["demo/granted", "demo/ungranted"]);
        let prepared = prepare(plan(&keys, &a, &m, &s)).expect("prepared");
        let request = &prepared.request;
        assert!(prepared.seal.is_none());
        assert_eq!(request.sealing, 0);
        assert!(request.claim_inbox.is_none());
        let opened = request
            .encrypted_secrets
            .decrypt_with_aad(&FLEET_KEY, request.job_id.as_bytes())
            .expect("opens under this job");
        assert_eq!(opened.len(), 1);
        assert_eq!(opened["demo/granted"].as_str(), "value-of-demo/granted");
        assert!(
            request
                .encrypted_secrets
                .decrypt_with_aad(&FLEET_KEY, Uuid::new_v4().as_bytes())
                .is_err(),
            "the envelope must not open for another job"
        );
        let wire = serde_json::to_string(request).expect("serialise");
        assert!(!wire.contains("value-of-demo"), "no value in the clear");
    }

    #[test]
    fn under_worker_identity_no_secret_travels_and_the_claim_is_signed() {
        let (keys, controller_key) = identity_keys();
        let a = actor("a", WriteCeiling::Write);
        let m = module(&["demo/*"]);
        let s = store(&["demo/granted", "demo/second", "other/x"]);
        let prepared = prepare(plan(&keys, &a, &m, &s)).expect("prepared");
        let mut request = prepared.request;
        assert!(prepared.seal.is_some(), "the secrets wait for one claim");
        assert_eq!(request.sealing, SEALING_CLAIM_ECIES);
        assert_eq!(request.claim_inbox.as_deref(), Some(CLAIMS));
        assert_eq!(request.secret_paths, ["demo/granted", "demo/second"]);
        assert!(request.encrypted_secrets.ciphertext.is_empty());
        assert_eq!(request.crypto_scheme, 1);
        let wire = serde_json::to_string(&request).expect("serialise");
        assert!(!wire.contains("value-of-demo"), "no value on the wire");

        let public = controller_key.verifying_key();
        assert!(request.verify_no_replay_ed25519(&[public], 60).is_ok());
        request.claim_inbox = Some("_INBOX.attacker".to_string());
        assert!(
            request.verify_no_replay_ed25519(&[public], 60).is_err(),
            "a redirected claim must not verify"
        );
        request.claim_inbox = Some(CLAIMS.to_string());
        request.sealing = 0;
        assert!(
            request.verify_no_replay_ed25519(&[public], 60).is_err(),
            "a dispatch downgraded to unsealed must not verify"
        );
    }

    #[test]
    fn a_dispatch_with_no_granted_secret_is_neither_enveloped_nor_sealed() {
        let (keys, _) = identity_keys();
        let a = actor("a", WriteCeiling::Write);
        let m = module(&["demo/granted"]);
        let prepared = prepare(plan(&keys, &a, &m, &store(&["other/x"]))).expect("prepared");
        assert!(prepared.seal.is_none());
        assert_eq!(prepared.request.sealing, 0);
        assert!(prepared.request.claim_inbox.is_none());
        assert!(prepared.request.encrypted_secrets.ciphertext.is_empty());
    }

    // ── results ─────────────────────────────────────────────────────────

    fn fleet_request(keys: &Keys) -> JobRequest {
        let a = actor("a", WriteCeiling::Write);
        prepare(plan(keys, &a, &module(&[]), &store(&[])))
            .expect("prepared")
            .request
    }

    fn result_for(request: &JobRequest, status: JobStatus) -> JobResult {
        let mut result = JobResult {
            job_id: request.job_id,
            status,
            output_payload: serde_json::json!({"kind": "ok"}).into(),
            logs: vec!["guest line".to_string()],
            execution_time_ms: 12,
            signature: Vec::new(),
            result_nonce: String::new(),
            worker_id: String::new(),
            crypto_scheme: 0,
            llm_usage: Vec::new(),
            fuel: None,
            dispatch_attempt: 0,
            workflow_execution_id: None,
        };
        result.bind_to_request(request);
        result
    }

    fn fleet_signed(request: &JobRequest, worker: &str) -> Vec<u8> {
        let mut result = result_for(request, JobStatus::Success);
        result
            .sign_with_worker_id(&FLEET_KEY, worker)
            .expect("sign");
        serde_json::to_vec(&result).expect("serialise")
    }

    #[test]
    fn a_fleet_signed_result_for_this_dispatch_is_taken_once() {
        let keys = fleet_keys();
        let request = fleet_request(&keys);
        let payload = fleet_signed(&request, "worker-1");
        let result = accept_result(&keys, &request, None, &payload).expect("accepted");
        assert_eq!(result.worker_id, "worker-1");
        assert_eq!(
            accept_result(&keys, &request, None, &payload).expect_err("a second time"),
            ResultRefusal::Unverified("replay")
        );
    }

    #[test]
    fn a_result_for_another_job_attempt_or_no_dispatch_is_not_this_jobs() {
        let keys = fleet_keys();
        let request = fleet_request(&keys);
        let other = fleet_request(&keys);

        let for_other = fleet_signed(&other, "worker-1");
        assert_eq!(
            accept_result(&keys, &request, None, &for_other).expect_err("another job"),
            ResultRefusal::NotThisDispatch
        );

        let mut later = result_for(&request, JobStatus::Success);
        later.dispatch_attempt = 1;
        later
            .sign_with_worker_id(&FLEET_KEY, "worker-1")
            .expect("sign");
        assert_eq!(
            accept_result(
                &keys,
                &request,
                None,
                &serde_json::to_vec(&later).expect("ser")
            )
            .expect_err("another attempt"),
            ResultRefusal::NotThisDispatch
        );

        let mut unbound = result_for(&request, JobStatus::Success);
        unbound.workflow_execution_id = None;
        unbound
            .sign_with_worker_id(&FLEET_KEY, "worker-1")
            .expect("sign");
        assert_eq!(
            accept_result(
                &keys,
                &request,
                None,
                &serde_json::to_vec(&unbound).expect("ser")
            )
            .expect_err("names no execution"),
            ResultRefusal::NotThisDispatch
        );
    }

    #[test]
    fn a_result_signed_with_another_key_or_changed_after_signing_is_refused() {
        let keys = fleet_keys();
        let request = fleet_request(&keys);

        let mut forged = result_for(&request, JobStatus::Success);
        forged
            .sign_with_worker_id(&[0x11; 32], "worker-1")
            .expect("sign");
        assert_eq!(
            accept_result(
                &keys,
                &request,
                None,
                &serde_json::to_vec(&forged).expect("ser")
            )
            .expect_err("another key"),
            ResultRefusal::Unverified("bad_signature")
        );

        let mut changed = result_for(&request, JobStatus::Failed);
        changed
            .sign_with_worker_id(&FLEET_KEY, "worker-1")
            .expect("sign");
        changed.status = JobStatus::Success;
        assert_eq!(
            accept_result(
                &keys,
                &request,
                None,
                &serde_json::to_vec(&changed).expect("ser")
            )
            .expect_err("changed after signing"),
            ResultRefusal::Unverified("bad_signature")
        );
    }

    #[test]
    fn an_oversized_or_unparseable_message_is_refused_before_anything_is_verified() {
        let keys = fleet_keys();
        let request = fleet_request(&keys);
        assert_eq!(
            accept_result(&keys, &request, None, b"not json").expect_err("garbage"),
            ResultRefusal::Malformed
        );
        let big = vec![b' '; MAX_RESULT_BYTES + 1];
        assert_eq!(
            accept_result(&keys, &request, None, &big).expect_err("too large"),
            ResultRefusal::TooLarge
        );
    }

    /// One worker identity the whole test binary believes, registered once:
    /// the registry of worker public keys is process-wide.
    fn listed_worker() -> (&'static str, &'static DispatchSigningKey) {
        static KEY: std::sync::OnceLock<DispatchSigningKey> = std::sync::OnceLock::new();
        let key = KEY.get_or_init(|| {
            let key = aegix_workflow_job_protocol::generate_dispatch_signing_key();
            aegix_workflow_job_protocol::set_dynamic_worker_public_keys([(
                "listed-worker".to_string(),
                key.verifying_key(),
            )]);
            key
        });
        ("listed-worker", key)
    }

    fn identity_request(keys: &Keys) -> JobRequest {
        let a = actor("a", WriteCeiling::Write);
        prepare(plan(
            keys,
            &a,
            &module(&["demo/*"]),
            &store(&["demo/granted"]),
        ))
        .expect("prepared")
        .request
    }

    #[test]
    fn under_worker_identity_a_fleet_signed_result_is_refused_by_its_scheme() {
        let (keys, _) = identity_keys();
        let request = identity_request(&keys);
        // Signed with the very ring this controller holds as a stand-in: the
        // refusal must not depend on the key being unknown.
        let mut result = result_for(&request, JobStatus::Success);
        result
            .sign_with_worker_id(keys.result_ring().signing_key().as_bytes(), "worker-1")
            .expect("sign");
        assert_eq!(
            accept_result(
                &keys,
                &request,
                None,
                &serde_json::to_vec(&result).expect("ser")
            )
            .expect_err("fleet key under worker identity"),
            ResultRefusal::Unverified("scheme_refused")
        );
    }

    #[test]
    fn under_worker_identity_only_a_listed_workers_own_signature_is_believed() {
        let (keys, _) = identity_keys();
        let (worker_id, worker_key) = listed_worker();
        let request = identity_request(&keys);

        let mut good = result_for(&request, JobStatus::Success);
        good.sign_ed25519_with_worker_id(worker_key, worker_id)
            .expect("sign");
        let payload = serde_json::to_vec(&good).expect("ser");
        accept_result(&keys, &request, Some((worker_id, 0)), &payload).expect("accepted");

        let stranger = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let request = identity_request(&keys);
        let mut as_listed = result_for(&request, JobStatus::Success);
        as_listed
            .sign_ed25519_with_worker_id(&stranger, worker_id)
            .expect("sign");
        assert_eq!(
            accept_result(
                &keys,
                &request,
                None,
                &serde_json::to_vec(&as_listed).expect("ser")
            )
            .expect_err("a stranger signing as a listed worker"),
            ResultRefusal::Unverified("bad_signature")
        );

        let mut unlisted = result_for(&request, JobStatus::Success);
        unlisted
            .sign_ed25519_with_worker_id(&stranger, "unlisted-worker")
            .expect("sign");
        assert!(matches!(
            accept_result(
                &keys,
                &request,
                None,
                &serde_json::to_vec(&unlisted).expect("ser")
            )
            .expect_err("an unlisted worker"),
            ResultRefusal::Unverified(_)
        ));
    }

    #[test]
    fn a_sealed_jobs_result_is_taken_only_from_the_worker_that_claimed_its_secrets() {
        let (keys, _) = identity_keys();
        let (worker_id, worker_key) = listed_worker();

        let request = identity_request(&keys);
        let mut result = result_for(&request, JobStatus::Success);
        result
            .sign_ed25519_with_worker_id(worker_key, worker_id)
            .expect("sign");
        let payload = serde_json::to_vec(&result).expect("ser");
        assert_eq!(
            accept_result(&keys, &request, Some(("another-worker", 0)), &payload)
                .expect_err("another worker holds the secrets"),
            ResultRefusal::NotTheClaimant
        );

        // The same worker, but the claim was for another attempt.
        let request = identity_request(&keys);
        let mut result = result_for(&request, JobStatus::Success);
        result
            .sign_ed25519_with_worker_id(worker_key, worker_id)
            .expect("sign");
        let payload = serde_json::to_vec(&result).expect("ser");
        assert_eq!(
            accept_result(&keys, &request, Some((worker_id, 1)), &payload)
                .expect_err("claimed for another attempt"),
            ResultRefusal::NotTheClaimant
        );
    }

    #[test]
    fn an_accepted_result_is_recorded_by_its_status_with_its_lines_capped() {
        let keys = fleet_keys();
        let request = fleet_request(&keys);

        let ok = result_for(&request, JobStatus::Success);
        let (state, outcome) = settle(ok, vec!["[host:forbidden] refused".to_string()]);
        assert_eq!(state, JobState::Completed);
        assert!(outcome.error.is_none());
        assert_eq!(
            outcome.log_lines,
            ["[host:forbidden] refused", "guest line"]
        );

        let mut failed = result_for(&request, JobStatus::Failed);
        failed.output_payload = serde_json::json!({"error": "fuel exhausted"}).into();
        failed.logs = vec!["x".repeat(MAX_LOG_LINE_BYTES * 2); MAX_LOG_LINES + 50];
        let (state, outcome) = settle(failed, vec!["guest line".to_string()]);
        assert_eq!(state, JobState::Failed);
        assert_eq!(outcome.error.as_deref(), Some("fuel exhausted"));
        assert!(outcome.log_lines.len() <= MAX_LOG_LINES);
        assert!(outcome
            .log_lines
            .iter()
            .all(|l| l.len() <= MAX_LOG_LINE_BYTES + '…'.len_utf8()));

        let timed = result_for(&request, JobStatus::TimedOut);
        let (state, outcome) = settle(timed, Vec::new());
        assert_eq!(state, JobState::TimedOut);
        assert_eq!(
            outcome.error.as_deref(),
            Some("the worker reported timeout")
        );
    }

    #[test]
    fn a_log_payload_gives_its_message_and_anything_else_gives_nothing() {
        let payload =
            br#"{"execution_id":"x","level":"warn","message":"[host:denied] no","source":"host"}"#;
        assert_eq!(log_message(payload).as_deref(), Some("[host:denied] no"));
        assert!(log_message(b"plain text").is_none());
        assert!(log_message(br#"{"level":"info"}"#).is_none());
        let long = "é".repeat(MAX_LOG_LINE_BYTES);
        let clipped = clip_log_line(&long);
        assert!(clipped.len() <= MAX_LOG_LINE_BYTES + '…'.len_utf8());
        assert!(clipped.ends_with('…'));
    }
}
