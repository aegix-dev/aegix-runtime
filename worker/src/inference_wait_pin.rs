//! Call-site pin: the worker's NATS job path excludes local-inference queueing
//! from the job's deadlines and tells the dispatcher (RFC 0014 P2).
//!
//! The mechanism is tested where it lives — the ledger and the pausable
//! deadline in `aegix-wasm-host`, the gate's reporting on its own
//! semaphore and through both LLM call sites, the dispatcher's pause in
//! `aegix-workflow-engine-nats`. What none of those can see is whether
//! `execute_job` WIRES it: a ledger built and never passed, an outer deadline
//! left as a plain `tokio::time::timeout`, or a notifier aimed at the unsigned
//! wire reply header would each compile and pass every other test. So this
//! reads the source itself (`job_execution.rs` since 2026-11-18, with
//! `main.rs`), from its own file for the reason `retry_policy_pin.rs` gives.

/// The worker's job path, production code only: `job_execution.rs` and
/// `main.rs`, read together (`retry_policy_pin::production_source`).
fn production_source() -> String {
    crate::retry_policy_pin::production_source()
}

/// The body of `async fn run_verified_job(` (the part of `execute_job` that
/// runs a dispatch once it has verified) up to the next top-level `fn`.
fn execute_job_body(prod: &str) -> &str {
    let start = prod
        .find("async fn run_verified_job(")
        .expect("vacuity guard: run_verified_job not found in main.rs");
    let rest = &prod[start..];
    let end = rest[1..]
        .find("\nasync fn ")
        .or_else(|| rest[1..].find("\nfn "))
        .map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

#[test]
fn the_nats_job_path_pauses_its_deadlines_for_local_inference_queueing() {
    let prod = production_source();
    let body = execute_job_body(&prod);
    assert!(
        body.contains("worker::inference_wait::with_pausable_deadline("),
        "the outer job deadline must be the pausable one"
    );
    assert!(
        !body.contains("tokio::time::timeout(\n        job_timeout"),
        "the outer job deadline reverted to a plain tokio::time::timeout"
    );
    assert!(
        body.contains("Some(inference_wait.clone()),"),
        "execute_job must hand the job's ledger to the runtime (the inner timeout, \
         the epoch bound and the LLM gate all read it from there)"
    );
    assert!(
        body.contains("req.reply_topic.as_deref().map(|inbox|")
            && body.contains("subjects::job_progress_for(inbox)"),
        "the progress notifier must be aimed at the job's SIGNED reply inbox"
    );
    assert!(
        !body.contains("msg.reply"),
        "execute_job must not read the unsigned wire reply header"
    );
}
