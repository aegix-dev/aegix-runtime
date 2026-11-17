//! Call-site pin: the worker refuses an inline envelope under
//! `AEGIX_ENVELOPE_SEALING=required` with the ONE decision,
//! `secret_claim::inline_envelope_refused`, as the whole condition of the
//! refusal, before anything decrypts the envelope (security review
//! 2026-11-06, finding 6).
//!
//! The decision is unit-tested in `secret_claim`. What that test cannot see is
//! whether `execute_job` asks it — the review's mutant (`if false &&` in front
//! of the condition) passed all 163 worker tests. This reads `main.rs`, like
//! `retry_policy_pin`, and lives in its own file so its needles are not in
//! the file it scans.

use crate::retry_policy_pin::production_source;

const GUARD: &str =
    "if worker::secret_claim::inline_envelope_refused(worker_sealing_required(), &req) {";

#[test]
fn the_inline_envelope_refusal_is_asked_unconditionally_before_any_decrypt() {
    let prod = production_source();
    let lines: Vec<&str> = prod.lines().map(str::trim).collect();
    let guards: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("inline_envelope_refused("))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        guards.len(),
        1,
        "one call of the inline-envelope decision in main.rs, found {}",
        guards.len()
    );
    let at = guards[0];
    assert_eq!(
        lines[at], GUARD,
        "the refusal's condition is the decision alone, with the process's own \
         `required` flag and this request — nothing in front of it may switch it off"
    );
    // Its body answers Failed and returns before the envelope is touched.
    let body_end = lines[at..]
        .iter()
        .position(|l| *l == "}")
        .map(|p| at + p)
        .expect("the guard's block closes");
    assert!(
        lines[at..body_end]
            .iter()
            .any(|l| l.starts_with("return failed_result(")),
        "the refusal returns a failed result"
    );
    let decrypt = lines
        .iter()
        .position(|l| l.contains(".decrypt_with_ring(&shared_key, req.workflow_execution_id"))
        .expect("vacuity guard: the inline decrypt is in main.rs");
    assert!(
        at < decrypt,
        "the refusal runs before the inline envelope is decrypted"
    );
}

/// Finding 10 (2026-11-06): the shared idempotency tier is read through the
/// ONE vouching rule, verified under this worker's own keys. Before, the hit
/// path verified under the keys registered for whatever id the entry named.
#[test]
fn the_shared_idempotency_tier_serves_only_what_this_worker_vouches_for() {
    let prod = production_source();
    assert_eq!(
        prod.matches("worker::job_idempotency::vouched_shared_entry(")
            .count(),
        1,
        "the shared tier's one reader asks the vouching rule"
    );
    assert_eq!(
        prod.matches("cached_result_verify_keys(own)").count(),
        1,
        "verified under this worker's own keys"
    );
    assert!(
        !prod.contains("cached_result_verify_keys(&r.worker_id)"),
        "never under the keys of the id the entry names"
    );
}
