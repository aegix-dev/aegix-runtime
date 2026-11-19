//! Call-site pin: a dispatch that did not verify has no result, and the one
//! rule for what is sent in answer is asked where the intake learns of it
//! (2026-11-15).
//!
//! `refused_dispatch_answer` is unit-tested beside itself, in
//! `refused_dispatch.rs` (`refused_dispatch_tests`). What those tests cannot see is whether the
//! intake asks it: until this date `execute_job` built a `Failed` result for a
//! dispatch that failed verification and the intake signed and published it
//! like any other, so a sender with no key was handed a worker-signed result
//! for a job of its choosing. A rule nobody calls would leave that as it was
//! with every unit test green. This reads `main.rs` for the intake, like
//! `retry_policy_pin`, and `refused_dispatch.rs` for the rule (moved there
//! 2026-11-18), and lives in its own file so its needles are not in a file
//! it scans.

use crate::retry_policy_pin::{production_of, production_source};

/// `prod` from `start` up to the next top-level `fn`.
fn top_level_fn<'a>(prod: &'a str, start: &str) -> &'a str {
    let at = prod
        .find(start)
        .unwrap_or_else(|| panic!("vacuity guard: `{start}` not found in the scanned source"));
    let rest = &prod[at..];
    let end = rest[1..]
        .find("\nasync fn ")
        .into_iter()
        .chain(rest[1..].find("\nfn "))
        .min()
        .map_or(rest.len(), |i| i + 1);
    &rest[..end]
}

/// `execute_job` verifies, and for a dispatch that does not verify returns the
/// refusal itself: it has no way to build a result for one.
#[test]
fn execute_job_builds_no_result_for_a_dispatch_that_did_not_verify() {
    let prod = production_source();
    let body = top_level_fn(&prod, "async fn execute_job(");
    assert!(
        body.contains(") -> Result<JobResult, VerifyError> {"),
        "execute_job's refusal of a dispatch is a value of its own, not a JobResult"
    );
    assert_eq!(
        body.matches("req.verify_dispatch(").count(),
        1,
        "vacuity guard: the primary verification is in execute_job"
    );
    assert!(
        body.contains("return Err(e);"),
        "a dispatch that does not verify returns its refusal"
    );
    for builds_a_result in [
        "JobResult {",
        "failed_result(",
        "signature_failure_payload(",
    ] {
        assert!(
            !body.contains(builds_a_result),
            "execute_job must not build a result (`{builds_a_result}`): everything after \
             verification is run_verified_job's, and a refused dispatch has none"
        );
    }
    assert_eq!(
        prod.matches("run_verified_job(").count(),
        2,
        "run_verified_job is defined once and called once, from execute_job"
    );
    assert!(
        body.contains("Ok(run_verified_job("),
        "and that call is behind the verification"
    );
}

/// The intake asks the one rule, and where the rule answers with nothing the
/// intake counts the drop and returns: nothing is signed and nothing is sent.
#[test]
fn the_intake_asks_the_one_rule_and_sends_nothing_when_it_says_so() {
    let prod = production_source();
    assert_eq!(
        prod.matches("refused_dispatch_answer(").count(),
        1,
        "the rule is asked once"
    );
    let rule_file = production_of(include_str!("refused_dispatch.rs"));
    assert_eq!(
        rule_file.matches("fn refused_dispatch_answer(").count(),
        1,
        "and defined once, in its own file"
    );
    let asked = prod
        .find("Err(refusal) => match refused_dispatch_answer(")
        .expect("the intake asks the rule for a dispatch execute_job refused");
    let arm = &prod[asked..];
    let none = arm.find("None => {").expect("the rule may answer nothing");
    let leaves = none
        + arm[none..]
            .find("drop(permit);\n")
            .expect("the nothing arm gives its permit back");
    let nothing_arm = &arm[none..leaves];
    assert!(
        nothing_arm.contains("rejected_jobs::record(")
            && nothing_arm.contains("rejected_jobs::RejectReason::unverified(refusal.kind())"),
        "the drop is counted under the verifier's class"
    );
    for sends in ["sign_job_result", "publish_result_with_retry(", ".publish("] {
        assert!(
            !nothing_arm.contains(sends),
            "nothing is signed or sent for a dispatch the rule answers with nothing (`{sends}`)"
        );
    }
    let after: Vec<&str> = arm[leaves..].lines().map(str::trim).take(2).collect();
    assert_eq!(
        after,
        ["drop(permit);", "return;"],
        "and the task ends there, before the signing and publishing below it"
    );
    // Only the rule builds the refusal payload that is signed; the other call
    // writes the operator's field dump to this worker's log.
    let rule = top_level_fn(&rule_file, "fn refused_dispatch_answer(");
    assert_eq!(
        rule.matches("signature_failure_payload(").count(),
        1,
        "the rule builds the one answer"
    );
    assert_eq!(
        rule_file.matches("signature_failure_payload(").count(),
        2,
        "its definition and the rule's answer"
    );
    assert_eq!(
        prod.matches("signature_failure_payload(").count(),
        1,
        "and in main.rs the diagnostic log line; no other caller"
    );
    assert!(
        nothing_arm.contains("diag = %signature_failure_payload(true, &req, &refusal),"),
        "that one is the log line in the nothing arm"
    );
}
