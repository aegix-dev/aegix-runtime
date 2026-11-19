//! Call-site pin: the worker's NATS job path reports fuel OUT OF BAND.
//!
//! The runtime measures each attempt's fuel into a caller-supplied
//! accumulator (`execute_job_with_full_features`'s `fuel_out`), before any
//! error return; `kill_switch_tests` proves that for an array output, a
//! module error and a fuel-exhausted run. What those tests cannot see is
//! whether THIS process passes an accumulator and drains it onto every
//! result it signs — the controller's hourly fuel budget depends on exactly
//! that, and a call passing `None` would leave every test green. It lives in
//! its own file because a pin inside the file it scans matches its own
//! needles (#944/#947). Stated as a TEXTUAL pin: `execute_job` needs a
//! broker to drive.

/// The worker's job path, production code only: `job_execution.rs` and
/// `main.rs`, read together (`retry_policy_pin::production_source`).
fn production_source() -> String {
    crate::retry_policy_pin::production_source()
}

#[test]
fn the_nats_job_path_passes_a_fuel_accumulator_and_drains_it_on_every_branch() {
    let prod = production_source();
    let pass = ["Some(fuel_acc", ".clone()),"].concat();
    assert_eq!(
        prod.matches(&pass).count(),
        1,
        "the runtime is given the accumulator"
    );
    // Success, failure and timeout each sign a result; each must carry the
    // measured fuel.
    let drain = ["fuel: worker::context::take_fuel", "(&fuel_acc),"].concat();
    assert_eq!(
        prod.matches(&drain).count(),
        3,
        "every result branch drains it"
    );
    // The oversize replacement keeps the fuel the dropped output spent.
    // It lives in `job_result.rs` since 2026-11-18; that file's own test
    // module has no such line, so the whole file is read.
    let keep = ["fuel: result", ".fuel,"].concat();
    assert_eq!(include_str!("job_result.rs").matches(&keep).count(), 1);
}
