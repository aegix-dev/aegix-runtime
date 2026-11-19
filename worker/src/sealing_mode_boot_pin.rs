//! Call-site pin: the worker refuses to boot on an unrecognised
//! `AEGIX_ENVELOPE_SEALING`, before the gate that asks the mode (2026-11-18).
//!
//! The parser is tested where it lives (`aegix_deploy_posture::
//! envelope_sealing`). What its tests cannot see is whether this binary asks
//! it at boot: without the call an unrecognised value reaches
//! `worker_sealing_required`, which then reads it as `required`, so the
//! worker would refuse every inline envelope while the operator believes
//! they turned sealing off, or the reverse on a controller. This reads
//! `boot_gates.rs`, from its own file so its needles are not in the file it
//! scans.

#[test]
fn the_boot_gates_refuse_an_unrecognised_sealing_mode_before_they_ask_it() {
    let src = crate::retry_policy_pin::production_of(include_str!("boot_gates.rs"));
    let refusal = ["aegix_deploy_posture::envelope_sealing::", "from_env()"].concat();
    assert_eq!(
        src.matches(&refusal).count(),
        1,
        "the boot gates ask the one parser, once"
    );
    let at = src.find(&refusal).expect("counted above");
    let statement = &src[at..at + src[at..].find(';').expect("a statement")];
    assert!(
        statement.ends_with('?'),
        "and an unrecognised value ends the boot: `{statement}`"
    );
    let asked = src
        .find("enforce_production_fleet_identity(")
        .expect("vacuity guard: the fleet-identity gate is in boot_gates.rs");
    assert!(
        at < asked,
        "the refusal comes before the gate that reads the mode"
    );
}
