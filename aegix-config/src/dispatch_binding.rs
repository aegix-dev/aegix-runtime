//! Whether the controller requires every data-plane RPC to name a live
//! dispatch (2026-10-29).
//!
//! A worker's memory, graph, database, model and integration-state calls
//! carry a signed `dispatch` binding — the job's run and its own
//! `module_executions` row — and the controller admits one only while that
//! dispatch is live and owned by the request's actor. A request with NO
//! binding comes from one of two senders: the controller's own rehearsal
//! runtime (`run_sandbox`, `test_module`), which signs with the controller's
//! identity and is admitted on that, or a worker build older than the field.
//! The second is the posture this switch decides.
//!
//! `AEGIX_RPC_REQUIRE_DISPATCH_BINDING` is read by the controller only:
//!
//! | value | meaning |
//! |---|---|
//! | unset, `true` | an unbound request from a worker key is REFUSED (the default) |
//! | `false` | an unbound request from a worker key is admitted — the rolling-upgrade window, while workers older than the field still run; logged at ERROR on every boot and reported by `security_audit` |
//! | anything else | the controller refuses to boot |
//!
//! A binding that IS present is checked whatever the switch says: waiving
//! tolerates absence, never a false statement.

/// The switch's name — the one spelling, for the boot log, the audit and the
/// configuration reference.
pub const SWITCH: &str = "AEGIX_RPC_REQUIRE_DISPATCH_BINDING";

/// What the controller does with an unbound request from a worker key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement {
    /// Refused. The default.
    Required,
    /// Admitted, by the operator's explicit word.
    Waived,
}

/// The decision, pure: from the switch's raw reading.
pub fn parse(reading: crate::BoolEnv) -> Result<Requirement, String> {
    match reading {
        crate::BoolEnv::Unset | crate::BoolEnv::Value(true) => Ok(Requirement::Required),
        crate::BoolEnv::Value(false) => Ok(Requirement::Waived),
        crate::BoolEnv::Unreadable(raw) => Err(format!(
            "{SWITCH}={raw:?} is not a boolean; it is unset or `true` (every data-plane RPC \
             from a worker names its live dispatch) or `false` (an unbound request from a \
             worker key is admitted, for the window in which workers older than the field \
             still run)"
        )),
    }
}

/// The requirement this process runs under, read once. `Err` is the boot
/// refusal; the gate treats a process that somehow runs past it as
/// [`Requirement::Required`].
pub fn requirement() -> Result<Requirement, String> {
    static CACHE: std::sync::OnceLock<Result<Requirement, String>> = std::sync::OnceLock::new();
    CACHE
        // The literal, not `SWITCH`: the configuration-reference lint (check 89)
        // recognises a read by the whole name at the call.
        .get_or_init(|| parse(crate::read_bool_env("AEGIX_RPC_REQUIRE_DISPATCH_BINDING")))
        .clone()
}

/// Apply [`requirement`] at boot: refuse an unreadable value, log a waiver
/// at ERROR so it is never a quiet default.
pub fn enforce_at_boot() -> Result<Requirement, String> {
    let requirement = requirement()?;
    if requirement == Requirement::Waived {
        tracing::error!(
            target: "talos_security",
            event_kind = "rpc_dispatch_binding_waived",
            switch = SWITCH,
            "the controller admits data-plane RPCs that name no dispatch when a worker key \
             signs them ({SWITCH}=false): any holder of a worker key reads and writes any \
             actor's memory until every worker runs a build that names its dispatch"
        );
    }
    Ok(requirement)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoolEnv;

    #[test]
    fn unset_and_true_require_the_binding() {
        assert_eq!(parse(BoolEnv::Unset), Ok(Requirement::Required));
        assert_eq!(parse(BoolEnv::Value(true)), Ok(Requirement::Required));
    }

    #[test]
    fn only_an_explicit_false_waives_it() {
        assert_eq!(parse(BoolEnv::Value(false)), Ok(Requirement::Waived));
    }

    #[test]
    fn an_unreadable_value_refuses_rather_than_choosing() {
        let err = parse(BoolEnv::Unreadable("maybe".into())).unwrap_err();
        assert!(err.contains(SWITCH), "{err}");
        assert!(err.contains("maybe"), "{err}");
    }
}
