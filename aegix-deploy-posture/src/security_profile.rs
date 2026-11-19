//! One operator-facing security profile (2026-10-29, recommendation (4) of
//! the whole-application review).
//!
//! Until this date the controller's and the worker's boot gates each read
//! their own acknowledgement — `AEGIX_ALLOW_LEGACY_FLEET_HMAC`,
//! `AEGIX_ALLOW_RLS_DISABLED`, `AEGIX_ALLOW_DISPATCH_SCHEME_FALLBACK`,
//! `AEGIX_ALLOW_UNSCOPED_DB_SANDBOX`, `AEGIX_WORKER_ALLOW_ENV_PROVIDER_KEYS`,
//! `AEGIX_ALLOW_UNATTESTED_WASM`, a requirement switch turned off by hand —
//! and each decided for itself whether the deployment was one that faces
//! users (`aegix_auth_types::browser_hardening_required()`) or one that is
//! `production` (`crate::is_production()`). An operator who wanted to know
//! "is this deployment hardened?" had to read eight switches and know which
//! predicate each gate used. `AEGIX_SECURITY_PROFILE` is that one answer.
//!
//! | value | meaning |
//! |---|---|
//! | `hardened` | every gate refuses; an acknowledgement set at all refuses boot; the switches the profile defaults are on. The default wherever `browser_hardening_required()` holds |
//! | `transitional` | every gate runs; an acknowledgement is honoured and logged at ERROR on every boot, exactly as before this date; the switches keep their historical defaults |
//! | `development` | no gate enforces. Refused wherever `browser_hardening_required()` holds; the default elsewhere |
//! | anything else | the process refuses to boot, in every environment |
//!
//! The individual switches keep working beneath the profile: `hardened`
//! turns their defaults on and refuses the acknowledgements, `transitional`
//! is the posture every deployment ran before this date, so a deployment
//! that names `transitional` on the day it rolls boots exactly as it did.
//!
//! **One reader.** [`profile`] is the one place the variable is read; a gate
//! asks [`SecurityProfile::enforces`] (its predicate),
//! [`SecurityProfile::honours_acknowledgements`] (whether to read its
//! acknowledgement at all) or [`SecurityProfile::default_on`] (the default of
//! a requirement switch it owns). A gate does not read `RUST_ENV` for its
//! verdict any more; `is_production()` stays for build and infrastructure
//! posture (structural check 103).

/// The variable's name — the one spelling, for the boot log, the audit and
/// the configuration reference.
pub const SWITCH: &str = "AEGIX_SECURITY_PROFILE";

/// The profile a process runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityProfile {
    /// Every gate refuses; no acknowledgement is honoured.
    Hardened,
    /// Every gate runs; an acknowledgement is honoured and logged at ERROR.
    Transitional,
    /// No gate enforces. Only where the deployment does not face users.
    Development,
}

impl SecurityProfile {
    /// The spelling the variable takes.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hardened => "hardened",
            Self::Transitional => "transitional",
            Self::Development => "development",
        }
    }

    /// Whether a boot gate enforces its rule under this profile. This is the
    /// predicate a gate asks in place of `browser_hardening_required()` or
    /// `is_production()`.
    #[must_use]
    pub const fn enforces(self) -> bool {
        !matches!(self, Self::Development)
    }

    /// Whether a gate reads its acknowledgement. Under `hardened` an
    /// acknowledgement is not read by any gate: [`enforce_at_boot`] has
    /// already refused the process that set one.
    #[must_use]
    pub const fn honours_acknowledgements(self) -> bool {
        matches!(self, Self::Transitional)
    }

    /// The default of a requirement switch the profile owns
    /// (`AEGIX_RLS_SET_ROLE`, `AEGIX_DISTRIBUTED_REPLAY`,
    /// `AEGIX_WRITE_CEILING_ENFORCED`, `AEGIX_WORKER_REG_REQUIRE_BOUND_TOKEN`):
    /// on under `hardened`, the historical
    /// `false` under the other two.
    #[must_use]
    pub const fn default_on(self) -> bool {
        matches!(self, Self::Hardened)
    }
}

/// Where the profile came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `AEGIX_SECURITY_PROFILE` named it.
    Set,
    /// The variable was unset: `hardened` where hardening holds, else
    /// `development`.
    Defaulted,
}

/// The profile as resolved, with what it was resolved from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolution {
    pub profile: SecurityProfile,
    pub source: Source,
    /// `browser_hardening_required()` as read beside the variable.
    pub hardening: bool,
}

/// The decision, pure: from the variable's raw value and whether the
/// deployment faces users. An unrecognised spelling is `Err` in EVERY
/// environment (as `SigstorePolicy::from_env_str` is): a misspelt
/// `hardened` must not boot as anything.
pub fn parse(raw: Option<&str>, hardening: bool) -> Result<Resolution, String> {
    let trimmed = raw.map(str::trim).filter(|r| !r.is_empty());
    let Some(word) = trimmed else {
        let profile = if hardening {
            SecurityProfile::Hardened
        } else {
            SecurityProfile::Development
        };
        return Ok(Resolution {
            profile,
            source: Source::Defaulted,
            hardening,
        });
    };
    let profile = match word.to_ascii_lowercase().as_str() {
        "hardened" => SecurityProfile::Hardened,
        "transitional" => SecurityProfile::Transitional,
        "development" => SecurityProfile::Development,
        _ => {
            return Err(format!(
                "{SWITCH}={word:?} is not a security profile; it is `hardened` (every gate \
                 refuses, no acknowledgement honoured), `transitional` (acknowledgements \
                 honoured and logged at ERROR on every boot) or `development` (no gate \
                 enforces; only where RUST_ENV does not face users)"
            ))
        }
    };
    if profile == SecurityProfile::Development && hardening {
        return Err(format!(
            "{SWITCH}=development is refused where the deployment faces users (RUST_ENV is \
             neither development nor test): a deployment that is not yet hardened names \
             `transitional` and acknowledges the surfaces still open"
        ));
    }
    Ok(Resolution {
        profile,
        source: Source::Set,
        hardening,
    })
}

/// The profile as this process's environment resolves it. Read on each call,
/// as `browser_hardening_required()` is: a boot gate reads it once, the few
/// per-request readers cache their own verdict.
pub fn resolution() -> Result<Resolution, String> {
    parse(
        // The literal, not `SWITCH`: the configuration-reference lint (check 89)
        // recognises a read by the whole name at the call.
        std::env::var("AEGIX_SECURITY_PROFILE").ok().as_deref(),
        aegix_auth_types::browser_hardening_required(),
    )
}

/// The profile a gate decides under. An unreadable value has already refused
/// boot in [`enforce_at_boot`]; a process that somehow runs past it decides
/// as `hardened`, the strictest.
#[must_use]
pub fn profile() -> SecurityProfile {
    // The same read as `resolution()`, spelled again rather than delegated:
    // check 89 attributes a read to the callers of the `pub fn` whose body
    // names the variable, and the worker's crates call this one.
    parse(
        std::env::var("AEGIX_SECURITY_PROFILE").ok().as_deref(),
        aegix_auth_types::browser_hardening_required(),
    )
    .map_or(SecurityProfile::Hardened, |r| r.profile)
}

/// One acknowledgement a process reads: a setting whose presence says "this
/// deployment runs with a surface open, on purpose".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Acknowledgement {
    /// A boolean waiver, in force when it reads `true`.
    Boolean(&'static str),
    /// A waiver that names what it acknowledges, in force when non-empty.
    Words(&'static str),
    /// A requirement switch turned off by hand, in force when it reads
    /// `false`. Listed here only for a switch no gate of its own refuses.
    SwitchOff(&'static str),
    /// A number that turns something on, in force when it reads as a
    /// positive integer (`WASM_RESULT_CACHE_TTL_SECS`: `0` and an unparsable
    /// value turn nothing on, as the runtime reads them).
    PositiveInteger(&'static str),
}

impl Acknowledgement {
    /// The variable's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Boolean(n) | Self::Words(n) | Self::SwitchOff(n) | Self::PositiveInteger(n) => n,
        }
    }

    /// Whether `raw` puts this acknowledgement in force. An unreadable
    /// boolean is not in force here: the gate that owns the switch refuses
    /// it with its own words.
    #[must_use]
    pub fn in_force(self, raw: Option<&str>) -> bool {
        let Some(raw) = raw else { return false };
        match self {
            Self::Boolean(_) => matches!(crate::parse_bool_env(raw), crate::BoolEnv::Value(true)),
            Self::SwitchOff(_) => {
                matches!(crate::parse_bool_env(raw), crate::BoolEnv::Value(false))
            }
            Self::Words(_) => !raw.trim().is_empty(),
            Self::PositiveInteger(_) => raw.trim().parse::<u64>().is_ok_and(|n| n > 0),
        }
    }
}

/// The process whose acknowledgements [`enforce_at_boot`] reads. Each name
/// is read here only to decide the profile's verdict on it; the gate that
/// owns it reads it again, with its own vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Process {
    Controller,
    Worker,
}

impl Process {
    /// The acknowledgements this process reads.
    #[must_use]
    pub const fn acknowledgements(self) -> &'static [Acknowledgement] {
        match self {
            Self::Controller => &[
                Acknowledgement::Words("AEGIX_ALLOW_LEGACY_FLEET_HMAC"),
                Acknowledgement::Boolean("AEGIX_ALLOW_RLS_DISABLED"),
                Acknowledgement::Boolean("AEGIX_ALLOW_DISPATCH_SCHEME_FALLBACK"),
                Acknowledgement::Boolean("AEGIX_ALLOW_UNSCOPED_DB_SANDBOX"),
                Acknowledgement::SwitchOff("AEGIX_RPC_REQUIRE_DISPATCH_BINDING"),
                Acknowledgement::SwitchOff("AEGIX_WRITE_CEILING_ENFORCED"),
                // 2026-11-06: unset reads `default_on()` (the registration
                // route admits only worker_id-bound provisioning tokens under
                // `hardened`); an explicit `false` is the acknowledgement.
                Acknowledgement::SwitchOff("AEGIX_WORKER_REG_REQUIRE_BOUND_TOKEN"),
                // 2026-11-06: the controller's in-process runtime validates
                // module SQL with the same rule as the worker's.
                Acknowledgement::Boolean("AEGIX_SQL_PERMISSIVE_EMPTY_ALLOWLIST"),
            ],
            Self::Worker => &[
                Acknowledgement::Words("AEGIX_ALLOW_LEGACY_FLEET_HMAC"),
                Acknowledgement::Boolean("AEGIX_WORKER_ALLOW_ENV_PROVIDER_KEYS"),
                Acknowledgement::Boolean("AEGIX_ALLOW_UNATTESTED_WASM"),
                Acknowledgement::SwitchOff("AEGIX_WRITE_CEILING_ENFORCED"),
                Acknowledgement::Boolean("AEGIX_SQL_PERMISSIVE_EMPTY_ALLOWLIST"),
            ],
        }
    }

    /// The development-only settings this process reads (2026-11-06): each
    /// opens a data-plane control a guest module meets, and NO enforcing
    /// profile accepts one — not `hardened`, and not `transitional` either,
    /// because none is a migration window: each is a convenience for a
    /// developer's machine. [`enforce_at_boot`] refuses a process that sets
    /// one under `hardened` or `transitional`; only `development` reads them.
    /// The controller is listed with the worker because its in-process
    /// runtime (`run_sandbox`, `test_module`, scratch sessions, replays)
    /// builds the same module contexts and the same runtime.
    ///
    /// * `WORKER_ALLOW_PRIVATE_HOST_TARGETS` — a name in `allowed_hosts` may
    ///   resolve to a private address (the guest SSRF defence relaxed).
    /// * `WASM_ALLOW_INSECURE_HTTP` — plaintext `http://` egress, `vault://`
    ///   headers included.
    /// * `WASM_RESULT_CACHE_TTL_SECS` — the module result cache, whose Redis
    ///   tier is sealed under a key every worker derives from
    ///   `WORKER_SHARED_KEY`, so one worker opens and writes every other's
    ///   entries, whatever tenant they came from.
    #[must_use]
    pub const fn development_only(self) -> &'static [Acknowledgement] {
        match self {
            Self::Controller | Self::Worker => &[
                Acknowledgement::Boolean("WORKER_ALLOW_PRIVATE_HOST_TARGETS"),
                Acknowledgement::Boolean("WASM_ALLOW_INSECURE_HTTP"),
                Acknowledgement::PositiveInteger("WASM_RESULT_CACHE_TTL_SECS"),
            ],
        }
    }

    /// The development-only settings of this process the environment puts in
    /// force, by name.
    #[must_use]
    pub fn development_only_in_force(self) -> Vec<&'static str> {
        self.development_only()
            .iter()
            .filter(|a| a.in_force(std::env::var(a.name()).ok().as_deref()))
            .map(|a| a.name())
            .collect()
    }

    /// The acknowledgements of this process that the environment puts in
    /// force, by name.
    #[must_use]
    pub fn acknowledgements_in_force(self) -> Vec<&'static str> {
        self.acknowledgements()
            .iter()
            .filter(|a| a.in_force(std::env::var(a.name()).ok().as_deref()))
            .map(|a| a.name())
            .collect()
    }
}

/// The boot verdict, pure: `hardened` refuses any acknowledgement in force,
/// the other two profiles boot.
pub fn boot_verdict(resolution: &Resolution, in_force: &[&str]) -> Result<(), String> {
    if resolution.profile == SecurityProfile::Hardened && !in_force.is_empty() {
        return Err(format!(
            "{SWITCH}=hardened refuses every acknowledgement, and {} {} set. Remove {} once the \
             surface it acknowledges is closed, or name {SWITCH}=transitional while it is \
             open (each acknowledgement is then logged at ERROR on every boot)",
            in_force.join(", "),
            if in_force.len() == 1 { "is" } else { "are" },
            if in_force.len() == 1 { "it" } else { "them" },
        ));
    }
    Ok(())
}

/// The development-only verdict, pure (2026-11-06): any profile that
/// enforces refuses a development-only setting in force
/// ([`Process::development_only`]); `development` boots with it. There is no
/// acknowledgement that waives it.
pub fn development_only_verdict(resolution: &Resolution, in_force: &[&str]) -> Result<(), String> {
    if resolution.profile.enforces() && !in_force.is_empty() {
        let one = in_force.len() == 1;
        return Err(format!(
            "{SWITCH}={} refuses {}: {} development-only, opening a control a guest module              meets (egress to a private address, plaintext http, or a module-output cache              sealed under a key every worker derives), and no acknowledgement covers {}.              Unset {}; only {SWITCH}=development, where RUST_ENV does not face users, reads {}",
            resolution.profile.name(),
            in_force.join(", "),
            if one { "it is" } else { "they are" },
            if one { "it" } else { "them" },
            if one { "it" } else { "them" },
            if one { "it" } else { "them" },
        ));
    }
    Ok(())
}

/// Apply the profile at boot. Call FIRST, before any gate that asks
/// [`profile`]: refuse an unreadable value, refuse an acknowledgement under
/// `hardened`, refuse a development-only setting under any profile that
/// enforces, log each acknowledgement under `transitional` at ERROR, and
/// say which profile this process runs under.
pub fn enforce_at_boot(process: Process) -> Result<Resolution, String> {
    let resolution = resolution()?;
    let in_force = process.acknowledgements_in_force();
    boot_verdict(&resolution, &in_force)?;
    development_only_verdict(&resolution, &process.development_only_in_force())?;
    tracing::info!(
        target: "talos_security",
        event_kind = "security_profile",
        profile = resolution.profile.name(),
        source = ?resolution.source,
        hardening_required = resolution.hardening,
        "{SWITCH} resolved"
    );
    if resolution.profile.honours_acknowledgements() {
        for name in in_force {
            tracing::error!(
                target: "talos_security",
                event_kind = "security_profile_acknowledgement",
                profile = resolution.profile.name(),
                acknowledgement = name,
                "{SWITCH}=transitional honours {name}: a surface this deployment could close \
                 is open by the operator's word; `hardened` refuses it"
            );
        }
    }
    Ok(resolution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use SecurityProfile::{Development, Hardened, Transitional};

    /// The one controller acknowledgement whose name ends in `suffix`.
    fn controller_name(suffix: &str) -> &'static str {
        let mut found = Process::Controller
            .acknowledgements()
            .iter()
            .map(|a| a.name())
            .filter(|n| n.ends_with(suffix));
        let name = found.next().expect("a controller acknowledgement");
        assert!(found.next().is_none(), "{suffix} names one");
        name
    }

    fn res(profile: SecurityProfile) -> Resolution {
        Resolution {
            profile,
            source: Source::Set,
            hardening: true,
        }
    }

    #[test]
    fn unset_defaults_to_hardened_where_hardening_holds_and_development_elsewhere() {
        let r = parse(None, true).unwrap();
        assert_eq!((r.profile, r.source), (Hardened, Source::Defaulted));
        let r = parse(Some("  "), true).unwrap();
        assert_eq!((r.profile, r.source), (Hardened, Source::Defaulted));
        let r = parse(None, false).unwrap();
        assert_eq!((r.profile, r.source), (Development, Source::Defaulted));
    }

    #[test]
    fn the_three_spellings_parse_whatever_their_case() {
        for (word, want) in [
            ("hardened", Hardened),
            ("Hardened", Hardened),
            (" TRANSITIONAL ", Transitional),
            ("development", Development),
        ] {
            let hardening = want != Development;
            let r = parse(Some(word), hardening).unwrap();
            assert_eq!(r.profile, want, "{word}");
            assert_eq!(r.source, Source::Set, "{word}");
        }
    }

    /// Mutation target: a reader that returned `Hardened` (or anything) for
    /// a spelling it does not know fails this in BOTH environments.
    #[test]
    fn an_unrecognised_spelling_refuses_in_every_environment() {
        for hardening in [true, false] {
            for word in ["hardend", "strict", "true", "1", "off"] {
                let err = parse(Some(word), hardening)
                    .unwrap_err_or_else(|r| panic!("{word:?} parsed as {:?}", r.profile));
                assert!(err.contains(SWITCH), "{err}");
                assert!(err.contains(word), "{err}");
            }
        }
    }

    #[test]
    fn development_is_refused_where_the_deployment_faces_users() {
        let err = parse(Some("development"), true).unwrap_err();
        assert!(err.contains("transitional"), "{err}");
        assert_eq!(
            parse(Some("development"), false).unwrap().profile,
            Development
        );
    }

    #[test]
    fn hardened_and_transitional_may_be_named_anywhere() {
        assert_eq!(parse(Some("hardened"), false).unwrap().profile, Hardened);
        assert_eq!(
            parse(Some("transitional"), false).unwrap().profile,
            Transitional
        );
    }

    #[test]
    fn the_predicates_follow_the_table() {
        assert!(Hardened.enforces() && Transitional.enforces() && !Development.enforces());
        assert!(
            !Hardened.honours_acknowledgements()
                && Transitional.honours_acknowledgements()
                && !Development.honours_acknowledgements()
        );
        assert!(Hardened.default_on() && !Transitional.default_on() && !Development.default_on());
    }

    #[test]
    fn an_acknowledgement_is_in_force_by_its_kind() {
        let b = Acknowledgement::Boolean("B");
        assert!(b.in_force(Some("true")) && b.in_force(Some("1")));
        assert!(!b.in_force(Some("false")) && !b.in_force(Some("maybe")) && !b.in_force(None));
        let w = Acknowledgement::Words("W");
        assert!(w.in_force(Some("rpc,envelope")) && w.in_force(Some("all")));
        assert!(!w.in_force(Some("  ")) && !w.in_force(None));
        let s = Acknowledgement::SwitchOff("S");
        assert!(s.in_force(Some("false")) && s.in_force(Some("0")));
        assert!(!s.in_force(Some("true")) && !s.in_force(None) && !s.in_force(Some("x")));
        let n = Acknowledgement::PositiveInteger("N");
        assert!(n.in_force(Some("300")) && n.in_force(Some(" 1 ")));
        assert!(!n.in_force(Some("0")) && !n.in_force(Some("-5")) && !n.in_force(Some("x")));
        assert!(!n.in_force(Some("")) && !n.in_force(None));
    }

    /// Mutation target: a verdict that booted `hardened` OR `transitional`
    /// with a development-only setting in force fails this. Unlike an
    /// acknowledgement, `transitional` does not honour one.
    #[test]
    fn every_enforcing_profile_refuses_a_development_only_setting() {
        for p in [Hardened, Transitional] {
            let err = development_only_verdict(&res(p), &["WASM_ALLOW_INSECURE_HTTP"])
                .unwrap_err_or_else(|()| panic!("{p:?} booted with a development-only setting"));
            assert!(err.contains("WASM_ALLOW_INSECURE_HTTP"), "{err}");
            assert!(err.contains(p.name()), "{err}");
            assert!(err.contains("it is development-only"), "{err}");
            let err = development_only_verdict(
                &res(p),
                &[
                    "WORKER_ALLOW_PRIVATE_HOST_TARGETS",
                    "WASM_RESULT_CACHE_TTL_SECS",
                ],
            )
            .unwrap_err();
            assert!(err.contains("they are development-only"), "{err}");
            assert_eq!(development_only_verdict(&res(p), &[]), Ok(()), "{p:?}");
        }
        let dev = Resolution {
            profile: Development,
            source: Source::Defaulted,
            hardening: false,
        };
        assert_eq!(
            development_only_verdict(&dev, &["WASM_RESULT_CACHE_TTL_SECS"]),
            Ok(())
        );
    }

    /// Both processes list the three development-only settings: the
    /// controller's in-process runtime builds the same contexts.
    #[test]
    fn both_processes_list_the_development_only_settings() {
        for p in [Process::Controller, Process::Worker] {
            let names: Vec<_> = p.development_only().iter().map(|a| a.name()).collect();
            assert_eq!(
                names,
                [
                    "WORKER_ALLOW_PRIVATE_HOST_TARGETS",
                    "WASM_ALLOW_INSECURE_HTTP",
                    "WASM_RESULT_CACHE_TTL_SECS"
                ],
                "{p:?}"
            );
            assert!(p
                .development_only()
                .contains(&Acknowledgement::PositiveInteger(
                    "WASM_RESULT_CACHE_TTL_SECS"
                )));
            // A development-only setting is not also an acknowledgement:
            // `transitional` must not honour it.
            assert!(!p
                .acknowledgements()
                .iter()
                .any(|a| names.contains(&a.name())));
        }
    }

    /// Mutation target: a verdict that booted `hardened` with an
    /// acknowledgement in force fails this.
    #[test]
    fn hardened_refuses_any_acknowledgement_in_force() {
        // The controller-only names are taken from the list, not spelled:
        // a whole literal here would read, to check 89, as a worker read.
        let rls = controller_name("RLS_DISABLED");
        let err = boot_verdict(&res(Hardened), &[rls]).unwrap_err();
        assert!(err.contains(rls), "{err}");
        assert!(err.contains("transitional"), "{err}");
        let err = boot_verdict(
            &res(Hardened),
            &[
                "AEGIX_ALLOW_LEGACY_FLEET_HMAC",
                "AEGIX_WRITE_CEILING_ENFORCED",
            ],
        )
        .unwrap_err();
        assert!(err.contains("are set"), "{err}");
        assert_eq!(boot_verdict(&res(Hardened), &[]), Ok(()));
    }

    #[test]
    fn transitional_and_development_boot_with_acknowledgements() {
        for p in [Transitional, Development] {
            assert_eq!(
                boot_verdict(&res(p), &[controller_name("RLS_DISABLED")]),
                Ok(()),
                "{p:?}"
            );
        }
    }

    #[test]
    fn each_process_lists_only_names_it_reads() {
        // Both processes read the fleet acknowledgement and own a write
        // ceiling; the rest are one process's own.
        let c = Process::Controller.acknowledgements();
        let w = Process::Worker.acknowledgements();
        assert!(c.contains(&Acknowledgement::Words("AEGIX_ALLOW_LEGACY_FLEET_HMAC")));
        assert!(w.contains(&Acknowledgement::Words("AEGIX_ALLOW_LEGACY_FLEET_HMAC")));
        let binding = controller_name("DISPATCH_BINDING");
        assert!(c.contains(&Acknowledgement::SwitchOff(binding)));
        assert!(!w.iter().any(|a| a.name() == binding));
        assert!(w.contains(&Acknowledgement::Boolean(
            "AEGIX_WORKER_ALLOW_ENV_PROVIDER_KEYS"
        )));
        assert!(!c
            .iter()
            .any(|a| a.name() == "AEGIX_WORKER_ALLOW_ENV_PROVIDER_KEYS"));
        // 2026-11-06: an explicit `false` of the bound-token switch is the
        // controller's own; the permissive SQL allowlist is read by both.
        let bound = controller_name("REG_REQUIRE_BOUND_TOKEN");
        assert!(c.contains(&Acknowledgement::SwitchOff(bound)));
        assert!(!w.iter().any(|a| a.name() == bound));
        let sql = Acknowledgement::Boolean("AEGIX_SQL_PERMISSIVE_EMPTY_ALLOWLIST");
        assert!(c.contains(&sql) && w.contains(&sql));
    }

    trait UnwrapErrOrElse<T, E> {
        fn unwrap_err_or_else(self, f: impl FnOnce(T) -> E) -> E;
    }
    impl<T, E> UnwrapErrOrElse<T, E> for Result<T, E> {
        fn unwrap_err_or_else(self, f: impl FnOnce(T) -> E) -> E {
            match self {
                Ok(v) => f(v),
                Err(e) => e,
            }
        }
    }
}
