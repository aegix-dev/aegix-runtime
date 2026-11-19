//! How `AEGIX_ENVELOPE_SEALING` is read: one parser for the controller and
//! the worker, and an unrecognised value is an error.
//!
//! The mode decides whether a job's secrets are sealed to the one worker
//! that claims them or ride the bus under a key every worker derives. Until
//! 2026-11-18 the controller and the worker each parsed it, and both read
//! anything they did not recognise as `off`: `requried`, `true` or `on` left
//! every dispatch's secrets under the fleet key with no line logged, in any
//! deployment the fleet-identity gate did not also stop. The same was closed
//! for `AEGIX_SIGSTORE_REQUIRED` on 2026-10-14 and for the security profile
//! on 2026-10-29.

/// The setting's name.
pub const ENVELOPE_SEALING_ENV: &str = "AEGIX_ENVELOPE_SEALING";

/// The secret-delivery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealingMode {
    /// The inline envelope under the fleet key. What an unset setting means.
    Off,
    /// Sealed to the claiming worker where it can claim; inline accepted.
    Audit,
    /// Sealed to the claiming worker; an inline envelope is refused.
    Required,
}

/// Read a value of the setting. Unset and empty are [`SealingMode::Off`];
/// `off`, `audit` and `required` are themselves, in any letter case and with
/// surrounding space; anything else is an error that names the value and the
/// three spellings.
pub fn parse(raw: Option<&str>) -> Result<SealingMode, String> {
    let Some(raw) = raw else {
        return Ok(SealingMode::Off);
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "off" => Ok(SealingMode::Off),
        "audit" => Ok(SealingMode::Audit),
        "required" => Ok(SealingMode::Required),
        _ => Err(format!(
            "{ENVELOPE_SEALING_ENV}={raw:?} is not a sealing mode: use `off`, `audit` or \
             `required`. Refusing to start, because an unrecognised value was once read as \
             `off`, which sends every job's secrets under the key the whole fleet holds"
        )),
    }
}

/// [`parse`] of the process's environment. A binary calls this at boot and
/// refuses to start on `Err`.
pub fn from_env() -> Result<SealingMode, String> {
    parse(std::env::var("AEGIX_ENVELOPE_SEALING").ok().as_deref())
}

/// The mode for a reader after boot. Boot has refused an unrecognised value
/// ([`from_env`]); should one be read all the same, it is read as
/// [`SealingMode::Required`], the strictest, never as `Off`.
#[must_use]
pub fn from_env_or_strictest() -> SealingMode {
    from_env().unwrap_or(SealingMode::Required)
}

#[cfg(test)]
mod tests {
    use super::{parse, SealingMode};

    #[test]
    fn the_three_spellings_and_unset_are_read() {
        assert_eq!(parse(None), Ok(SealingMode::Off));
        assert_eq!(parse(Some("")), Ok(SealingMode::Off));
        assert_eq!(parse(Some("  ")), Ok(SealingMode::Off));
        assert_eq!(parse(Some("off")), Ok(SealingMode::Off));
        assert_eq!(parse(Some("audit")), Ok(SealingMode::Audit));
        assert_eq!(parse(Some("required")), Ok(SealingMode::Required));
        assert_eq!(parse(Some(" Required\n")), Ok(SealingMode::Required));
        assert_eq!(parse(Some("AUDIT")), Ok(SealingMode::Audit));
    }

    /// The defect: each of these was read as `off`.
    #[test]
    fn an_unrecognised_value_is_an_error_and_never_off() {
        for wrong in [
            "requried",
            "true",
            "on",
            "1",
            "enforce",
            "require",
            "yes",
            "audit,required",
        ] {
            let err = parse(Some(wrong)).expect_err(wrong);
            assert!(err.contains(wrong), "{err}");
            assert!(
                err.contains("off") && err.contains("audit") && err.contains("required"),
                "the refusal names the three spellings: {err}"
            );
        }
    }
}
