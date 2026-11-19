use crate::{
    bool_env, bool_env_or_default, env_var_is_set_nonempty, get_env, positive_env_or_default,
};
use std::env;

/// Serialises the tests of this module that change the process's
/// environment: under `cargo test` they share one process, and two that
/// set and remove one variable would race.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    match LOCK.lock() {
        Ok(g) => g,
        // Poisoned by a panic in an earlier test: each test sets or
        // removes what it reads, so carrying on is safe.
        Err(poison) => poison.into_inner(),
    }
}

/// The whole defect class, pinned as one assertion: for `FOO=""` the
/// idiom `env::var("FOO").is_ok()` says CONFIGURED and
/// `env_var_is_set_nonempty` says NOT CONFIGURED. Every consumer in this
/// workspace agrees with the latter (`get_env` falls through to its
/// default here, `read_env_or_file` falls through to `<VAR>_FILE`), which
/// is what made the eleven prior repairs — MCP-590/591/592/597/598/599/
/// 611/615/620/621/625 — necessary. Structural lint check 73 forbids the
/// left-hand shape; this test is why.
#[test]
fn env_presence_empty_string_is_not_configured() {
    let _g = env_lock();
    const K: &str = "AEGIX_TEST_EMPTY_ENV_PRESENCE";

    env::set_var(K, "");
    assert!(
        env::var(K).is_ok(),
        "precondition: env::var returns Ok(\"\") for an empty var — if this \
         ever fails the defect class is gone and check 73 can be retired"
    );
    assert!(
        !env_var_is_set_nonempty(K),
        "an empty env var must NOT read as configured"
    );
    // ...and the rest of the config layer must agree with that verdict.
    assert_eq!(
        get_env(K, "fallback"),
        "fallback",
        "get_env must fall through to its default for an empty var"
    );

    env::remove_var(K);
}

#[test]
fn env_presence_unset_and_set_cases() {
    let _g = env_lock();
    const K: &str = "AEGIX_TEST_ENV_PRESENCE_SET";

    env::remove_var(K);
    assert!(
        !env_var_is_set_nonempty(K),
        "unset must read as unconfigured"
    );

    env::set_var(K, "value");
    assert!(
        env_var_is_set_nonempty(K),
        "a real value must read as configured"
    );

    env::remove_var(K);
}

/// Whitespace-only is deliberately CONFIGURED, so this helper agrees with
/// `get_env` (which returns `" "` verbatim rather than its default) and
/// with `read_env_or_file`. Neither trims, so trimming here would make the
/// "is it configured?" answer disagree with the value the caller then
/// reads. Pinned rather than left to accident — a future change to trim
/// must change all three together.
#[test]
fn env_presence_whitespace_only_is_configured() {
    let _g = env_lock();
    const K: &str = "AEGIX_TEST_ENV_PRESENCE_WS";

    env::set_var(K, " ");
    assert!(env_var_is_set_nonempty(K));
    assert_eq!(get_env(K, "fallback"), " ");

    env::remove_var(K);
}

/// MCP-643: =0 must collapse to the default (with WARN at runtime;
/// the test only verifies the return value here).
#[test]
fn test_positive_env_zero_substitutes_default() {
    let _g = env_lock();
    env::set_var("TEST_POS_ENV_ZERO", "0");
    let v: i32 = positive_env_or_default("TEST_POS_ENV_ZERO", 30);
    assert_eq!(v, 30);
    env::remove_var("TEST_POS_ENV_ZERO");
}

/// Negative values must also collapse to the default — destructive
/// SQL `interval '-N days'` would archive future rows.
#[test]
fn test_positive_env_negative_substitutes_default() {
    let _g = env_lock();
    env::set_var("TEST_POS_ENV_NEG", "-5");
    let v: i32 = positive_env_or_default("TEST_POS_ENV_NEG", 30);
    assert_eq!(v, 30);
    env::remove_var("TEST_POS_ENV_NEG");
}

/// Missing env var → default.
#[test]
fn test_positive_env_missing_uses_default() {
    let _g = env_lock();
    env::remove_var("TEST_POS_ENV_MISSING_12345");
    let v: i32 = positive_env_or_default("TEST_POS_ENV_MISSING_12345", 30);
    assert_eq!(v, 30);
}

/// Invalid (non-numeric) value → default.
#[test]
fn test_positive_env_invalid_uses_default() {
    let _g = env_lock();
    env::set_var("TEST_POS_ENV_INVALID", "not-a-number");
    let v: i32 = positive_env_or_default("TEST_POS_ENV_INVALID", 30);
    assert_eq!(v, 30);
    env::remove_var("TEST_POS_ENV_INVALID");
}

/// Valid positive value passes through.
#[test]
fn test_positive_env_positive_passes_through() {
    let _g = env_lock();
    env::set_var("TEST_POS_ENV_POS", "60");
    let v: i32 = positive_env_or_default("TEST_POS_ENV_POS", 30);
    assert_eq!(v, 60);
    env::remove_var("TEST_POS_ENV_POS");
}

#[test]
fn test_get_env_with_existing_var() {
    let _g = env_lock();
    env::set_var("TEST_CONFIG_VAR_1", "test_value");
    assert_eq!(get_env("TEST_CONFIG_VAR_1", "default"), "test_value");
    env::remove_var("TEST_CONFIG_VAR_1");
}

#[test]
fn test_get_env_with_missing_var() {
    let _g = env_lock();
    env::remove_var("TEST_CONFIG_VAR_NONEXISTENT_12345");
    assert_eq!(
        get_env("TEST_CONFIG_VAR_NONEXISTENT_12345", "default_value"),
        "default_value"
    );
}

// MCP-615 (2026-05-12): empty-string env var must use the default
// (not return ""). Helm `values.yaml` placeholders routinely produce
// `KEY=""`; pre-fix `get_env` returned the empty string and shadowed
// every downstream default. Single dedicated probe var keeps the
// test from racing other tests in the same process.
#[test]
fn test_get_env_empty_string_falls_back_to_default() {
    let _g = env_lock();
    env::set_var("TEST_CONFIG_MCP_615_PROBE", "");
    assert_eq!(
        get_env("TEST_CONFIG_MCP_615_PROBE", "fallback_default"),
        "fallback_default",
        "empty env var must use the default (MCP-615)"
    );
    env::remove_var("TEST_CONFIG_MCP_615_PROBE");
}

/// MCP-1060: canonical truthy tokens.
#[test]
fn bool_env_is_three_valued() {
    // package AN: the ONE boolean vocabulary; Some/Some/None, never a default.
    let _g = env_lock();
    for v in ["true", "1", "yes", "on", " ON ", "Yes"] {
        env::set_var("AEGIX_TEST_BOOL_ENV", v);
        assert_eq!(bool_env("AEGIX_TEST_BOOL_ENV"), Some(true), "{v:?}");
    }
    for v in ["false", "0", "no", "off", "OFF"] {
        env::set_var("AEGIX_TEST_BOOL_ENV", v);
        assert_eq!(bool_env("AEGIX_TEST_BOOL_ENV"), Some(false), "{v:?}");
    }
    for v in ["", "   ", "enable", "2"] {
        env::set_var("AEGIX_TEST_BOOL_ENV", v);
        assert_eq!(bool_env("AEGIX_TEST_BOOL_ENV"), None, "{v:?}");
    }
    env::remove_var("AEGIX_TEST_BOOL_ENV");
    assert_eq!(bool_env("AEGIX_TEST_BOOL_ENV"), None);
    // and the defaulting wrapper is exactly `unwrap_or(default)` over it
    assert!(bool_env_or_default("AEGIX_TEST_BOOL_ENV", true));
    assert!(!bool_env_or_default("AEGIX_TEST_BOOL_ENV", false));
}

#[test]
fn test_bool_env_truthy_tokens() {
    let _g = env_lock();
    for v in &[
        "true", "TRUE", "True", "1", "yes", "YES", "on", "ON", "  on  ",
    ] {
        env::set_var("TEST_BOOL_ENV", v);
        assert!(
            bool_env_or_default("TEST_BOOL_ENV", false),
            "expected truthy: {:?}",
            v
        );
    }
    env::remove_var("TEST_BOOL_ENV");
}

/// MCP-1060: canonical falsy tokens.
#[test]
fn test_bool_env_falsy_tokens() {
    let _g = env_lock();
    for v in &["false", "FALSE", "0", "no", "NO", "off", "OFF", "  off  "] {
        env::set_var("TEST_BOOL_ENV2", v);
        assert!(
            !bool_env_or_default("TEST_BOOL_ENV2", true),
            "expected falsy: {:?}",
            v
        );
    }
    env::remove_var("TEST_BOOL_ENV2");
}

/// MCP-1060: unset returns default in both directions.
#[test]
fn test_bool_env_unset_returns_default() {
    let _g = env_lock();
    env::remove_var("TEST_BOOL_ENV_UNSET_55555");
    assert!(bool_env_or_default("TEST_BOOL_ENV_UNSET_55555", true));
    assert!(!bool_env_or_default("TEST_BOOL_ENV_UNSET_55555", false));
}

/// MCP-1060: empty string treated as unset (same shape as
/// `get_env`'s MCP-615 fix — Helm placeholders set the var to `""`).
#[test]
fn test_bool_env_empty_returns_default() {
    let _g = env_lock();
    env::set_var("TEST_BOOL_ENV_EMPTY", "");
    assert!(bool_env_or_default("TEST_BOOL_ENV_EMPTY", true));
    assert!(!bool_env_or_default("TEST_BOOL_ENV_EMPTY", false));
    env::set_var("TEST_BOOL_ENV_EMPTY", "   ");
    assert!(bool_env_or_default("TEST_BOOL_ENV_EMPTY", true));
    assert!(!bool_env_or_default("TEST_BOOL_ENV_EMPTY", false));
    env::remove_var("TEST_BOOL_ENV_EMPTY");
}

/// MCP-1060: unrecognised values WARN + use default (not silently truthy).
#[test]
fn test_bool_env_unrecognised_returns_default() {
    let _g = env_lock();
    env::set_var("TEST_BOOL_ENV_GARBAGE", "enable");
    assert!(bool_env_or_default("TEST_BOOL_ENV_GARBAGE", true));
    assert!(!bool_env_or_default("TEST_BOOL_ENV_GARBAGE", false));
    env::set_var("TEST_BOOL_ENV_GARBAGE", "yarp");
    assert!(bool_env_or_default("TEST_BOOL_ENV_GARBAGE", true));
    assert!(!bool_env_or_default("TEST_BOOL_ENV_GARBAGE", false));
    env::remove_var("TEST_BOOL_ENV_GARBAGE");
}

/// The compile switch: unset is ON, a boolean token is honoured, and a
/// value that is not a boolean token is an error the boot validator
/// reports — never the default. A typo must not leave compiling on.
#[test]
fn the_compile_switch_does_not_fold_an_unreadable_value_into_the_default() {
    use crate::{module_compilation_from, parse_bool_env, BoolEnv};
    assert_eq!(module_compilation_from(BoolEnv::Unset), Ok(true));
    assert_eq!(module_compilation_from(parse_bool_env("")), Ok(true));
    assert_eq!(module_compilation_from(parse_bool_env("  ")), Ok(true));
    for on in ["true", "1", "yes", "on", " TRUE "] {
        assert_eq!(
            module_compilation_from(parse_bool_env(on)),
            Ok(true),
            "{on:?}"
        );
    }
    for off in ["false", "0", "no", "off", "Off"] {
        assert_eq!(
            module_compilation_from(parse_bool_env(off)),
            Ok(false),
            "{off:?}"
        );
    }
    for typo in ["disabled", "none", "fales", "registry-only"] {
        assert_eq!(
            module_compilation_from(parse_bool_env(typo)),
            Err(typo.to_string()),
            "{typo:?}"
        );
    }
}
