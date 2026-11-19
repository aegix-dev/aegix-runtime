//! What kind of deployment this process is in, and how its settings are read.
//!
//! Every binary of the runtime asks the same few questions before it does
//! anything else: is this production, which security profile holds, may the
//! fleet's shared key still be accepted, must a data call name its dispatch,
//! is a setting left under a name nothing reads any more. And every one reads
//! a boolean or a number out of the environment by the same rules, so that an
//! empty value, an unrecognised spelling or a zero is never taken for an
//! answer. This crate is those questions and those readers.
//!
//! It was cut out of `aegix-config` on 2026-11-18. That crate is the
//! platform's settings (memory, retention, the catalog registry, the addresses
//! a controller serves and links to) and re-exports every item here at the
//! path it had. A crate below the runtime boundary depends on this crate and
//! never on the platform's settings.

pub mod dispatch_binding;
pub mod envelope_sealing;
pub mod fleet_identity;
pub mod legacy_env;
pub mod process_posture;
pub mod security_profile;

use std::env;

/// Read an env var, returning `default` when the var is unset OR set to
/// an empty string.
///
/// MCP-615 (2026-05-12): pre-fix the helper used
/// `env::var(var).unwrap_or_else(|_| default.to_string())` which returns
/// `""` (not the default) when the operator sets the var to an empty
/// string. Helm `values.yaml` placeholders (`rustEnv: ""`,
/// `executionRetentionDays: ""`) routinely produce this shape and
/// silently shadowed every downstream default — same empty-env-var
/// class as MCP-590/591/597/598/599/611. Same fix shape:
/// `.ok().filter(|v| !v.is_empty()).unwrap_or_else(|| default.to_string())`.
///
/// Callers that need to distinguish "unset" from "empty value" should
/// reach for `env::var` directly. Most config-style helpers want
/// "use the default when no value is provided," for which this is the
/// correct shape.
pub fn get_env(var: &str, default: &str) -> String {
    env::var(var)
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| default.to_string())
}

/// Returns true iff `var` is set AND its value is non-empty.
///
/// **This is the one correct way to ask "is this env var configured?"**
/// `std::env::var(var).is_ok()` is NOT: it returns `true` for `Ok("")`, so a
/// Helm `values.yaml` placeholder (`talosMasterKey: ""`) or a shell
/// `export FOO=` reads as "configured" while every downstream consumer in
/// this workspace treats an empty value as absent — [`get_env`] falls through
/// to its default, and the platform's file-backed reader falls through to
/// `<VAR>_FILE`.
///
/// The class has been repaired eleven times under distinct ticket numbers
/// (MCP-590/591/592/597/598/599/611/615/620/621/625) and kept coming back
/// because every fix was local to one call site. MCP-625 is the canonical
/// writeup: four `security_audit` key checks reported "AEGIX_MASTER_KEY is
/// configured" and awarded +15 points while `kek_provider` refused to load
/// the empty key — "operators saw a green dashboard while critical security
/// primitives were disabled". Structural lint check 73 now fails the build on
/// the bad shape and points here.
///
/// Note the asymmetry this helper deliberately preserves: it answers
/// "configured?", NOT "present?". Code that genuinely needs to distinguish an
/// empty value from an unset one must call `env::var` directly and say why.
pub fn env_var_is_set_nonempty(var: &str) -> bool {
    env::var(var).ok().filter(|v| !v.is_empty()).is_some()
}

pub fn is_production() -> bool {
    get_env("RUST_ENV", "development") == "production"
}

pub fn is_development() -> bool {
    !is_production()
}

/// Whether this deployment builds modules from source. **Default ON.**
///
/// Set `AEGIX_MODULE_COMPILATION=false|0|no|off` for a registry-only
/// deployment: the controller then never runs a toolchain over module
/// source — no compile, no lint, no source analysis — and every module it
/// runs comes from the OCI registry (`AEGIX_REGISTRY_URL`, which the boot
/// validator requires in this mode).
///
/// `Err` carries the raw value when the variable is set to something that
/// is not a boolean token. This switch turns a capability off, so an
/// unreadable value is not folded into the default the way [`bool_env`]
/// folds one: the boot validator refuses to start on it, and
/// [`module_compilation_enabled`] reads it as OFF.
pub fn module_compilation() -> Result<bool, String> {
    module_compilation_from(read_bool_env(MODULE_COMPILATION_ENV))
}

/// [`module_compilation`] as a pure function of the value read.
pub fn module_compilation_from(read: BoolEnv) -> Result<bool, String> {
    match read {
        BoolEnv::Unset => Ok(true),
        BoolEnv::Value(v) => Ok(v),
        BoolEnv::Unreadable(raw) => Err(raw),
    }
}

/// [`module_compilation`] for a caller that must act: an unreadable value
/// is OFF (fail closed — the operator set the switch and it cannot be read).
pub fn module_compilation_enabled() -> bool {
    module_compilation().unwrap_or(false)
}

/// The env var behind [`module_compilation`]. Declared after its readers:
/// the configuration-reference lint attributes a variable to the `pub fn`
/// above its literal, and a reader is what vouches for the row.
pub const MODULE_COMPILATION_ENV: &str = "AEGIX_MODULE_COMPILATION";

/// MCP-1060 (2026-05-15): read a boolean env var with a canonical set
/// of truthy / falsy tokens. Accepts `true | 1 | yes | on` (truthy) and
/// `false | 0 | no | off` (falsy), case-insensitive, leading/trailing
/// whitespace tolerant. Unset, empty, or unrecognised → `default`.
///
/// Pre-1060 three sites had inline copies of the same predicate:
/// `aegix-auth::verify_token` (`JWT_REQUIRE_AUD`),
/// `talos-workflow-signing::strict_mode` (`AEGIX_WORKFLOW_SIGNING_STRICT`),
/// `worker::host_impl::ALLOW_PRIVATE_HOST_TARGETS`. Slight predicate
/// drift across them: the worker accepted `"on"`, the other two didn't.
/// The auth site is the per-request hot path — `verify_token` is called
/// on every authenticated request, and the inline `env::var` read takes
/// the process-wide environ lock + allocates a String each time.
/// Operators routing through this helper PLUS wrapping in `LazyLock`
/// remove the per-request env-read entirely.
///
/// Unrecognised values (`=foo`, `=enable`, etc.) WARN with
/// `event_kind=env_bool_unrecognised_substituted` so misconfiguration
/// is visible without flipping behaviour silently.
///
/// Sibling of `positive_env_or_default` (MCP-643).
/// Three-valued boolean env read (2026-09-12, package AN): `Some(true)` for
/// `true | 1 | yes | on`, `Some(false)` for `false | 0 | no | off`
/// (case-insensitive, whitespace-tolerant), `None` when unset, empty or
/// unrecognised — the unrecognised case WARNs exactly as
/// [`bool_env_or_default`] does. Use this where "unset" has its own meaning
/// (`AEGIX_REPLAY_FAIL_CLOSED` / `AEGIX_COMPILATION_CONTAINER`: unset ⇒
/// `is_production()`); use `bool_env_or_default` for a plain default.
///
/// This is the ONE boolean-token vocabulary for the workspace (check 90):
/// before it, 23 sites parsed their variable inline against sets ranging
/// from a lone `"1"` to eight spellings, and two variables were parsed by
/// TWO readers that disagreed — `ENABLE_EDGE_ROUTING` (`== "true"` in the
/// engine dispatcher, the full set in `edge_routing_enabled()` used by the
/// Gmail push) and `WORKER_ALLOW_PRIVATE_HOST_TARGETS` (`== "1"` in the SSRF
/// resolver, the full set in the host limits) — so one env value could turn a
/// control on at one layer and leave it off at the other.
pub fn bool_env(var: &str) -> Option<bool> {
    match read_bool_env(var) {
        BoolEnv::Unset => None,
        BoolEnv::Value(v) => Some(v),
        BoolEnv::Unreadable(raw) => {
            tracing::warn!(
                target: "aegix_config",
                event_kind = "env_bool_unrecognised_substituted",
                var = var,
                configured = %raw,
                "{var}={raw:?} is not a recognised boolean token; treating it as unset"
            );
            None
        }
    }
}

/// What a boolean env var says, with the unreadable case kept apart from
/// the unset one. [`bool_env`] folds `Unreadable` into "unset" (and WARNs),
/// which is right for a tuning flag and wrong for a switch that turns a
/// capability OFF: there a typo must not leave the capability on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoolEnv {
    /// Unset, or set to an empty / whitespace-only string.
    Unset,
    /// One of the tokens [`bool_env`] documents.
    Value(bool),
    /// Set to something that is not a boolean token (the raw value).
    Unreadable(String),
}

/// Read `var` against the one boolean-token vocabulary without deciding
/// what an unreadable value means.
pub fn read_bool_env(var: &str) -> BoolEnv {
    match env::var(var) {
        Ok(raw) => parse_bool_env(&raw),
        Err(_) => BoolEnv::Unset,
    }
}

/// The token vocabulary itself, as a pure function of the raw value.
pub fn parse_bool_env(raw: &str) -> BoolEnv {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return BoolEnv::Unset;
    }
    match trimmed.to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => BoolEnv::Value(true),
        "false" | "0" | "no" | "off" => BoolEnv::Value(false),
        _ => BoolEnv::Unreadable(raw.to_string()),
    }
}

pub fn bool_env_or_default(var: &str, default: bool) -> bool {
    bool_env(var).unwrap_or(default)
}

/// MCP-643 (2026-05-13): read a positive-integer env var, treating
/// missing, invalid, AND `=0` as "use default". Many retention /
/// cleanup / cap config envs in the controller (ARCHIVE_AFTER_DAYS,
/// AUDIT_LOG_RETENTION_DAYS, WASM_CACHE_*) have a destructive failure
/// mode when set to 0 — `retention_days=0` deletes every row older
/// than now (i.e., everything), `max_size_mb=0` evicts every cached
/// entry on the next sweep, etc.
///
/// Operators typically intend `=0` to mean "unlimited" / "disabled"
/// (common UNIX convention) but the SQL `< NOW() - interval '0 days'`
/// or `> 0 modules` cap gives the opposite. Substitute the default +
/// WARN so misconfiguration is visible without producing silent data
/// loss. Sibling to MCP-639 / MCP-640 / MCP-642 (worker / reporter
/// equivalents).
///
/// Generic over `T: FromStr + PartialOrd + Display + Copy` so callers
/// can use `i32`, `i64`, `u64`, etc. The `> zero` check uses
/// `T::default()` which is 0 for all primitive integers.
pub fn positive_env_or_default<T>(var: &str, default: T) -> T
where
    T: std::str::FromStr + std::fmt::Display + Default + PartialOrd + Copy,
{
    let parsed = env::var(var).ok().and_then(|v| v.parse::<T>().ok());
    match parsed {
        Some(n) if n > T::default() => n,
        Some(n) => {
            tracing::warn!(
                target: "aegix_config",
                event_kind = "env_nonpositive_substituted",
                var = var,
                configured = %n,
                default = %default,
                "{var}={n} is a misconfiguration (would produce destructive zero/negative behaviour); using default {default}"
            );
            default
        }
        None => default,
    }
}

#[cfg(test)]
#[path = "posture_tests.rs"]
mod tests;
