//! A binary's build identity: the commit it was built from, whether the tree
//! was dirty, and when it was built. One home for the controller, the worker
//! and the MCP handlers, which until 2026-10-21 each carried a copy of the
//! same `build.rs`.
//!
//! # Why there is no build script
//!
//! A `build.rs` that watches `.git/HEAD` and `.git/index` re-runs on every
//! `git add`, `commit`, `checkout`, `stash` and even `status`, and cargo then
//! recompiles the crate that owns it AND every crate above it — a dependent is
//! marked dirty because "the dependency was rebuilt", whether or not the
//! script's output changed (measured 2026-10-21 on a two-crate toy workspace,
//! and on this one: `touch .git/index` cost a 151 s recompile of
//! `aegix-mcp-handlers` and the controller, then 199 s more on the next
//! `cargo check --workspace`). Moving the script into a leaf crate does not
//! help: the leaf's dependents rebuild all the same. So nothing here watches
//! `.git`, and the identity is derived two ways:
//!
//! * **Baked at compile time from `GIT_SHA_OVERRIDE` / `GIT_DIRTY_OVERRIDE`**
//!   when they are set — `option_env!`, which rustc records in the crate's
//!   dep-info so the (tiny) leaf recompiles only when the VALUE changes. The
//!   Dockerfiles set both from build args (`.git` is not in the build
//!   context), so an image is stamped exactly as it was before; `make`
//!   recipes that build images set them inline for `docker compose`.
//! * **Asked of `git` at run time** otherwise — a binary run from a checkout
//!   reports that checkout's `HEAD` and status. Nothing in a plain `cargo`
//!   build reads the variables, so a local build never recompiles for a git
//!   operation.
//!
//! The dirty flag is baked from the variable verbatim when set (an image built
//! with `GIT_DIRTY_OVERRIDE=false` is clean whatever the builder's tree was),
//! and otherwise asked of `git status --porcelain`.
//!
//! The build TIME is not stamped at all: a stamp that changes on every build
//! forces a recompile by itself. [`built_at_rfc3339`] reads the modification
//! time of the running executable instead, which is when it was linked —
//! `COPY --from=builder` keeps it, so an image reports its build time too.
//!
//! # Stated limits
//!
//! A binary run from a checkout reports the checkout's commit, not the commit
//! it was built from: build, commit, run the old binary, and it names the new
//! commit. Images (every deployment, and `make up`) are exact. The
//! controller↔worker build-skew diagnostic compares the two sides' strings, so
//! both must compose them through [`build_version`]; a bare-`cargo` controller
//! and worker in one checkout always agree.

use std::process::Command;
use std::sync::OnceLock;

/// The commit stamped into this crate at compile time, if the build was told
/// one. `unknown` and the empty string count as "not told", as the build
/// script treated them.
const BAKED_GIT_SHA: Option<&str> = option_env!("GIT_SHA_OVERRIDE");

/// The dirty flag stamped at compile time, verbatim, if the build was told one.
const BAKED_GIT_DIRTY: Option<&str> = option_env!("GIT_DIRTY_OVERRIDE");

/// The sha reported when neither the build nor `git` can name one.
pub const UNKNOWN_SHA: &str = "unknown";

/// What a binary knows about its own build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildIdentity {
    /// Short (7-character) commit sha, or [`UNKNOWN_SHA`].
    pub git_sha: String,
    /// Whether the working tree had uncommitted changes.
    pub git_dirty: bool,
}

impl BuildIdentity {
    /// `{pkg_version}+{sha}{-dirty?}` — the ONE composition every surface
    /// reports (`session_start.server_version`, `get_platform_info`, the
    /// controller's registration handshake, the worker's self-registration).
    /// The skew diagnostic compares the `+sha[-dirty]` suffix, so a second
    /// spelling anywhere would make a healthy fleet look split.
    #[must_use]
    pub fn version_string(&self, pkg_version: &str) -> String {
        format!(
            "{}+{}{}",
            pkg_version,
            self.git_sha,
            if self.git_dirty { "-dirty" } else { "" }
        )
    }
}

/// This process's build identity, derived once and kept.
pub fn identity() -> &'static BuildIdentity {
    static IDENTITY: OnceLock<BuildIdentity> = OnceLock::new();
    IDENTITY.get_or_init(|| derive_identity(BAKED_GIT_SHA, BAKED_GIT_DIRTY))
}

/// `{pkg_version}+{sha}{-dirty?}` for this process. Pass the CALLER's
/// `env!("CARGO_PKG_VERSION")`: the controller is versioned `1.0.0-rN`, the
/// others take the workspace version, and only the suffix is ever compared.
#[must_use]
pub fn build_version(pkg_version: &str) -> String {
    identity().version_string(pkg_version)
}

/// When this executable was built, as an RFC 3339 UTC timestamp: the
/// modification time of the running binary, which is when it was linked.
/// `None` when the executable or its metadata cannot be read.
pub fn built_at_rfc3339() -> Option<&'static str> {
    static BUILT_AT: OnceLock<Option<String>> = OnceLock::new();
    BUILT_AT
        .get_or_init(|| {
            let modified = std::fs::metadata(std::env::current_exe().ok()?)
                .ok()?
                .modified()
                .ok()?;
            let secs = modified
                .duration_since(std::time::UNIX_EPOCH)
                .ok()?
                .as_secs();
            Some(rfc3339_utc(secs))
        })
        .as_deref()
}

/// The precedence the deleted build scripts applied: a baked sha that is not
/// empty and not `unknown` wins, then `git`, then [`UNKNOWN_SHA`]; a baked
/// dirty flag is taken verbatim (`"true"` and nothing else is dirty), else
/// `git status`, else clean.
fn derive_identity(baked_sha: Option<&str>, baked_dirty: Option<&str>) -> BuildIdentity {
    let git_sha = baked_sha
        .map(str::trim)
        .filter(|s| !s.is_empty() && *s != UNKNOWN_SHA)
        .map(str::to_string)
        .or_else(|| git(&["rev-parse", "--short=7", "HEAD"]).filter(|s| !s.is_empty()))
        .unwrap_or_else(|| UNKNOWN_SHA.to_string());
    let git_dirty = match baked_dirty {
        Some(flag) => flag.trim() == "true",
        None => git(&["status", "--porcelain"]).is_some_and(|out| !out.is_empty()),
    };
    BuildIdentity { git_sha, git_dirty }
}

/// Run `git` in the process's working directory and return its trimmed
/// stdout, or `None` when git is absent, fails, or this is not a checkout.
/// `GIT_OPTIONAL_LOCKS=0` keeps `git status` from rewriting the index as a
/// side effect of being asked.
fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// `YYYY-MM-DDTHH:MM:SSZ` from seconds since the Unix epoch, with no date
/// dependency (this crate has none).
fn rfc3339_utc(secs: u64) -> String {
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, mo, d) = civil_from_days(days as i64);
    format!(
        "{y:04}-{mo:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60
    )
}

/// Howard Hinnant's `civil_from_days`
/// (<http://howardhinnant.github.io/date_algorithms.html#civil_from_days>).
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_is_the_one_composition() {
        let clean = BuildIdentity {
            git_sha: "abc1234".into(),
            git_dirty: false,
        };
        assert_eq!(clean.version_string("1.0.0-r306"), "1.0.0-r306+abc1234");
        let dirty = BuildIdentity {
            git_sha: "abc1234".into(),
            git_dirty: true,
        };
        assert_eq!(dirty.version_string("0.1.0"), "0.1.0+abc1234-dirty");
    }

    #[test]
    fn a_baked_sha_wins_and_unknown_or_empty_does_not_count() {
        let baked = derive_identity(Some("deadbee"), Some("false"));
        assert_eq!(baked.git_sha, "deadbee");
        assert!(!baked.git_dirty);
        // `unknown` and "" fall through to git, or to UNKNOWN_SHA where no
        // repository is around the tree (a source archive, the public tree
        // before it is committed anywhere). Where git answers, what was
        // passed is never what is reported.
        let in_a_checkout =
            git(&["rev-parse", "--short=7", "HEAD"]).is_some_and(|sha| !sha.is_empty());
        for told in ["unknown", "", "  "] {
            let id = derive_identity(Some(told), Some("false"));
            if in_a_checkout || told != UNKNOWN_SHA {
                assert_ne!(id.git_sha, told, "{told:?} must not be reported as-is");
            }
            assert!(
                id.git_sha == UNKNOWN_SHA || id.git_sha.len() == 7,
                "fell through to git or unknown, got {:?}",
                id.git_sha
            );
        }
    }

    #[test]
    fn a_baked_dirty_flag_is_taken_verbatim() {
        assert!(derive_identity(Some("abc1234"), Some("true")).git_dirty);
        for not_dirty in ["false", "", "TRUE", "yes", "1"] {
            assert!(
                !derive_identity(Some("abc1234"), Some(not_dirty)).git_dirty,
                "{not_dirty:?} is not the spelling `true`"
            );
        }
    }

    #[test]
    fn the_image_defaults_report_unknown_or_the_checkout() {
        // The Dockerfiles default the args to `unknown` / `false`; a build
        // that was not told a sha and has no checkout reports UNKNOWN_SHA.
        let id = derive_identity(Some("unknown"), Some("false"));
        assert!(id.git_sha == UNKNOWN_SHA || id.git_sha.len() == 7);
        assert!(!id.git_dirty);
    }

    #[test]
    fn rfc3339_formatting_matches_known_instants() {
        assert_eq!(rfc3339_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(rfc3339_utc(1_700_000_000), "2023-11-14T22:13:20Z");
        assert_eq!(rfc3339_utc(1_792_540_800), "2026-10-21T00:00:00Z");
    }

    #[test]
    fn built_at_is_a_parseable_timestamp_for_this_test_binary() {
        let built = built_at_rfc3339().expect("the test binary's own mtime is readable");
        assert_eq!(built.len(), "2026-10-21T00:00:00Z".len());
        assert!(built.ends_with('Z'));
        assert_eq!(&built[4..5], "-");
        assert_eq!(&built[10..11], "T");
    }

    #[test]
    fn identity_is_derived_once() {
        assert!(std::ptr::eq(identity(), identity()));
    }
}
