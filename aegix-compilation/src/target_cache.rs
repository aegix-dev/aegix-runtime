//! Per-user persistent `CARGO_TARGET_DIR` cache for runtime WASM compiles.
//!
//! Every `compile_to_wasm*` call builds in a fresh throwaway workspace, so
//! without a persistent target dir cargo recompiles the entire dependency
//! graph (serde, chrono, wit-bindgen, …) on every call — the dominant cost
//! of the 15-30 s compile cycle. Dependencies are identical across compiles
//! (fixed allowlist + read-only registry snapshot), so a persistent target
//! dir turns the second and later compiles into "recompile the user's
//! lib.rs only" (~2-3 s).
//!
//! # Security invariant: the cache is scoped PER USER, never shared
//!
//! The build sandbox runs user-supplied Rust (proc-macros execute at build
//! time) with the target dir mounted read-write. Cargo's fingerprint
//! checks are freshness checks, not integrity checks — a hostile build can
//! overwrite any cached `.rlib`/`.rmeta` in the mounted dir, and a later
//! build that trusts those artifacts links the poisoned bytes into its
//! WASM. A fleet-shared cache would therefore let tenant A inject code
//! into tenant B's modules. Keying the cache by the requesting `user_id`
//! bounds poisoning to the attacker's own modules — exactly the trust they
//! already have over their own source. Do not "optimise" this into a
//! shared cache.
//!
//! # Layout, lifecycle
//!
//! `{root}/{user_id}/` — root defaults to `/tmp/cargo-target/per-user`
//! (under the same mount the controller image already persists across
//! container restarts in compose; pod-lifetime tmpfs on k8s). Each use
//! touches `{dir}/.last_used`; a rate-limited opportunistic sweep removes
//! user dirs idle past the TTL so the cache can't grow with
//! distinct-users-ever-seen (the keyed-cache sweep rule).
//!
//! Env knobs:
//! * `AEGIX_COMPILE_TARGET_CACHE` — `0|false|no|off` disables (default on).
//! * `AEGIX_COMPILE_TARGET_CACHE_DIR` — cache root override.
//! * `AEGIX_COMPILE_TARGET_CACHE_TTL_HOURS` — idle eviction TTL
//!   (default 168 = 7 days; `0` = never sweep).
//! * `AEGIX_COMPILE_TARGET_CACHE_MAX_MB` — size past which a user's cache
//!   is dropped whole by the sweep (default 2048).
//!
//! # Growth
//!
//! Idle eviction alone bounds the number of user dirs, not the size of an
//! ACTIVE user's. Every compile builds a package whose name carries its job
//! id, so its outputs never overwrite the last compile's and would pile up
//! for as long as the user keeps compiling. Two bounds, then: a compile's
//! own job-named outputs are removed when it ends ([`JobOutputs`]) — the
//! shared dependency artifacts, which are the point of the cache, stay — and
//! the sweep drops any user dir that has still grown past the size cap.
//!
//! The directory is mounted read-write into the build sandbox, so nothing in
//! it is trusted: no walk here follows a symlink, and the marker is written
//! without following one.

use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use uuid::Uuid;

const DEFAULT_ROOT: &str = "/tmp/cargo-target/per-user";
const DEFAULT_TTL_HOURS: u64 = 168;
const LAST_USED_MARKER: &str = ".last_used";
const DEFAULT_MAX_MB: u64 = 2048;
/// Most entries one size measurement visits. A cache holding more is treated
/// as over its cap, so the measurement itself stays cheap.
const MAX_MEASURED_ENTRIES: usize = 200_000;
/// How far below the target dir a job's own outputs can sit:
/// `{triple}/{profile}/{deps|.fingerprint|incremental|build}/{entry}`.
const JOB_OUTPUT_DEPTH: usize = 4;
/// Minimum interval between sweep passes. The sweep is O(number of user
/// dirs) of `readdir` + stat — cheap, but there is no reason to run it on
/// every compile.
const SWEEP_INTERVAL: Duration = Duration::from_secs(3600);

/// On unless explicitly off, through the shared vocabulary
/// (`aegix_config::bool_env`; an unrecognised value WARNs and keeps the
/// default). Package CB: this was a private off-list.
fn cache_enabled() -> bool {
    aegix_config::bool_env_or_default("AEGIX_COMPILE_TARGET_CACHE", true)
}

fn cache_root() -> PathBuf {
    match std::env::var("AEGIX_COMPILE_TARGET_CACHE_DIR") {
        Ok(v) if !v.trim().is_empty() => PathBuf::from(v.trim()),
        _ => PathBuf::from(DEFAULT_ROOT),
    }
}

/// Idle TTL before a user's cache dir is swept. `0` disables sweeping.
fn ttl() -> Duration {
    let hours = std::env::var("AEGIX_COMPILE_TARGET_CACHE_TTL_HOURS")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_TTL_HOURS);
    Duration::from_secs(hours.saturating_mul(3600))
}

/// Size past which the sweep drops a user's cache dir whole.
fn max_bytes() -> u64 {
    aegix_config::positive_env_or_default::<u64>(
        "AEGIX_COMPILE_TARGET_CACHE_MAX_MB",
        DEFAULT_MAX_MB,
    )
    .saturating_mul(1024 * 1024)
}

/// The per-user cache dir. `user_id` is a `Uuid`, so the path component is
/// structurally safe (no separators, no traversal).
fn user_cache_dir(root: &Path, user_id: Uuid) -> PathBuf {
    root.join(user_id.to_string())
}

/// Resolve (and create) the persistent target dir for this user's compile.
/// Returns `None` when the cache is disabled or the dir can't be created —
/// callers fall back to the legacy throwaway `{workspace}/target`, so a
/// cache-infrastructure problem degrades to slow, never to broken.
pub(crate) fn resolve_for(user_id: Uuid) -> Option<PathBuf> {
    // The nil id is not a user: every caller that substitutes it for a
    // missing identity would share ONE cache directory — the fleet-shared
    // cache this module exists to forbid (security review 2026-10-14, G-22).
    // Such a compile runs cold, as `lint_code` with no user already does.
    if user_id.is_nil() || !cache_enabled() {
        return None;
    }
    let root = cache_root();
    let dir = user_cache_dir(&root, user_id);
    if let Err(e) = std::fs::create_dir_all(&dir) {
        tracing::warn!(
            target: "aegix_compilation",
            event_kind = "target_cache_unavailable",
            error = %e,
            dir = %dir.display(),
            "could not create per-user target cache dir — compiling cold"
        );
        return None;
    }
    // Touch the marker so the sweep sees this user as active. Recreating
    // the file updates its mtime; failure only risks early eviction.
    touch_marker(&dir);
    maybe_sweep(&root);
    Some(dir)
}

/// Recreate the marker without following a symlink. The build sandbox can
/// write this directory, so a plain `fs::write` here would truncate whatever
/// a planted `.last_used` link pointed at, with the controller's authority.
/// Removing the name first and creating it exclusively means the write lands
/// on a new regular file or not at all.
fn touch_marker(dir: &Path) {
    let marker = dir.join(LAST_USED_MARKER);
    let _ = std::fs::remove_file(&marker);
    let _ = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker);
}

/// Bytes held under `dir`, or `None` once that passes `stop_above` or the walk
/// passes [`MAX_MEASURED_ENTRIES`]. Symlinks are counted as entries and never
/// followed; an unreadable directory counts as empty.
fn dir_bytes(dir: &Path, stop_above: u64) -> Option<u64> {
    let mut total: u64 = 0;
    let mut entries = 0usize;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&d) else {
            continue;
        };
        for entry in read.flatten() {
            entries += 1;
            if entries > MAX_MEASURED_ENTRIES {
                return None;
            }
            let Ok(meta) = entry.path().symlink_metadata() else {
                continue;
            };
            if meta.is_dir() {
                stack.push(entry.path());
            } else {
                total = total.saturating_add(meta.len());
                if total > stop_above {
                    return None;
                }
            }
        }
    }
    Some(total)
}

/// Whether a target-dir entry named `file_name` belongs to the package
/// `stem` (its name with `-` or with `_`): `stem.wasm`, `stem.d`,
/// `libstem.rlib`, `stem-<hash>…`. The stem ends in the job's id, so nothing
/// but that job's outputs can match.
fn is_job_output(file_name: &str, stems: &[String; 2]) -> bool {
    let name = file_name.strip_prefix("lib").unwrap_or(file_name);
    stems.iter().any(|stem| {
        name.strip_prefix(stem.as_str())
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(['-', '.']))
    })
}

/// Remove everything under `target_dir` that the package `package_name`
/// produced, leaving other packages' (the shared dependencies') artifacts in
/// place. Returns how many entries were removed. Never follows a symlink: a
/// link is removed as a link, and only real directories are descended into.
pub(crate) fn remove_job_outputs(target_dir: &Path, package_name: &str) -> usize {
    if package_name.is_empty() {
        return 0;
    }
    let stems = [package_name.to_string(), package_name.replace('-', "_")];
    let mut removed = 0;
    let mut stack = vec![(target_dir.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in read.flatten() {
            let path = entry.path();
            let Ok(meta) = path.symlink_metadata() else {
                continue;
            };
            let is_dir = meta.is_dir();
            if is_job_output(&entry.file_name().to_string_lossy(), &stems) {
                let gone = if is_dir {
                    std::fs::remove_dir_all(&path)
                } else {
                    std::fs::remove_file(&path)
                };
                removed += usize::from(gone.is_ok());
            } else if is_dir && depth + 1 < JOB_OUTPUT_DEPTH {
                stack.push((path, depth + 1));
            }
        }
    }
    removed
}

/// One compile's claim on the per-user cache: when dropped, that compile's
/// job-named outputs are removed from it. A guard, so every way out of the
/// compile — success, a failed build, a timeout dropping the future — cleans
/// up. Does nothing when the compile ran without the cache.
pub(crate) struct JobOutputs {
    target: Option<(PathBuf, String)>,
}

impl JobOutputs {
    pub(crate) fn new(target_dir: Option<PathBuf>, package_name: &str) -> Self {
        Self {
            target: target_dir.map(|dir| (dir, package_name.to_string())),
        }
    }
}

impl Drop for JobOutputs {
    fn drop(&mut self) {
        let Some((dir, package)) = self.target.take() else {
            return;
        };
        let clean = move || {
            remove_job_outputs(&dir, &package);
        };
        // Directory walks stay off the async executor when there is one.
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => drop(handle.spawn_blocking(clean)),
            Err(_) => clean(),
        }
    }
}

/// Rate-limited opportunistic sweep (at most one pass per
/// [`SWEEP_INTERVAL`] per process; concurrent compiles skip via
/// `try_lock` instead of queueing).
fn maybe_sweep(root: &Path) {
    use std::sync::{Mutex, OnceLock};
    static LAST_SWEEP: OnceLock<Mutex<Option<std::time::Instant>>> = OnceLock::new();
    let last = LAST_SWEEP.get_or_init(|| Mutex::new(None));
    let Ok(mut guard) = last.try_lock() else {
        return;
    };
    if guard.map(|t| t.elapsed() < SWEEP_INTERVAL).unwrap_or(false) {
        return;
    }
    *guard = Some(std::time::Instant::now());
    let ttl = ttl();
    let removed = if ttl.is_zero() {
        0
    } else {
        sweep_stale(root, ttl, SystemTime::now())
    };
    let oversized = sweep_oversized(root, max_bytes());
    if removed > 0 || oversized > 0 {
        tracing::info!(
            target: "aegix_compilation",
            event_kind = "target_cache_swept",
            removed,
            oversized,
            "evicted idle or oversized per-user compile target caches"
        );
    }
}

/// Remove user cache dirs holding more than `max` bytes. A dir is dropped
/// whole — the next compile rebuilds its dependencies once — because the
/// cache has no notion of which artifacts are still wanted.
fn sweep_oversized(root: &Path, max: u64) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        let is_real_dir = path.symlink_metadata().map(|m| m.is_dir()).unwrap_or(false);
        if is_real_dir && dir_bytes(&path, max).is_none() && std::fs::remove_dir_all(&path).is_ok()
        {
            removed += 1;
        }
    }
    removed
}

/// Remove user cache dirs whose `.last_used` marker (dir mtime as
/// fallback) is older than `ttl` relative to `now`. Split out with `now`
/// as a parameter so eviction logic is unit-testable without mutating
/// filesystem timestamps.
fn sweep_stale(root: &Path, ttl: Duration, now: SystemTime) -> usize {
    let Ok(entries) = std::fs::read_dir(root) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.symlink_metadata().map(|m| m.is_dir()).unwrap_or(false) {
            continue;
        }
        let last_used = std::fs::symlink_metadata(path.join(LAST_USED_MARKER))
            .and_then(|m| m.modified())
            .or_else(|_| std::fs::symlink_metadata(&path).and_then(|m| m.modified()));
        let stale = match last_used {
            Ok(t) => now.duration_since(t).map(|age| age > ttl).unwrap_or(false),
            // Unreadable metadata: leave it alone rather than guess.
            Err(_) => false,
        };
        if stale && std::fs::remove_dir_all(&path).is_ok() {
            removed += 1;
        }
    }
    removed
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_nil_user_gets_no_shared_cache() {
        assert_eq!(resolve_for(Uuid::nil()), None);
    }

    #[test]
    fn user_dir_is_uuid_keyed_under_root() {
        let id = Uuid::nil();
        let dir = user_cache_dir(Path::new("/cache"), id);
        assert_eq!(
            dir,
            PathBuf::from("/cache/00000000-0000-0000-0000-000000000000")
        );
    }

    #[test]
    fn sweep_removes_only_dirs_past_ttl() {
        let root = tempfile::tempdir().expect("tempdir");
        let stale = root.path().join(Uuid::new_v4().to_string());
        let fresh = root.path().join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::create_dir_all(&fresh).unwrap();
        std::fs::write(stale.join(LAST_USED_MARKER), b"").unwrap();
        std::fs::write(fresh.join(LAST_USED_MARKER), b"").unwrap();

        let ttl = Duration::from_secs(3600);
        // "now" far in the future relative to the markers just written →
        // both are stale; "now" = now → neither is.
        assert_eq!(sweep_stale(root.path(), ttl, SystemTime::now()), 0);
        assert!(stale.exists() && fresh.exists());

        let future = SystemTime::now() + ttl + Duration::from_secs(60);
        // Give one dir a fresh marker relative to `future` by rewriting it
        // is impossible without mtime control — instead assert the
        // all-stale case, which pins the removal path.
        assert_eq!(sweep_stale(root.path(), ttl, future), 2);
        assert!(!stale.exists() && !fresh.exists());
    }

    #[test]
    fn sweep_ignores_plain_files_in_root() {
        let root = tempfile::tempdir().expect("tempdir");
        std::fs::write(root.path().join("stray-file"), b"x").unwrap();
        let future = SystemTime::now() + Duration::from_secs(999_999);
        assert_eq!(sweep_stale(root.path(), Duration::from_secs(1), future), 0);
        assert!(root.path().join("stray-file").exists());
    }

    #[cfg(unix)]
    #[test]
    fn touching_the_marker_does_not_write_through_a_planted_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        std::fs::write(&victim, b"keep me").unwrap();
        std::os::unix::fs::symlink(&victim, dir.path().join(LAST_USED_MARKER)).unwrap();

        touch_marker(dir.path());

        assert_eq!(std::fs::read(&victim).unwrap(), b"keep me");
        let marker = dir
            .path()
            .join(LAST_USED_MARKER)
            .symlink_metadata()
            .unwrap();
        assert!(
            marker.file_type().is_file(),
            "the marker is a regular file again"
        );
    }

    /// A target dir after one compile of `mod-<job>`: its own outputs in the
    /// places cargo puts them, next to a dependency's.
    fn target_dir_after_compile(package: &str) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let under = package.replace('-', "_");
        let release = dir.path().join("wasm32-wasip2").join("release");
        for sub in ["deps", ".fingerprint", "incremental"] {
            std::fs::create_dir_all(release.join(sub)).unwrap();
        }
        std::fs::write(release.join(format!("{under}.wasm")), b"w").unwrap();
        std::fs::write(release.join(format!("{under}.d")), b"d").unwrap();
        std::fs::write(
            release.join("deps").join(format!("{under}-0a1b.wasm")),
            b"w",
        )
        .unwrap();
        std::fs::write(
            release.join("deps").join(format!("lib{under}-0a1b.rlib")),
            b"r",
        )
        .unwrap();
        std::fs::create_dir_all(release.join(".fingerprint").join(format!("{package}-0a1b")))
            .unwrap();
        std::fs::write(
            release
                .join(".fingerprint")
                .join(format!("{package}-0a1b"))
                .join("dep-lib"),
            b"f",
        )
        .unwrap();
        // The shared dependency the cache exists to keep.
        std::fs::write(release.join("deps").join("libserde-77aa.rlib"), b"serde").unwrap();
        std::fs::create_dir_all(release.join(".fingerprint").join("serde-77aa")).unwrap();
        dir
    }

    #[test]
    fn a_jobs_outputs_are_removed_and_the_dependencies_kept() {
        let package = "mod-0f9a2b3c4d5e6f708192a3b4c5d6e7f8";
        let dir = target_dir_after_compile(package);
        let release = dir.path().join("wasm32-wasip2").join("release");

        assert_eq!(remove_job_outputs(dir.path(), package), 5);

        let left = |sub: &str| {
            let mut names: Vec<String> = std::fs::read_dir(release.join(sub))
                .unwrap()
                .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
                .collect();
            names.sort();
            names
        };
        assert_eq!(left("deps"), ["libserde-77aa.rlib"]);
        assert_eq!(left(".fingerprint"), ["serde-77aa"]);
        assert_eq!(left(""), [".fingerprint", "deps", "incremental"]);
    }

    #[test]
    fn only_the_named_package_matches() {
        let stems = ["mod-abc".to_string(), "mod_abc".to_string()];
        for own in [
            "mod_abc.wasm",
            "mod_abc.d",
            "libmod_abc-1f.rlib",
            "mod-abc-1f",
            "mod_abc",
        ] {
            assert!(is_job_output(own, &stems), "{own}");
        }
        // A longer name that merely starts the same way is another package.
        for other in [
            "mod_abcd.wasm",
            "mod_abc_extra-1f",
            "serde-77aa",
            "libserde-77aa.rlib",
        ] {
            assert!(!is_job_output(other, &stems), "{other}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_removes_a_planted_link_without_touching_its_target() {
        let package = "mod-0f9a";
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("mod_0f9a.wasm"), b"keep").unwrap();
        // A job-named link to a directory, and a link standing in for `deps`.
        std::os::unix::fs::symlink(outside.path(), dir.path().join("mod_0f9a-link")).unwrap();
        std::os::unix::fs::symlink(outside.path(), dir.path().join("deps")).unwrap();

        assert_eq!(remove_job_outputs(dir.path(), package), 1);

        assert!(dir.path().join("mod_0f9a-link").symlink_metadata().is_err());
        assert!(
            outside.path().join("mod_0f9a.wasm").exists(),
            "not descended into"
        );
    }

    #[test]
    fn the_guard_cleans_up_when_dropped_and_is_inert_without_a_cache() {
        let package = "mod-0f9a2b3c4d5e6f708192a3b4c5d6e7f8";
        let dir = target_dir_after_compile(package);
        drop(JobOutputs::new(Some(dir.path().to_path_buf()), package));
        let release = dir.path().join("wasm32-wasip2").join("release");
        assert!(!release
            .join(format!("{}.wasm", package.replace('-', "_")))
            .exists());
        assert!(release.join("deps").join("libserde-77aa.rlib").exists());

        drop(JobOutputs::new(None, package));
    }

    #[test]
    fn a_dir_is_measured_without_following_links_and_stops_at_the_bound() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("a/b")).unwrap();
        std::fs::write(dir.path().join("a/one"), vec![0u8; 1000]).unwrap();
        std::fs::write(dir.path().join("a/b/two"), vec![0u8; 500]).unwrap();
        assert_eq!(dir_bytes(dir.path(), 10_000), Some(1500));
        assert_eq!(dir_bytes(dir.path(), 1499), None);

        #[cfg(unix)]
        {
            let big = tempfile::tempdir().unwrap();
            std::fs::write(big.path().join("huge"), vec![0u8; 50_000]).unwrap();
            std::os::unix::fs::symlink(big.path(), dir.path().join("a/link")).unwrap();
            let measured = dir_bytes(dir.path(), 10_000).expect("the link's target is not counted");
            assert!(measured < 2000, "got {measured}");
        }
    }

    #[test]
    fn the_sweep_drops_only_user_dirs_past_the_size_cap() {
        let root = tempfile::tempdir().unwrap();
        let big = root.path().join(Uuid::new_v4().to_string());
        let small = root.path().join(Uuid::new_v4().to_string());
        std::fs::create_dir_all(&big).unwrap();
        std::fs::create_dir_all(&small).unwrap();
        std::fs::write(big.join("artifact"), vec![0u8; 4096]).unwrap();
        std::fs::write(small.join("artifact"), vec![0u8; 16]).unwrap();
        std::fs::write(root.path().join("stray-file"), vec![0u8; 8192]).unwrap();

        assert_eq!(sweep_oversized(root.path(), 1024), 1);
        assert!(!big.exists());
        assert!(small.exists());
        assert!(root.path().join("stray-file").exists());
    }
}
