//! Worker self-reported identity.
//!
//! Extracted from `main.rs` (was `pub(crate) fn worker_identity`) so the
//! library — specifically `host_impl::build_signed_agent_envelope` — can
//! reference the same resolved identity that `main.rs::handle_*` paths
//! pass to `JobResult::sign_with_worker_id`. Pre-extraction the function
//! lived in the binary only; `host_impl.rs` (library code) could not see
//! it, so a duplicate `OnceLock` inside the library would have cached a
//! distinct value, breaking forensic attribution at signed-envelope
//! subscribers.
//!
//! L-11 (2026-05-22): The worker's self-reported identity, bound into
//! every signed [`aegix_workflow_job_protocol::JobResult`] via
//! `sign_with_worker_id`.
//!
//! Resolution order:
//!   1. `AEGIX_WORKER_ID` env var (operator-supplied, explicit).
//!   2. `HOSTNAME` env var (Kubernetes injects this automatically as
//!      the pod name — typically `talos-worker-<rs>-<5hex>`).
//!   3. A random 16-byte hex string generated once at startup
//!      (`fallback-<hex>`). This branch only fires in dev containers
//!      that have neither env set.
//!
//! The result is sanitized to the
//! [`aegix_workflow_job_protocol::validate_worker_id`] charset
//! (`[A-Za-z0-9._-]{0,128}`) and cached in a [`std::sync::OnceLock`] so
//! every signing call site reads the same value without re-parsing env
//! each time.
//!
//! Note: this is NOT cryptographic identity — any process holding
//! `WORKER_SHARED_KEY` can sign as any `worker_id`. It is forensic
//! visibility (which pod produced which result, surfaced in the
//! controller's audit log) plus the wire-format anchor that a future
//! per-worker HKDF subkey scheme can dispatch on.
//!
//! **THE FORENSIC HALF OF THAT PROMISE IS NOT KEPT WHENEVER RESOLUTION
//! STEP 1 WINS ACROSS REPLICAS.** Every `JobResult` and every signed
//! audit event from every replica then carries the SAME `worker_id`, so
//! "which pod produced which result" has no answer — a job, an audit
//! event and a crash cannot be attributed to a replica. Only step 2
//! (`HOSTNAME` → pod name) delivers per-pod attribution.
//!
//! **WHICH SHIPPED CONFIGURATIONS ARE IN THAT STATE — the precise list,
//! because an earlier version of this note named the chart and was
//! wrong.** The Helm chart's worker deployment template renders
//! `AEGIX_WORKER_ID` ZERO times; the `values.yaml` line offering
//! `AEGIX_WORKER_ID: "fleet"` is COMMENTED OUT inside the opt-in
//! RFC-0010 worker-trust block ("Uncomment together with the controller
//! half"). So a DEFAULT `helm install` resolves at step 2 and DOES get
//! per-pod attribution. The postures that lose it are:
//!
//!   * the dev compose stack, which sets one `AEGIX_WORKER_ID` for both
//!     worker replicas (`.env`);
//!   * a chart install whose operator has uncommented that block to run
//!     the single-key Ed25519 fleet;
//!   * any deployment setting `AEGIX_WORKER_ID` per-fleet rather than
//!     per-pod through `worker.extraEnv`.
//!
//! Where it applies this is a stated cost, not a bug to fix here.
//! Giving those replicas distinct ids would break dispatch verification
//! against the static `AEGIX_WORKER_PUBLIC_KEYS` ring, which looks a
//! worker's public key up BY `worker_id`. An operator who needs
//! per-replica forensics under that posture must move to per-worker
//! registered identities first (worker.extraEnv), not merely vary this
//! value.

//!
//! **EPHEMERAL IDENTITY (2026-11-06,
//! `docs/engineering-log/packages/2026-11-06-per-worker-nats-credentials.md`).**
//! With `AEGIX_WORKER_IDENTITY=ephemeral` the id is minted per PROCESS:
//! `<hostname>-<16 hex>`, the hostname reduced to one NATS subject token. The
//! worker binary mints its Ed25519 key in memory alongside it and registers
//! both through the NATS auth callout on its first connect, so every replica —
//! and every restart — is its own identity with its own inbox scope, and a
//! restart is a new identity rather than a trust-on-first-use conflict.
//! `AEGIX_WORKER_ID` is ignored in that mode (a warning says so).

use std::sync::OnceLock;

static WORKER_ID: OnceLock<String> = OnceLock::new();

/// How the worker's identity is made: `AEGIX_WORKER_IDENTITY`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityMode {
    /// Unset or `configured`: `AEGIX_WORKER_ID` / `HOSTNAME` and the
    /// operator-provisioned `AEGIX_WORKER_SIGNING_KEY`, as before.
    Configured,
    /// `ephemeral`: a fresh id and key per process.
    Ephemeral,
}

/// Parse a `AEGIX_WORKER_IDENTITY` value. An unrecognised spelling is an
/// error the worker refuses to boot on, never a silent default.
pub fn parse_identity_mode(raw: Option<&str>) -> Result<IdentityMode, String> {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(IdentityMode::Configured),
        Some(v) if v.eq_ignore_ascii_case("configured") => Ok(IdentityMode::Configured),
        Some(v) if v.eq_ignore_ascii_case("ephemeral") => Ok(IdentityMode::Ephemeral),
        Some(v) => Err(format!(
            "AEGIX_WORKER_IDENTITY must be `configured` or `ephemeral`, got {v:?}"
        )),
    }
}

/// This process's identity mode. A malformed setting reads as `Configured`
/// here; the worker's boot validates it with [`parse_identity_mode`] first and
/// refuses to start.
pub fn identity_mode() -> IdentityMode {
    static MODE: OnceLock<IdentityMode> = OnceLock::new();
    *MODE.get_or_init(|| {
        parse_identity_mode(std::env::var("AEGIX_WORKER_IDENTITY").ok().as_deref())
            .unwrap_or(IdentityMode::Configured)
    })
}

/// An ephemeral worker id: `base` reduced to one subject token (every
/// character outside `[A-Za-z0-9_-]` becomes `-`, so no `.`), bounded so the
/// whole id fits `MAX_WORKER_ID_LEN`, then `-` and `suffix_hex`.
fn ephemeral_worker_id(base: &str, suffix_hex: &str) -> String {
    let mut token: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    let budget = aegix_workflow_job_protocol::MAX_WORKER_ID_LEN - 1 - suffix_hex.len();
    token.truncate(budget);
    let token = token.trim_matches('-');
    let token = if token.is_empty() { "worker" } else { token };
    format!("{token}-{suffix_hex}")
}

/// Returns the worker's resolved identity. Idempotent; cached on first call.
pub fn worker_identity() -> &'static str {
    WORKER_ID.get_or_init(resolve_worker_id)
}

fn resolve_worker_id() -> String {
    // 0. Ephemeral: a fresh id per process, whatever else is set.
    if identity_mode() == IdentityMode::Ephemeral {
        if std::env::var("AEGIX_WORKER_ID").is_ok_and(|v| !v.trim().is_empty()) {
            tracing::warn!(
                "AEGIX_WORKER_ID is ignored under AEGIX_WORKER_IDENTITY=ephemeral: \
                 each process mints its own id"
            );
        }
        let mut buf = [0u8; 8];
        aegix_random::fill(&mut buf);
        let host = std::env::var("HOSTNAME").unwrap_or_default();
        return ephemeral_worker_id(host.trim(), &hex::encode(buf));
    }

    // 1. AEGIX_WORKER_ID — explicit operator override.
    if let Ok(v) = std::env::var("AEGIX_WORKER_ID") {
        let v = v.trim();
        if !v.is_empty() {
            let sanitized = sanitize(v);
            if !sanitized.is_empty() {
                return sanitized;
            }
        }
    }

    // 2. HOSTNAME — Kubernetes pod name in cluster deployments.
    if let Ok(v) = std::env::var("HOSTNAME") {
        let v = v.trim();
        if !v.is_empty() {
            let sanitized = sanitize(v);
            if !sanitized.is_empty() {
                return sanitized;
            }
        }
    }

    // 3. Random fallback — dev / CI containers without HOSTNAME.
    let mut buf = [0u8; 8];
    aegix_random::fill(&mut buf);
    let id = format!("fallback-{}", hex::encode(buf));
    tracing::warn!(
        worker_id = %id,
        "AEGIX_WORKER_ID and HOSTNAME both unset — using random fallback. \
         Set AEGIX_WORKER_ID (or rely on Kubernetes pod-name HOSTNAME) for \
         stable forensic attribution across restarts."
    );
    id
}

/// Sanitize a raw identity string to the
/// [`aegix_workflow_job_protocol::validate_worker_id`] charset. Out-of-set
/// characters become `-`; the result is truncated to `MAX_WORKER_ID_LEN`.
fn sanitize(raw: &str) -> String {
    let mut s: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if s.len() > aegix_workflow_job_protocol::MAX_WORKER_ID_LEN {
        s.truncate(aegix_workflow_job_protocol::MAX_WORKER_ID_LEN);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::worker_identity;

    #[test]
    fn returns_validatable_id() {
        let id = worker_identity();
        aegix_workflow_job_protocol::validate_worker_id(id)
            .expect("resolved worker_id must satisfy validate_worker_id");
    }

    #[test]
    fn cached_across_calls() {
        let a: &'static str = worker_identity();
        let b: &'static str = worker_identity();
        assert_eq!(
            a.as_ptr(),
            b.as_ptr(),
            "OnceLock should cache the same allocation"
        );
    }
}

#[cfg(test)]
mod ephemeral_identity_tests {
    use super::*;
    use aegix_workflow_job_protocol::nats_permissions::worker_inbox_token_is_valid;

    #[test]
    fn the_identity_mode_is_one_of_two_spellings() {
        assert_eq!(parse_identity_mode(None), Ok(IdentityMode::Configured));
        assert_eq!(parse_identity_mode(Some(" ")), Ok(IdentityMode::Configured));
        assert_eq!(
            parse_identity_mode(Some("configured")),
            Ok(IdentityMode::Configured)
        );
        assert_eq!(
            parse_identity_mode(Some("Ephemeral")),
            Ok(IdentityMode::Ephemeral)
        );
        assert!(parse_identity_mode(Some("per-pod")).is_err());
    }

    /// An ephemeral id is always ONE NATS subject token and a valid worker
    /// id, whatever the hostname: the callout refuses any other, and the
    /// worker would never connect.
    #[test]
    fn an_ephemeral_id_is_one_subject_token() {
        let suffix = "0123456789abcdef";
        for host in [
            "talos-worker-7f9c6d-abcde",
            "worker.example.internal",
            "",
            "...",
            "host with spaces",
            &"x".repeat(400),
        ] {
            let id = ephemeral_worker_id(host, suffix);
            assert!(id.ends_with(&format!("-{suffix}")), "{id}");
            assert!(worker_inbox_token_is_valid(&id), "{host:?} -> {id:?}");
        }
        assert_eq!(
            ephemeral_worker_id("worker.example.internal", suffix),
            "worker-example-internal-0123456789abcdef"
        );
        assert_eq!(ephemeral_worker_id("", suffix), "worker-0123456789abcdef");
    }
}
