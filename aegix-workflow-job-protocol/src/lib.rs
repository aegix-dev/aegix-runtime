//! Shared job protocol between Controller and Workers.
//!
//! Security model:
//! - Secrets are AES-256-GCM encrypted before transmission over NATS.
//! - Every JobRequest is HMAC-SHA256 signed using a pre-shared key
//!   (WORKER_SHARED_KEY) to prevent injection of malicious jobs.
//! - A `job_nonce` (timestamp + random hex) is included to prevent replay attacks.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use uuid::Uuid;

/// Canonical NATS subject registry — one authoritative name per `talos.*`
/// subject shared across process boundaries.
pub mod read_only_posts;
pub mod vault_path_log;
pub use vault_path_log::{
    extract_vault_refs, redact_oauth_provider_key_for_log, redact_vault_path_for_log, VaultRef,
};
pub mod heartbeat;
pub use heartbeat::{
    WorkerHeartbeat, WORKER_HEARTBEAT_DOMAIN, WORKER_HEARTBEAT_MAX_AGE_SECS,
    WORKER_HEARTBEAT_MAX_INTERVAL_SECS,
};
pub mod vault_paths;
pub use vault_paths::{
    is_controller_internal_vault_path, is_external_llm_host, is_llm_provider_vault_path,
    is_tier2_llm_vault_path, provider_tier, vault_path_permitted, vault_path_prefetched,
    EXTERNAL_LLM_HOSTS, LLM_PROVIDER_VAULT_PATHS, SECRET_GRANT_DELIVERY_NOTE,
    VAULT_BODY_SUBSTITUTION_SURFACES_NOTE,
};
pub mod dispatch_mint;
pub use dispatch_mint::{
    dispatch_mint, gcp_impersonated_path, grant_reaches_minted_paths, parse_gcp_impersonated_path,
    DispatchMint, GcpImpersonationTarget, MintScheme, GCP_IMPERSONATED_PREFIX,
    GCP_IMPERSONATED_SUFFIX, GITHUB_APP_SCHEME,
};
pub mod http_methods;
pub use http_methods::{
    method_permitted, sandbox_default_methods, ALL_HTTP_METHODS, METHOD_ALLOWLIST_REMEDY,
};
pub mod encrypted_secrets;
pub use encrypted_secrets::{AesGcmSecretEnvelope, EncryptedSecrets};
pub mod signed_json;
pub use signed_json::{RawSigned, SignedJson};
pub mod job_progress;
pub use job_progress::{JobProgress, JobProgressState};
pub mod cancel;
pub use cancel::{CancelCommand, EXECUTION_CANCEL_DOMAIN, EXECUTION_CANCEL_MAX_AGE_SECS};
pub mod shared_key;
pub use shared_key::{
    load_worker_key_ring, load_worker_shared_key, load_worker_shared_key_previous,
    worker_key_fingerprint,
};
pub mod sql_functions;
pub use sql_functions::{
    is_allowed_guest_sql_function, is_allowed_sql_function, is_disallowed_sql_function,
    ALLOWED_SQL_FUNCTIONS, DISALLOWED_SQL_FUNCTIONS, DISALLOWED_SQL_FUNCTION_PREFIXES,
    GUEST_EXCLUDED_SQL_FUNCTIONS, SQL_TEXT_EVALUATOR_FUNCTIONS,
};
pub mod subjects;
/// The wire spelling of an inline `wasm_bytes` field — base64 written, base64
/// or the pre-2026-10-30 integer list read.
pub mod wasm_bytes_wire;

/// Broker-level permission sets for the worker's NATS credential — the one
/// home the two rendered `nats.conf` fragments are pinned to.
pub mod nats_permissions;

/// RFC 0010 P3 (D3b) — per-execution ephemeral secret-envelope sealing.
pub mod envelope_seal;

/// Shared wire-invariant property harness (generator + counterexamples).
/// Compiled only for this crate's own tests, or for downstream dev-builds
/// that opt in via the non-default `test-support` feature — never in a
/// production build.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub use envelope_seal::{
    seal_secrets, sealed_result_refused, ClaimResponse, RecordedClaimant, SealOutput,
    SealedSecrets, SecretClaim, WorkerEphemeral,
};

type HmacSha256 = Hmac<Sha256>;

/// RFC 0010 P3 secret-delivery scheme carried by `JobRequest`.
/// `0` = legacy inline WSK envelope (today, default);
/// `1` = claim-based ECIES sealing (D3b). Security-relevant (an attacker must
/// not downgrade `1`→`0` to force a WSK envelope), so it is bound into the
/// dispatch signing payload — but ONLY when non-zero, so a scheme-`0` message's
/// signed bytes stay byte-identical to the pre-P3 wire format.
pub const SEALING_INLINE_WSK: u8 = 0;
/// See [`SEALING_INLINE_WSK`]. Claim-based ephemeral ECIES sealing.
pub const SEALING_CLAIM_ECIES: u8 = 1;

/// `skip_serializing_if` predicate: omit `sealing` from the wire JSON when it is
/// the legacy default, so a scheme-0 (inline-WSK) message serializes
/// byte-identically to the pre-P3 format. Signature is fixed by serde (`&T`).
#[allow(clippy::trivially_copy_pass_by_ref)]
fn sealing_is_default(v: &u8) -> bool {
    *v == SEALING_INLINE_WSK
}

/// HKDF-SHA256 `info` label for the secret-envelope AES-256-GCM subkey.
///
/// The 32-byte `WORKER_SHARED_KEY` is the *root*; the envelope cipher
/// uses a subkey expanded from it under this label, so the encryption
/// key is domain-separated from the HMAC signing key — historically the
/// two were the same raw bytes. Both the controller (seal) and the
/// worker (open) derive the identical subkey, so the round-trip is
/// consistent by construction. Bumping the `v1` suffix forces a clean
/// fleet-wide re-key (restart controller + workers together, same as
/// rotating `WORKER_SHARED_KEY` itself).
const ENVELOPE_AEAD_KEY_LABEL: &[u8] = b"talos/worker-shared-key/envelope-aead/v1";

/// v2 label (finding #1): the per-job envelope subkey folds the job's AAD
/// (the execution context bytes) into the HKDF `info`, so each job gets
/// its OWN AES key. The AES-GCM random-nonce birthday budget is then
/// per-job rather than shared across every envelope the fleet seals under
/// one `WORKER_SHARED_KEY`. Distinct label from v1 so the two subkeys
/// never collide.
const ENVELOPE_AEAD_KEY_LABEL_V2: &[u8] = b"talos/worker-shared-key/envelope-aead/v2-per-job";

/// v1 (legacy) envelope subkey: a single static subkey per root, shared by
/// every envelope. Used for the no-AAD wrappers (`encrypt`/`decrypt`) and
/// as the decrypt fallback for envelopes sealed before the v2 rollout.
fn derive_envelope_aead_key_v1(root: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut subkey = [0u8; 32];
    hk.expand(ENVELOPE_AEAD_KEY_LABEL, &mut subkey)
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// v2 per-job envelope subkey: `aad` (the job/execution context) is the
/// HKDF `info`, so the subkey is unique per job. Pure and deterministic;
/// controller (seal) and worker (open) derive it identically.
fn derive_envelope_aead_key_v2(root: &[u8], aad: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(ENVELOPE_AEAD_KEY_LABEL_V2), root);
    let mut subkey = [0u8; 32];
    hk.expand(aad, &mut subkey)
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// Select the envelope AES key for an AAD context. A non-empty `aad` (the
/// production per-job path) uses the v2 per-job derivation; an empty `aad`
/// (the legacy no-AAD `encrypt`/`decrypt` wrappers) preserves the exact v1
/// static behavior so those byte-for-byte round-trips are unchanged.
fn envelope_seal_key(root: &[u8], aad: &[u8]) -> [u8; 32] {
    if aad.is_empty() {
        derive_envelope_aead_key_v1(root)
    } else {
        derive_envelope_aead_key_v2(root, aad)
    }
}

/// HKDF-SHA256 `info` label for the per-worker HMAC signing subkey (codebase
/// review 2026-07-03, item #1). Distinct from the envelope-AEAD labels so the
/// signing subkey is domain-separated from every encryption subkey derived from
/// the same `WORKER_SHARED_KEY` root.
const WORKER_SIGNING_KEY_LABEL: &[u8] = b"talos/worker-shared-key/per-worker-signing/v1";

/// Derive a **per-worker** HMAC signing subkey from the fleet root
/// (`WORKER_SHARED_KEY`) bound to a specific `worker_id`.
///
/// `key = HKDF-SHA256(ikm = root, salt = WORKER_SIGNING_KEY_LABEL, info = worker_id)`
///
/// # Status: building block only — NOT a standalone mitigation
///
/// This is a domain-separated per-identity KDF, kept as a foundation for a
/// future asymmetric worker-trust redesign. It is **inert** (no sign/verify path
/// calls it) and, on its own, does **not** reduce the blast radius of a worker
/// compromise.
///
/// Why not: under the current *symmetric*-HMAC architecture the worker must hold
/// the fleet root anyway — to verify the controller's `JobRequest` (with HMAC,
/// verify-capability == forge-capability) and to decrypt the per-job secret
/// envelope. A wasmtime sandbox escape therefore recovers the root regardless of
/// how `JobResult` is signed, and with the root the attacker can derive *any*
/// worker's key from this very function. Signing `JobResult` per-worker while the
/// root is still resident is security theater. The genuine fix removes
/// root-equivalent material from the worker, which requires asymmetric crypto
/// (Ed25519 for controller→worker verification; per-worker keypairs for
/// worker→controller; an ECIES/per-execution scheme for the secret envelope).
/// See `docs/reviews/security-hardening-followups-2026-07-03.md` (corrected
/// Finding #1) for the analysis and the RFC-scoped plan.
///
/// Pure and deterministic: worker (sign) and controller (verify) derive it
/// identically. `worker_id` should already be [`validate_worker_id`]-clean at
/// the call site; the derivation itself is defined for any byte string.
pub fn derive_worker_signing_key(root: &[u8], worker_id: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(WORKER_SIGNING_KEY_LABEL), root);
    let mut subkey = [0u8; 32];
    hk.expand(worker_id.as_bytes(), &mut subkey)
        .expect("HKDF-SHA256 expand to 32 bytes is always a valid length");
    subkey
}

/// Length-prefix a variable-width string segment for a canonical signing
/// payload: `"<byte-len>:<value>"`. Prefixing makes the boundary against the
/// next segment unambiguous, so two adjacent free-form fields can't be shifted
/// to forge an identical concatenation (the payload-collision class the
/// `JobRequest` signing payload guards against). Shared by every
/// `signing_payload` impl so the discipline can't drift between them.
fn lp(s: &str) -> String {
    format!("{}:{}", s.len(), s)
}

/// Maximum future-skew tolerance for nonce timestamps (seconds).
///
/// Controller and worker sit on the same NATS cluster and should be
/// within a few seconds via NTP. A larger tolerance would extend the
/// effective replay window (a future-dated signature stays valid for
/// `FUTURE_SKEW + max_age_secs` total). A 5 s ≈ 5000 ms asymmetric
/// window is a common choice for signed-NATS RPC.
const MAX_FUTURE_SKEW_SECS: u64 = 5;

// ============================================================================
// Verifier role marker (L-4, 2026-05-22)
// ============================================================================
//
// Pre-r300/r301 the controller had two consumers of every JobResult —
// the primary inline dispatcher AND a background audit subscriber —
// and BOTH called `verify()`, which inserts the result nonce into the
// process-local `JOB_NONCE_CACHE`. The second verifier always lost
// the race with "result_nonce already seen", failing every workflow.
// The fix was twofold: (a) the worker single-publishes each result
// to one subject; (b) the split `verify` / `verify_no_replay` API.
//
// `verify` / `verify_no_replay` are still correct, but the choice
// between them is encoded only in the method name — a future caller
// can grep for one and copy-paste it into the wrong role. The
// `Verifier` enum forces the caller to declare intent at the type
// level, and `verify_as` dispatches on it. New code should prefer
// this API; the bare `verify` / `verify_no_replay` are kept for
// existing callers and tests.

/// L-4 marker that selects which verification flavour a caller wants.
///
/// Declaring intent at the type level prevents the regression class
/// behind the r300 incident: an audit subscriber accidentally calling
/// `verify()` instead of `verify_no_replay()` and racing the primary
/// verifier into "result_nonce already seen" errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verifier {
    /// **Primary** verifier: the single inline consumer that converts
    /// the signed result into a durable side effect (DB write, reply
    /// to a NATS request inbox, return to a webhook caller). Records
    /// the nonce in the process-local replay cache so the same
    /// signed result cannot be applied twice. There must be EXACTLY
    /// ONE primary verifier per result per controller process.
    Primary,
    /// **Observer** verifier: a passive consumer (audit subscriber,
    /// metrics emitter) whose only side effect is idempotent under
    /// replay. HMAC + freshness are checked; the nonce is NOT
    /// inserted into the replay cache. Use this whenever the same
    /// signed result might reach another consumer that already runs
    /// as the [`Primary`](Self::Primary).
    Observer,
}

// ============================================================================
// Replay-resistant nonce cache (single-use within freshness window)
// ============================================================================
//
// The freshness check on its own (now - ts <= max_age_secs) is necessary
// but not sufficient — within that window, an attacker who captures a
// signed JobRequest from NATS can replay it any number of times. The
// nonce cache turns that into a single-use guarantee: each (nonce, ts)
// pair is admitted exactly once; subsequent attempts return a "replay
// detected" error.
//
// Implementation: std-only (`Mutex<HashMap<String, u64>>`) keyed on the
// nonce string with the timestamp as value. On each insert we sweep
// entries older than `2 × max_age_secs` (some slack for clock skew),
// which keeps memory bounded at `rate × 2 × max_age_secs`. With
// max_age_secs = 300 and 100 verify/sec that's ~60k entries — small.
// A hard cap of 200k entries triggers a more aggressive sweep under
// abnormal load to keep the worker from OOMing.
//
// Workspace consistency: this mirrors the two-generation pattern in
// `aegix-memory::rpc_auth` but uses a single Mutex<HashMap> rather than
// rotating DashMaps because (a) this crate is published to crates.io
// and we don't want to add `dashmap` + `arc-swap` as required deps,
// and (b) under realistic load (sub-millisecond Mutex contention) the
// simpler form is performant enough. Revisit if profiling shows the
// Mutex becoming a hot spot.

const NONCE_CACHE_HARD_CAP: usize = 200_000;

/// Retention floor for the shared nonce cache, in seconds.
///
/// **THE CACHE IS SHARED BY EVERY SIGNED TYPE IN THE PROCESS, SO ITS SWEEP
/// MUST NOT BE DERIVED FROM ONE CALLER'S WINDOW.** Both sweeps below used to
/// compute their cutoff from the `max_age_secs` of whichever verifier
/// happened to trigger them. That is only sound while every verifier in the
/// process passes the same window — which was true (300 everywhere) until the
/// 2026-08 fleet heartbeat verified at 60. A 60-second caller then swept at
/// `now - 120`, evicting `JobResult` nonces the 300-second verifier was still
/// relying on, and a captured result replayed in the `(120s, 300s]` band
/// passed freshness, passed its MAC, found no cache entry, and was applied a
/// second time. Effective single-use protection silently narrowed from 300s
/// to 120s on any controller holding more than 1024 nonces.
///
/// This floor is the widest window any verifier in the workspace passes today
/// (300s, in `verify_dispatch` for `JobResult` / `JobRequest`), so a fresh process is correct from
/// its very first verify rather than from its first WIDE verify.
/// [`WIDEST_VERIFY_WINDOW_SECS`] then covers a future caller that is wider
/// still, so this constant does not have to be kept in sync by hand.
///
/// Raising retention is always safe: a nonce outside its own freshness window
/// is refused by the freshness check before the cache is ever consulted, so a
/// longer-lived entry can never cause a false replay rejection — only bounded
/// extra memory.
const NONCE_RETENTION_FLOOR_SECS: u64 = 300;

/// Ceiling on how far [`WIDEST_VERIFY_WINDOW_SECS`] may be dragged upward by a
/// caller, so a pathological `max_age_secs` (a test, a misconfiguration,
/// `u64::MAX`) cannot disable the sweep and turn the cache into an unbounded
/// allocation.
const NONCE_RETENTION_CEILING_SECS: u64 = 3600;

/// High-water mark of every freshness window this process has verified under,
/// clamped to [`NONCE_RETENTION_CEILING_SECS`].
///
/// The sweep honours `max(floor, high-water)`, never the caller's own value,
/// so a narrow verifier can never evict a wider verifier's live nonces.
static WIDEST_VERIFY_WINDOW_SECS: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(NONCE_RETENTION_FLOOR_SECS);

/// How long the shared cache must remember a nonce, given that *this* call
/// arrived with `max_age_secs`. See [`NONCE_RETENTION_FLOOR_SECS`].
fn nonce_retention_secs(max_age_secs: u64) -> u64 {
    let clamped = max_age_secs.min(NONCE_RETENTION_CEILING_SECS);
    let previous =
        WIDEST_VERIFY_WINDOW_SECS.fetch_max(clamped, std::sync::atomic::Ordering::Relaxed);
    previous.max(clamped).max(NONCE_RETENTION_FLOOR_SECS)
}

/// How many inserts the nonce cache accepts between two expiry sweeps once it
/// is past the small-size threshold. Before 2026-09-10 the cache ran
/// `HashMap::retain` on EVERY insert above 1024 entries — an O(n) walk per
/// verify on exactly the busy processes that hold many nonces, so the cost
/// grew with load in the worst direction. Sweeping every 256 inserts bounds
/// the amortised cost to O(1) per verify while keeping the map within
/// `256` entries of where the every-insert sweep would have left it. The
/// hard-cap emergency valve below is unchanged and still runs on every insert
/// that finds the map at [`NONCE_CACHE_HARD_CAP`], so memory stays bounded.
/// Sweep frequency has no bearing on correctness: a stale-but-unswept entry
/// can only ever collide with the SAME nonce string, which is the replay the
/// cache exists to refuse.
const NONCE_SWEEP_EVERY_N_INSERTS: u32 = 256;

struct JobNonceCache {
    seen: std::sync::Mutex<HashMap<String, u64>>,
    /// Inserts since the last expiry sweep (see [`NONCE_SWEEP_EVERY_N_INSERTS`]).
    /// Only ever read/written under `seen`'s lock, so `Relaxed` is enough; it
    /// is atomic purely so the struct stays `Sync` without a second mutex.
    inserts_since_sweep: std::sync::atomic::AtomicU32,
}

impl JobNonceCache {
    fn new() -> Self {
        Self {
            seen: std::sync::Mutex::new(HashMap::new()),
            inserts_since_sweep: std::sync::atomic::AtomicU32::new(0),
        }
    }

    /// Test shorthand: `true` only when [`Self::admit`] admitted the nonce.
    #[cfg(test)]
    fn check_and_record(&self, nonce: &str, ts: u64, max_age_secs: u64) -> bool {
        self.admit(nonce, ts, max_age_secs) == NonceAdmission::Fresh
    }

    /// Record `nonce` if it is fresh. Refuses a replay, and refuses (fails
    /// closed) when the cache is still at [`NONCE_CACHE_HARD_CAP`] after the
    /// emergency sweep — admitting it anyway would let a flood grow the map
    /// without bound, and evicting a live entry would open a replay hole.
    fn admit(&self, nonce: &str, ts: u64, max_age_secs: u64) -> NonceAdmission {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(ts);
        // Poison-tolerant: rebuild the lock state on poison rather than
        // hard-failing every subsequent call. A poisoned mutex here only
        // means a previous panic happened mid-update; the data itself is
        // a HashMap that's safe to keep using.
        let mut g = match self.seen.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        // Sweep entries older than 2× the RETENTION window — never 2× this
        // caller's own `max_age_secs`. The cache is shared by every signed
        // type in the process, so a narrow verifier computing the cutoff from
        // its own window evicts a wider verifier's still-live nonces (see
        // `NONCE_RETENTION_FLOOR_SECS`). The 2× slack absorbs clock skew and
        // avoids an admitting-then-rejecting race when (now, ts) straddle the
        // boundary.
        let retention = nonce_retention_secs(max_age_secs);
        let cutoff = now.saturating_sub(retention.saturating_mul(2));
        // Skip the sweep at small sizes — pure overhead. Above 1k entries it
        // is worth it, but not on EVERY insert (an O(n) walk per verify on a
        // busy process): amortise it to one sweep per
        // `NONCE_SWEEP_EVERY_N_INSERTS` inserts. See the constant's docs.
        if g.len() > 1024
            && self
                .inserts_since_sweep
                .load(std::sync::atomic::Ordering::Relaxed)
                >= NONCE_SWEEP_EVERY_N_INSERTS
        {
            g.retain(|_, t| *t > cutoff);
            self.inserts_since_sweep
                .store(0, std::sync::atomic::Ordering::Relaxed);
        }
        if g.contains_key(nonce) {
            return NonceAdmission::Replay;
        }
        // Hard cap: if rate × 2× retention exceeds 200k entries, we're under
        // abnormal load (or a flood). Drop everything older than the strict
        // freshness window to free space — again the RETENTION window, so the
        // emergency valve cannot open a replay hole for a wider verifier that
        // this one knows nothing about.
        if g.len() >= NONCE_CACHE_HARD_CAP {
            let aggressive_cutoff = now.saturating_sub(retention);
            g.retain(|_, t| *t > aggressive_cutoff);
            if g.len() >= NONCE_CACHE_HARD_CAP {
                return NonceAdmission::CacheFull;
            }
        }
        g.insert(nonce.to_string(), ts);
        self.inserts_since_sweep
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        NonceAdmission::Fresh
    }
}

/// Outcome of recording a nonce in the shared replay cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NonceAdmission {
    Fresh,
    Replay,
    /// Every live entry is still inside its retention window and the map is
    /// at the hard cap — refused rather than grown or evicted.
    CacheFull,
}

/// Upper bound on a signed message's nonce (`"<unix_secs>:<hex>"`). Producers
/// emit ≤ 53 bytes (20-digit u64, `:`, 32 hex); the nonce is stored in the
/// replay cache, so an unbounded one is a memory lever for any signer.
const MAX_SIGNED_NONCE_LEN: usize = 96;

static JOB_NONCE_CACHE: std::sync::LazyLock<JobNonceCache> =
    std::sync::LazyLock::new(JobNonceCache::new);

/// Check whether `nonce` (with stamped timestamp `ts`) has been seen
/// within the freshness window. Returns `true` on first observation
/// (and atomically records it), `false` on replay. Used by every
/// `verify()` impl in this crate after HMAC verification succeeds.
fn check_and_record_job_nonce(nonce: &str, ts: u64, max_age_secs: u64) -> NonceAdmission {
    JOB_NONCE_CACHE.admit(nonce, ts, max_age_secs)
}

/// Current entry count of the process-local job-nonce replay cache.
///
/// Surfaced for `/health` / metrics endpoints so operators can correlate
/// "approaching `NONCE_CACHE_HARD_CAP`" (200k) with upstream traffic
/// rate. Sustained near-cap usage suggests either legitimate high
/// throughput (raise the cap) or a replay flood (gate at the NATS
/// subject level upstream).
///
/// Reading the cache size takes the same mutex as
/// `check_and_record_job_nonce`. The lock is held only long enough to
/// call `.len()`; the contention impact at typical query rates is
/// negligible (microseconds).
///
/// Returns `0` if the cache lock is currently poisoned (which only
/// happens if a previous panic occurred mid-mutation). The
/// `check_and_record` path itself is poison-tolerant so the cache
/// remains functional — this accessor errs on the side of "0" rather
/// than panic-on-read.
pub fn job_nonce_cache_size() -> usize {
    JOB_NONCE_CACHE.seen.lock().map(|g| g.len()).unwrap_or(0)
}

/// Maximum length of a `worker_id` in bytes. Pod names and host names
/// in practice fit well under 64 bytes (Kubernetes' RFC-1123 label cap
/// is 63 chars); 128 leaves slack for synthetic prefixes/suffixes.
pub const MAX_WORKER_ID_LEN: usize = 128;

/// Validate a self-reported worker identity before binding it into a
/// HMAC-signed result. The charset (`A-Z`, `a-z`, `0-9`, `.`, `-`, `_`)
/// is restricted so the colon-delimited signing-payload format stays
/// unambiguous — without this, a worker_id containing `:` could shift
/// the field boundary and let the same HMAC verify under a different
/// interpretation of the payload.
///
/// An empty `worker_id` is permitted (the back-compat `sign()` wrapper
/// passes the empty string) and renders as `""` in the signing payload.
/// Production worker code is expected to supply a non-empty value.
pub fn validate_worker_id(worker_id: &str) -> Result<(), String> {
    if worker_id == CONTROLLER_RPC_IDENTITY {
        return Err(format!(
            "worker_id {CONTROLLER_RPC_IDENTITY:?} is reserved for the controller's own RPC \
             signing identity"
        ));
    }
    if worker_id.len() > MAX_WORKER_ID_LEN {
        return Err(format!(
            "worker_id too long: {} bytes (max {MAX_WORKER_ID_LEN})",
            worker_id.len()
        ));
    }
    if !worker_id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_')
    {
        return Err("worker_id contains invalid chars (allowed: A-Z a-z 0-9 . - _)".into());
    }
    Ok(())
}

#[cfg(test)]
mod envelope_key_derivation_tests {
    use super::{derive_envelope_aead_key_v1, derive_envelope_aead_key_v2};

    /// Ciphertexts sealed OUTSIDE this code — by Python's `cryptography`
    /// (AES-256-GCM), under keys derived by RFC 5869 in Python — over made-up
    /// inputs, opened here by the real decrypt path. A worker on one build must open what a
    /// controller on another sealed across a change of AEAD library, and a round trip
    /// through one version of a library cannot show that.
    #[test]
    fn an_envelope_sealed_by_another_implementation_opens() {
        let root = b"made-up worker shared key, 32 b!";
        let aad = b"made-up execution 0001";
        let nonce = hex::decode("0102030405060708090a0b0c").unwrap();
        let expected: std::collections::HashMap<String, String> =
            [("made-up/secret".to_string(), "value".to_string())].into();

        let v2 = super::EncryptedSecrets {
            ciphertext: hex::decode(
                "fb4ec72b497618e7de8b21228ea4e060f3298e3dcf3b672b2686a8ea28660cbfeade61a26112af42e1ee",
            )
            .unwrap(),
            nonce: nonce.clone(),
        };
        assert_eq!(
            super::plain_secret_map(&v2.decrypt_with_aad(root, aad).expect("opens")),
            expected
        );
        assert!(v2
            .decrypt_with_aad(root, b"made-up execution 0002")
            .is_err());

        let v1 = super::EncryptedSecrets {
            ciphertext: hex::decode(
                "4e6073493eb14680e402ef0a5fa4c08f8bbd89684edf5b4933c9c8f3daaa0c055c8f77ca5ca8e96e9403",
            )
            .unwrap(),
            nonce,
        };
        assert_eq!(
            super::plain_secret_map(&v1.decrypt(root).expect("opens")),
            expected
        );
    }

    /// Known answers for the key derivation, computed OUTSIDE this code — by
    /// Python's standard `hmac`/`hashlib`, implementing RFC 5869 directly —
    /// for made-up inputs. Every envelope ever written decrypts only if this
    /// derivation never changes; a dependency bump that altered it would make
    /// them all unreadable without a single test failing elsewhere.
    #[test]
    fn the_envelope_key_derivation_matches_rfc_5869() {
        let root = b"made-up worker shared key, 32 b!";
        assert_eq!(
            hex::encode(derive_envelope_aead_key_v1(root)),
            "d5d27a24c06debcca733cc7317e2819724b2b3077b8273a227b4f7ec014f4c57"
        );
        assert_eq!(
            hex::encode(derive_envelope_aead_key_v2(root, b"made-up execution 0001")),
            "f28889c330c69cfb71d57b57389219e642ea419cb79ee9d88df46543a35be0e7"
        );
    }
}

#[cfg(test)]
mod worker_id_validation_tests {
    use super::validate_worker_id;

    #[test]
    fn accepts_empty() {
        validate_worker_id("").unwrap();
    }

    #[test]
    fn accepts_typical_pod_name() {
        validate_worker_id("talos-worker-abc-12345").unwrap();
    }

    #[test]
    fn accepts_uuid_style() {
        validate_worker_id("ab12cd34-ef56-7890-1234-567890abcdef").unwrap();
    }

    #[test]
    fn rejects_colon() {
        // The signing payload is colon-delimited; embedded `:` would
        // shift the field boundary.
        assert!(validate_worker_id("worker:1").is_err());
    }

    #[test]
    fn rejects_whitespace() {
        assert!(validate_worker_id("worker 1").is_err());
        assert!(validate_worker_id("worker\n1").is_err());
    }

    #[test]
    fn rejects_null_byte() {
        assert!(validate_worker_id("worker\0").is_err());
    }

    #[test]
    fn rejects_overlong() {
        let big = "a".repeat(super::MAX_WORKER_ID_LEN + 1);
        assert!(validate_worker_id(&big).is_err());
    }

    #[test]
    fn accepts_max_length() {
        let max = "a".repeat(super::MAX_WORKER_ID_LEN);
        validate_worker_id(&max).unwrap();
    }
}

// ============================================================================
// Shared sign/verify core — `SignedMessage`
// ============================================================================
//
// Every signed NATS message type in this crate (`JobRequest`, `JobResult`,
// `WorkerHeartbeat`) shares the
// exact same HMAC / nonce-freshness / replay-cache / key-ring machinery.
// Historically each type carried its own hand-rolled copy of that logic
// (~5 near-identical families) — a drift surface for subtle security code
// (this crate carries the r300/r301 dual-verify incident history). The
// crate-private trait below holds the logic ONCE; each type supplies only
// its canonical `signing_payload()` bytes (untouched — wire-format-stable),
// its nonce/signature field accessors, and the nonce field's name for the
// byte-for-byte-stable error strings.
//
// The public API is unchanged: the inherent `sign` / `verify` /
// `verify_no_replay` / `*_with_ring` methods on each type are thin wrappers
// over these defaults, so worker/controller/engine callers need no changes
// and the verify() vs verify_no_replay() split (CLAUDE.md "Verify-once
// rule") is preserved exactly — `verify_core` is the ONLY path that inserts
// into `JOB_NONCE_CACHE`; `verify_no_replay_core` never touches it.

// ============================================================================
// RFC 0010 P1 — Ed25519 controller→worker dispatch signature scheme
// ============================================================================
//
// The `WORKER_SHARED_KEY` HMAC path (crypto scheme 0) is symmetric: a worker
// that can verify a `JobRequest` can also forge one. Because the worker runs
// untrusted WASM, a sandbox escape recovers the shared key and can mint
// dispatches for any actor/tenant. Ed25519 (scheme 1) breaks that symmetry: the
// controller signs with its private key and the worker holds only the *public*
// key, so a compromised worker can verify dispatches but cannot forge them.
//
// Rollout safety (see RFC 0010 P1):
// - `crypto_scheme` is an unsigned dispatch hint. It is NOT bound into the HMAC
//   payload, so the scheme-0 `signing_payload()` bytes stay byte-identical to
//   the pre-P1 wire format — no coordinated restart is needed for the HMAC path.
// - Downgrade is still prevented: the two schemes sign DIFFERENT bytes (Ed25519
//   signs `ed25519_signing_input`, which appends a domain tag), and the verifier
//   dispatches on `crypto_scheme`. Flipping the hint routes the message to the
//   wrong verify method, where the signature (which the attacker cannot forge
//   for the other scheme) fails. Turning HMAC acceptance off entirely (P4) is
//   the flag on the worker's dispatch call, not a payload change.

/// Signature scheme tag carried by `JobRequest`.
/// Scheme 0 = legacy `WORKER_SHARED_KEY` HMAC-SHA256; scheme 1 = Ed25519.
pub const CRYPTO_SCHEME_HMAC: u8 = 0;
/// See [`CRYPTO_SCHEME_HMAC`].
pub const CRYPTO_SCHEME_ED25519: u8 = 1;

/// Domain-separation suffix appended to the canonical payload before Ed25519
/// signing/verification. Keeps an Ed25519 dispatch signature from ever being
/// confused with an HMAC over "the same" message, and versions the scheme so a
/// future format can bump the tag for a clean re-key.
const ED25519_DISPATCH_DOMAIN_TAG: &[u8] = b":talos-dispatch-ed25519-v1";

/// Re-exported so the controller (sign) and worker (verify) name the dispatch
/// key types without pinning the `ed25519-dalek` version in their own manifests.
pub use ed25519_dalek::{SigningKey as DispatchSigningKey, VerifyingKey as DispatchVerifyingKey};

/// Parse a 32-byte Ed25519 **public** (verifying) key from lowercase/uppercase
/// hex. Used by the worker to load `AEGIX_CONTROLLER_PUBLIC_KEY`. Fails closed on
/// wrong length or non-canonical encoding.
pub fn parse_ed25519_verifying_key_hex(hex_str: &str) -> Result<DispatchVerifyingKey, String> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| "controller public key: invalid hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "controller public key: must be 32 bytes".to_string())?;
    DispatchVerifyingKey::from_bytes(&arr)
        .map_err(|_| "controller public key: not a valid Ed25519 point".to_string())
}

/// Parse a 32-byte Ed25519 **public** (verifying) key from raw bytes. Used by the
/// controller's RFC 0010 P2 inc.4 refresh task to turn a `worker_identities`
/// `bytea` column into a verifying key before merging it into the dynamic
/// overlay. Fails closed on a non-canonical point — a bad row is skipped rather
/// than poisoning the snapshot. Keeps callers off a direct `ed25519-dalek` dep.
pub fn parse_ed25519_verifying_key_bytes(bytes: &[u8; 32]) -> Result<DispatchVerifyingKey, String> {
    DispatchVerifyingKey::from_bytes(bytes)
        .map_err(|_| "worker public key: not a valid Ed25519 point".to_string())
}

/// Domain-separation prefix for the worker-registration proof-of-possession
/// message (RFC 0010 P2 inc.4). A version bump invalidates every older proof.
const WORKER_REGISTRATION_POP_DOMAIN: &[u8] = b"talos/worker-key-registration/v1";

/// Build the canonical proof-of-possession message a worker signs to prove it
/// holds the private key for `public_key` when self-registering over the network.
/// Length-prefixed, domain-separated, fixed-little-endian so two distinct field
/// tuples can never collide onto the same bytes. Pure and deterministic.
#[must_use]
pub fn worker_registration_pop_message(
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
    issued_at_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    let wid = worker_id.as_bytes();
    let non = nonce.as_bytes();
    let mut msg = Vec::with_capacity(
        WORKER_REGISTRATION_POP_DOMAIN.len() + 8 + wid.len() + 32 + 1 + 8 + 8 + non.len(),
    );
    msg.extend_from_slice(WORKER_REGISTRATION_POP_DOMAIN);
    msg.extend_from_slice(&(wid.len() as u64).to_le_bytes());
    msg.extend_from_slice(wid);
    msg.extend_from_slice(public_key);
    msg.push(u8::from(supports_sealing));
    msg.extend_from_slice(&issued_at_ms.to_le_bytes());
    msg.extend_from_slice(&(non.len() as u64).to_le_bytes());
    msg.extend_from_slice(non);
    msg
}

/// Sign a worker-registration proof-of-possession with the worker's Ed25519
/// signing key; returns the 64-byte signature. Used by the worker's boot-time
/// self-registration client. The controller checks it with
/// [`verify_worker_registration_proof`].
#[must_use]
pub fn sign_worker_registration_proof(
    signing_key: &DispatchSigningKey,
    worker_id: &str,
    public_key: &[u8; 32],
    supports_sealing: bool,
    issued_at_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let msg = worker_registration_pop_message(
        worker_id,
        public_key,
        supports_sealing,
        issued_at_ms,
        nonce,
    );
    signing_key.sign(&msg).to_bytes().to_vec()
}

/// Verify a worker-registration proof-of-possession: `proof` MUST be a valid
/// Ed25519 signature by `public_key` over the canonical message for these exact
/// fields. Proves the registrant holds the private key for the key it registers,
/// so it cannot register a public key it does not control, nor alter any signed
/// field without invalidating the proof. Uses `verify_strict` (rejects
/// small-order keys and signature malleability). Fails closed on a malformed
/// signature or any field mismatch. Does NOT check freshness or caller
/// authorization — the endpoint layers a bearer-token gate and a freshness
/// window on top.
pub fn verify_worker_registration_proof(
    public_key: &[u8; 32],
    worker_id: &str,
    supports_sealing: bool,
    issued_at_ms: u64,
    nonce: &str,
    proof: &[u8],
) -> Result<(), String> {
    let vk = DispatchVerifyingKey::from_bytes(public_key)
        .map_err(|_| "registration proof: public_key is not a valid Ed25519 point".to_string())?;
    let sig_bytes: [u8; 64] = proof
        .try_into()
        .map_err(|_| "registration proof: signature must be 64 bytes".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let msg = worker_registration_pop_message(
        worker_id,
        public_key,
        supports_sealing,
        issued_at_ms,
        nonce,
    );
    vk.verify_strict(&msg, &sig)
        .map_err(|_| "registration proof: signature verification failed".to_string())
}

/// Domain-separation prefix for the worker LIVENESS proof-of-possession message.
///
/// DELIBERATELY DISTINCT from [`WORKER_REGISTRATION_POP_DOMAIN`]: the two proofs
/// authorize different things (registration can CREATE a trusted identity; a
/// liveness ping can only refresh the clock on one that already exists), so a
/// proof minted for one must never be replayable as the other. Domain separation
/// is what makes that structural rather than a matter of which endpoint the
/// bytes happen to arrive at.
const WORKER_LIVENESS_POP_DOMAIN: &[u8] = b"talos/worker-key-liveness/v1";

/// Build the canonical proof-of-possession message a worker signs to prove it is
/// STILL RUNNING and still holds the private key for `public_key`.
///
/// Same length-prefixed, domain-separated, fixed-little-endian construction as
/// [`worker_registration_pop_message`] so two distinct field tuples can never
/// collide onto the same bytes. Pure and deterministic.
///
/// Note there is no `supports_sealing` field: a liveness ping is not allowed to
/// change any property of the row it touches, only `last_liveness_at`. So there
/// is no row PROPERTY a replayed proof could alter — but it can still move that
/// one timestamp, which is the value the reaper's window is measured from. The
/// bound on that is freshness (`issued_at_ms` is signed and the endpoint
/// enforces a 300s past window), not this field list.
#[must_use]
pub fn worker_liveness_pop_message(
    worker_id: &str,
    public_key: &[u8; 32],
    issued_at_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    let wid = worker_id.as_bytes();
    let non = nonce.as_bytes();
    let mut msg = Vec::with_capacity(
        WORKER_LIVENESS_POP_DOMAIN.len() + 8 + wid.len() + 32 + 8 + 8 + non.len(),
    );
    msg.extend_from_slice(WORKER_LIVENESS_POP_DOMAIN);
    msg.extend_from_slice(&(wid.len() as u64).to_le_bytes());
    msg.extend_from_slice(wid);
    msg.extend_from_slice(public_key);
    msg.extend_from_slice(&issued_at_ms.to_le_bytes());
    msg.extend_from_slice(&(non.len() as u64).to_le_bytes());
    msg.extend_from_slice(non);
    msg
}

/// Sign a worker liveness proof-of-possession; returns the 64-byte signature.
/// Used by the worker's periodic liveness pinger. Checked by
/// [`verify_worker_liveness_proof`].
#[must_use]
pub fn sign_worker_liveness_proof(
    signing_key: &DispatchSigningKey,
    worker_id: &str,
    public_key: &[u8; 32],
    issued_at_ms: u64,
    nonce: &str,
) -> Vec<u8> {
    use ed25519_dalek::Signer;
    let msg = worker_liveness_pop_message(worker_id, public_key, issued_at_ms, nonce);
    signing_key.sign(&msg).to_bytes().to_vec()
}

/// Verify a worker liveness proof-of-possession: `proof` MUST be a valid Ed25519
/// signature by `public_key` over the canonical message for these exact fields.
///
/// This is the ONLY credential the liveness endpoint accepts — no bearer token
/// is involved. That is deliberate and is what makes the ping work for every
/// registration path: a worker admitted by a SINGLE-USE provisioning token has
/// burned that token and has no reusable bearer left, so a scheme that re-used
/// the registration endpoint's auth could not refresh it and the sweep would
/// reap a live worker. Possession of the already-registered private key is both
/// stronger evidence than a fleet-shared bearer and available to every worker
/// forever.
///
/// Uses `verify_strict` (rejects small-order keys and signature malleability)
/// and fails closed on any malformed input. Does NOT check freshness or that the
/// key is registered — the endpoint layers a freshness window on top and the
/// repository's guarded UPDATE is what requires an ACTIVE row.
pub fn verify_worker_liveness_proof(
    public_key: &[u8; 32],
    worker_id: &str,
    issued_at_ms: u64,
    nonce: &str,
    proof: &[u8],
) -> Result<(), String> {
    let vk = DispatchVerifyingKey::from_bytes(public_key)
        .map_err(|_| "liveness proof: public_key is not a valid Ed25519 point".to_string())?;
    let sig_bytes: [u8; 64] = proof
        .try_into()
        .map_err(|_| "liveness proof: signature must be 64 bytes".to_string())?;
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    let msg = worker_liveness_pop_message(worker_id, public_key, issued_at_ms, nonce);
    vk.verify_strict(&msg, &sig)
        .map_err(|_| "liveness proof: signature verification failed".to_string())
}

/// Parse a 32-byte Ed25519 **private** (signing) key seed from hex. Used by the
/// controller to load its dispatch signing key. The seed is secret — callers
/// must source it from a Secret / KMS, never a plaintext config committed to
/// the repo. Fails closed on wrong length.
pub fn parse_ed25519_signing_key_hex(hex_str: &str) -> Result<DispatchSigningKey, String> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| "controller signing key: invalid hex".to_string())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| "controller signing key: must be a 32-byte seed".to_string())?;
    Ok(DispatchSigningKey::from_bytes(&arr))
}

/// A fresh Ed25519 signing key from the operating system's random source.
///
/// The one way a signing key is generated. `SigningKey::generate` takes a
/// random-number generator by the `rand_core` trait of whichever generation
/// the curve library was built against, which is not the workspace's `rand`;
/// a key is 32 random bytes, so this draws them and builds the key from them.
#[must_use]
pub fn generate_dispatch_signing_key() -> DispatchSigningKey {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    aegix_random::fill(seed.as_mut());
    DispatchSigningKey::from_bytes(&seed)
}

/// Generate a fresh Ed25519 keypair for the RFC 0010 worker-trust boundary,
/// returned as `(signing_seed_hex, verifying_key_hex)` — both 64-char lowercase
/// hex, in the exact shape [`parse_ed25519_signing_key_hex`] /
/// [`parse_ed25519_verifying_key_hex`] accept. The seed is SECRET (store it in a
/// Secret / KMS and hand it to exactly one process); the verifying key is public
/// and is what the peer configures. Backs the `controller
/// generate-worker-trust-keypair` operator subcommand — the ONE supported way
/// to mint keys for `AEGIX_{CONTROLLER,WORKER}_SIGNING_KEY` +
/// `AEGIX_{CONTROLLER_PUBLIC_KEY,WORKER_PUBLIC_KEYS}`.
#[must_use]
pub fn generate_ed25519_keypair_hex() -> (String, String) {
    let sk = generate_dispatch_signing_key();
    let vk = sk.verifying_key();
    (hex::encode(sk.to_bytes()), hex::encode(vk.to_bytes()))
}

/// The controller's dispatch-signing choice, constructed once at boot from
/// config and used at every `JobRequest` sign site so the
/// scheme lives in ONE place. `Hmac` keeps the legacy `WORKER_SHARED_KEY` path;
/// `Ed25519` signs with the controller's private key (RFC 0010 P1).
#[derive(Clone)]
pub enum DispatchSigner {
    /// Scheme 0 — symmetric HMAC-SHA256 under the pre-shared key.
    Hmac(std::sync::Arc<Vec<u8>>),
    /// Scheme 1 — Ed25519 under the controller's private key.
    Ed25519(std::sync::Arc<DispatchSigningKey>),
}

// Redacted Debug (lint check 37): never render key material.
impl std::fmt::Debug for DispatchSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Hmac(_) => f.write_str("DispatchSigner::Hmac(<redacted>)"),
            Self::Ed25519(_) => f.write_str("DispatchSigner::Ed25519(<redacted>)"),
        }
    }
}

impl DispatchSigner {
    /// The wire `crypto_scheme` this signer stamps.
    #[must_use]
    pub fn scheme(&self) -> u8 {
        match self {
            Self::Hmac(_) => CRYPTO_SCHEME_HMAC,
            Self::Ed25519(_) => CRYPTO_SCHEME_ED25519,
        }
    }

    /// Sign a `JobRequest` under this signer's scheme (sets nonce + signature +
    /// `crypto_scheme`).
    pub fn sign_job(&self, req: &mut JobRequest) -> Result<(), String> {
        match self {
            Self::Hmac(k) => req.sign(k),
            Self::Ed25519(sk) => req.sign_ed25519(sk),
        }
    }

    /// Sign a [`CancelCommand`] under this signer's scheme.
    ///
    /// The cancel rides the SAME scheme as job dispatch on purpose. An
    /// HMAC-only cancel would be refused outright by a fleet running
    /// `AEGIX_DISPATCH_SCHEME=ed25519` with legacy HMAC disabled — the
    /// producer would publish, the worker would reject on
    /// `SchemeRefused`, and the operator would see a cancel that "worked"
    /// and did nothing. Routing it through the same signer is what stops
    /// this shipping as another built-but-never-effective mechanism.
    pub fn sign_cancel(&self, cmd: &mut CancelCommand) -> Result<(), String> {
        match self {
            Self::Hmac(k) => cmd.sign(k),
            Self::Ed25519(sk) => cmd.sign_ed25519(sk),
        }
    }
}

/// The process-wide Ed25519 dispatch signer, resolved once from env, or `None`
/// when Ed25519 dispatch is not configured (the default) — in which case every
/// sign site keeps its legacy HMAC path. `Some` is returned only when
/// `AEGIX_DISPATCH_SCHEME=ed25519` AND a valid 32-byte-hex-seed
/// `AEGIX_CONTROLLER_SIGNING_KEY` is present. A requested-but-misconfigured
/// setup logs an error and returns `None` (fall back to HMAC, which the
/// dual-verify worker still accepts, so a bad key can't strand dispatch during
/// rollout — OUTSIDE production; since 2026-09-12 the controller's boot gate
/// `aegix_engine::nats_run::enforce_production_dispatch_scheme_posture` refuses
/// that state in production unless acknowledged). Single source of truth for
/// ALL controller sign sites (engine
/// dispatcher, retry re-sign, module-push paths) so the scheme can't diverge
/// between them.
///
/// Reads env like the sibling `load_worker_key_ring` / `load_worker_shared_key_previous`
/// helpers; cached in a `OnceLock` so the key is parsed once.
/// The controller's configured Ed25519 seed, `AEGIX_CONTROLLER_SIGNING_KEY`,
/// parsed once: the ONE reader of that variable. `None` when it is unset or
/// not a 64-hex seed; the dispatch signer and the controller's RPC identity
/// both read it from here.
#[must_use]
pub fn configured_controller_signing_key() -> Option<std::sync::Arc<DispatchSigningKey>> {
    static CACHE: std::sync::OnceLock<Option<std::sync::Arc<DispatchSigningKey>>> =
        std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let hex_seed = std::env::var("AEGIX_CONTROLLER_SIGNING_KEY").ok()?;
            parse_ed25519_signing_key_hex(&hex_seed)
                .ok()
                .map(std::sync::Arc::new)
        })
        .clone()
}

/// HKDF `info` for [`derive_controller_rpc_identity_key`]. Versioned: a change
/// to the derivation is a new string, never a silent re-key.
pub const CONTROLLER_RPC_IDENTITY_INFO: &[u8] = b"talos-controller-rpc-identity/v1";

/// The controller's RPC signing identity, derived from its dispatch seed
/// (2026-10-29): `HKDF-SHA256(ikm = seed, info = CONTROLLER_RPC_IDENTITY_INFO)`
/// as a fresh Ed25519 seed. A key of its own, not the dispatch key reused
/// across two signed protocols; the same seed on every replica derives the
/// same identity, so a rehearsal signed by one controller verifies at
/// another. Signed under [`CONTROLLER_RPC_IDENTITY`].
#[must_use]
pub fn derive_controller_rpc_identity_key(seed: &DispatchSigningKey) -> DispatchSigningKey {
    let ikm = zeroize::Zeroizing::new(seed.to_bytes());
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, ikm.as_ref());
    let mut okm = zeroize::Zeroizing::new([0u8; 32]);
    hk.expand(CONTROLLER_RPC_IDENTITY_INFO, okm.as_mut())
        .expect("32 bytes is within HKDF-SHA256's output limit");
    DispatchSigningKey::from_bytes(&okm)
}

#[must_use]
pub fn configured_dispatch_signer() -> Option<DispatchSigner> {
    static CACHE: std::sync::OnceLock<Option<DispatchSigner>> = std::sync::OnceLock::new();
    CACHE
        .get_or_init(|| {
            let scheme = std::env::var("AEGIX_DISPATCH_SCHEME").unwrap_or_default();
            if !scheme.eq_ignore_ascii_case("ed25519") {
                return None;
            }
            // NB: this crate has no `tracing` dep by design; the controller's
            // `aegix-engine` wrapper logs a missing or unparsable seed loudly
            // at boot.
            configured_controller_signing_key().map(DispatchSigner::Ed25519)
        })
        .clone()
}

/// Per-worker Ed25519 **result-verifying** key registry, parsed once from
/// `AEGIX_WORKER_PUBLIC_KEYS` (RFC 0010 P2). Format: comma-separated
/// `worker_id=hex32` pairs; a `worker_id` MAY repeat to publish several keys
/// (rotation / blue-green rollout), and every key registered for that id is
/// tried at verify time. Malformed or empty entries are skipped (that entry
/// fails closed) rather than poisoning the whole registry — one bad line can't
/// strand the fleet. An unknown `worker_id` yields an empty slice, so
/// `verify_dispatch` fails closed because no key matches.
///
/// The controller holds only worker *public* keys, so it can verify a
/// worker-signed result but cannot forge one — the asymmetric half of the
/// result-path trust boundary, mirroring the worker holding only the
/// controller's public key on the dispatch path.
type WorkerKeyMap = std::collections::HashMap<String, Vec<DispatchVerifyingKey>>;

/// The env-parsed base registry (`AEGIX_WORKER_PUBLIC_KEYS`), parsed exactly
/// once. Immutable; the dynamic (DB-backed, RFC 0010 P2 inc.4) overlay is merged
/// on top of a clone of this by [`set_dynamic_worker_public_keys`].
fn env_worker_public_key_registry() -> &'static WorkerKeyMap {
    static ENV: std::sync::OnceLock<WorkerKeyMap> = std::sync::OnceLock::new();
    ENV.get_or_init(|| {
        std::env::var("AEGIX_WORKER_PUBLIC_KEYS")
            .map(|raw| parse_worker_public_keys(&raw))
            .unwrap_or_default()
    })
}

/// The live verifying-key snapshot readers hit on the hot `verify_dispatch` path.
/// Seeded lazily from the env registry — so a worker (which never installs a
/// dynamic overlay) keeps pure env-only behaviour — and atomically replaced by
/// the controller's refresh task via [`set_dynamic_worker_public_keys`].
///
/// `ArcSwap` gives lock-free O(1) reads on the verify hot path and an atomic
/// pointer swap on refresh (no reader ever blocks on a writer), the same shape
/// `rpc_auth` uses for its rotating nonce cache.
fn worker_public_key_snapshot() -> &'static arc_swap::ArcSwap<WorkerKeyMap> {
    static SNAP: std::sync::OnceLock<arc_swap::ArcSwap<WorkerKeyMap>> = std::sync::OnceLock::new();
    SNAP.get_or_init(|| arc_swap::ArcSwap::from_pointee(base_worker_public_key_registry()))
}

/// The `worker_id` the controller signs its OWN data-plane RPCs under
/// (2026-10-29): the in-process rehearsal runtime behind `run_sandbox` and
/// `test_module` runs no dispatch, so its memory and state calls carry no
/// dispatch binding and are admitted on this identity instead. Reserved:
/// [`validate_worker_id`] refuses it, so no worker registers or boots as it,
/// and the env ring and the DB overlay never carry it.
pub const CONTROLLER_RPC_IDENTITY: &str = "talos-controller";

/// The controller's own RPC verifying key, installed once at boot by
/// [`register_controller_rpc_verifying_key`]. A worker never sets it.
static CONTROLLER_RPC_KEY: std::sync::OnceLock<DispatchVerifyingKey> = std::sync::OnceLock::new();

/// `union(env registry, the controller's own key)`: what every snapshot is
/// rebuilt from, so the controller's identity survives each dynamic refresh.
fn base_worker_public_key_registry() -> WorkerKeyMap {
    let mut base = env_worker_public_key_registry().clone();
    base.remove(CONTROLLER_RPC_IDENTITY);
    if let Some(vk) = CONTROLLER_RPC_KEY.get() {
        base.insert(CONTROLLER_RPC_IDENTITY.to_string(), vec![*vk]);
    }
    base
}

/// **Controller-only.** Install the verifying half of the controller's own
/// RPC signing identity under [`CONTROLLER_RPC_IDENTITY`], so the RPC
/// subscribers in this process (and, when the key is the configured
/// `AEGIX_CONTROLLER_SIGNING_KEY`, in every replica) resolve it. First
/// registration wins; returns whether this call installed it.
pub fn register_controller_rpc_verifying_key(vk: DispatchVerifyingKey) -> bool {
    if CONTROLLER_RPC_KEY.set(vk).is_err() {
        return false;
    }
    let mut merged = (**worker_public_key_snapshot().load()).clone();
    merged.remove(CONTROLLER_RPC_IDENTITY);
    if let Some(vk) = CONTROLLER_RPC_KEY.get() {
        merged.insert(CONTROLLER_RPC_IDENTITY.to_string(), vec![*vk]);
    }
    worker_public_key_snapshot().store(std::sync::Arc::new(merged));
    true
}

/// **Controller-only.** Replace the dynamic worker-key overlay with `dynamic`,
/// rebuilding the live snapshot as `union(env static registry, dynamic)` and
/// atomically swapping it in. Full-replacement (NOT additive): each call rebuilds
/// from the immutable env base, so a key that was deactivated in the DB and hence
/// dropped from `dynamic` disappears from the snapshot on the next refresh — the
/// controller's refresh task passes the complete active DB set every interval.
///
/// Env-registered keys always survive (they are the operator-pinned base);
/// dynamic keys byte-identical to an env key are de-duplicated so a worker whose
/// key is in both places is not verified against twice. The worker never calls
/// this, so its behaviour is unchanged. Idempotent and safe to call repeatedly.
pub fn set_dynamic_worker_public_keys(
    dynamic: impl IntoIterator<Item = (String, DispatchVerifyingKey)>,
) {
    let mut merged = base_worker_public_key_registry();
    for (worker_id, vk) in dynamic {
        // A row under the controller's reserved id cannot be registered
        // (`validate_worker_id`); one that exists anyway names no worker.
        if worker_id == CONTROLLER_RPC_IDENTITY {
            continue;
        }
        let slot = merged.entry(worker_id).or_default();
        if !slot
            .iter()
            .any(|existing| existing.to_bytes() == vk.to_bytes())
        {
            slot.push(vk);
        }
    }
    worker_public_key_snapshot().store(std::sync::Arc::new(merged));
}

/// Pure parser for the `AEGIX_WORKER_PUBLIC_KEYS` value — extracted from
/// [`worker_public_key_registry`] so the skip-malformed / repeat-id-for-rotation
/// behaviour is unit-testable without mutating process env. See that function
/// for the format and fail-closed semantics.
fn parse_worker_public_keys(
    raw: &str,
) -> std::collections::HashMap<String, Vec<DispatchVerifyingKey>> {
    let mut map: std::collections::HashMap<String, Vec<DispatchVerifyingKey>> =
        std::collections::HashMap::new();
    for entry in raw.split(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let Some((wid, hexk)) = entry.split_once('=') else {
            continue;
        };
        let wid = wid.trim();
        if wid.is_empty() {
            continue;
        }
        let Ok(vk) = parse_ed25519_verifying_key_hex(hexk) else {
            continue;
        };
        map.entry(wid.to_string()).or_default().push(vk);
    }
    map
}

/// Ed25519 result-verifying key(s) registered for `worker_id` (possibly several,
/// for rotation). Reads the live snapshot = `union(env registry, dynamic DB
/// overlay)`. Empty when the worker is unknown or no key is registered anywhere —
/// `JobResult::verify_dispatch` then fails closed on an Ed25519-scheme result.
/// Lock-free; see [`worker_public_key_snapshot`] / [`set_dynamic_worker_public_keys`].
#[must_use]
pub fn worker_public_keys(worker_id: &str) -> Vec<DispatchVerifyingKey> {
    worker_public_key_snapshot()
        .load()
        .get(worker_id)
        .cloned()
        .unwrap_or_default()
}

/// Enumerate the STATIC operator-pinned worker ring (`AEGIX_WORKER_PUBLIC_KEYS`)
/// as `(worker_id, key_count)` pairs, sorted by `worker_id`.
///
/// Exists because a worker that authenticates off this env ring never calls the
/// self-registration endpoint, so it owns NO `worker_identities` row and is
/// structurally invisible to every DB-backed fleet view — the dev stack's only
/// worker was missing from `get_platform_info.fleet` for exactly this reason.
/// Reporting surfaces merge this list in so "no rows" can mean "no workers"
/// rather than "no workers I happen to look at".
///
/// **Never returns key bytes.** A verifying key is public, but an operator API
/// has no use for 64 hex chars per worker: the only diagnostic question the ring
/// answers is *which ids does this controller trust, and is one of them carrying
/// a rotation overlap* — `key_count` says that. Widening this to the key
/// material would hand every reader a fingerprint of the trust root for zero
/// added answer.
///
/// Reads the immutable ENV base registry ONLY, never the live snapshot: the
/// dynamic overlay is the DB-registered set, which the caller already lists from
/// the repository. Mixing them here would double-count a registered worker as
/// static.
#[must_use]
pub fn static_worker_ring() -> Vec<(String, usize)> {
    summarize_worker_ring(env_worker_public_key_registry())
}

/// Whether the STATIC operator-pinned ring (`AEGIX_WORKER_PUBLIC_KEYS`) holds
/// `public_key` for `worker_id`. Reads the immutable env base only, like
/// [`static_worker_ring`]: the NATS auth callout admits a pinned key by this,
/// and reads the database itself for a registered one, so a key deactivated in
/// the database is refused at once rather than at the next overlay refresh.
#[must_use]
pub fn static_worker_ring_holds(worker_id: &str, public_key: &[u8; 32]) -> bool {
    env_worker_public_key_registry()
        .get(worker_id)
        .is_some_and(|keys| keys.iter().any(|k| &k.to_bytes() == public_key))
}

/// Pure half of [`static_worker_ring`], split out so the summarisation (and its
/// tolerance for whatever [`parse_worker_public_keys`] admits) is unit-testable
/// without mutating process env — the env registry is a `OnceLock` and cannot be
/// re-parsed per test.
fn summarize_worker_ring(map: &WorkerKeyMap) -> Vec<(String, usize)> {
    let mut out: Vec<(String, usize)> = map
        .iter()
        .map(|(worker_id, keys)| (worker_id.clone(), keys.len()))
        .collect();
    // HashMap iteration order is nondeterministic; the report must not reshuffle
    // itself between two calls on identical input.
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Whether the controller still accepts legacy-HMAC-signed job results.
/// Default `true` (accept — the rollout posture while workers migrate to
/// per-worker Ed25519). `AEGIX_RESULT_REQUIRE_ED25519` ∈ {`1`,`true`,`yes`,`on`}
/// flips it to `false`: the RFC 0010 P4 enforcement flip that refuses HMAC
/// results once every worker signs Ed25519. Cached; single source of truth for
/// the `accept_legacy_hmac` argument at every controller result-verify site.
#[must_use]
pub fn result_accept_legacy_hmac() -> bool {
    static CACHE: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    // allow-inline-env-bool: this crate carries no aegix-config/tracing dependency
    // by design (it is the wire protocol both binaries share); the truthy set below
    // is pinned equal to aegix_deploy_posture::bool_env\'s by `result_require_flag_spellings`.
    *CACHE.get_or_init(|| {
        !matches!(
            std::env::var("AEGIX_RESULT_REQUIRE_ED25519")
                .ok()
                .as_deref(),
            Some("1" | "true" | "yes" | "on")
        )
    })
}

/// **Why** a signed message failed verification — the axis an operator needs.
///
/// A signature that verifies cryptographically but arrived outside its freshness
/// window is a **liveness** failure (the sender stalled, or the two hosts'
/// clocks disagree). A signature that does not verify is a **security** failure.
/// Before this split, both surfaced as "signature verification failed", which
/// sent operators hunting an attacker after a host suspend froze the fleet
/// (2026-08-20/24: six executions, two clusters, ages 902–919 s, every one a
/// valid signature).
///
/// Fail-closed is unchanged: every variant is still a REJECTION. This type only
/// says which kind of rejection it was.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VerifyFailureKind {
    /// Nonce parsed, timestamp older than `max_age_secs`. The signature itself
    /// was never reached — but a message this old is *usually* a stall, not an
    /// attack, because a forger has no reason to send a stale nonce.
    /// **LIVENESS.**
    Stale,
    /// Nonce timestamp is ahead of this host's clock by more than
    /// [`MAX_FUTURE_SKEW_SECS`]. **LIVENESS** (clock skew), though it is also
    /// what a naive replay-forward would look like.
    ClockSkewAhead,
    /// Nonce is not `"<unix_secs>:<hex>"`. **SECURITY** — a stalled sender still
    /// emits a well-formed nonce.
    MalformedNonce,
    /// MAC / Ed25519 mismatch, no key in the ring matched, or the message's
    /// crypto scheme is refused/unknown. **SECURITY.**
    BadSignature,
    /// The nonce was already recorded inside the replay window. **SECURITY.**
    Replay,
    /// Local key material could not be loaded. **OPERATIONAL** — neither the
    /// peer's liveness nor its honesty is in question.
    KeyError,
    /// The message's `crypto_scheme` is unknown, or is legacy HMAC while
    /// Ed25519-only enforcement is on. **OPERATIONAL/version skew** — kept
    /// separate from [`Self::BadSignature`] because the operator action is a
    /// controller/worker version or flag reconciliation, not an investigation.
    SchemeRefused,
}

impl VerifyFailureKind {
    /// `true` when the message was well-formed and the failure is about WHEN it
    /// arrived rather than WHO sent it. Operators should read a `true` here as
    /// "the fleet or a clock is unhealthy", never as "someone tampered".
    #[must_use]
    pub fn is_liveness(self) -> bool {
        matches!(self, Self::Stale | Self::ClockSkewAhead)
    }

    /// Closed, bounded label set for metrics / structured logs. Never contains
    /// a nonce, a signature, a key, or any payload — only the class.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Stale => "stale",
            Self::ClockSkewAhead => "clock_skew_ahead",
            Self::MalformedNonce => "malformed_nonce",
            Self::BadSignature => "bad_signature",
            Self::Replay => "replay",
            Self::KeyError => "key_error",
            Self::SchemeRefused => "scheme_refused",
        }
    }

    /// Every label this enum can ever emit. Use it to pre-seed a metric's label
    /// set so an absent series is distinguishable from a zero one
    /// (`absent-is-not-zero`).
    pub const ALL: &'static [Self] = &[
        Self::Stale,
        Self::ClockSkewAhead,
        Self::MalformedNonce,
        Self::BadSignature,
        Self::Replay,
        Self::KeyError,
        Self::SchemeRefused,
    ];
}

/// A verification rejection: the byte-stable operator message PLUS the typed
/// reason it was produced for.
///
/// `Display` renders exactly the string the pre-split code returned, so every
/// existing `format!("…: {e}")` call site and every test that matches on the
/// message text is byte-identical. New call sites read [`Self::kind`] instead of
/// parsing the text — deriving a classification by string-sniffing is the defect
/// this type exists to avoid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyError {
    kind: VerifyFailureKind,
    message: String,
    age_secs: Option<u64>,
}

impl VerifyError {
    /// Build a rejection with an explicit reason. Exposed so downstream crates
    /// (and their tests) can synthesise a rejection whose class is known,
    /// instead of matching on prose.
    #[must_use]
    pub fn from_parts(
        kind: VerifyFailureKind,
        message: impl Into<String>,
        age_secs: Option<u64>,
    ) -> Self {
        Self {
            kind,
            message: message.into(),
            age_secs,
        }
    }

    pub(crate) fn new(kind: VerifyFailureKind, message: String) -> Self {
        Self {
            kind,
            message,
            age_secs: None,
        }
    }

    pub(crate) fn with_age(kind: VerifyFailureKind, message: String, age_secs: u64) -> Self {
        Self {
            kind,
            message,
            age_secs: Some(age_secs),
        }
    }

    /// The typed reason. Branch on this, never on the message text.
    #[must_use]
    pub fn kind(&self) -> VerifyFailureKind {
        self.kind
    }

    /// `true` for a well-formed message that arrived at the wrong TIME.
    #[must_use]
    pub fn is_liveness(&self) -> bool {
        self.kind.is_liveness()
    }

    /// How far outside the window the message was, in seconds, when that is the
    /// reason it was rejected. An age is not a secret and is the one number that
    /// tells an operator how long the stall was.
    #[must_use]
    pub fn age_secs(&self) -> Option<u64> {
        self.age_secs
    }
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for VerifyError {}

impl From<VerifyError> for String {
    fn from(e: VerifyError) -> Self {
        e.message
    }
}

/// The phrase every LIVENESS rejection headline contains, and no other headline
/// does.
///
/// Downstream classifiers (notably the ops-alert `classify_execution_error`)
/// only ever see the rendered `error_message` string from the database, so they
/// cannot read [`VerifyFailureKind`]. Sharing this constant makes that coupling
/// explicit and compile-checked at both ends instead of leaving two
/// independently-maintained literals to drift.
pub const LIVENESS_REJECTION_MARKER: &str = "rejected on AGE, before its signature was evaluated";

/// Operator-facing headline for a rejected signed message, split so that a
/// LIVENESS failure never reads as tampering. **Constant strings only** — this
/// carries no bytes derived from the rejected message, so it is safe to place
/// in a payload the receiver will sign and publish after refusing an
/// UNAUTHENTICATED request. Use [`describe_verify_failure`] wherever the
/// protocol detail is also wanted (logs, controller-side error messages).
///
/// `noun` names the thing that was rejected ("Job result", "Job dispatch").
///
/// **Deliberately does NOT claim the signature was valid.** The freshness check
/// runs BEFORE the signature check ([`SignedMessage::verify_no_replay_core`]),
/// so on a `Stale` rejection the signature was never evaluated. Saying "valid
/// but stale" would be a new instance of exactly the defect this split fixes:
/// a message asserting something it did not measure.
#[must_use]
pub fn verify_failure_headline(noun: &str, kind: VerifyFailureKind) -> String {
    match kind {
        VerifyFailureKind::Stale => format!(
            "{noun} arrived outside its freshness window and was \
             {LIVENESS_REJECTION_MARKER} — this is a liveness failure \
             (sender/receiver stall, paused host, or clock skew), not tampering"
        ),
        VerifyFailureKind::ClockSkewAhead => format!(
            "{noun} carries a timestamp ahead of this host's clock and was \
             {LIVENESS_REJECTION_MARKER} — check clock sync between controller \
             and workers"
        ),
        VerifyFailureKind::KeyError => {
            format!("{noun} could not be verified — local key material problem")
        }
        VerifyFailureKind::SchemeRefused => format!(
            "{noun} was refused on its crypto scheme, not on its signature — \
             reconcile controller/worker versions and the Ed25519 enforcement flag"
        ),
        VerifyFailureKind::Replay
        | VerifyFailureKind::BadSignature
        | VerifyFailureKind::MalformedNonce => {
            format!("{noun} signature verification failed")
        }
    }
}

/// Coarse, actionable CLASS of a rejected signed message, derived from the
/// verifier's own [`VerifyFailureKind`] and **never** from its prose.
///
/// This is the token the worker puts in a rejection payload's `reason_class`
/// (see `signature_failure_payload`) and the token
/// [`JobResult::is_pre_execution_rejection`] matches against. It lived as a
/// private `classify_verify_failure` in `worker/src/main.rs` until 2026-09-23,
/// when the controller's dispatcher became a second reader: the receiver
/// decides the class, the sender-side retry policy acts on it, and two copies
/// of that mapping drifting apart is a retry decision taken on a class that no
/// longer means what the reader thinks. So there is one.
///
/// Each token implies a DIFFERENT operator action, which is why they must not
/// collapse: `key_config` is a deploy/env fault, `scheme_mismatch` is
/// controller/worker version skew, `replay` is a nonce-cache interaction,
/// `stale_timestamp` is a LIVENESS failure, and `mismatch` is a genuine
/// signing-payload divergence.
///
/// **Not to be confused with `aegix_wasm_host::reason_class`**, a
/// different namespace stamped as a `[reason_class=<token>]` marker INSIDE an
/// error string for host-call failures (`dns`, `tls`, `cancelled`, …) and read
/// by `aegix_retry_intelligence::classify_error`. That one describes a call the
/// module made; this one describes a message the receiver refused. They never
/// collide — this is a top-level JSON key, that one is text inside a value —
/// but they answer different questions and must not be read for each other.
#[must_use]
pub fn verify_failure_class(kind: VerifyFailureKind) -> &'static str {
    match kind {
        VerifyFailureKind::Replay => "replay",
        VerifyFailureKind::SchemeRefused => "scheme_mismatch",
        VerifyFailureKind::KeyError => "key_config",
        VerifyFailureKind::Stale | VerifyFailureKind::ClockSkewAhead => {
            VERIFY_CLASS_STALE_TIMESTAMP
        }
        VerifyFailureKind::BadSignature | VerifyFailureKind::MalformedNonce => "mismatch",
        // NO `_` arm, and that is the one behavioural gain from the move.
        // `VerifyFailureKind` is `#[non_exhaustive]`, so the worker's copy
        // NEEDED a catch-all and a new variant silently became "mismatch" —
        // i.e. read as tampering, the exact collapse the token set exists to
        // prevent. `#[non_exhaustive]` does not apply inside the defining
        // crate, so here the match is EXHAUSTIVE: a new variant fails to
        // compile until someone gives it a token, and the compiler enumerates
        // the population instead of a comment asking politely.
    }
}

/// [`verify_failure_class`] for a message rejected on AGE — the one class that
/// means "the receiver refused this dispatch as a LIVENESS failure".
pub const VERIFY_CLASS_STALE_TIMESTAMP: &str = "stale_timestamp";

/// The CLOSED set of [`verify_failure_class`] tokens for which a rejected
/// dispatch may be re-sent.
///
/// Membership requires BOTH halves, and the second is why the set is this
/// small rather than "everything the receiver refused before running":
///
/// * **safe** — the receiver refused the message before the module could run,
///   so a re-dispatch cannot duplicate a side effect; and
/// * **useful** — re-sending fixes the condition. A re-sign mints a fresh
///   nonce, and the nonce carries the timestamp the freshness window is
///   measured from (see `check_freshness_window`), so a message refused for
///   being too old is refused for a property the re-send changes.
///
/// Deliberately EXCLUDED, each for its own reason:
/// * `replay` — the receiver has already SEEN this nonce, which is evidence a
///   previous attempt was accepted and may have run. Re-sending is precisely
///   what the nonce cache exists to stop.
/// * `mismatch` — a security event; re-sending re-admits the same forgery.
/// * `key_config` / `scheme_mismatch` — deterministic deploy faults. The module
///   did not run, so re-sending is *safe*, but identical bytes get an identical
///   refusal: it would burn the allowance and change nothing.
pub const PRE_EXECUTION_REJECTION_CLASSES: &[&str] = &[VERIFY_CLASS_STALE_TIMESTAMP];

/// [`verify_failure_headline`] plus the byte-stable protocol detail.
///
/// The detail can contain a value taken from the rejected message (the
/// `crypto_scheme` byte, the observed age), so this belongs in logs and in
/// controller-side error messages — NOT in a payload that gets signed and
/// republished in response to an unauthenticated request.
#[must_use]
pub fn describe_verify_failure(noun: &str, e: &VerifyError) -> String {
    format!("{}: {e}", verify_failure_headline(noun, e.kind()))
}

/// Crate-private core shared by every signed NATS message type.
///
/// Implementors provide the canonical signing payload plus nonce/signature
/// field access; the provided methods implement sign, HMAC+freshness
/// verification, replay-cache recording, and key-ring rotation support
/// exactly once for all five message types.
trait SignedMessage {
    /// The nonce field's name as it appears in every error string
    /// (`"job_nonce"` / `"result_nonce"` / `"heartbeat_nonce"`).
    /// Error messages are byte-for-byte stable — callers and tests
    /// match on them (e.g. `"result_nonce already seen"`).
    const NONCE_LABEL: &'static str;

    /// Canonical byte string signed / verified by HMAC-SHA256. Forwards to
    /// the type's inherent `signing_payload()` — the append-only,
    /// wire-format-stable payload construction stays per-type and untouched.
    fn payload_bytes(&self) -> Vec<u8>;

    /// The nonce field (`"{unix_secs}:{random_hex}"`).
    fn nonce(&self) -> &str;

    /// Set the nonce field (called by [`Self::sign_core`]).
    fn set_nonce(&mut self, nonce: String);

    /// The HMAC-SHA256 signature field.
    fn signature(&self) -> &[u8];

    /// Set the signature field (called by [`Self::sign_core`]).
    fn set_signature(&mut self, signature: Vec<u8>);

    /// Structural precondition every verify path checks BEFORE touching the
    /// nonce or the signature. Default: nothing to check.
    ///
    /// The result types override this to run [`validate_worker_id`] on the
    /// RECEIVED `worker_id`. Until 2026-09-10 that charset rule was enforced
    /// only at SIGN time (`sign_with_worker_id`), i.e. only against a worker
    /// that was already honest. `worker_id` is the last UNPREFIXED field in
    /// the result signing payload and the `:llm_usage:<hash>` segment is
    /// conditionally appended right after it, so a forged
    /// `worker_id = "w1:llm_usage:<h>"` on a result with EMPTY `llm_usage`
    /// produced byte-identical signing bytes to an honest `worker_id = "w1"`
    /// carrying the usage that hashes to `<h>` — one valid MAC, two readings
    /// of the payload. Refusing the ambiguous shape at the verifier closes it
    /// with no wire change. Classed as [`VerifyFailureKind::BadSignature`]:
    /// it is a SECURITY finding about the message, not a liveness one.
    fn check_payload_shape(&self) -> Result<(), VerifyError> {
        Ok(())
    }

    /// Shared signing core: build a fresh nonce
    /// (`"<unix_seconds>:<16 random hex bytes>"`), then HMAC-SHA256 the
    /// canonical payload with the pre-shared `key`. Sets both fields.
    fn sign_core(&mut self, key: &[u8]) -> Result<(), String> {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = aegix_random::bytes::<16>();
        self.set_nonce(format!("{}:{}", ts, hex::encode(rand_bytes)));

        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key)
            .map_err(|e| format!("HMAC key error: {e}"))?;
        mac.update(&self.payload_bytes());
        self.set_signature(mac.finalize().into_bytes().to_vec());
        Ok(())
    }

    /// Nonce parse + freshness window (past `max_age_secs`, future
    /// `MAX_FUTURE_SKEW_SECS`). Signature-scheme-independent, so BOTH the HMAC
    /// and the Ed25519 verify paths build on it — the replay/freshness discipline
    /// is identical across schemes; only the signature primitive differs.
    /// Returns the parsed nonce timestamp on success.
    ///
    /// Check order is timestamp-parse before hex-validation. (Pre-refactor the
    /// since-removed `PipelineJobResult` alone checked hex first — accidental
    /// drift; the orders are otherwise equivalent, differing only in WHICH
    /// error string is returned for a nonce malformed in both ways at once.)
    fn check_freshness_window(&self, max_age_secs: u64) -> Result<u64, VerifyError> {
        if self.nonce().len() > MAX_SIGNED_NONCE_LEN {
            return Err(VerifyError::new(
                VerifyFailureKind::MalformedNonce,
                format!("oversized {}", Self::NONCE_LABEL),
            ));
        }
        let parts: Vec<&str> = self.nonce().splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(VerifyError::new(
                VerifyFailureKind::MalformedNonce,
                format!("malformed {}", Self::NONCE_LABEL),
            ));
        }
        let ts: u64 = parts[0].parse().map_err(|_| {
            VerifyError::new(
                VerifyFailureKind::MalformedNonce,
                format!("invalid timestamp in {}", Self::NONCE_LABEL),
            )
        })?;
        if hex::decode(parts[1]).is_err() {
            return Err(VerifyError::new(
                VerifyFailureKind::MalformedNonce,
                format!("invalid hex in {}", Self::NONCE_LABEL),
            ));
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        if now.saturating_sub(ts) > max_age_secs {
            let age = now.saturating_sub(ts);
            // LIVENESS, not tampering: the signature has not even been checked
            // yet. See `VerifyFailureKind::Stale`.
            return Err(VerifyError::with_age(
                VerifyFailureKind::Stale,
                format!(
                    "{} is too old ({} s, max {})",
                    Self::NONCE_LABEL,
                    age,
                    max_age_secs
                ),
                age,
            ));
        }
        if ts.saturating_sub(now) > MAX_FUTURE_SKEW_SECS {
            let ahead = ts.saturating_sub(now);
            return Err(VerifyError::with_age(
                VerifyFailureKind::ClockSkewAhead,
                format!(
                    "{} is in the future ({} s ahead, max {})",
                    Self::NONCE_LABEL,
                    ahead,
                    MAX_FUTURE_SKEW_SECS
                ),
                ahead,
            ));
        }
        Ok(ts)
    }

    /// Shared verify-without-replay-recording core: freshness window +
    /// constant-time HMAC. **Never touches the replay cache** — this is the
    /// observer half of the verify-once split. Returns the parsed nonce
    /// timestamp on success.
    fn verify_no_replay_core(&self, key: &[u8], max_age_secs: u64) -> Result<u64, VerifyError> {
        self.check_payload_shape()?;
        let ts = self.check_freshness_window(max_age_secs)?;
        self.check_hmac(key)?;
        Ok(ts)
    }

    /// The constant-time HMAC check alone, over [`Self::payload_bytes`].
    fn check_hmac(&self, key: &[u8]) -> Result<(), VerifyError> {
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).map_err(|e| {
            VerifyError::new(VerifyFailureKind::KeyError, format!("HMAC key error: {e}"))
        })?;
        mac.update(&self.payload_bytes());
        mac.verify_slice(self.signature()).map_err(|_| {
            VerifyError::new(
                VerifyFailureKind::BadSignature,
                "HMAC signature verification failed".to_string(),
            )
        })
    }

    /// The signature alone, against each ring member: no freshness window and
    /// no replay cache. See [`JobRequest::verify_signature_only_dispatch`],
    /// the one caller, for what this may and may not be used for.
    fn signature_only_with_ring_core(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
    ) -> Result<(), VerifyError> {
        self.check_payload_shape()?;
        let mut keys = ring.verify_keys().iter();
        let signing = keys.next().expect("WorkerKeyRing is never empty");
        let signing_err = match self.check_hmac(signing.as_bytes()) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        };
        for prev in keys {
            if self.check_hmac(prev.as_bytes()).is_ok() {
                return Ok(());
            }
        }
        Err(signing_err)
    }

    /// The Ed25519 signature alone: no freshness window and no replay cache.
    fn signature_only_ed25519_core(
        &self,
        keys: &[DispatchVerifyingKey],
    ) -> Result<(), VerifyError> {
        self.check_payload_shape()?;
        self.check_ed25519(keys)
    }

    /// Canonical bytes signed / verified under the Ed25519 dispatch scheme: the
    /// type's HMAC `payload_bytes()` plus [`ED25519_DISPATCH_DOMAIN_TAG`]. The
    /// domain tag means an Ed25519 signature and an HMAC over "the same" message
    /// commit to different bytes — no cross-scheme confusion — and binds the
    /// scheme/version.
    fn ed25519_signing_input(&self) -> Vec<u8> {
        let mut v = self.payload_bytes();
        v.extend_from_slice(ED25519_DISPATCH_DOMAIN_TAG);
        v
    }

    /// Ed25519 signing core: fresh nonce + Ed25519 signature over
    /// [`Self::ed25519_signing_input`] with the controller's private key. Sets
    /// both the nonce and the (64-byte) signature field. The nonce is set FIRST
    /// so it is covered by the signature (it is part of `payload_bytes`).
    fn sign_core_ed25519(&mut self, signing_key: &DispatchSigningKey) -> Result<(), String> {
        use ed25519_dalek::Signer;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("system time error: {e}"))?
            .as_secs();
        let rand_bytes: [u8; 16] = aegix_random::bytes::<16>();
        self.set_nonce(format!("{}:{}", ts, hex::encode(rand_bytes)));
        let sig = signing_key.sign(&self.ed25519_signing_input());
        self.set_signature(sig.to_bytes().to_vec());
        Ok(())
    }

    /// Ed25519 verify-without-replay: freshness window + Ed25519 signature check
    /// against each provided controller public key (first match wins, so a
    /// rotated controller key with an overlap window verifies). Uses
    /// `verify_strict` (rejects non-canonical `R`/small-order points). Touches
    /// no replay cache. Returns the parsed nonce timestamp on success.
    fn verify_no_replay_ed25519_core(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<u64, VerifyError> {
        self.check_payload_shape()?;
        let ts = self.check_freshness_window(max_age_secs)?;
        self.check_ed25519(keys)?;
        Ok(ts)
    }

    /// The Ed25519 signature check alone, over
    /// [`Self::ed25519_signing_input`]: first matching key wins.
    fn check_ed25519(&self, keys: &[DispatchVerifyingKey]) -> Result<(), VerifyError> {
        if keys.is_empty() {
            return Err(VerifyError::new(
                VerifyFailureKind::KeyError,
                "no controller Ed25519 verifying key configured".to_string(),
            ));
        }
        let sig = ed25519_dalek::Signature::from_slice(self.signature()).map_err(|_| {
            VerifyError::new(
                VerifyFailureKind::BadSignature,
                "malformed Ed25519 signature".to_string(),
            )
        })?;
        let input = self.ed25519_signing_input();
        for k in keys {
            if k.verify_strict(&input, &sig).is_ok() {
                return Ok(());
            }
        }
        Err(VerifyError::new(
            VerifyFailureKind::BadSignature,
            "Ed25519 signature verification failed".to_string(),
        ))
    }

    /// Ed25519 primary-verifier core: [`Self::verify_no_replay_ed25519_core`]
    /// plus replay-cache recording (verify-once). Records the nonce exactly once,
    /// only after a key matches.
    fn verify_ed25519_core(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<(), VerifyError> {
        let ts = self.verify_no_replay_ed25519_core(keys, max_age_secs)?;
        self.record_nonce_or_replay_err(ts, max_age_secs)
    }

    /// Record the (already HMAC+freshness-verified) nonce in the
    /// process-local replay cache, or fail with the byte-stable
    /// `"<nonce> already seen"` replay error. This is the ONLY place the
    /// shared core inserts into `JOB_NONCE_CACHE`.
    fn record_nonce_or_replay_err(&self, ts: u64, max_age_secs: u64) -> Result<(), VerifyError> {
        // Replay protection: refuse a nonce we have seen before within
        // the freshness window. HMAC alone catches forgery; without
        // this check, anyone with NATS-publish access can capture a
        // signed message and re-fire it any number of times until
        // ts + max_age_secs expires.
        match check_and_record_job_nonce(self.nonce(), ts, max_age_secs) {
            NonceAdmission::Fresh => Ok(()),
            NonceAdmission::Replay => Err(VerifyError::new(
                VerifyFailureKind::Replay,
                format!(
                    "{} already seen (replay attempt within {}-second window)",
                    Self::NONCE_LABEL,
                    max_age_secs
                ),
            )),
            // Classed with Replay (the replay guard refused it); the message
            // says why, so it is not mistaken for a duplicate.
            NonceAdmission::CacheFull => Err(VerifyError::new(
                VerifyFailureKind::Replay,
                format!(
                    "{} refused: replay cache full ({} live entries) — failing closed",
                    Self::NONCE_LABEL,
                    NONCE_CACHE_HARD_CAP
                ),
            )),
        }
    }

    /// Shared primary-verifier core: [`Self::verify_no_replay_core`] plus
    /// replay-cache recording. Exactly one primary caller per signed
    /// message per process (verify-once rule).
    fn verify_core(&self, key: &[u8], max_age_secs: u64) -> Result<(), VerifyError> {
        let ts = self.verify_no_replay_core(key, max_age_secs)?;
        self.record_nonce_or_replay_err(ts, max_age_secs)
    }

    /// Ring variant of [`Self::verify_no_replay_core`]: HMAC+freshness
    /// against the signing key first, then each staged previous key; first
    /// match wins. Returns the signing-key error if all fail. Touches no
    /// replay cache — which is what makes the multi-key loop safe (a naive
    /// `for k { self.verify(k) }` would insert the nonce on the first
    /// attempt and spuriously fail the second key as a replay).
    fn verify_no_replay_with_ring_core(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<u64, VerifyError> {
        let mut keys = ring.verify_keys().iter();
        let signing = keys.next().expect("WorkerKeyRing is never empty");
        let signing_err = match self.verify_no_replay_core(signing.as_bytes(), max_age_secs) {
            Ok(ts) => return Ok(ts),
            Err(e) => e,
        };
        for prev in keys {
            if let Ok(ts) = self.verify_no_replay_core(prev.as_bytes(), max_age_secs) {
                return Ok(ts);
            }
        }
        Err(signing_err)
    }

    /// Sign with a nonce timestamp `age_secs` in the PAST, producing a message
    /// whose HMAC is genuinely valid over that back-dated nonce.
    ///
    /// This is the only way to build the real-world shape — a correctly signed
    /// message that has since aged out — because the nonce is part of the
    /// signed payload, so merely rewriting the timestamp of an already-signed
    /// message breaks the MAC and no longer proves anything about staleness.
    /// Test-only: production signing always mints a nonce at `now`.
    #[cfg(test)]
    fn sign_backdated_for_test(&mut self, key: &[u8], age_secs: u64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_secs();
        self.set_nonce(format!(
            "{}:{}",
            now.saturating_sub(age_secs),
            hex::encode([7u8; 16])
        ));
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key).expect("HMAC key");
        mac.update(&self.payload_bytes());
        self.set_signature(mac.finalize().into_bytes().to_vec());
    }

    /// Ring variant of [`Self::verify_core`]: the nonce is recorded exactly
    /// once, only after a ring member matches.
    fn verify_with_ring_core(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<(), VerifyError> {
        let ts = self.verify_no_replay_with_ring_core(ring, max_age_secs)?;
        self.record_nonce_or_replay_err(ts, max_age_secs)
    }
}

/// Hard cap for the job-nonce replay cache.
///
/// Exposed so health endpoints can report the headroom (`size / cap`)
/// alongside the raw size. The constant lives in this crate to keep a
/// single source of truth.
pub const JOB_NONCE_CACHE_CAPACITY: usize = NONCE_CACHE_HARD_CAP;

#[cfg(test)]
#[allow(dead_code)] // helper for future tests that exercise replay protection
fn clear_job_nonce_cache_for_test() {
    if let Ok(mut g) = JOB_NONCE_CACHE.seen.lock() {
        g.clear();
    }
}

/// Serializes EVERY test in this binary that touches the process-global
/// [`JOB_NONCE_CACHE`] — both the ones that wipe or bulk-fill it and the ones
/// that depend on a nonce they just recorded still being there.
///
/// It lives at crate scope rather than inside
/// `shared_nonce_cache_retention_tests` because the tests it has to serialize
/// against are in a DIFFERENT module. As a module-private static its doc
/// comment claimed to guard "against interleaving with other tests in this
/// binary", and it could not: nothing outside that module could name it. So
/// `clear_job_nonce_cache_for_test` wiped the cache out from under whichever
/// replay test happened to be running in parallel, and its
/// "second verify() on the same nonce must fail" assertion failed — observed
/// intermittently at roughly 1 run in 5 across
/// `ed25519_primary_verify_records_replay`,
/// `job_request_verify_no_replay_does_not_poison_cache` and
/// `worker_heartbeat_verify_no_replay_does_not_poison_cache`, and green under
/// `--test-threads=1`.
///
/// A flaky replay-protection test is worse than a missing one: it trains the
/// reader to re-run rather than to look, on the one assertion that says a
/// captured message cannot be applied twice.
///
/// Locked with `unwrap_or_else(|p| p.into_inner())` everywhere — a panicking
/// test must not poison the mutex and convert one failure into N.
#[cfg(test)]
pub(crate) static NONCE_CACHE_TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// At the hard cap with every entry still live, the cache refuses rather than
/// growing past the cap (pre-fix it swept nothing and inserted anyway).
#[cfg(test)]
#[test]
fn a_full_nonce_cache_fails_closed() {
    let cache = JobNonceCache::new();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    {
        let mut g = cache.seen.lock().unwrap();
        for i in 0..NONCE_CACHE_HARD_CAP {
            g.insert(format!("live-{i}"), now);
        }
    }
    assert_eq!(cache.admit("new", now, 300), NonceAdmission::CacheFull);
    assert_eq!(cache.admit("live-7", now, 300), NonceAdmission::Replay);
    assert_eq!(cache.seen.lock().unwrap().len(), NONCE_CACHE_HARD_CAP);
    // Once the entries age out, the emergency sweep frees room again.
    for t in cache.seen.lock().unwrap().values_mut() {
        *t = now - 10_000;
    }
    assert_eq!(cache.admit("new", now, 300), NonceAdmission::Fresh);
}

/// The shared nonce cache is cross-type: a narrow verifier must never sweep
/// away a wider verifier's live nonces.
///
/// This is not a hypothetical. Until the 2026-08 fix, both sweeps derived
/// their cutoff from the `max_age_secs` of whichever call happened to trigger
/// them, which was sound only while every verifier in the process passed the
/// same window. The controller passed 300 everywhere until the fleet
/// heartbeat began verifying at 60; a 60-second caller then swept at
/// `now - 120`, and a `JobResult` captured off the bus and replayed in the
/// `(120s, 300s]` band passed freshness, passed its MAC, found no cache
/// entry, and was applied a SECOND time. Single-use protection for job
/// results narrowed from 300s to 120s on any controller holding more than
/// 1024 nonces — which is ~1.7 verifies/second sustained, i.e. an ordinary
/// busy controller.
///
/// The test drives the cache directly rather than through a message type
/// because the defect is in the shared cache, not in any one signed type, and
/// because a message-level test would have to fabricate a 150-second-old
/// signature to see it.
#[cfg(test)]
mod shared_nonce_cache_retention_tests {
    use super::*;

    /// Guards the process-global cache + high-water mark against interleaving
    /// with other tests in this binary. The static is crate-scoped
    /// ([`NONCE_CACHE_TEST_SERIAL`]) precisely so that claim is true — a
    /// module-private one could only ever guard this module.
    use super::NONCE_CACHE_TEST_SERIAL as SERIAL;

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
    }

    #[test]
    fn a_narrow_verifier_must_not_evict_a_wider_verifiers_live_nonces() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        clear_job_nonce_cache_for_test();
        let now = now_secs();

        // A JobResult verified under the 300s dispatch window, stamped 150s
        // ago: comfortably INSIDE its own freshness window, so replaying it
        // must still be refused.
        let victim = "victim-job-result-nonce";
        assert!(
            JOB_NONCE_CACHE.check_and_record(victim, now - 150, 300),
            "first observation must be admitted"
        );

        // Push the map past the sweep threshold (the sweep is skipped at or
        // below 1024 entries, which is why the defect needs a busy process).
        for i in 0..1100 {
            JOB_NONCE_CACHE.check_and_record(&format!("filler-{i}"), now, 300);
        }

        // Now the fleet heartbeat verifies under its 60s window. Pre-fix this
        // swept at `now - 120` and took the victim with it.
        assert!(JOB_NONCE_CACHE.check_and_record("heartbeat-nonce", now, 60));

        assert!(
            !JOB_NONCE_CACHE.check_and_record(victim, now - 150, 300),
            "a 60-second verifier swept a 300-second verifier's live nonce: a \
             captured JobResult replayed between 120s and 300s after its \
             timestamp would now be applied twice"
        );
        // Leave the shared cache as we found it: the 1100 fillers are inert
        // (unique keys), but a test that grows a process-global by 1100
        // entries and walks away is how the next reader's size assertion
        // becomes order-dependent.
        clear_job_nonce_cache_for_test();
    }

    /// The same rule on the hard-cap emergency valve, which had the identical
    /// defect one branch down: at 200k entries it re-swept at
    /// `now - max_age_secs`, so a 60-second caller would drop everything
    /// older than 60 seconds. Asserted at the retention level rather than by
    /// allocating 200k entries.
    #[test]
    fn the_retention_window_is_never_narrower_than_the_widest_verifier() {
        let _serial = SERIAL.lock().unwrap_or_else(|p| p.into_inner());
        assert_eq!(
            nonce_retention_secs(60),
            NONCE_RETENTION_FLOOR_SECS,
            "a narrow caller must be lifted to the floor, not honoured"
        );
        assert_eq!(
            nonce_retention_secs(300),
            300,
            "the workspace-wide window is the floor"
        );
        // A wider future caller raises the high-water mark for everyone…
        assert_eq!(nonce_retention_secs(900), 900);
        assert_eq!(
            nonce_retention_secs(60),
            900,
            "…and a narrow caller arriving afterwards still cannot narrow it"
        );
        // …but not without bound, or the sweep would stop reclaiming.
        assert_eq!(
            nonce_retention_secs(u64::MAX),
            NONCE_RETENTION_CEILING_SECS,
            "a pathological window must not disable the sweep"
        );
        // Reset the high-water mark so ordering between tests in this binary
        // stays irrelevant. (Raising it is always SAFE — it can only cost
        // memory — so a leak here would not corrupt another test's result.)
        WIDEST_VERIFY_WINDOW_SECS.store(
            NONCE_RETENTION_FLOOR_SECS,
            std::sync::atomic::Ordering::Relaxed,
        );
    }
}

/// `skip_serializing_if` helpers for zero-default numeric fields —
/// keeps default-valued wire messages byte-identical to the
/// pre-field format (the wire-format stability rule).
///
/// The `&T` signature is REQUIRED by serde: `skip_serializing_if` calls
/// the predicate as `fn(&FieldType) -> bool`. Clippy's
/// `trivially_copy_pass_by_ref` would prefer by-value for these Copy
/// types, but serde's contract dictates the reference — allow it.
fn default_priority() -> u8 {
    100
}

#[cfg(test)]
mod per_worker_signing_key_tests {
    use super::{derive_envelope_aead_key_v1, derive_worker_signing_key, WORKER_SIGNING_KEY_LABEL};

    const ROOT: &[u8] = b"0123456789abcdef0123456789abcdef"; // 32 bytes

    #[test]
    fn deterministic_for_same_inputs() {
        // Worker (sign) and controller (verify) must derive byte-identical keys.
        assert_eq!(
            derive_worker_signing_key(ROOT, "talos-worker-abc-12345"),
            derive_worker_signing_key(ROOT, "talos-worker-abc-12345"),
        );
    }

    #[test]
    fn distinct_per_worker_id() {
        // The whole point: worker-A's key cannot sign as worker-B. Different
        // worker_id ⇒ different key, so a compromised worker holding only its
        // own derived key can't forge worker-B's signatures.
        let a = derive_worker_signing_key(ROOT, "worker-a");
        let b = derive_worker_signing_key(ROOT, "worker-b");
        assert_ne!(a, b, "distinct worker_ids must yield distinct signing keys");
    }

    #[test]
    fn distinct_per_root() {
        // A different fleet root ⇒ different key for the same worker_id.
        let root2: &[u8] = b"ffffffffffffffffffffffffffffffff";
        assert_ne!(
            derive_worker_signing_key(ROOT, "worker-a"),
            derive_worker_signing_key(root2, "worker-a"),
        );
    }

    #[test]
    fn domain_separated_from_envelope_key() {
        // The signing subkey must not collide with the envelope-AEAD subkey
        // derived from the same root — distinct HKDF labels guarantee it. A
        // collision would let an envelope key be used as a signing key or vice
        // versa. (Empty worker_id vs. the v1 envelope's no-info derivation is
        // the closest-adjacent pair; assert they differ.)
        assert_ne!(
            derive_worker_signing_key(ROOT, ""),
            derive_envelope_aead_key_v1(ROOT),
        );
    }

    #[test]
    fn label_is_stable() {
        // The label is part of the wire contract: changing it silently breaks
        // verification fleet-wide (worker signs under new label, controller
        // verifies under old). Pin it so a bump is a deliberate, reviewed change.
        assert_eq!(
            WORKER_SIGNING_KEY_LABEL,
            b"talos/worker-shared-key/per-worker-signing/v1"
        );
    }

    #[test]
    fn empty_worker_id_is_defined() {
        // The back-compat `sign()` wrapper uses an empty worker_id; derivation
        // must be well-defined (not panic) for it even though production uses a
        // real id.
        let k = derive_worker_signing_key(ROOT, "");
        assert_eq!(k.len(), 32);
    }
}

// ============================================================================
// Re-exports of the dispatch types (the vault-path rules that were here are in vault_paths.rs)
// ============================================================================

/// The write-ceiling DECISION, re-exported from its one home in engine-core so
/// the worker's host-function gate and the controller's `__memory_write__`
/// envelope gate answer the same question with the same code (#750).
pub use aegix_dispatch_types::write_ceiling_denies;
/// Re-export so controller + worker can `use aegix_workflow_job_protocol::LlmTier`
/// without pulling engine-core directly. The underlying type lives in
/// engine-core because `DispatchJob` carries it through the dispatch
/// pipeline and engine-core sits below job-protocol in the dep graph.
pub use aegix_dispatch_types::EgressScope;
pub use aegix_dispatch_types::LlmTier;
/// The resolved secret map, `HashMap<String, Zeroizing<String>>`: every value
/// is wiped when dropped. It is the ONE type a secret map has from the store
/// to the worker's slot table — the controller resolves one, the envelope
/// opens into one, the claim client returns one, the runtime takes one. No
/// `HashMap<String, String>` of secrets exists after the AEAD opens
/// (security review 2026-10-15, C-10; structural lint check 107).
pub use aegix_dispatch_types::SecretMap;

/// Test helper: an opened [`SecretMap`] as plain text, so a test can compare
/// it with the fixture it encrypted. Test code only — production never
/// unwraps a whole map.
#[cfg(test)]
pub(crate) fn plain_secret_map(map: &SecretMap) -> HashMap<String, String> {
    map.iter()
        .map(|(k, v)| (k.clone(), v.to_string()))
        .collect()
}
pub use aegix_dispatch_types::WriteCeiling;
/// Re-exported so the worker can name the axis without a direct
/// `aegix-dispatch-types` dependency — `aegix-wasm-host` reaches
/// core only through this crate, and adding that edge to name one enum
/// would invert the layering the rest of the ceiling already respects.
pub use aegix_dispatch_types::{
    effective_write_ceiling, http_verb_ceiling_from_db, write_ceiling_denies_axis, ActorCeilings,
    CeilingAxis,
};
/// RFC 0014 P2: the waiting-is-not-charged arithmetic, re-exported for the
/// worker for the same layering reason as the ceiling items above.
pub use aegix_dispatch_types::{WaitAccounting, LOCAL_INFERENCE_WAIT_CREDIT_CAP_SECS};

// ============================================================================
// Job request / result
// ============================================================================

/// Upper bound on the per-job fuel a worker will honour from
/// [`JobRequest::max_fuel`].
///
/// Mirrors the controller's `aegix_workflow_engine::DEFAULT_MAX_FUEL_PER_NODE`
/// (50 M instructions, ~5 s of dense numeric work) — pinned equal by a test in
/// `aegix-workflow-engine-nats`, the one crate that depends on both. Lives here
/// rather than being imported from the engine because the worker is
/// deliberately engine-free. A worker may LOWER its ceiling via
/// `AEGIX_WORKER_MAX_JOB_FUEL`; it never raises it above what the request
/// asked for. The clamp is defence in depth behind the signature binding: the
/// signed value stops an on-wire rewrite, the clamp stops a mis-capping
/// controller.
pub const MAX_JOB_FUEL: u64 = 50_000_000;

/// A job dispatched by the Controller to a Worker via NATS.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobRequest {
    pub job_id: Uuid,
    pub workflow_execution_id: Uuid,
    pub module_uri: String,
    /// Node input. [`SignedJson`], not `Value`: the dispatch signature covers
    /// the exact wire text of this payload (see the type's docs for why
    /// re-serialising cannot be made safe).
    pub input_payload: SignedJson,

    /// AES-256-GCM encrypted secret map (opens into a [`SecretMap`]).
    /// Encrypted with the pre-shared `WORKER_SHARED_KEY`.
    /// Never log or expose directly.
    // `default = "…::empty"` (not bare `#[serde(default)]`) because
    // EncryptedSecrets is intentionally non-Default; the produced value
    // (empty ciphertext) is byte-identical to the old Default, so the
    // wire format is unchanged.
    #[serde(default = "EncryptedSecrets::empty")]
    pub encrypted_secrets: EncryptedSecrets,

    pub timeout_ms: u64,

    /// Job priority (0 = lowest, 255 = highest). Default: 100.
    /// Higher-priority jobs are dequeued before lower-priority ones.
    #[serde(default = "default_priority")]
    pub priority: u8,

    /// Absolute deadline as Unix timestamp (seconds). If set, the job MUST
    /// complete before this time or be treated as failed.  0 = no deadline.
    #[serde(default)]
    pub deadline_unix_secs: u64,

    /// Opaque cancellation token.  If set, the worker checks this token
    /// periodically and aborts execution if the token is revoked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_token: Option<String>,

    pub allowed_hosts: Vec<String>,
    /// HTTP method allowlist. EMPTY DENIES EVERY VERB; non-empty = only those.
    ///
    /// The asymmetry this doc used to describe is GONE as of 2026-09-24: an
    /// empty `allowed_hosts` denies all hosts, an empty `allowed_secrets`
    /// denies all secrets, and an empty `allowed_methods` now denies every
    /// verb too ([`method_permitted`]). The retry classifier
    /// (`aegix_workflow_engine_core::default_max_retries_for_module`)
    /// treats an empty list as UNKNOWN rather than read-only and grants
    /// no default retries — read-only has to be declared.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// Secret allowlist. Empty = deny all. `["*"]` = allow all. Otherwise explicit secret names.
    #[serde(default)]
    pub allowed_secrets: Vec<String>,
    /// SQL operation allowlist. Empty = allow all. Otherwise explicit types (SELECT, INSERT, etc.).
    #[serde(default)]
    pub allowed_sql_operations: Vec<String>,
    /// When true, the module may call `expose_secret` (Tier-2) to receive
    /// raw secret plaintext in WASM guest memory. Default: false (blocked).
    #[serde(default)]
    pub allow_tier2_exposure: bool,

    /// HMAC-SHA256 over the canonical job fields (see [`JobRequest::sign`]).
    pub signature: Vec<u8>,

    /// Nonce used for replay-attack prevention: `"{unix_secs}:{random_hex}"`.
    pub job_nonce: String,

    /// Actor ID that owns this execution. When set, the worker routes
    /// WIT agent-memory get/set/search calls to the persistent actor_memory
    /// Postgres table instead of the ephemeral in-memory HashMap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_id: Option<Uuid>,

    /// Optional WASM module bytes.  When present the worker uses these
    /// directly instead of reading from `module_uri`, avoiding file-system
    /// coupling and improving performance.
    ///
    /// On the wire a base64 string since 2026-10-30 (read: base64 OR the
    /// integer list serde_json wrote before — [`wasm_bytes_wire`]). The
    /// signature binds `sha256` of the RAW bytes, so the spelling is
    /// transport only. Whether bytes ride inline at all is decided by
    /// `aegix_dispatch_types::inline_wasm::rides_inline`, a check on
    /// the ENCODED length against the NATS `max_payload` budget.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "wasm_bytes_wire"
    )]
    pub wasm_bytes: Option<Vec<u8>>,

    /// Capability world hint for the worker's tiered linker selection.
    ///
    /// When present and not "unknown", the worker uses this instead of
    /// re-inspecting the WASM binary.  This is critical for sandbox modules
    /// (stored in `node_templates.precompiled_wasm`) whose world name may
    /// not survive the Wizer snapshot step.
    ///
    /// Accepts both bare names ("minimal") and WIT world names ("minimal-node",
    /// "automation-node").
    ///
    /// H-3 (2026-05-23): NOW HMAC-bound at the end of the signing payload.
    /// The previous "performance hint, linker enforces real security at
    /// instantiation time" disclaimer was only true when the worker
    /// re-derived the world from the WASM binary; for precompiled (Wizer)
    /// modules whose embedded world name doesn't survive, the controller's
    /// hint IS the policy decision. Binding it into the signature closes
    /// the tampering path where an attacker on the NATS subject would flip
    /// `minimal-node` → `automation-node` and trick the worker into
    /// selecting a wider tiered linker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_world: Option<String>,

    /// Integration name this module was compiled under, if any. When set,
    /// the module can call integration-scoped host functions (e.g. an
    /// `integration-state::*` WIT interface) and the worker signs every
    /// downstream RPC request with this value. When None, the host
    /// function returns `unauthorized` — non-integration modules cannot
    /// write to the shared integration-state table.
    ///
    /// Populated by the engine from `wasm_modules.integration_name` /
    /// `node_templates.integration_name`. Guest code has no way to
    /// supply or change this value — the worker reads it from the
    /// request, never from WIT arguments.
    ///
    /// Bound by the dispatch signature (`lp(integration_name)` in
    /// `signing_payload`, pinned by the wire-format snapshots) — until
    /// 2026-10-14 this comment said it was not (security review B-12) — and
    /// the RPC layer signs it again on every integration-state request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub integration_name: Option<String>,

    /// Expected SHA-256 hex digest of the WASM binary loaded from `module_uri`.
    ///
    /// Set by the controller from `wasm_modules.content_hash` (recorded at
    /// compile/registration time).  When present and `wasm_bytes` is absent
    /// (i.e. the worker will load the binary from the registry or Redis), the
    /// worker MUST verify that `sha256(loaded_bytes) == expected_wasm_hash`
    /// before execution.  A mismatch indicates tampering in the storage layer.
    ///
    /// Included in the HMAC signing payload so the commitment is tamper-evident.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_wasm_hash: Option<String>,

    /// Maximum fuel (WASM instructions) for this job.
    ///
    /// Set by the controller from the node's `max_fuel` config key or the
    /// module's stored `max_fuel` column.  When non-zero the worker SHOULD use
    /// this value instead of its global `WASM_FUEL_LIMIT` default.
    /// Capped at [`MAX_JOB_FUEL`] (50M) by the controller to prevent abuse,
    /// and clamped to the worker's own ceiling again on receipt.
    /// Zero means "use the worker's default fuel limit".
    ///
    /// Bound into the signing payload as a trailing `:fuel=<n>` segment ONLY
    /// when non-zero (since 2026-09-10; see `signing_payload`).
    #[serde(default)]
    pub max_fuel: u64,

    /// User ID that owns this execution — used for ownership-scoped
    /// resources (integration_state writes, per-user rate limiting,
    /// audit trails). Populated by the controller from the workflow
    /// owner's user_id. Nil UUID indicates 'no user context' (system
    /// executions); integration_state host fns reject those.
    ///
    /// Added to JobRequest alongside `actor_id` so host fns that need
    /// user scoping (integration_state::{set,get,...}) don't have to
    /// conflate it with actor_id.
    #[serde(default)]
    pub user_id: Uuid,

    /// Maximum LLM data-egress tier this job is allowed to reach.
    /// Sourced from `actors.max_llm_tier` for actor-bound executions,
    /// `Tier2` (no restriction) for system jobs and pre-actor workflows.
    ///
    /// Worker enforcement: when this is `Tier1`, the worker's
    /// `get_llm_api_key` refuses to resolve keys for Anthropic / OpenAI
    /// / Gemini and the job fails closed with a clear "actor X is
    /// tier-1, provider Y forbidden" error.
    ///
    /// HMAC-bound: included in the signing payload so an on-wire
    /// attacker can't downgrade a tier-1 ceiling to tier-2 to redirect
    /// a sensitive actor's data to an external provider.
    #[serde(default)]
    pub max_llm_tier: LlmTier,

    /// Data-mutation ceiling this job is allowed to exercise. Sourced from
    /// `actors.max_write_ceiling` for actor-bound executions; `Write` (no
    /// restriction) for trusted system / actor-less jobs and — via
    /// `#[serde(default)]` — for legacy wire messages that predate this field.
    ///
    /// Worker enforcement (gated by `AEGIX_WRITE_CEILING_ENFORCED`): when
    /// this is `ReadOnly`, every data-mutating host surface (actor-memory
    /// writes, DB DML, non-GET HTTP, webhook/email/messaging/object-storage/
    /// integration-state writes, GraphQL execute) is refused, failing closed.
    ///
    /// HMAC-bound: included in the signing payload so an on-wire attacker
    /// can't upgrade a `readonly` job to `write` and make a read-only actor
    /// mutate data.
    #[serde(default)]
    pub max_write_ceiling: WriteCeiling,

    /// Blanket network-egress scope — a security axis INDEPENDENT of
    /// `max_llm_tier`. `None` (the default, and every legacy/existing actor)
    /// falls back to the tier-derived default (`Tier1` ⇒ local, `Tier2` ⇒
    /// public). `Some(Local)` denies all public egress; `Some(Public)` permits
    /// it (subject to `allowed_hosts` + SSRF filtering) even for a `Tier1`
    /// actor whose LLM stays hard-gated local. See [`EgressScope`].
    ///
    /// HMAC-bound ONLY when `Some` (see `signing_payload`): a `None` value
    /// appends nothing, keeping every pre-existing signature byte-identical, so
    /// the field ships inert. An on-wire attacker cannot flip `Public`→`Local`
    /// (or vice-versa) without invalidating the signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub egress_scope: Option<EgressScope>,
    /// Per-actor override for the VERB-INFERRED half of the write ceiling.
    ///
    /// `max_write_ceiling` above governs all fifteen gated ops. Three of them
    /// — `http::fetch`, `http::fetch_all` and `graphql::execute` — decide
    /// "is this a mutation?" by INFERRING it from the HTTP verb, and that
    /// inference over-refuses by design: a POST that is a READ on the target
    /// API (Plaid's `/accounts/balance/get`, Elasticsearch's `_search`) is
    /// refused anyway, because GET is the only verb the gate can call a read.
    /// This field lets an operator correct that inference for ONE actor
    /// without granting the twelve categorical ops (`agent-memory-set`,
    /// `email-send`, `messaging-publish`, `database-query`, …), which is what
    /// raising `max_write_ceiling` to `write` does today.
    ///
    /// `None` = INHERIT `max_write_ceiling`, which is byte-identical to the
    /// pre-2026-09-24 behaviour on every path. HMAC-bound ONLY when `Some`
    /// (see `signing_payload`), so a `None` appends nothing, pre-existing
    /// signatures stay byte-identical, and the field ships inert — no
    /// coordinated controller+worker restart for the default path, unlike
    /// `max_write_ceiling` itself, which is bound unconditionally. When
    /// `Some`, an on-wire attacker can neither strip it (which would re-impose
    /// the inference on a deliberately-overridden actor) nor flip
    /// `readonly`→`write`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_verb_ceiling: Option<WriteCeiling>,

    /// When true, non-GET HTTP requests are mocked (returns 200 with dry_run metadata).
    /// GET requests execute normally for data fetching.
    #[serde(default)]
    pub dry_run: bool,

    /// The POSTs the module declared to be reads, as `<host><path>` entries
    /// (see [`read_only_posts`]). Read ONLY under `dry_run`: a POST an entry
    /// names is sent for real, where every other non-GET request is stubbed.
    /// It grants nothing; `allowed_hosts` and `allowed_methods` still decide
    /// whether the request may be made at all.
    ///
    /// Empty for every module that declares none, and then absent from the
    /// wire and from the signed bytes (`:rop=`, appended last), so a job of
    /// such a module is byte-identical to the format before the field. When
    /// present it is HMAC-bound: an on-wire attacker can neither add an entry
    /// (turning a rehearsed send into a real one) nor strip one.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub read_only_posts: Vec<String>,

    /// H-1: signed reply-inbox commitment.
    ///
    /// When `Some(subject)`, the worker MUST publish its `JobResult`
    /// to exactly this NATS subject — regardless of what arrives in
    /// the unsigned `msg.reply` NATS header. Pre-fix, an on-wire
    /// attacker (or anyone with NATS publish rights) could substitute
    /// `msg.reply` with an arbitrary subject (e.g. `talos.admin.*`)
    /// and the worker would happily publish a legitimately-signed
    /// JobResult there, leaking execution output.
    ///
    /// Populated by the dispatcher when the transport supports
    /// inbox pre-allocation (`JobTransport::new_reply_inbox`).
    /// `None` falls back to the legacy "trust msg.reply" path for
    /// backward compatibility with older controllers / transports.
    ///
    /// HMAC-bound via the signing payload (appended at end per the
    /// wire-format stability rule).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reply_topic: Option<String>,

    /// RFC 0010 P1: signature scheme this request was signed under.
    /// [`CRYPTO_SCHEME_HMAC`] (0, default) = legacy `WORKER_SHARED_KEY`
    /// HMAC-SHA256; [`CRYPTO_SCHEME_ED25519`] (1) = Ed25519 with the controller's
    /// private key. An unsigned dispatch hint: the verifier routes on it, and a
    /// flip only sends the message to the wrong verify method (where the
    /// scheme-specific signature the attacker can't forge fails). NOT part of the
    /// HMAC `signing_payload()`, so scheme-0 bytes stay identical to pre-P1.
    #[serde(default)]
    pub crypto_scheme: u8,

    /// RFC 0010 P3 (D3b): secret-delivery scheme. [`SEALING_INLINE_WSK`] (0,
    /// default) = the inline WSK envelope in `encrypted_secrets` (today);
    /// [`SEALING_CLAIM_ECIES`] (1) = claim-based ephemeral sealing — the worker
    /// claims the job with an ephemeral key and the controller seals to it.
    /// Bound into `signing_payload()` ONLY when non-zero (so scheme-0 bytes are
    /// unchanged), which makes a `1`→`0` downgrade invalidate the signature.
    /// Omitted from the wire JSON when 0 so a legacy message is byte-identical.
    #[serde(default, skip_serializing_if = "sealing_is_default")]
    pub sealing: u8,

    /// RFC 0010 P3: the vault paths this job is permitted to resolve, sent in
    /// the clear (paths are not secrets; values are). Populated ONLY when
    /// `sealing == SEALING_CLAIM_ECIES`; the controller resolves + seals the
    /// *values* on claim, reusing the existing per-module allowlist so the claim
    /// cannot widen scope. When `sealing == 1`, `encrypted_secrets` is empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_paths: Vec<String>,

    /// RFC 0010 P3 (D3b): the NATS subject the worker sends its `SecretClaim` to.
    /// Set by the dispatcher (to the dispatching replica's per-process claim
    /// responder inbox) ONLY when `sealing == SEALING_CLAIM_ECIES`. Bound into
    /// `signing_payload()` when sealing is non-zero — same reasoning as
    /// `reply_topic`: an on-wire attacker must not redirect the claim (which
    /// carries the worker's ephemeral public key) to a subject they control and
    /// have the controller seal the secrets straight to them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claim_inbox: Option<String>,

    /// Opt-in idempotency key for a SEND node (webhook / HTTP POST / messaging).
    ///
    /// When the workflow author declares idempotency on a node (config key
    /// `__idempotency_key__`), the engine stamps a STABLE key here — stable
    /// across retry attempts of the same dispatch, unique per logical send. The
    /// worker emits it as an `Idempotency-Key` HTTP header on MUTATING outbound
    /// requests (`fetch` / `webhook::send`) so a retried send is deduplicated at
    /// the destination (the Stripe / RFC-draft industry pattern). Its presence is
    /// ALSO what lets the engine's method-aware retry default grant retries to an
    /// otherwise-non-idempotent send world — see
    /// `aegix_workflow_engine_core::default_max_retries_for_module`.
    ///
    /// HMAC-bound ONLY when `Some` (see [`Self::signing_payload`]): a `None`
    /// value (every non-declaring node, and every legacy wire message) appends
    /// NOTHING, so pre-existing signatures stay byte-identical and the field
    /// ships inert. When `Some`, the `:idem=<key>` suffix is bound so an on-wire
    /// attacker cannot strip the key (forcing a duplicate on retry) or swap it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idempotency_key: Option<String>,

    /// Which CONTROLLER DISPATCH of this job this message is. `0` (the
    /// default, and every legacy wire message) is the first dispatch.
    ///
    /// The controller's retry loop
    /// (`aegix_workflow_engine_nats::execute_job_with_retry`) re-dispatches the
    /// SAME `job_id` — its own doc notes the worker re-sees it — and the worker
    /// is credential-free: it cannot read the prior dispatch's audit ledger, so
    /// it opens a NEW hash chain at `sequence_num` 1 against the same genesis.
    /// Two such chains land under one WORM prefix and, with no key to tell them
    /// apart, the offline verifier reported `DuplicateSequence` — positive
    /// tamper evidence — for a job that had merely been retried. A
    /// credential-free worker cannot know it is a re-dispatch unless the
    /// controller tells it; this field is the controller telling it.
    ///
    /// HMAC-bound ONLY when non-zero (see [`Self::signing_payload`]): a `0`
    /// appends NOTHING, so an all-default request is byte-identical on the wire
    /// and in its MAC and the field ships inert. When non-zero, the
    /// `:attempt=<n>` suffix is bound so an on-wire attacker can neither strip
    /// it (re-merging two attempts into one chain, manufacturing a false tamper
    /// finding) nor forge one (splitting a tampered chain into partitions that
    /// each verify).
    #[serde(default, skip_serializing_if = "dispatch_attempt_is_default")]
    pub dispatch_attempt: u32,
}

/// `skip_serializing_if` predicate for [`JobRequest::dispatch_attempt`].
///
/// Serde mandates the by-reference signature, which is why clippy's
/// `trivially_copy_pass_by_ref` is allowed here — the same reason
/// `sealing_is_default` above carries it.
#[allow(clippy::trivially_copy_pass_by_ref)]
fn dispatch_attempt_is_default(n: &u32) -> bool {
    *n == 0
}

impl JobRequest {
    /// Canonical byte string signed / verified by HMAC-SHA256.
    ///
    /// All security-sensitive fields are covered so that an attacker cannot
    /// substitute `input_payload`, secrets, WASM bytes, timeout, or allowed
    /// hosts without invalidating the signature.
    ///
    /// Format:
    /// `job_id:wex_id:module_uri:job_nonce:sha256(input):sha256(secrets_ciphertext):timeout_ms:sorted_hosts:sorted_methods:sha256(wasm_bytes)|expected_wasm_hash|none`
    ///
    /// When `wasm_bytes` is inline, the field is `sha256(wasm_bytes)`.
    /// When `wasm_bytes` is absent but `expected_wasm_hash` is set, the field is that hash
    /// (tamper-evident commitment to the content the worker will load from `module_uri`).
    /// Otherwise the sentinel "none" is used.
    #[allow(clippy::too_many_lines)] // canonical signing payload — one linear format!
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;

        // Hash large/variable fields to fixed-size hex representations.
        // This prevents payload-substitution attacks where an attacker could
        // replace input_payload, secrets, or wasm_bytes with malicious content.
        //
        // `raw_bytes()`, never `to_string()` on the parsed value: the digest
        // must cover the exact wire text, because re-serialising a parsed
        // payload is not idempotent for floats (see [`SignedJson`]).
        let input_hash = hex::encode(Sha256::digest(self.input_payload.raw_bytes()));
        let secrets_hash = hex::encode(Sha256::digest(&self.encrypted_secrets.ciphertext));

        // Sort allowed_hosts so the signature is stable regardless of array order.
        let mut hosts = self.allowed_hosts.clone();
        hosts.sort_unstable();
        let hosts_str = hosts.join(",");

        // Sort allowed_methods for the same reason: order must not matter.
        let mut methods = self.allowed_methods.clone();
        methods.sort_unstable();
        let methods_str = methods.join(",");

        // Wasm integrity commitment:
        // - Inline bytes → sha256(bytes) (already covers the content)
        // - No inline bytes + expected hash → that hash (tamper-evident URI-content binding)
        // - Neither → "none"
        let wasm_hash = if let Some(b) = self.wasm_bytes.as_deref() {
            hex::encode(Sha256::digest(b))
        } else if let Some(ref h) = self.expected_wasm_hash {
            h.clone()
        } else {
            "none".to_string()
        };

        // integration_name is part of the module's identity for
        // integration-state scoping — a NATS-channel tampering attacker
        // could otherwise swap "gcal" → "gmail" in flight and redirect
        // a module's writes into a different integration's namespace
        // without invalidating the signature. The sentinel "-" is used
        // for modules that aren't integrations so an absent value is
        // still tamper-evident (distinct from the empty string).
        //
        // Wire-format stability rule: this field is appended at the END
        // of the format string — adding it here is safe during a
        // coordinated controller+worker restart; reordering the
        // existing positions would break every deployed signature.
        let integration_name = self.integration_name.as_deref().unwrap_or("-");

        // M-4: actor_id bound. Pre-fix, an on-wire attacker could
        // change A→B without invalidating the signature; the worker
        // would then sign every downstream MemoryRpcRequest with the
        // tampered actor_id and the controller would accept it
        // (correctly signed by the worker key with the wrong actor_id).
        // Sentinel "-" for None so absence is tamper-evident.
        let actor_id_str = self
            .actor_id
            .map(|u| u.to_string())
            .unwrap_or_else(|| "-".to_string());

        // M-5: capability-grant fields bound (defense-in-depth). Even
        // though the encrypted_secrets blob and worker host-internal
        // deny-list together prevent any unauthorised secret read,
        // capability claims should be self-consistent with the signed
        // message. Pre-fix, allowed_secrets / allowed_sql_operations /
        // allow_tier2_exposure could be tampered without invalidating
        // the signature.
        let mut allowed_secrets_sorted = self.allowed_secrets.clone();
        allowed_secrets_sorted.sort_unstable();
        let allowed_secrets_str = allowed_secrets_sorted.join(",");
        let mut allowed_sql_sorted = self.allowed_sql_operations.clone();
        allowed_sql_sorted.sort_unstable();
        let allowed_sql_str = allowed_sql_sorted.join(",");

        // L-9: every variable-length field is now length-prefixed in
        // its hashed/encoded form. Field-internal `:` characters can no
        // longer cause a collision between two semantically-different
        // payloads. The legacy fixed-width fields (UUIDs, hex digests,
        // numbers, sentinel "-") use unambiguous formats so a `:`
        // delimiter remains safe. The user-controlled string fields
        // (module_uri, hosts_str, methods_str, integration_name,
        // allowed_secrets_str, allowed_sql_str, actor_id_str) are
        // emitted as `<len>:<bytes>` to remove the ambiguity.
        //
        // Defense-in-depth: today the existing fixed-width-prefix
        // header already disambiguates, but an extension that adds a
        // new free-form string field could re-introduce the collision
        // class. The length-prefix discipline is forward-safe.
        // (`lp` is the module-level length-prefix helper.)

        // H-1: reply_topic. Sentinel `-` for None so absence is
        // tamper-evident (an attacker can't strip the field to
        // downgrade verification). Length-prefixed because the inbox
        // subject is variable-length and contains `.` separators (so
        // it could collide against adjacent fields under naive
        // concatenation).
        let reply_topic_str = self.reply_topic.as_deref().unwrap_or("-");

        // Wasm-security review 2026-05-23 (H-3, H-7): bind the remaining
        // policy-controlling fields. Each was previously unsigned, which
        // gave anyone with NATS-publish rights on the job subject a
        // tamper window:
        //
        // - `capability_world` (H-3). Pre-fix doc described it as a
        //   performance hint, "linker enforces real security at
        //   instantiation time." That's only true if the worker
        //   ALWAYS re-derives the world from the WASM binary. For
        //   `precompiled_wasm` (Wizer-snapshotted) the world name may
        //   not survive — in which case the controller's hint IS the
        //   policy. An attacker who flips `minimal-node` → `automation-node`
        //   on the wire could select a wider tiered linker that resolves
        //   host fns the module would otherwise lack. Sentinel `-` for
        //   None.
        // - `dry_run` (H-7). Tamperer flips `true → false` to convert
        //   planning-mode into a real-side-effect run (real HTTP POSTs,
        //   real webhooks, real DB writes).
        // - `priority` (H-7). Queue-jumping / starving — a NATS-publish
        //   attacker can promote arbitrary jobs to drown out legitimate
        //   high-priority work.
        // - `deadline_unix_secs` (H-7). Tamperer sets a past timestamp
        //   to force premature failure; reading the field is one of
        //   the worker's loop conditions.
        // - `cancellation_token` (H-7). Stripping the token leaves an
        //   in-flight job uncancellable — resource hog / cost overrun.
        let capability_world_str = self.capability_world.as_deref().unwrap_or("-");
        let cancellation_token_str = self.cancellation_token.as_deref().unwrap_or("-");

        let mut payload = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            self.workflow_execution_id,
            lp(&self.module_uri),
            self.job_nonce,
            input_hash,
            secrets_hash,
            self.timeout_ms,
            lp(&hosts_str),
            lp(&methods_str),
            wasm_hash,
            lp(integration_name),
            // Appended AT THE END per the wire-format stability rule —
            // inserting in the middle would break every deployed
            // signature. user_id bound so an on-wire attacker can't
            // redirect a module's writes to a different user's
            // integration-state namespace.
            self.user_id,
            // Appended AT THE END for the same reason. Tier-ceiling
            // bound so an attacker can't downgrade a tier-1 actor's
            // ceiling on the wire to redirect data to an external LLM.
            self.max_llm_tier.as_signing_str(),
            // M-4: actor_id appended AT THE END.
            lp(&actor_id_str),
            // M-5: capability grants appended AT THE END.
            lp(&allowed_secrets_str),
            lp(&allowed_sql_str),
            self.allow_tier2_exposure,
            // H-1: reply_topic appended AT THE END so an on-wire
            // attacker can't redirect a worker's signed JobResult to
            // an attacker-controlled subject via the unsigned
            // msg.reply NATS header.
            lp(reply_topic_str),
            // H-3 (2026-05-23): capability_world appended AT THE END.
            lp(capability_world_str),
            // H-7 (2026-05-23): dry_run appended AT THE END.
            self.dry_run,
            // H-7 (2026-05-23): priority appended AT THE END.
            self.priority,
            // H-7 (2026-05-23): deadline_unix_secs appended AT THE END.
            self.deadline_unix_secs,
            // H-7 (2026-05-23): cancellation_token appended AT THE END.
            lp(cancellation_token_str),
            // Write-ceiling appended AT THE END (after all prior fields, before
            // the conditional sealing block) per the wire-format stability rule.
            // HMAC-bound so an on-wire attacker can't upgrade a `readonly` job to
            // `write` and make a read-only actor mutate data. As a new signed
            // field this needs a coordinated controller+worker restart, same as
            // `max_llm_tier` before it.
            self.max_write_ceiling.as_signing_str(),
        );

        // Egress-scope override appended AT THE END, ONLY when `Some`, per the
        // wire-format stability rule. A `None` (the default + every legacy /
        // existing actor) appends NOTHING, so pre-existing signatures stay
        // byte-identical and the field ships inert — no coordinated restart for
        // the default path. When `Some`, the `:egress=<scope>` suffix is
        // HMAC-bound so an on-wire attacker can't flip `public`↔`local` (e.g.
        // downgrade an air-gapped actor to public egress, or strip a
        // local-only actor's exfiltration block). Bound AFTER `max_write_ceiling`
        // and BEFORE the conditional sealing block.
        if let Some(scope) = self.egress_scope {
            use std::fmt::Write as _;
            let _ = write!(payload, ":egress={}", scope.as_signing_str());
        }

        // Verb-inference override appended AT THE END, ONLY when `Some`, per
        // the wire-format stability rule. `None` — the default and every
        // existing actor — appends NOTHING, so pre-existing signatures stay
        // byte-identical and the field ships inert; `max_write_ceiling` above
        // is bound UNCONDITIONALLY and needed a coordinated restart, this one
        // does not. When `Some`, the `:hvc=<ceiling>` suffix is HMAC-bound, so
        // an attacker can neither STRIP it (re-imposing the verb inference on
        // an actor an operator deliberately overrode, a denial) nor flip
        // `readonly`→`write` (granting POST-shaped calls the operator refused).
        if let Some(hvc) = self.http_verb_ceiling {
            use std::fmt::Write as _;
            let _ = write!(payload, ":hvc={}", hvc.as_signing_str());
        }

        // RFC 0010 P3 (D3b): bind `sealing` + `secret_paths` ONLY when a
        // non-legacy sealing scheme is in effect. For `sealing == 0` (today's
        // inline WSK envelope) nothing is appended, so the signed bytes are
        // byte-identical to the pre-P3 wire format — no coordinated restart for
        // the legacy path. When `sealing == 1`, appending the marker + sorted
        // paths makes a `1`→`0` downgrade (or a widened `secret_paths`) fail
        // verification, because the two produce different signed bytes.
        if self.sealing != 0 {
            use std::fmt::Write as _;
            let mut paths = self.secret_paths.clone();
            paths.sort_unstable();
            // claim_inbox bound with a `-` sentinel for None so its absence is
            // tamper-evident (an attacker can't strip it to redirect the claim).
            let claim_inbox = self.claim_inbox.as_deref().unwrap_or("-");
            let _ = write!(
                payload,
                ":{}:{}:{}",
                self.sealing,
                lp(&paths.join(",")),
                lp(claim_inbox)
            );
        }

        // Idempotency key appended AT THE END, ONLY when `Some`, per the
        // wire-format stability rule — a `None` (every non-declaring node +
        // every legacy message) appends nothing, so pre-existing signatures are
        // byte-identical and the field ships inert. When `Some`, binding the key
        // stops an on-wire attacker from stripping it (which would let a retried
        // send re-fire un-deduped) or swapping it for a colliding value.
        // Length-prefixed because a user-supplied key is free-form.
        if let Some(ref idem) = self.idempotency_key {
            use std::fmt::Write as _;
            let _ = write!(payload, ":idem={}", lp(idem));
        }

        // Dispatch attempt appended AT THE VERY END, ONLY when non-zero, per
        // the wire-format stability rule. Attempt 0 — the first dispatch, and
        // every legacy message — appends nothing, so the signed bytes are
        // byte-identical to the pre-field format and no coordinated restart is
        // needed for the default path. When non-zero, binding it stops an
        // on-wire attacker from stripping the attempt (which would re-merge two
        // dispatches into one audit chain and manufacture a false
        // `DuplicateSequence` tamper finding) or forging one (which would split
        // a single tampered chain into partitions that each verify clean).
        // Fixed-width decimal, so no length prefix is needed.
        if self.dispatch_attempt != 0 {
            use std::fmt::Write as _;
            let _ = write!(payload, ":attempt={}", self.dispatch_attempt);
        }

        // Per-job fuel appended AT THE VERY END (after `:attempt=`), ONLY when
        // non-zero, per the wire-format stability rule. Zero — "use the
        // worker's default" — appends nothing, so a fuel-less message is
        // byte-identical to the pre-field format. Until 2026-09-10 this was
        // the ONE resource bound on `JobRequest` an on-wire attacker could
        // rewrite without invalidating the signature: inflating it turns a 5 M-instruction node
        // into a 50 M one on the worker's CPU, deflating it fails an honest
        // node with "fuel exhausted". The worker ALSO clamps the value to its
        // own ceiling (`MAX_JOB_FUEL` by default) so the bound holds even
        // against a controller that mis-caps.
        //
        // DEPLOY ORDERING: unlike `:attempt=`, a NON-zero `max_fuel` is the
        // COMMON case (the controller stamps it from node config / the
        // module's column), so this segment changes the signed bytes of most
        // live dispatches. Controller and worker must roll TOGETHER for it;
        // a mixed pair refuses every fuel-carrying dispatch on both sides
        // (fail-closed, never a silent acceptance).
        if self.max_fuel != 0 {
            use std::fmt::Write as _;
            let _ = write!(payload, ":fuel={}", self.max_fuel);
        }

        // The secret envelope's nonce, AT THE VERY END (after `:fuel=`), only
        // when the job carries an envelope (security review 2026-10-14, B-10).
        // Until then only the ciphertext was hashed in, so an on-path attacker
        // could flip the nonce of a validly signed dispatch and the job failed
        // as "decrypt failed" rather than as a refused signature. Twelve bytes,
        // hex, fixed width — no length prefix. A secret-less job appends
        // nothing and is byte-identical to the pre-field format; a job WITH
        // secrets changes its signed bytes, so controller and worker roll
        // together, as for `:fuel=`.
        if !self.encrypted_secrets.nonce.is_empty() {
            use std::fmt::Write as _;
            let _ = write!(
                payload,
                ":sn={}",
                hex::encode(&self.encrypted_secrets.nonce)
            );
        }

        // The module's declared read-only POSTs, AT THE VERY END (after
        // `:sn=`), only when it declares any. A module that declares none,
        // which is every module before this field and nearly every one after,
        // appends nothing and is byte-identical to the earlier format, so the
        // field ships inert. When present the sorted list is length-prefixed
        // and bound: adding an entry would make a dry run send for real a
        // request it would have stubbed, and stripping one would stub a read
        // the rehearsal depends on. A job that carries a declaration changes
        // its signed bytes, so controller and worker roll together for it.
        if !self.read_only_posts.is_empty() {
            use std::fmt::Write as _;
            let _ = write!(
                payload,
                ":rop={}",
                lp(&read_only_posts::signing_text(&self.read_only_posts))
            );
        }

        payload.into_bytes()
    }

    /// Diagnostic snapshot of the per-field hashes that
    /// [`Self::signing_payload`] consumes for `input_payload` and
    /// `encrypted_secrets.ciphertext`, plus the input's serialized byte
    /// length. Surfaced by the dispatcher's `signature_diag` WARN log
    /// (controller side) and the worker's `signature verification failed`
    /// `output_payload.diag` (worker side) so operators can field-by-field
    /// compare what the two sides hashed when verification mismatched.
    /// Cheap to compute; safe to call on production traffic. Not
    /// security-sensitive (the same hashes already go into the signature).
    pub fn diag_hashes(&self) -> (String, String, usize) {
        use sha2::Digest;
        // MUST hash the same bytes as `signing_payload` — a diagnostic that
        // reports a different digest than the signature covers sends operators
        // chasing the wrong difference. (Reporting the SAME bytes on both sides
        // is what made the 2026-07-27 root cause findable at all.)
        let input_hash = hex::encode(Sha256::digest(self.input_payload.raw_bytes()));
        let secrets_hash = hex::encode(Sha256::digest(&self.encrypted_secrets.ciphertext));
        (input_hash, secrets_hash, self.input_payload.raw_len())
    }

    /// Sign the request using the pre-shared `key`.
    ///
    /// Sets `self.signature` and `self.job_nonce` (timestamp + random hex).
    /// Call this after all other fields have been populated.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_core(key)
    }

    /// Verify the HMAC signature and nonce freshness, *and* record the
    /// nonce in the process-local replay cache. Subsequent `verify()`
    /// calls against the same nonce within the freshness window will
    /// fail with `"job_nonce already seen"`.
    ///
    /// Use this at the **primary action point** for the request — the
    /// place where the message is converted into a worker dispatch.
    /// There must be EXACTLY ONE primary verifier per `JobRequest`
    /// per worker process. Passive observers (metrics, audit
    /// subscribers) MUST call [`verify_no_replay`](Self::verify_no_replay)
    /// instead — calling `verify()` from two consumers of the same
    /// signed request causes the second one to fail with a spurious
    /// replay error. See CLAUDE.md "Verify-once rule for signed NATS
    /// messages" for the architectural mandate.
    ///
    /// Returns `Err` if the signature is invalid or the nonce is older than
    /// `max_age_secs` (default recommendation: 300 s / 5 minutes).
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        self.verify_core(key, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Verify against a [`WorkerKeyRing`] (decrypt/verify-ring), recording the
    /// nonce exactly once. HMAC+freshness is tried per ring member via
    /// [`Self::verify_no_replay`] — which never touches the replay cache — so
    /// the nonce is recorded only after a key matches. This avoids the
    /// multi-key nonce-cache hazard a naive `for k { self.verify(k) }` loop
    /// would create. The worker uses this to verify dispatched jobs during a
    /// rolling `WORKER_SHARED_KEY` rotation.
    ///
    /// [`WorkerKeyRing`]: aegix_dispatch_types::WorkerKeyRing
    pub fn verify_with_ring(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_with_ring_core(ring, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Ring variant of [`Self::verify_no_replay`]: HMAC+freshness against the
    /// signing key first, then each staged previous key; first match wins.
    /// Returns the signing-key error if all fail. Touches no replay cache.
    pub fn verify_no_replay_with_ring(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_with_ring_core(ring, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Verify HMAC signature and nonce freshness **without** recording
    /// the nonce in the replay cache. Returns the parsed timestamp on
    /// success.
    ///
    /// 2026-05-28 audit F5: per CLAUDE.md "Verify-once rule for signed
    /// NATS messages — Adding a new signed message type? Add both
    /// verify() and verify_no_replay() together up front; the
    /// prophylactic split is cheap, the regression is total (every
    /// job fails)." Pre-fix `JobRequest` had only `verify()`; today
    /// only one consumer verifies so no dual-cache bug, but the
    /// architectural mandate is to add the split BEFORE the second
    /// consumer lands, not after.
    ///
    /// Use at passive observers (metrics/audit subscribers downstream
    /// of a primary `verify()` caller). HMAC continues to gate
    /// forgery and the freshness window continues to gate stale-replay;
    /// replay protection is the responsibility of the primary verifier.
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        self.verify_no_replay_core(key, max_age_secs)
            .map_err(|e| e.to_string())
    }

    // ── RFC 0010 P1: Ed25519 dispatch scheme ──────────────────────────────

    /// Sign under the Ed25519 dispatch scheme with the controller's private key.
    /// Sets `crypto_scheme = CRYPTO_SCHEME_ED25519`, a fresh `job_nonce`, and the
    /// 64-byte signature. Call after all other fields are populated.
    pub fn sign_ed25519(&mut self, signing_key: &DispatchSigningKey) -> Result<(), String> {
        self.crypto_scheme = CRYPTO_SCHEME_ED25519;
        self.sign_core_ed25519(signing_key)
    }

    /// **Primary** Ed25519 verify: freshness + signature against the controller
    /// public key(s), then record the nonce (verify-once). `keys` may carry a
    /// rotated-out previous controller key for an overlap window.
    pub fn verify_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_ed25519_core(keys, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Observer Ed25519 verify: freshness + signature only, no replay-cache
    /// write. Returns the parsed nonce timestamp.
    pub fn verify_no_replay_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_ed25519_core(keys, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Scheme-dispatching **primary** verify for the worker. Routes on
    /// `self.crypto_scheme`:
    /// - [`CRYPTO_SCHEME_ED25519`] → verify against `ed_keys`.
    /// - [`CRYPTO_SCHEME_HMAC`] → verify against the `hmac_ring`, but ONLY if
    ///   `accept_legacy_hmac` is true. Setting it false is the RFC 0010 P4
    ///   enforcement flip: the worker refuses legacy-HMAC dispatches once the
    ///   fleet is fully on Ed25519.
    /// - any other value → reject (unknown scheme).
    ///
    /// Records the nonce exactly once on success (verify-once rule preserved
    /// across both schemes).
    pub fn verify_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_ed25519_core(ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC dispatch refused (Ed25519-only enforcement enabled)"
                            .to_string(),
                    ));
                }
                self.verify_with_ring_core(hmac_ring, max_age_secs)
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown dispatch crypto_scheme: {other}"),
            )),
        }
    }

    /// Scheme-dispatching **Observer** verify: freshness + signature only,
    /// NEVER touching the process-local replay cache. Routes on
    /// `self.crypto_scheme` exactly like [`Self::verify_dispatch`] (same
    /// `accept_legacy_hmac` P4 semantics) but uses the no-replay primitive on
    /// both arms. Returns the parsed nonce timestamp.
    ///
    /// Use at a pre-check that runs BEFORE the primary `verify_dispatch` on
    /// the same message in the same process — the worker's idempotency-cache
    /// gate is the motivating site. Until 2026-09-10 that gate called the
    /// HMAC-only `verify_no_replay_with_ring`, so under an Ed25519 dispatch
    /// (`crypto_scheme = 1`) it was ALWAYS false and the whole idempotency
    /// layer was dead on exactly the fleet posture (`AEGIX_DISPATCH_SCHEME=
    /// ed25519`) the dev stack runs. The verify-once rule is preserved: this
    /// method records nothing, so the downstream primary still records the
    /// nonce exactly once.
    pub fn verify_no_replay_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<u64, VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_no_replay_ed25519_core(ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC dispatch refused (Ed25519-only enforcement enabled)"
                            .to_string(),
                    ));
                }
                self.verify_no_replay_with_ring_core(hmac_ring, max_age_secs)
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown dispatch crypto_scheme: {other}"),
            )),
        }
    }

    /// Is this dispatch's signature the controller's, whatever its age?
    ///
    /// The signature and nothing else: no freshness window, no replay cache.
    /// Routes on `self.crypto_scheme` as [`Self::verify_dispatch`] does, with
    /// the same `accept_legacy_hmac` meaning.
    ///
    /// **This is never a reason to run a job.** It answers one question for
    /// one caller: a worker has ALREADY refused a dispatch because it arrived
    /// outside its time window (a refusal made before the signature is looked
    /// at), and must decide whether it may tell the dispatcher so. A dispatch
    /// that passes this was written by the controller, so its job id, attempt,
    /// execution and reply subject are the controller's own and a signed
    /// refusal sent there names a dispatch the controller really made. One
    /// that fails it is bytes from anyone, and is answered with nothing.
    pub fn verify_signature_only_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        ed_keys: &[DispatchVerifyingKey],
        accept_legacy_hmac: bool,
    ) -> Result<(), VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.signature_only_ed25519_core(ed_keys),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC dispatch refused (Ed25519-only enforcement enabled)"
                            .to_string(),
                    ));
                }
                self.signature_only_with_ring_core(hmac_ring)
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown dispatch crypto_scheme: {other}"),
            )),
        }
    }
}

impl SignedMessage for JobRequest {
    const NONCE_LABEL: &'static str = "job_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn nonce(&self) -> &str {
        &self.job_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.job_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

/// Job status reported by a Worker.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub enum JobStatus {
    Success,
    Failed,
    TimedOut,
}

/// Upper bound on the number of [`LlmUsageEntry`] rows a single result may
/// carry. The worker aggregates provider token usage per `(provider, model)`
/// before draining into the result, so this is a bound on *distinct model
/// combinations used in one job*, not on the call count. Truncating keeps the
/// signed payload small and prevents a runaway module (looping over many
/// model names) from bloating every result message. See
/// [`aggregate_llm_usage`].
pub const MAX_LLM_USAGE_ENTRIES: usize = 16;

/// Per-`(provider, model)` LLM token usage observed by the worker during a
/// single job, surfaced to the controller inside the SIGNED
/// [`JobResult`] (workers are credential-free and
/// DB-free — usage cannot be written to the DB from the worker; it rides the
/// signed result instead).
///
/// Aggregated per provider+model (NOT per call) so the vec is bounded by the
/// number of distinct models a job touches. `calls` records how many
/// individual completions folded into this row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmUsageEntry {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub calls: u32,
}

impl LlmUsageEntry {
    /// Canonical single-line form for the signing digest. Fixed-shape,
    /// pipe-delimited; neither `provider` nor `model` may contain `|` in
    /// practice (provider is a fixed enum-ish string, model is a
    /// provider-issued identifier), and even if they did the collision is
    /// only a hash pre-image concern the SHA-256 absorbs.
    fn canonical_line(&self) -> String {
        format!(
            "{}|{}|{}|{}|{}",
            self.provider, self.model, self.prompt_tokens, self.completion_tokens, self.calls
        )
    }
}

/// Fold raw per-call `(provider, model, prompt_tokens, completion_tokens)`
/// observations into a bounded, order-independent `Vec<LlmUsageEntry>`
/// aggregated per `(provider, model)`.
///
/// PURE — no I/O, deterministic. Both the worker's usage-drain path and the
/// unit tests call this exact function so the merge logic can't drift. Token
/// counts accumulate with saturating `u32` arithmetic (a single call can't
/// realistically exceed `u32::MAX` tokens, but saturating keeps it total).
/// The result is sorted by `(provider, model)` and truncated to
/// [`MAX_LLM_USAGE_ENTRIES`] so the signing digest and wire size are bounded.
pub fn aggregate_llm_usage(
    raw: impl IntoIterator<Item = (String, String, u32, u32)>,
) -> Vec<LlmUsageEntry> {
    use std::collections::BTreeMap;
    let mut acc: BTreeMap<(String, String), (u32, u32, u32)> = BTreeMap::new();
    for (provider, model, prompt, completion) in raw {
        let slot = acc.entry((provider, model)).or_insert((0, 0, 0));
        slot.0 = slot.0.saturating_add(prompt);
        slot.1 = slot.1.saturating_add(completion);
        slot.2 = slot.2.saturating_add(1);
    }
    acc.into_iter()
        .map(|((provider, model), (p, c, calls))| LlmUsageEntry {
            provider,
            model,
            prompt_tokens: p,
            completion_tokens: c,
            calls,
        })
        .take(MAX_LLM_USAGE_ENTRIES)
        .collect()
}

/// Bind an `llm_usage` vec into a signing payload: returns `Some(hex_sha256)`
/// of the canonical, sorted, newline-joined entry lines when non-empty, or
/// `None` when the vec is empty (so an empty vec appends NOTHING to the
/// signing payload and old messages verify byte-identically).
///
/// Entries are sorted before hashing so the digest is order-independent —
/// two results with the same usage in a different vec order sign the same.
fn llm_usage_signing_hash(entries: &[LlmUsageEntry]) -> Option<String> {
    use sha2::Digest;
    if entries.is_empty() {
        return None;
    }
    let mut lines: Vec<String> = entries.iter().map(LlmUsageEntry::canonical_line).collect();
    lines.sort_unstable();
    Some(hex::encode(Sha256::digest(lines.join("\n").as_bytes())))
}

/// [`SignedMessage::check_payload_shape`] body of [`JobResult`]: the received `worker_id` must satisfy the same
/// charset rule the signer enforces, or the colon-delimited signing payload
/// is ambiguous (see the trait method's docs for the concrete collision).
fn check_result_worker_id_shape(worker_id: &str) -> Result<(), VerifyError> {
    validate_worker_id(worker_id).map_err(|m| {
        VerifyError::new(
            VerifyFailureKind::BadSignature,
            format!("result worker_id rejected before signature check: {m}"),
        )
    })
}

/// The key under which a worker reports, on a module's output, the outbound
/// calls a DRY RUN answered with a stub instead of making:
/// `{"stubbed_calls": <n>, "by_surface": {"http": 2, "webhook": 1}}`.
///
/// Worker-authored and set-or-REMOVE (`aegix_wasm_host::dry_run`): on a
/// dry run it is written whatever the module returned, zero included; on an
/// ordinary run it is removed. It rides inside the signed `output_payload`,
/// so it needs no wire field of its own.
pub const DRY_RUN_REPORT_KEY: &str = "__dry_run__";

/// The value a worker writes under [`DRY_RUN_REPORT_KEY`]: the calls it
/// answered with a stub, in total and by host surface. The one writer of the
/// shape; [`read_dry_run_report`] is the one reader.
#[must_use]
pub fn dry_run_report<'a>(
    by_surface: impl IntoIterator<Item = (&'a str, u32)>,
) -> serde_json::Value {
    let mut total: u64 = 0;
    let by_surface: serde_json::Map<String, serde_json::Value> = by_surface
        .into_iter()
        .map(|(surface, count)| {
            total = total.saturating_add(u64::from(count));
            (surface.to_string(), serde_json::json!(count))
        })
        .collect();
    serde_json::json!({ "stubbed_calls": total, "by_surface": by_surface })
}

/// The key, inside the dry-run report, under which a worker counts the POSTs
/// it SENT under a dry run because the module declared them reads
/// ([`read_only_posts`]). Written only when the count is not zero, so the
/// report of a module that declares none is the report it always was.
pub const DRY_RUN_DECLARED_READS_KEY: &str = "declared_reads";

/// [`dry_run_report`], with the declared reads that were sent for real.
#[must_use]
pub fn dry_run_report_with_declared_reads<'a>(
    by_surface: impl IntoIterator<Item = (&'a str, u32)>,
    declared_reads: u32,
) -> serde_json::Value {
    let mut report = dry_run_report(by_surface);
    if declared_reads > 0 {
        if let Some(object) = report.as_object_mut() {
            object.insert(
                DRY_RUN_DECLARED_READS_KEY.to_string(),
                serde_json::json!(declared_reads),
            );
        }
    }
    report
}

/// The declared reads a node's dry-run report counts: 0 when the output
/// carries no report, or a report that counts none.
#[must_use]
pub fn read_declared_reads(output: &serde_json::Value) -> u64 {
    if read_dry_run_report(output).is_none() {
        return 0;
    }
    output
        .get(DRY_RUN_REPORT_KEY)
        .and_then(|r| r.get(DRY_RUN_DECLARED_READS_KEY))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
}

/// The dry-run report on one node's output, as `(stubbed_calls, by_surface)`,
/// or `None` when the output carries none.
///
/// A value of another shape under the key is not a report: the stub RESPONSE
/// a module is handed carries `"__dry_run__": true`, and an output the worker
/// did not stamp may hold anything.
#[must_use]
pub fn read_dry_run_report(
    node_output: &serde_json::Value,
) -> Option<(u64, serde_json::Map<String, serde_json::Value>)> {
    let report = node_output.get(DRY_RUN_REPORT_KEY)?.as_object()?;
    Some((
        report.get("stubbed_calls")?.as_u64()?,
        report.get("by_surface")?.as_object()?.clone(),
    ))
}

#[cfg(test)]
mod dry_run_report_tests {
    use super::{dry_run_report, read_dry_run_report, DRY_RUN_REPORT_KEY};
    use serde_json::json;

    #[test]
    fn what_the_worker_writes_is_what_the_controller_reads() {
        let report = dry_run_report([("http", 2), ("webhook", 1)]);
        assert_eq!(
            report,
            json!({ "stubbed_calls": 3, "by_surface": { "http": 2, "webhook": 1 } })
        );
        let output = json!({ "sent": true, DRY_RUN_REPORT_KEY: report });
        let (stubbed, by_surface) = read_dry_run_report(&output).expect("a report");
        assert_eq!(stubbed, 3);
        assert_eq!(by_surface.get("http"), Some(&json!(2)));

        // Nothing stubbed is still a report.
        let none = json!({ DRY_RUN_REPORT_KEY: dry_run_report(std::iter::empty()) });
        assert_eq!(read_dry_run_report(&none).map(|r| r.0), Some(0));
    }

    #[test]
    fn another_shape_under_the_key_is_not_a_report() {
        for not_a_report in [
            json!({ DRY_RUN_REPORT_KEY: true }),
            json!({ DRY_RUN_REPORT_KEY: { "stubbed_calls": "many", "by_surface": {} } }),
            json!({ DRY_RUN_REPORT_KEY: { "stubbed_calls": 1 } }),
            json!({ "sent": true }),
            json!("a bare string"),
        ] {
            assert!(
                read_dry_run_report(&not_a_report).is_none(),
                "{not_a_report}"
            );
        }
    }
}

/// WASM fuel one job spent, measured by the worker and carried OUT OF BAND
/// on [`JobResult::fuel`].
///
/// The worker also stamps `__fuel_consumed__` / `__fuel_limit__` into the
/// module's OUTPUT, but only when that output is a JSON object — an array,
/// string or number output has nowhere to put them, and a failed run returns
/// no output at all. Fuel read from the output therefore missed every
/// non-object result and every failure, and the actor's hourly fuel budget
/// (`max_fuel_per_hour`) never counted them. This field is the carrier that
/// does not depend on the output's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FuelMeasure {
    /// Fuel the job's WASM consumed, summed over every in-worker attempt.
    pub consumed: u64,
    /// The fuel limit the worker enforced.
    pub limit: u64,
}

impl FuelMeasure {
    /// The fixed-shape text bound into a signing payload.
    fn canonical_segment(&self) -> String {
        format!("{}/{}", self.consumed, self.limit)
    }
}

/// Where a result's fuel figure came from. See [`spent_fuel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuelSource {
    /// The signed out-of-band [`FuelMeasure`] field.
    OutOfBand,
    /// The `__fuel_consumed__` key in the output (a worker that predates the
    /// out-of-band field).
    InBand,
}

/// Fuel a verified result reports as spent, ready to record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SpentFuel {
    /// Fuel consumed; always `> 0`.
    pub consumed: u64,
    /// The enforced limit, when the result carried one.
    pub limit: Option<u64>,
    /// Which carrier supplied it.
    pub source: FuelSource,
}

/// The ONE rule for reading a result's spent fuel. Every recorder (the NATS
/// dispatcher's fuel sink, the webhook router, the result observer) calls
/// this, so no two ledgers can disagree about a result.
///
/// - The signed out-of-band [`FuelMeasure`] wins whenever it is present,
///   whatever the output's shape or the job's status.
/// - Otherwise the in-band `__fuel_consumed__` key is read, so a result from
///   a worker that predates the field is still counted exactly as before.
///   Never both: a result is recorded from one carrier, so nothing is
///   counted twice.
/// - A zero or absent measurement yields `None` — there is nothing to record,
///   and writing `0` would assert a measurement.
#[must_use]
pub fn spent_fuel(
    out_of_band: Option<FuelMeasure>,
    output: &serde_json::Value,
) -> Option<SpentFuel> {
    use aegix_dispatch_types::fuel::{FUEL_CONSUMED, FUEL_LIMIT};
    if let Some(m) = out_of_band {
        return (m.consumed > 0).then_some(SpentFuel {
            consumed: m.consumed,
            limit: (m.limit > 0).then_some(m.limit),
            source: FuelSource::OutOfBand,
        });
    }
    let consumed = output
        .get(FUEL_CONSUMED)
        .and_then(serde_json::Value::as_u64)
        .filter(|f| *f > 0)?;
    Some(SpentFuel {
        consumed,
        limit: output
            .get(FUEL_LIMIT)
            .and_then(serde_json::Value::as_u64)
            .filter(|l| *l > 0),
        source: FuelSource::InBand,
    })
}

/// Result returned by a Worker to the Controller via NATS.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobResult {
    pub job_id: Uuid,
    pub status: JobStatus,
    /// Node output. [`SignedJson`] for the same reason as
    /// [`JobRequest::input_payload`] — the result signature covers its exact
    /// wire text, in the worker→controller direction.
    pub output_payload: SignedJson,
    pub logs: Vec<String>,
    pub execution_time_ms: u64,
    /// HMAC-SHA256 signature over canonical result fields (see [`JobResult::sign`]).
    /// Allows the controller to verify the result came from a legitimate worker.
    #[serde(default)]
    pub signature: Vec<u8>,
    /// Nonce for replay prevention: `"{unix_secs}:{random_hex}"`.
    #[serde(default)]
    pub result_nonce: String,
    /// Self-reported worker identity, HMAC-bound by [`JobResult::sign_with_worker_id`].
    ///
    /// Plain pre-shared HMAC keys cannot distinguish results from worker-A vs.
    /// worker-B — any process holding `WORKER_SHARED_KEY` can sign for any
    /// `job_id`. Binding the worker's own id into the signed payload gives the
    /// controller forensic visibility (which pod produced which result) and
    /// opens the path to per-worker HKDF subkeys in a future rev.
    ///
    /// Charset is restricted (`[A-Za-z0-9._-]{0,128}`) so the colon-delimited
    /// signing payload format stays unambiguous. Empty string is permitted for
    /// the [`JobResult::sign`] back-compat wrapper; production worker code uses
    /// [`JobResult::sign_with_worker_id`].
    #[serde(default)]
    pub worker_id: String,

    /// RFC 0010 P2: signature scheme this result was signed under.
    /// [`CRYPTO_SCHEME_HMAC`] (0, default) = legacy `WORKER_SHARED_KEY` HMAC;
    /// [`CRYPTO_SCHEME_ED25519`] (1) = the worker's own Ed25519 private key
    /// (verified by the controller against the worker's registered public key,
    /// keyed by `worker_id`). Unsigned dispatch hint — a flip routes to the wrong
    /// verify method where the scheme-specific signature fails. NOT part of the
    /// HMAC `signing_payload()`, so scheme-0 bytes stay identical to pre-P2.
    #[serde(default)]
    pub crypto_scheme: u8,

    /// Per-`(provider, model)` LLM token usage observed during this job.
    /// Empty for jobs that made no LLM calls. Bound into
    /// [`Self::signing_payload`] ONLY when non-empty (append-at-end, so old
    /// messages with no usage sign byte-identically — no coordinated restart
    /// for the no-LLM path). The controller attributes these tokens to the
    /// execution's actor/user from ITS OWN records; the worker-supplied
    /// provider/model/counts are advisory metrics, not an identity claim.
    /// Capped at [`MAX_LLM_USAGE_ENTRIES`] by the worker.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub llm_usage: Vec<LlmUsageEntry>,

    /// WASM fuel this job spent — see [`FuelMeasure`]. `None` from a worker
    /// that predates the field, and for a job that never ran a module (a
    /// pre-execution rejection). Bound into [`Self::signing_payload`] ONLY
    /// when present (append-at-end), so a result without it signs
    /// byte-identically to the pre-field format. Read it through
    /// [`JobResult::spent_fuel`], never directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel: Option<FuelMeasure>,

    /// The `dispatch_attempt` of the [`JobRequest`] this result answers
    /// (security review 2026-10-14, B-9). A retry keeps the `job_id` and the
    /// reply inbox and bumps the attempt; without this a slow attempt's result
    /// arriving during the next attempt was taken as the next attempt's.
    /// Stamped by [`JobResult::bind_to_request`] before signing. Bound into
    /// [`Self::signing_payload`] ONLY when non-zero (`:attempt=<n>`, the
    /// request's own idiom), so an all-default result signs byte-identically to
    /// the pre-field format.
    #[serde(default, skip_serializing_if = "dispatch_attempt_is_default")]
    pub dispatch_attempt: u32,

    /// The `workflow_execution_id` of the [`JobRequest`] this result answers
    /// (B-9). `None` from a worker that predates the field. Bound into
    /// [`Self::signing_payload`] ONLY when present (`:exec=<uuid>`), after
    /// `:attempt=`. A result that carries it is checked against the dispatch
    /// it arrives for ([`JobResult::answers`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workflow_execution_id: Option<Uuid>,
}

/// Which dispatch a [`JobRequest`] is: what a [`JobResult`] for it must name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchIdentity {
    pub job_id: Uuid,
    pub dispatch_attempt: u32,
    pub workflow_execution_id: Uuid,
}

impl JobRequest {
    /// The identity a result for this request must name. See
    /// [`JobResult::answers`].
    #[must_use]
    pub fn dispatch_identity(&self) -> DispatchIdentity {
        DispatchIdentity {
            job_id: self.job_id,
            dispatch_attempt: self.dispatch_attempt,
            workflow_execution_id: self.workflow_execution_id,
        }
    }
}

/// How a [`JobResult`] relates to the dispatch it arrived for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultAnswer {
    /// Names this job, this attempt and this execution.
    ThisDispatch,
    /// Names this job and no execution: a worker that predates the binding.
    /// Its attempt cannot be told apart, so it is taken as before (the
    /// rollout case; see the package record).
    Unbound,
    /// Names this job and execution and an EARLIER attempt: a slow attempt's
    /// result. Not this attempt's answer.
    EarlierAttempt,
    /// Names another job, another execution, or a LATER attempt than any
    /// sent. Refused.
    Mismatch,
}

impl JobResult {
    /// Stamp the dispatch this result answers, from the request it answers.
    /// Call before signing; every worker sign site does.
    pub fn bind_to_request(&mut self, req: &JobRequest) {
        self.dispatch_attempt = req.dispatch_attempt;
        self.workflow_execution_id = Some(req.workflow_execution_id);
    }

    /// Does this result answer `dispatch`? The ONE rule a receiver applies
    /// (security review 2026-10-14, B-9). Read only after the signature is
    /// verified, except to SKIP an [`ResultAnswer::EarlierAttempt`] before it
    /// is verified (it is never accepted either way).
    #[must_use]
    pub fn answers(&self, dispatch: &DispatchIdentity) -> ResultAnswer {
        if self.job_id != dispatch.job_id {
            return ResultAnswer::Mismatch;
        }
        let Some(execution) = self.workflow_execution_id else {
            return if self.dispatch_attempt == 0 {
                ResultAnswer::Unbound
            } else {
                // An attempt without an execution is no worker's output.
                ResultAnswer::Mismatch
            };
        };
        if execution != dispatch.workflow_execution_id {
            return ResultAnswer::Mismatch;
        }
        match self.dispatch_attempt.cmp(&dispatch.dispatch_attempt) {
            std::cmp::Ordering::Equal => ResultAnswer::ThisDispatch,
            std::cmp::Ordering::Less => ResultAnswer::EarlierAttempt,
            std::cmp::Ordering::Greater => ResultAnswer::Mismatch,
        }
    }
}

impl JobResult {
    /// The fuel this verified result reports as spent. See [`spent_fuel`].
    #[must_use]
    pub fn spent_fuel(&self) -> Option<SpentFuel> {
        spent_fuel(self.fuel, self.output_payload.value())
    }

    /// Does the output payload carry an application-level `success: false`?
    ///
    /// WASM modules like `database-query` return [`JobStatus::Success`] but
    /// include `{"success": false, "error": "..."}` in the payload when the
    /// query itself fails. Only a JSON **boolean** `false` counts — a string
    /// `"false"`, `null` or an absent key all read as "not a failure", which
    /// is exactly the dispatcher's historical `as_bool() == Some(false)` test.
    #[must_use]
    pub fn payload_reports_failure(&self) -> bool {
        self.output_payload
            .value()
            .get("success")
            .and_then(serde_json::Value::as_bool)
            == Some(false)
    }

    /// Would the controller's dispatcher accept this result as a TERMINAL
    /// success — i.e. return it to the engine rather than retry the job?
    ///
    /// `status == Success` AND NOT [`Self::payload_reports_failure`]. This is
    /// the predicate `aegix_workflow_engine_nats::execute_job_with_retry` has
    /// always applied inline; it now lives HERE because the worker needs the
    /// SAME answer on the other side of the wire. The worker's idempotency
    /// cache (`worker::job_idempotency`) may re-publish a cached result for a
    /// re-seen `job_id` ONLY when that result is one the controller would not
    /// retry: the dispatcher's application-failure retry keeps the `job_id`
    /// and bumps `dispatch_attempt`, so a cached `Failed` (or `success:false`)
    /// result would be replayed verbatim on every retry and the whole retry
    /// budget would be spent re-reading one transient failure. Two copies of
    /// this test drifting apart is precisely that bug, so there is one.
    #[must_use]
    pub fn is_terminal_success(&self) -> bool {
        matches!(self.status, JobStatus::Success) && !self.payload_reports_failure()
    }

    /// Did the RECEIVER refuse this dispatch before the module ran, for a
    /// reason a re-dispatch can fix?
    ///
    /// True only for a result whose `status` is [`JobStatus::Failed`] AND whose
    /// payload carries a top-level `reason_class` in
    /// [`PRE_EXECUTION_REJECTION_CLASSES`]. Such a result is not a module
    /// error at all: the worker verifies the request at the top of
    /// `execute_job` and returns this payload ~280 lines before it ever loads
    /// the module, so nothing ran. Measured on the reference fleet over 30 days
    /// to 2026-09-22: all 11 such workflow failures have a `module_executions`
    /// row with **zero** fuel consumed.
    ///
    /// # Why `status == Failed` is load-bearing, not belt-and-braces
    ///
    /// The payload of a `Failed` result is always worker-authored — every
    /// constructor on that path builds its own `json!({...})` — whereas a
    /// module's OWN JSON reaches the wire only under
    /// [`JobStatus::Success`] (the `success: false` shape
    /// [`Self::payload_reports_failure`] detects). Without the status test a
    /// module could return `{"success": false, "reason_class":
    /// "stale_timestamp"}` and talk the controller into re-dispatching it —
    /// duplicating whatever side effect it had already performed. With it, the
    /// shape is unforgeable by a module: only a holder of the worker signing
    /// key can produce it, and such a holder can already fabricate any result.
    /// The re-dispatch allowance is a small constant for that reason, so even
    /// then the blast radius is bounded.
    ///
    /// Pinned by `pre_execution_rejection_tests`, including the negative
    /// control that the same `reason_class` under `Success` reads false.
    #[must_use]
    pub fn is_pre_execution_rejection(&self) -> bool {
        if !matches!(self.status, JobStatus::Failed) {
            return false;
        }
        self.output_payload
            .value()
            .get("reason_class")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|c| PRE_EXECUTION_REJECTION_CLASSES.contains(&c))
    }

    /// Canonical byte string signed / verified by HMAC-SHA256.
    ///
    /// Format:
    /// `job_id:status:result_nonce:sha256(output_payload):execution_time_ms:sha256(logs_canonical)`
    ///
    /// L-10: `logs` is now part of the signing payload via a SHA-256 of
    /// the canonical newline-joined form. Pre-fix, an attacker tampering
    /// with the logs field in flight could inject misleading log lines
    /// without invalidating the signature. No capability impact, but
    /// audit-trail integrity matters for incident response.
    ///
    /// L-11 (2026-05-22): `worker_id` is appended at the end of the
    /// signing payload so a result captured from one worker can't be
    /// re-published as if it came from another. The charset is enforced
    /// by [`validate_worker_id`] so the colon-delimited format stays
    /// unambiguous (no `:` smuggling). Empty `worker_id` is permitted
    /// (renders as `""`) — the [`JobResult::sign`] back-compat wrapper
    /// leaves it empty; production worker code calls
    /// [`JobResult::sign_with_worker_id`].
    fn signing_payload(&self) -> Vec<u8> {
        use sha2::Digest;
        let status_str = match self.status {
            JobStatus::Success => "success",
            JobStatus::Failed => "failed",
            JobStatus::TimedOut => "timedout",
        };
        // Exact wire text, never a re-serialisation — see [`SignedJson`].
        let output_hash = hex::encode(Sha256::digest(self.output_payload.raw_bytes()));
        // Canonicalise logs by joining with `\n` (a stable separator
        // that no individual log line can contain — Vec<String> elements
        // are pre-split on newlines by the worker). Hash to a fixed
        // 64-char hex digest so the signing payload size is bounded.
        let logs_hash = hex::encode(Sha256::digest(self.logs.join("\n").as_bytes()));
        let mut payload = format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.job_id,
            status_str,
            self.result_nonce,
            output_hash,
            self.execution_time_ms,
            // L-10: appended AT THE END per the wire-format stability rule.
            logs_hash,
            // L-11: appended AT THE END (after L-10) per the same rule.
            self.worker_id,
        );
        // R2 token ledger (2026-07-20): bind `llm_usage` ONLY when non-empty,
        // mirroring the `sealing != 0` conditional-append precedent on
        // JobRequest. A result with no LLM usage signs byte-identically to the
        // pre-R2 format (old workers / old messages verify unchanged); a
        // result that DOES carry usage commits to the sorted canonical entry
        // digest, so an on-wire tamperer can't inflate/deflate another
        // actor's token attribution without invalidating the signature.
        if let Some(usage_hash) = llm_usage_signing_hash(&self.llm_usage) {
            use std::fmt::Write as _;
            let _ = write!(payload, ":llm_usage:{usage_hash}");
        }
        // Out-of-band fuel (2026-09-29): conditional append-at-end, after
        // `:llm_usage:`. Absent = pre-field bytes. Present = the actor's
        // budget figure is bound, so an on-wire tamperer cannot deflate it.
        if let Some(fuel) = self.fuel {
            use std::fmt::Write as _;
            let _ = write!(payload, ":fuel={}", fuel.canonical_segment());
        }
        // B-9 (2026-10-14): the dispatch this result answers, each segment
        // appended at the end ONLY when non-default, after `:fuel=`. An
        // unbound result signs byte-identically to the pre-field format; a
        // bound one cannot have its attempt or execution changed in flight.
        if self.dispatch_attempt != 0 {
            use std::fmt::Write as _;
            let _ = write!(payload, ":attempt={}", self.dispatch_attempt);
        }
        if let Some(execution) = self.workflow_execution_id {
            use std::fmt::Write as _;
            let _ = write!(payload, ":exec={execution}");
        }
        payload.into_bytes()
    }

    /// Sign the result using the pre-shared `key`. **Back-compat wrapper —
    /// production worker code should call
    /// [`JobResult::sign_with_worker_id`] so the worker identity is bound
    /// into the signature.**
    ///
    /// Sets `self.signature` and `self.result_nonce`. The `worker_id`
    /// field is left untouched (empty by default), so the signed payload
    /// commits to an empty identity. Test fixtures that don't care about
    /// per-worker attribution use this path; the worker process must use
    /// `sign_with_worker_id`. A `lint-structural.sh` check rejects raw
    /// `.sign(` in the `worker/` tree to prevent regressions.
    pub fn sign(&mut self, key: &[u8]) -> Result<(), String> {
        self.sign_with_worker_id(key, "")
    }

    /// Sign the result and bind the worker's self-reported identity.
    ///
    /// `worker_id` is validated by [`validate_worker_id`] (charset
    /// `[A-Za-z0-9._-]{0,128}`); invalid ids fail closed before any HMAC
    /// is computed so a misconfigured worker can't accidentally publish a
    /// malformed-but-signed result.
    pub fn sign_with_worker_id(&mut self, key: &[u8], worker_id: &str) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        self.worker_id = worker_id.to_string();
        self.sign_core(key)
    }

    /// Verify the HMAC signature and nonce freshness, *and* record the
    /// nonce in the process-local replay cache. Subsequent `verify()`
    /// calls against the same nonce within the freshness window will
    /// fail with `"result_nonce already seen"`.
    ///
    /// Use this at the **primary action point** for a result — the
    /// place where the message is converted into a side effect that
    /// would be wrong to apply twice. There must be EXACTLY ONE
    /// primary verifier per `JobResult` per controller process.
    /// Passive observers (e.g. an audit/DB-update subscriber that
    /// already runs downstream of the primary) MUST call
    /// [`verify_no_replay`](Self::verify_no_replay) instead — calling
    /// `verify()` from two consumers of the same signed result causes
    /// the second one to fail with a spurious replay error.
    pub fn verify(&self, key: &[u8], max_age_secs: u64) -> Result<(), String> {
        self.verify_core(key, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// L-4 typed verifier: dispatches to [`Self::verify`] for
    /// [`Verifier::Primary`] and [`Self::verify_no_replay`] for
    /// [`Verifier::Observer`]. New code should prefer this method —
    /// the role becomes explicit at the call site instead of being
    /// encoded only in the method name.
    pub fn verify_as(&self, key: &[u8], max_age_secs: u64, role: Verifier) -> Result<(), String> {
        match role {
            Verifier::Primary => self.verify(key, max_age_secs),
            Verifier::Observer => self.verify_no_replay(key, max_age_secs).map(|_| ()),
        }
    }

    /// Ring variant of [`Self::verify_as`]. The controller verifies worker
    /// results here; carrying the verify-ring lets a result signed under a
    /// staged previous key validate during a rolling `WORKER_SHARED_KEY`
    /// rotation. `Primary` records the nonce exactly once (after a key
    /// matches, via [`Self::verify_with_ring`]); `Observer` never touches the
    /// replay cache.
    pub fn verify_as_with_ring(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
        max_age_secs: u64,
        role: Verifier,
    ) -> Result<(), String> {
        match role {
            Verifier::Primary => self.verify_with_ring(ring, max_age_secs),
            Verifier::Observer => self
                .verify_no_replay_with_ring(ring, max_age_secs)
                .map(|_| ()),
        }
    }

    /// Ring variant of [`Self::verify`]: HMAC+freshness per ring member,
    /// nonce recorded exactly once after a match. See
    /// [`JobRequest::verify_with_ring`] for why this is loop-safe.
    pub fn verify_with_ring(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_with_ring_core(ring, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Ring variant of [`Self::verify_no_replay`]: signing key first, then
    /// each staged previous key; first match wins, signing-key error if all
    /// fail. Touches no replay cache.
    pub fn verify_no_replay_with_ring(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_with_ring_core(ring, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Verify HMAC signature and nonce freshness **without** recording
    /// the nonce in the replay cache. Returns the parsed timestamp on
    /// success, allowing the caller to chain a manual cache update if
    /// desired.
    ///
    /// Use this at **passive observer** call sites that consume a
    /// signed result already verified-with-replay-protection by some
    /// other primary verifier in the same process — e.g. an audit
    /// subscriber whose only side effect is an idempotent DB write. (The
    /// `talos.results.*` observer is NOT one: it is the sole consumer of
    /// module-bound results and so their primary verifier — security review
    /// 2026-10-14, B-1.) HMAC continues to gate forgery and the
    /// freshness window continues to gate stale-replay; replay
    /// protection is the responsibility of the primary verifier.
    ///
    /// **Security invariant**: there must be at least one primary
    /// `verify()` caller in the chain for any given result. If you're
    /// adding a NEW result-consumer and it's the only verifier in its
    /// chain, use `verify()` (not this method).
    pub fn verify_no_replay(&self, key: &[u8], max_age_secs: u64) -> Result<u64, String> {
        self.verify_no_replay_core(key, max_age_secs)
            .map_err(|e| e.to_string())
    }

    // ── RFC 0010 P2: per-worker Ed25519 result signing ────────────────────

    /// Sign under the worker's Ed25519 key (scheme 1) and bind `worker_id`.
    /// The controller verifies against the public key registered for that
    /// `worker_id`, so a compromised worker holding only its own private key can
    /// sign results only as itself. `worker_id` is validated (charset) and MUST
    /// be non-empty under Ed25519 — an empty id has no registered key to verify
    /// against.
    pub fn sign_ed25519_with_worker_id(
        &mut self,
        signing_key: &DispatchSigningKey,
        worker_id: &str,
    ) -> Result<(), String> {
        validate_worker_id(worker_id)?;
        if worker_id.is_empty() {
            return Err("Ed25519 result signing requires a non-empty worker_id".to_string());
        }
        self.worker_id = worker_id.to_string();
        self.crypto_scheme = CRYPTO_SCHEME_ED25519;
        self.sign_core_ed25519(signing_key)
    }

    /// **Primary** Ed25519 result verify (controller): freshness + signature
    /// against the worker's public key(s), then record the nonce (verify-once).
    pub fn verify_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<(), String> {
        self.verify_ed25519_core(keys, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Observer Ed25519 result verify: freshness + signature only, no replay
    /// write. For passive audit subscribers (see the verify-once rule).
    pub fn verify_no_replay_ed25519(
        &self,
        keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
    ) -> Result<u64, String> {
        self.verify_no_replay_ed25519_core(keys, max_age_secs)
            .map_err(|e| e.to_string())
    }

    /// Scheme-dispatching **primary** verify for the controller. Routes on
    /// `self.crypto_scheme`: Ed25519 against `worker_ed_keys` (the keys
    /// registered for `self.worker_id`), or legacy HMAC against `hmac_ring` when
    /// `accept_legacy_hmac` (the P4 flip refuses HMAC once the fleet is on
    /// Ed25519). Records the nonce exactly once. Use [`Verifier`] semantics via
    /// [`Self::verify_as`] for the HMAC path when you need Observer.
    pub fn verify_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        worker_ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self.verify_ed25519_core(worker_ed_keys, max_age_secs),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC result refused (Ed25519-only enforcement enabled)".to_string(),
                    ));
                }
                self.verify_with_ring_core(hmac_ring, max_age_secs)
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown result crypto_scheme: {other}"),
            )),
        }
    }

    /// Scheme-dispatching **Observer** verify (passive audit subscribers
    /// downstream of a primary): freshness + signature only, NEVER touching the
    /// process-local replay cache. Routes on `self.crypto_scheme` exactly like
    /// [`Self::verify_dispatch`] but uses the no-replay primitive on both arms,
    /// honouring the verify-once rule (the request-reply dispatcher is the sole
    /// Primary verifier). Use this at any site whose only side effect is an
    /// idempotent DB write.
    pub fn verify_no_replay_dispatch(
        &self,
        hmac_ring: &aegix_dispatch_types::WorkerKeyRing,
        worker_ed_keys: &[DispatchVerifyingKey],
        max_age_secs: u64,
        accept_legacy_hmac: bool,
    ) -> Result<(), VerifyError> {
        match self.crypto_scheme {
            CRYPTO_SCHEME_ED25519 => self
                .verify_no_replay_ed25519_core(worker_ed_keys, max_age_secs)
                .map(|_| ()),
            CRYPTO_SCHEME_HMAC => {
                if !accept_legacy_hmac {
                    return Err(VerifyError::new(
                        VerifyFailureKind::SchemeRefused,
                        "legacy HMAC result refused (Ed25519-only enforcement enabled)".to_string(),
                    ));
                }
                self.verify_no_replay_with_ring_core(hmac_ring, max_age_secs)
                    .map(|_| ())
            }
            other => Err(VerifyError::new(
                VerifyFailureKind::SchemeRefused,
                format!("unknown result crypto_scheme: {other}"),
            )),
        }
    }
}

impl SignedMessage for JobResult {
    const NONCE_LABEL: &'static str = "result_nonce";

    fn payload_bytes(&self) -> Vec<u8> {
        self.signing_payload()
    }
    fn check_payload_shape(&self) -> Result<(), VerifyError> {
        check_result_worker_id_shape(&self.worker_id)
    }
    fn nonce(&self) -> &str {
        &self.result_nonce
    }
    fn set_nonce(&mut self, nonce: String) {
        self.result_nonce = nonce;
    }
    fn signature(&self) -> &[u8] {
        &self.signature
    }
    fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }
}

// ============================================================================
// Job progress (RFC 0014 P2)
// ============================================================================

#[cfg(test)]
#[path = "job_progress_tests.rs"]
mod job_progress_tests;

#[cfg(test)]
#[path = "result_binding_tests.rs"]
mod result_binding_tests;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod decrypt_ring_tests {
    use super::*;
    use aegix_dispatch_types::{WorkerKeyRing, WorkerSharedKey};

    fn secrets() -> HashMap<String, String> {
        HashMap::from([("api_key".to_string(), "s3cr3t".to_string())])
    }

    #[test]
    fn ring_decrypts_with_current_key() {
        let cur = vec![0x01u8; 32];
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets(), &cur, b"exec").unwrap();
        let ring = WorkerKeyRing::single(WorkerSharedKey::new(cur));
        assert_eq!(
            plain_secret_map(&enc.decrypt_with_ring(&ring, b"exec").unwrap()),
            secrets()
        );
    }

    #[test]
    fn ring_decrypts_secrets_sealed_under_previous_key() {
        // Controller (not yet flipped) sealed under OLD; this worker's current
        // key is NEW, OLD staged as previous.
        let old = vec![0x0Au8; 32];
        let new = vec![0x0Bu8; 32];
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets(), &old, b"exec").unwrap();

        let new_only = WorkerKeyRing::single(WorkerSharedKey::new(new.clone()));
        assert!(enc.decrypt_with_ring(&new_only, b"exec").is_err());

        let ring = WorkerKeyRing::new(WorkerSharedKey::new(new), [WorkerSharedKey::new(old)]);
        assert_eq!(
            plain_secret_map(&enc.decrypt_with_ring(&ring, b"exec").unwrap()),
            secrets()
        );
    }

    #[test]
    fn ring_preserves_aad_binding() {
        let cur = vec![0x01u8; 32];
        let enc = EncryptedSecrets::encrypt_with_aad(&secrets(), &cur, b"exec-a").unwrap();
        let ring = WorkerKeyRing::new(
            WorkerSharedKey::new(cur),
            [WorkerSharedKey::new(vec![0x02u8; 32])],
        );
        // Right key, wrong AAD — no ring member rescues a transposed ciphertext.
        assert!(enc.decrypt_with_ring(&ring, b"exec-b").is_err());
    }
}

#[cfg(test)]
mod tests;

/// The [`CancelCommand`] security boundary, asserted in both directions.
///
/// This message is different in kind from the others on the bus: its whole
/// authority is destructive, and it is a fleet-wide broadcast that every
/// worker receives. So the negative cases — unsigned, forged, tampered,
/// replayed, stale, wrong-scheme, cross-type — carry more weight than the
/// happy path, and each is asserted against the SAME command that verifies
/// cleanly, so a test cannot pass by accidentally rejecting everything.
#[cfg(test)]
mod cancel_command_tests {
    use super::*;
    use aegix_dispatch_types::{WorkerKeyRing, WorkerSharedKey};

    const KEY: [u8; 32] = [0x11; 32];
    const OTHER_KEY: [u8; 32] = [0x22; 32];

    fn ring(k: [u8; 32]) -> WorkerKeyRing {
        WorkerKeyRing::single(WorkerSharedKey::new(k.to_vec()))
    }

    fn signed(exec: Uuid) -> CancelCommand {
        let mut cmd = CancelCommand::new(exec);
        cmd.sign(&KEY).expect("sign");
        cmd
    }

    /// The happy path, so every rejection below is a rejection OF SOMETHING
    /// THAT WOULD OTHERWISE WORK.
    #[test]
    fn a_correctly_signed_command_verifies() {
        let exec = Uuid::new_v4();
        let cmd = signed(exec);
        assert_eq!(cmd.crypto_scheme, CRYPTO_SCHEME_HMAC);
        cmd.verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect("a freshly signed command must verify");
        assert_eq!(cmd.workflow_execution_id, exec);
    }

    /// **The denial-of-service case.** Without a signature check, anyone able
    /// to publish on the bus could abort arbitrary executions by observing or
    /// guessing execution ids — the cancel subject is a fleet-wide constant.
    #[test]
    fn an_unsigned_command_is_refused() {
        let cmd = CancelCommand::new(Uuid::new_v4());
        assert!(cmd.signature.is_empty() && cmd.cancel_nonce.is_empty());
        let err = cmd
            .verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect_err("an unsigned cancel must never be honoured");
        assert_eq!(err.kind(), VerifyFailureKind::MalformedNonce);
    }

    /// A signature minted under a different key — the "attacker has bus
    /// access but not the shared key" case.
    #[test]
    fn a_forged_command_is_refused() {
        let mut cmd = CancelCommand::new(Uuid::new_v4());
        cmd.sign(&OTHER_KEY).expect("sign");
        let err = cmd
            .verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect_err("a cancel signed with the wrong key must be refused");
        assert_eq!(err.kind(), VerifyFailureKind::BadSignature);
    }

    /// The execution id is the ONLY authority-bearing field, so it must be
    /// bound by the MAC: swapping it must invalidate a captured command
    /// rather than re-aim it at another tenant's execution.
    #[test]
    fn retargeting_a_captured_command_invalidates_it() {
        let mut cmd = signed(Uuid::new_v4());
        cmd.workflow_execution_id = Uuid::new_v4();
        let err = cmd
            .verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect_err("re-aiming a captured cancel must break the MAC");
        assert_eq!(err.kind(), VerifyFailureKind::BadSignature);
    }

    /// Verify-once. A captured command is not re-firable inside its freshness
    /// window, and the error string is the byte-stable one callers match on.
    #[test]
    fn a_captured_command_cannot_be_replayed() {
        let cmd = signed(Uuid::new_v4());
        cmd.verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect("first primary verify succeeds");
        let err = cmd
            .verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect_err("a replayed cancel must be refused");
        assert_eq!(err.kind(), VerifyFailureKind::Replay);
        assert!(
            err.to_string().contains("cancel_nonce already seen"),
            "unexpected error: {err}"
        );
    }

    /// The observer half must NOT consume the nonce — otherwise adding any
    /// passive consumer would silently disarm the primary verifier for every
    /// message (the r300/r301 outage shape).
    #[test]
    fn the_observer_verify_does_not_consume_the_nonce() {
        let cmd = signed(Uuid::new_v4());
        cmd.verify_no_replay_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect("observer verify succeeds");
        cmd.verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect("the primary verify must still succeed after an observer read");
    }

    /// Outside the freshness window the command is refused on liveness alone.
    #[test]
    fn a_stale_command_is_refused() {
        let mut cmd = CancelCommand::new(Uuid::new_v4());
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            - (EXECUTION_CANCEL_MAX_AGE_SECS + 5);
        cmd.cancel_nonce = format!("{ts}:{}", hex::encode([7u8; 16]));
        cmd.sign_core_with_fixed_nonce_for_test(&KEY);
        let err = cmd
            .verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect_err("a stale cancel must be refused");
        assert_eq!(err.kind(), VerifyFailureKind::Stale);
    }

    /// The window is deliberately shorter than a job dispatch's 300 s: a
    /// stale dispatch wastes work, a stale cancel destroys it. Pinned at
    /// COMPILE time (`const` assertions), so widening it fails the build.
    const _: () = assert!(EXECUTION_CANCEL_MAX_AGE_SECS < 300);
    const _: () = assert!(
        EXECUTION_CANCEL_MAX_AGE_SECS > MAX_FUTURE_SKEW_SECS,
        "the past window must exceed the future-skew tolerance"
    );

    /// Ed25519 is the scheme a fleet running `AEGIX_DISPATCH_REQUIRE_ED25519`
    /// accepts, and the only one it accepts. Both directions.
    #[test]
    fn ed25519_signing_verifies_only_against_the_right_controller_key() {
        let sk = parse_ed25519_signing_key_hex(&hex::encode([3u8; 32])).expect("seed");
        let other = parse_ed25519_signing_key_hex(&hex::encode([4u8; 32])).expect("seed");
        let mut cmd = CancelCommand::new(Uuid::new_v4());
        cmd.sign_ed25519(&sk).expect("sign");
        assert_eq!(cmd.crypto_scheme, CRYPTO_SCHEME_ED25519);

        // Enforcement ON (`accept_legacy_hmac = false`) — the posture the dev
        // stack runs — and it still verifies.
        cmd.verify_dispatch(
            &ring(KEY),
            &[sk.verifying_key()],
            EXECUTION_CANCEL_MAX_AGE_SECS,
            false,
        )
        .expect("an Ed25519 cancel must verify under enforcement");

        let mut replayable = CancelCommand::new(cmd.workflow_execution_id);
        replayable.sign_ed25519(&sk).expect("sign");
        let err = replayable
            .verify_dispatch(
                &ring(KEY),
                &[other.verifying_key()],
                EXECUTION_CANCEL_MAX_AGE_SECS,
                false,
            )
            .expect_err("a different controller key must not verify");
        assert_eq!(err.kind(), VerifyFailureKind::BadSignature);
    }

    /// **The reason this message carries a `crypto_scheme` at all.** A fleet
    /// with Ed25519 enforcement on refuses HMAC. Had the producer signed
    /// HMAC-only, every cancel in that posture would be refused — a producer
    /// that publishes and never takes effect, which is the exact defect this
    /// whole change exists to remove.
    #[test]
    fn hmac_is_refused_once_ed25519_enforcement_is_on() {
        let cmd = signed(Uuid::new_v4());
        let err = cmd
            .verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, false)
            .expect_err("legacy HMAC must be refused under enforcement");
        assert_eq!(err.kind(), VerifyFailureKind::SchemeRefused);

        // FALSIFICATION: the identical command verifies with enforcement off,
        // so the refusal above is about the SCHEME and not about the command.
        let ok = signed(cmd.workflow_execution_id);
        ok.verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect("the same command verifies when legacy HMAC is accepted");
    }

    #[test]
    fn an_unknown_scheme_is_refused() {
        let mut cmd = signed(Uuid::new_v4());
        cmd.crypto_scheme = 99;
        let err = cmd
            .verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect_err("an unknown scheme must fail closed");
        assert_eq!(err.kind(), VerifyFailureKind::SchemeRefused);
    }

    /// Cross-type confusion, both directions. A heartbeat is signed under the
    /// same fleet-shared key and rides the same bus; if its bytes could be
    /// read as a cancel, an observability publish would become a fleet-wide
    /// abort primitive.
    #[test]
    fn a_heartbeat_cannot_be_read_as_a_cancel() {
        let mut hb = WorkerHeartbeat {
            worker_id: "dev-worker-fleet".to_string(),
            capabilities: vec!["wasm".to_string()],
            cpu_usage_pct: 1.0,
            build_version: None,
            signature: vec![],
            heartbeat_nonce: String::new(),
        };
        hb.sign(&KEY).expect("sign");

        // Lift the heartbeat's MAC and nonce onto a cancel: refused.
        let mut cmd = CancelCommand::new(Uuid::new_v4());
        cmd.cancel_nonce = hb.heartbeat_nonce.clone();
        cmd.signature = hb.signature.clone();
        assert!(cmd
            .verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .is_err());

        // And the reverse.
        let signed_cmd = signed(Uuid::new_v4());
        let mut hb2 = hb.clone();
        hb2.heartbeat_nonce = signed_cmd.cancel_nonce.clone();
        hb2.signature = signed_cmd.signature.clone();
        assert!(hb2
            .verify_no_replay(&KEY, WORKER_HEARTBEAT_MAX_AGE_SECS)
            .is_err());
    }

    /// Byte-level domain separation, not just behavioural. Two types are
    /// distinguishable today by accident of field layout; a domain tag keeps
    /// them distinguishable after an innocent field addition. Prefix-freedom
    /// is what stops one framing being reinterpreted as another.
    #[test]
    fn the_cancel_domain_is_distinct_and_prefix_free() {
        let cmd = signed(Uuid::new_v4());
        assert!(cmd.payload_bytes().starts_with(EXECUTION_CANCEL_DOMAIN));

        let domains: [&[u8]; 4] = [
            EXECUTION_CANCEL_DOMAIN,
            WORKER_HEARTBEAT_DOMAIN,
            WORKER_LIVENESS_POP_DOMAIN,
            WORKER_REGISTRATION_POP_DOMAIN,
        ];
        for (i, a) in domains.iter().enumerate() {
            for (j, b) in domains.iter().enumerate() {
                if i != j {
                    assert!(!a.starts_with(b), "domain {i} must not extend domain {j}");
                }
            }
        }
    }

    /// The subject is a fleet-wide constant and NOTHING tenant-specific may
    /// appear in it — NATS subjects are world-readable via `/subsz`. The
    /// execution id travels in the signed body.
    #[test]
    fn the_cancel_subject_carries_no_tenant_data() {
        assert_eq!(subjects::WORKERS_CMD_CANCEL, "talos.workers.cmd.cancel");
        assert!(subjects::WORKERS_CMD_CANCEL.starts_with(subjects::NAMESPACE_PREFIX));
        // No wildcard, no interpolation point, no per-execution suffix.
        assert!(!subjects::WORKERS_CMD_CANCEL.contains('*'));
        assert!(!subjects::WORKERS_CMD_CANCEL.contains('>'));
        let cmd = signed(Uuid::new_v4());
        assert!(!subjects::WORKERS_CMD_CANCEL.contains(&cmd.workflow_execution_id.to_string()));
    }

    /// The command round-trips over the wire unchanged — the signature is
    /// computed over fields, so a serialise/deserialise cycle must preserve
    /// verifiability.
    #[test]
    fn the_command_survives_a_json_round_trip() {
        let cmd = signed(Uuid::new_v4());
        let bytes = serde_json::to_vec(&cmd).expect("encode");
        let back: CancelCommand = serde_json::from_slice(&bytes).expect("decode");
        assert_eq!(back.workflow_execution_id, cmd.workflow_execution_id);
        back.verify_dispatch(&ring(KEY), &[], EXECUTION_CANCEL_MAX_AGE_SECS, true)
            .expect("a round-tripped command must still verify");
        // Small enough that the worker's 4 KiB payload cap is generous.
        assert!(bytes.len() < 512, "unexpected wire size: {}", bytes.len());
    }
}

#[cfg(test)]
mod worker_shared_key_precedence_tests {
    //! An EMPTY `WORKER_SHARED_KEY` must not shadow a populated
    //! `WORKER_SHARED_KEY_FILE`.
    //!
    //! `env::var` returns `Ok("")` for a variable that is set but empty, so
    //! before the fix a `Some("")` short-circuited the `_FILE` fallback and the
    //! file was never read. The failure was not silent, but it MISDIAGNOSED:
    //! the empty string reached the length check and reported
    //! "must be 32 bytes ... got 0 bytes", pointing an operator at a key that
    //! was correct all along.
    //!
    //! These tests mutate process-wide env, so they are serialised against each
    //! other. Verified safe at author time: no other test in this crate's lib
    //! module or its three integration binaries reads `WORKER_SHARED_KEY`.

    use std::io::Write;
    use std::sync::Mutex;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    const VALID_HEX: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Restores both variables on drop, so a panicking assert cannot leak state
    /// into another test.
    struct EnvGuard;
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            std::env::remove_var("WORKER_SHARED_KEY");
            std::env::remove_var("WORKER_SHARED_KEY_FILE");
        }
    }

    #[test]
    fn an_empty_env_var_does_not_shadow_a_populated_key_file() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvGuard;

        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(f, "{VALID_HEX}").expect("write key");

        std::env::set_var("WORKER_SHARED_KEY", "");
        std::env::set_var("WORKER_SHARED_KEY_FILE", f.path());

        let key = super::load_worker_shared_key()
            .expect("an empty env var must fall through to the _FILE source");
        assert_eq!(
            key.as_bytes().len(),
            32,
            "the key must come from the file, not the empty env var"
        );
    }

    #[test]
    fn a_whitespace_only_env_var_also_falls_through() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvGuard;

        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(f, "{VALID_HEX}").expect("write key");

        std::env::set_var("WORKER_SHARED_KEY", "   ");
        std::env::set_var("WORKER_SHARED_KEY_FILE", f.path());

        assert!(
            super::load_worker_shared_key().is_ok(),
            "whitespace is as empty as empty for a hex key"
        );
    }

    #[test]
    fn a_populated_env_var_still_wins_over_the_file() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _guard = EnvGuard;

        let mut f = tempfile::NamedTempFile::new().expect("temp file");
        writeln!(f, "{}", "f".repeat(64)).expect("write key");

        std::env::set_var("WORKER_SHARED_KEY", VALID_HEX);
        std::env::set_var("WORKER_SHARED_KEY_FILE", f.path());

        let key = super::load_worker_shared_key().expect("valid env key");
        assert_eq!(
            key.as_bytes(),
            hex::decode(VALID_HEX).unwrap().as_slice(),
            "a non-empty env var must keep precedence over the file"
        );
    }
}

/// 2026-09-10 protocol review (tasks D1/D2/D3/D4/D8). Each test names the
/// defect it pins; the fixtures are local so this module does not depend on
/// the private helpers of `mod tests`.
#[cfg(test)]
mod protocol_review_2026_09_tests {
    use super::*;

    const KEY: [u8; 32] = [0x42; 32];

    fn ring() -> aegix_dispatch_types::WorkerKeyRing {
        aegix_dispatch_types::WorkerKeyRing::single(aegix_dispatch_types::WorkerSharedKey::new(
            KEY.to_vec(),
        ))
    }

    fn request() -> JobRequest {
        JobRequest {
            crypto_scheme: 0,
            sealing: 0,
            secret_paths: Vec::new(),
            claim_inbox: None,
            job_id: Uuid::new_v4(),
            workflow_execution_id: Uuid::new_v4(),
            module_uri: "wasm://m/v1".to_string(),
            input_payload: serde_json::json!({"k": 1}).into(),
            encrypted_secrets: EncryptedSecrets::empty(),
            timeout_ms: 30_000,
            priority: 100,
            deadline_unix_secs: 0,
            cancellation_token: None,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            allowed_secrets: vec![],
            allowed_sql_operations: vec![],
            allow_tier2_exposure: false,
            signature: vec![],
            max_llm_tier: LlmTier::default(),
            max_write_ceiling: WriteCeiling::default(),
            egress_scope: None,
            http_verb_ceiling: None,
            job_nonce: String::new(),
            actor_id: None,
            wasm_bytes: None,
            capability_world: None,
            integration_name: None,
            user_id: Uuid::nil(),
            expected_wasm_hash: None,
            max_fuel: 0,
            dry_run: false,
            read_only_posts: Vec::new(),
            reply_topic: None,
            idempotency_key: None,
            dispatch_attempt: 0,
        }
    }

    fn result(status: JobStatus, payload: serde_json::Value) -> JobResult {
        JobResult {
            dispatch_attempt: 0,
            workflow_execution_id: None,
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: Uuid::new_v4(),
            status,
            output_payload: payload.into(),
            logs: vec![],
            execution_time_ms: 1,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
            fuel: None,
        }
    }

    fn fresh_nonce() -> String {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let r: [u8; 16] = aegix_random::bytes::<16>();
        format!("{ts}:{}", hex::encode(r))
    }

    /// HMAC over whatever `signing_payload()` yields, with NO sign-time
    /// validation — the shape an attacker (or a buggy worker) can put on the
    /// wire, which `sign_with_worker_id` refuses to produce.
    fn raw_hmac_sign<M: SignedMessage>(m: &mut M) {
        m.set_nonce(fresh_nonce());
        let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(&KEY).expect("key");
        mac.update(&m.payload_bytes());
        m.set_signature(mac.finalize().into_bytes().to_vec());
    }

    // ── D1: ONE home for the controller's success test ─────────────────────

    #[test]
    fn terminal_success_mirrors_the_dispatcher_predicate_exactly() {
        // Success with no `success` key → terminal success.
        assert!(result(JobStatus::Success, serde_json::json!({"ok": true})).is_terminal_success());
        // Success with `success: true` → terminal success.
        assert!(
            result(JobStatus::Success, serde_json::json!({"success": true})).is_terminal_success()
        );
        // Success with `success: false` → the application failed; the
        // dispatcher retries this, so it must NOT be a terminal success.
        let app_failed = result(
            JobStatus::Success,
            serde_json::json!({"success": false, "error": "query failed"}),
        );
        assert!(app_failed.payload_reports_failure());
        assert!(!app_failed.is_terminal_success());
        // Only a JSON boolean counts — a string "false" or null is not a
        // failure marker (the dispatcher's `as_bool() == Some(false)`).
        assert!(
            result(JobStatus::Success, serde_json::json!({"success": "false"}))
                .is_terminal_success()
        );
        assert!(
            result(JobStatus::Success, serde_json::json!({"success": null})).is_terminal_success()
        );
        // Non-Success statuses are never terminal successes, whatever the
        // payload says.
        assert!(
            !result(JobStatus::Failed, serde_json::json!({"success": true})).is_terminal_success()
        );
        assert!(
            !result(JobStatus::TimedOut, serde_json::json!({"ok": true})).is_terminal_success()
        );
    }

    // ── D2: scheme-routing OBSERVER verifier on the request types ──────────

    #[test]
    fn request_observer_verify_routes_by_scheme_and_records_no_nonce() {
        let _serial = NONCE_CACHE_TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let ring = ring();
        let sk = crate::generate_dispatch_signing_key();
        let pk = sk.verifying_key();

        // Ed25519-signed request: the OLD pre-check (`verify_no_replay_with_ring`,
        // HMAC only) is false for it — the defect — while the scheme-routing
        // observer accepts it.
        let mut ed = request();
        ed.sign_ed25519(&sk).unwrap();
        assert!(
            ed.verify_no_replay_with_ring(&ring, 300).is_err(),
            "control: the HMAC-only observer cannot see an Ed25519 dispatch"
        );
        ed.verify_no_replay_dispatch(&ring, &[pk], 300, false)
            .expect("Ed25519 dispatch verifies at the observer");
        // Observer recorded NOTHING: the primary still admits the nonce once…
        ed.verify_dispatch(&ring, &[pk], 300, false)
            .expect("primary verify after the observer must not see a replay");
        // …and exactly once.
        assert!(ed.verify_dispatch(&ring, &[pk], 300, false).is_err());

        // HMAC-signed request: accepted while legacy HMAC is accepted, refused
        // under P4 enforcement — same semantics as `verify_dispatch`.
        let mut hm = request();
        hm.sign(&KEY).unwrap();
        hm.verify_no_replay_dispatch(&ring, &[pk], 300, true)
            .expect("HMAC dispatch verifies at the observer during rollout");
        let refused = hm
            .verify_no_replay_dispatch(&ring, &[pk], 300, false)
            .expect_err("P4: legacy HMAC refused");
        assert_eq!(refused.kind(), VerifyFailureKind::SchemeRefused);

        // Unknown scheme byte → refused, not silently treated as HMAC.
        let mut unk = request();
        unk.sign(&KEY).unwrap();
        unk.crypto_scheme = 77;
        assert!(unk
            .verify_no_replay_dispatch(&ring, &[pk], 300, true)
            .is_err());
    }

    // ── D3: max_fuel is signature-bound ─────────────────────────────────────

    #[test]
    fn max_fuel_is_bound_against_inflate_deflate_strip_and_forge() {
        let mut signed = request();
        signed.max_fuel = 1_000_000;
        signed.sign(&KEY).unwrap();
        signed
            .verify_no_replay(&KEY, 300)
            .expect("the honest message verifies");

        let mut inflated = signed.clone();
        inflated.max_fuel = 50_000_000;
        assert!(
            inflated.verify_no_replay(&KEY, 300).is_err(),
            "inflating max_fuel must invalidate the signature"
        );
        let mut deflated = signed.clone();
        deflated.max_fuel = 1;
        assert!(
            deflated.verify_no_replay(&KEY, 300).is_err(),
            "deflating max_fuel must invalidate the signature"
        );
        let mut stripped = signed.clone();
        stripped.max_fuel = 0;
        assert!(
            stripped.verify_no_replay(&KEY, 300).is_err(),
            "stripping max_fuel (falling back to the worker default) must invalidate the signature"
        );

        // Reverse direction: a fuel-less message cannot have fuel forged on.
        let mut zero = request();
        zero.sign(&KEY).unwrap();
        let mut forged = zero.clone();
        forged.max_fuel = 50_000_000;
        assert!(forged.verify_no_replay(&KEY, 300).is_err());
        zero.verify_no_replay(&KEY, 300)
            .expect("attempt-0/fuel-0 verifies");
    }

    /// All-default bytes are UNCHANGED: `max_fuel == 0` appends nothing, so
    /// the payload is byte-identical to the pre-field format. Asserted by
    /// rebuilding the payload with the field's segment removed by hand.
    #[test]
    fn zero_max_fuel_appends_nothing_to_the_signing_payload() {
        let mut a = request();
        a.job_nonce = "0:00000000000000000000000000000000".into();
        let bytes = a.signing_payload();
        assert!(
            !String::from_utf8_lossy(&bytes).contains(":fuel="),
            "a zero max_fuel must not appear in the signed bytes"
        );
        a.max_fuel = 7;
        let with = String::from_utf8_lossy(&a.signing_payload()).to_string();
        assert!(
            with.ends_with(":fuel=7"),
            "fuel segment is appended LAST: {with}"
        );
        // And it sits AFTER the attempt segment when both are present.
        a.dispatch_attempt = 2;
        let both = String::from_utf8_lossy(&a.signing_payload()).to_string();
        assert!(both.ends_with(":attempt=2:fuel=7"), "{both}");
    }

    // ── D4: worker_id field-boundary collision ──────────────────────────────

    /// The collision itself, spelled out: a result with EMPTY `llm_usage` and
    /// `worker_id = "w1:llm_usage:<h>"` has the SAME signing bytes as an honest
    /// `worker_id = "w1"` result whose usage hashes to `<h>`. One MAC verifies
    /// both readings. The verifier must therefore refuse the malformed
    /// `worker_id` before it ever compares a MAC.
    #[test]
    fn job_result_with_colon_in_worker_id_is_refused_at_every_verifier() {
        let _serial = NONCE_CACHE_TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        let usage = vec![LlmUsageEntry {
            provider: "ollama".into(),
            model: "qwen".into(),
            prompt_tokens: 10,
            completion_tokens: 5,
            calls: 1,
        }];
        let h = llm_usage_signing_hash(&usage).expect("non-empty usage hashes");

        // The honest result: real usage, clean worker id.
        let mut honest = result(JobStatus::Success, serde_json::json!({"ok": true}));
        honest.worker_id = "w1".into();
        honest.llm_usage = usage;
        honest.result_nonce = "0:00000000000000000000000000000000".into();

        // The forgery: NO usage, the usage segment smuggled into worker_id.
        let mut forged = honest.clone();
        forged.llm_usage = vec![];
        forged.worker_id = format!("w1:llm_usage:{h}");
        assert_eq!(
            honest.signing_payload(),
            forged.signing_payload(),
            "this IS the collision: two messages, one set of signed bytes"
        );

        // Sign the forgery raw (bypassing sign-time validation, as an attacker
        // holding the fleet key or a buggy worker would).
        raw_hmac_sign(&mut forged);
        let ring = ring();
        let e = forged
            .verify_no_replay(&KEY, 300)
            .expect_err("observer must refuse a colon-bearing worker_id");
        assert!(e.contains("worker_id"), "{e}");
        assert!(forged.verify(&KEY, 300).is_err());
        assert!(forged.verify_no_replay_with_ring(&ring, 300).is_err());
        assert!(forged.verify_with_ring(&ring, 300).is_err());
        let ve = forged
            .verify_dispatch(&ring, &[], 300, true)
            .expect_err("scheme-routing primary refuses too");
        assert_eq!(ve.kind(), VerifyFailureKind::BadSignature);
        assert!(forged
            .verify_no_replay_dispatch(&ring, &[], 300, true)
            .is_err());
        // Ed25519 arm as well (the shape check runs before the key lookup).
        forged.crypto_scheme = CRYPTO_SCHEME_ED25519;
        let sk = crate::generate_dispatch_signing_key();
        assert!(forged
            .verify_no_replay_ed25519(&[sk.verifying_key()], 300)
            .is_err());

        // POSITIVE CONTROL: the same raw signing over a CLEAN worker_id
        // verifies, so the refusals above are about the worker_id and not
        // about the hand-rolled signature.
        let mut clean = result(JobStatus::Success, serde_json::json!({"ok": true}));
        clean.worker_id = "w1".into();
        raw_hmac_sign(&mut clean);
        clean
            .verify_no_replay(&KEY, 300)
            .expect("control: a clean worker_id still verifies");
    }

    // ── D8: throttled sweep still reclaims ──────────────────────────────────

    /// The sweep now runs once per `NONCE_SWEEP_EVERY_N_INSERTS` inserts above
    /// the 1024 threshold instead of on every insert. It must still RECLAIM:
    /// a flood of already-expired nonces cannot grow the map past
    /// `1024 + NONCE_SWEEP_EVERY_N_INSERTS` live entries.
    #[test]
    fn the_throttled_sweep_still_reclaims_expired_nonces() {
        let _serial = NONCE_CACHE_TEST_SERIAL
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        clear_job_nonce_cache_for_test();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        // Far older than 2× any retention window this crate will compute.
        let ancient = now.saturating_sub(10 * NONCE_RETENTION_CEILING_SECS);
        let bound = 1024 + NONCE_SWEEP_EVERY_N_INSERTS as usize;
        for i in 0..5_000u32 {
            JOB_NONCE_CACHE.check_and_record(&format!("expired-{i}"), ancient, 300);
            assert!(
                job_nonce_cache_size() <= bound,
                "insert {i}: {} live entries — the throttled sweep stopped reclaiming",
                job_nonce_cache_size()
            );
        }
        clear_job_nonce_cache_for_test();
    }
}

#[cfg(test)]
mod result_require_flag_spellings {
    //! `result_accept_legacy_hmac` is the ONE env-boolean reader in this crate
    //! that does not route through `aegix_deploy_posture::bool_env` (no aegix-config /
    //! tracing dependency here, by design). Its truthy set must stay equal to
    //! that helper's — `true | 1 | yes | on` — or `AEGIX_RESULT_REQUIRE_ED25519`
    //! becomes the divergent parser check 90 exists to prevent.
    #[test]
    fn truthy_set_matches_talos_config() {
        let src = include_str!("lib.rs");
        let site = src
            .find("std::env::var(\"AEGIX_RESULT_REQUIRE_ED25519\")")
            .expect("reader present");
        let window = &src[site..site + 200];
        assert!(
            window.contains(r#"Some("1" | "true" | "yes" | "on")"#),
            "AEGIX_RESULT_REQUIRE_ED25519's inline truthy set drifted from aegix_deploy_posture::bool_env's: {window}"
        );
    }
}

/// Guards for the pre-execution rejection predicate — the one signal that lets
/// the controller's dispatcher re-send a job instead of judging it as a module
/// error. Every clause of [`JobResult::is_pre_execution_rejection`] and every
/// membership decision in [`PRE_EXECUTION_REJECTION_CLASSES`] is pinned here,
/// because getting either wrong in the permissive direction re-runs a module
/// that already ran.
#[cfg(test)]
mod pre_execution_rejection_tests {
    use super::*;

    fn rejection(status: JobStatus, payload: serde_json::Value) -> JobResult {
        JobResult {
            dispatch_attempt: 0,
            workflow_execution_id: None,
            llm_usage: vec![],
            crypto_scheme: 0,
            job_id: uuid::Uuid::from_u128(11),
            status,
            output_payload: payload.into(),
            logs: vec![],
            execution_time_ms: 0,
            signature: vec![],
            result_nonce: String::new(),
            worker_id: String::new(),
            fuel: None,
        }
    }

    /// The whole point: a worker that refused the dispatch on age is saying
    /// "nothing ran", and the controller may re-send.
    #[test]
    fn a_stale_dispatch_rejection_is_a_pre_execution_rejection() {
        let r = rejection(
            JobStatus::Failed,
            serde_json::json!({
                "error": verify_failure_headline("Job dispatch", VerifyFailureKind::Stale),
                "reason_class": verify_failure_class(VerifyFailureKind::Stale),
            }),
        );
        assert!(r.is_pre_execution_rejection());
        // The clock-skew twin classifies the same and must behave the same.
        let ahead = rejection(
            JobStatus::Failed,
            serde_json::json!({
                "reason_class": verify_failure_class(VerifyFailureKind::ClockSkewAhead),
            }),
        );
        assert!(ahead.is_pre_execution_rejection());
    }

    /// NEGATIVE CONTROL, and the reason `status == Failed` is in the predicate.
    ///
    /// A module's own JSON reaches the wire only under `Success` (the
    /// `success: false` shape). If the status test were dropped, a module could
    /// return this payload and talk the controller into re-dispatching it —
    /// duplicating a side effect it had already performed. Deleting the
    /// `matches!(self.status, JobStatus::Failed)` guard turns this red.
    #[test]
    fn a_module_cannot_forge_a_rejection_through_its_own_output() {
        let forged = rejection(
            JobStatus::Success,
            serde_json::json!({
                "success": false,
                "error": "I already sent the email, please run me again",
                "reason_class": VERIFY_CLASS_STALE_TIMESTAMP,
            }),
        );
        assert!(
            !forged.is_pre_execution_rejection(),
            "a Success-status payload is module-authored and must never be \
             readable as a receiver-side rejection"
        );
        // It is still an ordinary application failure, judged by the node's own
        // retry policy — the behaviour this predicate must not change.
        assert!(forged.payload_reports_failure());
        assert!(!forged.is_terminal_success());
    }

    /// The classes NOT in the set, each for its own reason. A future widening
    /// has to delete a line here, which is where the argument lives.
    #[test]
    fn the_excluded_classes_stay_excluded() {
        for kind in [
            // Evidence a previous attempt was accepted and may have RUN.
            VerifyFailureKind::Replay,
            // A security event; re-sending re-admits the same forgery.
            VerifyFailureKind::BadSignature,
            VerifyFailureKind::MalformedNonce,
            // Deterministic deploy faults: safe to re-send, but identical bytes
            // earn an identical refusal, so it would burn the allowance.
            VerifyFailureKind::KeyError,
            VerifyFailureKind::SchemeRefused,
        ] {
            let class = verify_failure_class(kind);
            assert!(
                !PRE_EXECUTION_REJECTION_CLASSES.contains(&class),
                "{kind:?} classified as {class}, which must not authorise a re-dispatch"
            );
            let r = rejection(
                JobStatus::Failed,
                serde_json::json!({ "reason_class": class }),
            );
            assert!(!r.is_pre_execution_rejection(), "{kind:?}");
        }
    }

    /// An ordinary worker-side failure carries no `reason_class` key at all
    /// (`failed_result` builds `{"error": msg}`), and an unknown token is not
    /// membership. Both must read false rather than defaulting open.
    #[test]
    fn absent_or_unknown_classes_do_not_authorise_a_redispatch() {
        assert!(!rejection(
            JobStatus::Failed,
            serde_json::json!({"error": "execution failure: something broke"})
        )
        .is_pre_execution_rejection());
        assert!(!rejection(
            JobStatus::Failed,
            serde_json::json!({"reason_class": "some_future_token"})
        )
        .is_pre_execution_rejection());
        // Not a string, and not an object at all — neither may panic or pass.
        assert!(!rejection(
            JobStatus::Failed,
            serde_json::json!({"reason_class": ["stale_timestamp"]})
        )
        .is_pre_execution_rejection());
        assert!(
            !rejection(JobStatus::Failed, serde_json::json!("stale")).is_pre_execution_rejection()
        );
    }

    /// The token set is the CONTRACT between the two processes: the worker
    /// stamps it, the controller matches it. A rename on either side breaks a
    /// re-dispatch silently (the controller simply stops recognising a
    /// liveness failure and goes back to asking a Gmail predicate about it), so
    /// the literals are pinned rather than round-tripped through the function
    /// that produces them.
    #[test]
    fn the_wire_tokens_are_pinned() {
        assert_eq!(VERIFY_CLASS_STALE_TIMESTAMP, "stale_timestamp");
        assert_eq!(PRE_EXECUTION_REJECTION_CLASSES, &["stale_timestamp"]);
        assert_eq!(verify_failure_class(VerifyFailureKind::Replay), "replay");
        assert_eq!(
            verify_failure_class(VerifyFailureKind::SchemeRefused),
            "scheme_mismatch"
        );
        assert_eq!(
            verify_failure_class(VerifyFailureKind::KeyError),
            "key_config"
        );
        assert_eq!(
            verify_failure_class(VerifyFailureKind::Stale),
            "stale_timestamp"
        );
        assert_eq!(
            verify_failure_class(VerifyFailureKind::BadSignature),
            "mismatch"
        );
        assert_eq!(
            verify_failure_class(VerifyFailureKind::MalformedNonce),
            "mismatch"
        );
    }
}
