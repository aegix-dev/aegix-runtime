//! Reading the fleet key and its predecessor from the environment or a file.
//!
//! Moved out of `lib.rs` 2026-11-18, unchanged; every public item is
//! re-exported at the crate root, where it was.

use crate::HmacSha256;
use hmac::Mac;

/// Decode the `WORKER_SHARED_KEY` environment variable (64 hex chars → 32 bytes)
/// and return it wrapped in a [`WorkerSharedKey`].
///
/// Both the controller and the worker must call this at startup and fail-fast
/// if the key is absent or malformed.
///
/// # Key rotation
///
/// This returns only the **signing** key. For restart-free rotation, prefer
/// [`load_worker_key_ring`], which additionally loads `WORKER_SHARED_KEY_PREVIOUS`
/// and accepts signatures made under previous keys during a rolling restart.
/// `load_worker_shared_key` is retained for call sites that only ever *sign*
/// (they always use the current key) and for backward compatibility.
///
/// Historically this loader documented that rotation *required a simultaneous
/// restart*, because a bare single-key `OnceLock` rejects every signature made
/// under a different key. See [`WorkerKeyRing`] for why a verify-ring lifts
/// that constraint without a wire-format change or key-ID negotiation.
///
/// [`WorkerSharedKey`]: aegix_dispatch_types::WorkerSharedKey
/// [`WorkerKeyRing`]: aegix_dispatch_types::WorkerKeyRing
pub fn load_worker_shared_key() -> Result<aegix_dispatch_types::WorkerSharedKey, String> {
    // Support Docker secrets via WORKER_SHARED_KEY_FILE in addition to direct env var.
    //
    // `.filter(|s| !s.trim().is_empty())` on the DIRECT env var is load-bearing,
    // not defensive. `env::var` returns `Ok("")` for a variable that is set but
    // empty — a Helm `values.yaml` placeholder, or `export WORKER_SHARED_KEY=`
    // — and without the filter that `Some("")` SHORT-CIRCUITS the `_FILE`
    // fallback, so a populated `WORKER_SHARED_KEY_FILE` is never read.
    //
    // The failure is not silent, but it MISDIAGNOSES: the empty string reaches
    // `hex::decode` (which accepts it) and fails the length check as
    // "WORKER_SHARED_KEY must be 32 bytes (64 hex chars), got 0 bytes" — which
    // sends an operator to regenerate a key that was correct all along, sitting
    // unread in the file.
    //
    // The `_FILE` branch below already filtered empties before this fix; the
    // asymmetry between the two sources is what made the bug easy to miss.
    // Same class as #701 (`env::var(..).is_ok()` matching `Ok("")`), which
    // closed the PRESENCE-test variant across 14 sites and added lint check 73.
    // This is the PRECEDENCE variant: an empty value shadowing a valid
    // fallback. Check 73 does not catch it — it keys on presence predicates,
    // and this is an `.ok()` feeding an `or_else` chain.
    let hex_key = std::env::var("WORKER_SHARED_KEY")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("WORKER_SHARED_KEY_FILE").ok().and_then(|path| {
                std::fs::read_to_string(&path)
                    .map(|s| s.trim_end_matches('\n').trim_end_matches('\r').to_string())
                    .ok()
                    .filter(|s| !s.is_empty())
            })
        })
        .ok_or_else(|| {
            "WORKER_SHARED_KEY environment variable is not set (or WORKER_SHARED_KEY_FILE for Docker secrets). \
             Generate with: openssl rand -hex 32"
                .to_string()
        })?;

    let key = hex::decode(hex_key.trim())
        .map_err(|e| format!("WORKER_SHARED_KEY is not valid hex: {e}"))?;

    if key.len() != 32 {
        return Err(format!(
            "WORKER_SHARED_KEY must be 32 bytes (64 hex chars), got {} bytes",
            key.len()
        ));
    }

    Ok(aegix_dispatch_types::WorkerSharedKey::new(key))
}

/// Decode one 64-hex-char (`32`-byte) shared key from a raw string, applying
/// the same length + hex validation as [`load_worker_shared_key`]. Used by
/// [`load_worker_key_ring`] to parse each comma-separated previous key.
fn decode_shared_key_hex(
    hex_key: &str,
    label: &str,
) -> Result<aegix_dispatch_types::WorkerSharedKey, String> {
    let key = hex::decode(hex_key.trim()).map_err(|e| format!("{label} is not valid hex: {e}"))?;
    if key.len() != 32 {
        return Err(format!(
            "{label} must be 32 bytes (64 hex chars), got {} bytes",
            key.len()
        ));
    }
    Ok(aegix_dispatch_types::WorkerSharedKey::new(key))
}

/// Load the worker-shared **key ring** for restart-free signing-key rotation.
///
/// * `WORKER_SHARED_KEY` (or `WORKER_SHARED_KEY_FILE`) — the current signing
///   key. Required; fail-fast if absent or malformed (delegates to
///   [`load_worker_shared_key`]).
/// * `WORKER_SHARED_KEY_PREVIOUS` — optional, comma-separated list of previous
///   64-hex-char keys accepted **for verification only**. Empty / unset means
///   a single-key ring identical to the old behavior.
///
/// New messages are signed under the current key; inbound messages signed
/// under any ring member verify successfully. See [`WorkerKeyRing`] for the
/// rotation workflow and the security rationale (no wire change, no key-ID
/// negotiation, explicit + freshness-bounded acceptance).
///
/// At startup the caller should log [`worker_key_fingerprint`] for each ring
/// member so an operator can confirm the controller and worker fleet agree —
/// the same drift-detection pattern the AOT key ring uses.
///
/// [`WorkerKeyRing`]: aegix_dispatch_types::WorkerKeyRing
pub fn load_worker_key_ring() -> Result<aegix_dispatch_types::WorkerKeyRing, String> {
    let signing = load_worker_shared_key()?;
    let previous = load_worker_shared_key_previous()?;
    Ok(aegix_dispatch_types::WorkerKeyRing::new(signing, previous))
}

/// Load just the previous (verify/decrypt-only) keys from
/// `WORKER_SHARED_KEY_PREVIOUS` — the comma-separated list staged during a
/// rolling rotation. Empty when unset. Factored out of [`load_worker_key_ring`]
/// so a consumer that already holds the current signing key (e.g. the engine's
/// `build_nats_dispatcher`) can build the verify-ring without re-reading
/// `WORKER_SHARED_KEY`.
pub fn load_worker_shared_key_previous(
) -> Result<Vec<aegix_dispatch_types::WorkerSharedKey>, String> {
    let mut previous = Vec::new();
    if let Ok(prev) = std::env::var("WORKER_SHARED_KEY_PREVIOUS") {
        for (idx, raw) in prev.split(',').enumerate() {
            let raw = raw.trim();
            if raw.is_empty() {
                continue;
            }
            // Label each entry so a bad previous key points at the right slot
            // without echoing the (secret) value.
            previous.push(decode_shared_key_hex(
                raw,
                &format!("WORKER_SHARED_KEY_PREVIOUS[{idx}]"),
            )?);
        }
    }
    Ok(previous)
}

/// Stable, non-secret fingerprint of a shared key for drift-detection logging.
///
/// Returns the first 8 hex chars of `HMAC-SHA256(key, "talos-worker-shared-key-fingerprint-v1")`.
/// Using an HMAC (rather than a bare hash of the key) keeps the key bytes one
/// pre-image away from the log line; 32 bits is enough to spot a controller↔
/// worker mismatch while revealing nothing usable about the key.
#[must_use]
pub fn worker_key_fingerprint(key: &[u8]) -> String {
    let mut mac = <HmacSha256 as hmac::KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA256 accepts a key of any length");
    mac.update(b"talos-worker-shared-key-fingerprint-v1");
    let tag = mac.finalize().into_bytes();
    hex::encode(&tag[..4])
}
