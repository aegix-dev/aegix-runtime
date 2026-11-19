//! The secrets a dispatch carries, sealed for the wire: `EncryptedSecrets`
//! and the envelope that opens into a `SecretMap`.
//!
//! Moved out of `lib.rs` 2026-11-18, unchanged; every public item is
//! re-exported at the crate root, where it was.

use crate::{
    derive_envelope_aead_key_v1, derive_envelope_aead_key_v2, envelope_seal_key, SecretMap,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Encrypted secret store for transit over untrusted channels (e.g. NATS).
///
/// The plaintext is JSON-serialized `HashMap<String, String>` encrypted
/// with AES-256-GCM using the pre-shared `WORKER_SHARED_KEY`.
///
/// **Intentionally NOT `Default`.** An empty `EncryptedSecrets` is a
/// legitimate value (a job with no secrets), but it must be constructed
/// via the explicitly-named [`EncryptedSecrets::empty`] so it can never
/// arise by *accident* — e.g. `encrypted_secrets: aegix_workflow_job_protocol::EncryptedSecrets::empty()` in
/// a dispatch path that should have called `secrets_pipeline::build_encrypted_secrets_for`,
/// which silently strips a module's secret access (the real loop-node
/// bug, 2026-04-16). This makes lint check 17 a compiler guarantee: the
/// empty case now costs a deliberate `::empty()` at the call site.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EncryptedSecrets {
    /// AES-256-GCM ciphertext.
    pub ciphertext: Vec<u8>,
    /// 12-byte random nonce (unique per encryption).
    pub nonce: Vec<u8>,
}

impl EncryptedSecrets {
    /// The empty secret store — a job that legitimately carries no
    /// secrets. Deliberately named (not `Default`) so choosing "no
    /// secrets" is always an explicit decision at the call site. If a
    /// module is *expected* to have secrets, do NOT use this — go through
    /// the engine's `secrets_pipeline::build_encrypted_secrets_for` prefetch instead.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            ciphertext: Vec::new(),
            nonce: Vec::new(),
        }
    }
}

/// Reference [`SecretEnvelope`] impl backing the workspace's default
/// dispatch path. Seals the plaintext secrets map with AES-256-GCM,
/// using a caller-supplied 32-byte key as the AEAD key and a fresh
/// random 12-byte nonce per call. The AEAD tag authenticates the
/// ciphertext in-place, so callers do not need to add an outer MAC.
///
/// Construct as `AesGcmSecretEnvelope` (unit struct — no state). The
/// engine holds an `Arc<dyn SecretEnvelope>` and calls
/// [`SecretEnvelope::seal`] once per dispatch.
///
/// # Security properties
///
/// * Fresh 96-bit nonce per call (`aegix_random`).
/// * Authenticated (AES-GCM's GMAC covers the ciphertext).
/// * Key length is validated — a non-32-byte key returns an error
///   rather than silently truncating.
///
/// [`SecretEnvelope`]: aegix_dispatch_types::SecretEnvelope
/// [`SecretEnvelope::seal`]: aegix_dispatch_types::SecretEnvelope::seal
#[derive(Debug, Clone, Copy, Default)]
pub struct AesGcmSecretEnvelope;

#[async_trait::async_trait]
impl aegix_dispatch_types::SecretEnvelope for AesGcmSecretEnvelope {
    async fn seal(
        &self,
        secrets: &aegix_dispatch_types::SecretMap,
        shared_key: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), aegix_dispatch_types::BoxError> {
        // Empty map is a valid input — return the sentinel (empty
        // ciphertext + empty nonce) so the engine can short-circuit
        // without running AES on nothing.
        if secrets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let enc = EncryptedSecrets::encrypt(secrets, shared_key)
            .map_err(|e| -> aegix_dispatch_types::BoxError { e.into() })?;
        Ok((enc.ciphertext, enc.nonce))
    }

    /// L-1: override the default to actually bind `aad` into the
    /// AES-GCM tag.
    async fn seal_with_aad(
        &self,
        secrets: &aegix_dispatch_types::SecretMap,
        shared_key: &[u8],
        aad: &[u8],
    ) -> Result<(Vec<u8>, Vec<u8>), aegix_dispatch_types::BoxError> {
        if secrets.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let enc = EncryptedSecrets::encrypt_with_aad(secrets, shared_key, aad)
            .map_err(|e| -> aegix_dispatch_types::BoxError { e.into() })?;
        Ok((enc.ciphertext, enc.nonce))
    }
}

impl EncryptedSecrets {
    /// Encrypt a secrets map using AES-256-GCM.
    ///
    /// `key` must be exactly 32 bytes (256 bits).
    ///
    /// L-1 (2026-05-22): backwards-compatible no-AAD wrapper. New
    /// call sites should prefer [`Self::encrypt_with_aad`] passing
    /// `workflow_execution_id.as_bytes()` as the AAD — that ties the
    /// AES-GCM authentication tag to the specific execution and makes
    /// a transposed ciphertext (lifted from one execution into another
    /// with the same shared key) fail to decrypt rather than relying
    /// solely on the wider JobRequest HMAC to catch the tamper.
    pub fn encrypt<V: AsRef<str>>(
        secrets: &HashMap<String, V>,
        key: &[u8],
    ) -> Result<Self, String> {
        Self::encrypt_with_aad(secrets, key, &[])
    }

    /// L-1: Encrypt a secrets map with `aad` bound into the AES-GCM
    /// authentication tag.
    ///
    /// `key` is the 32-byte root `WORKER_SHARED_KEY`. It is **not** used
    /// as the AES-GCM key directly: the cipher key is HKDF-SHA256-expanded
    /// from it (see [`ENVELOPE_AEAD_KEY_LABEL`]) so the encryption key is
    /// domain-separated from the HMAC signing key. [`Self::decrypt_with_aad`]
    /// performs the identical derivation.
    ///
    /// The `aad` is the dispatching workflow execution id (e.g.
    /// `workflow_execution_id.as_bytes()`) — that produces an
    /// in-protocol binding between the ciphertext and the execution
    /// it travels in.
    /// Decryption MUST be done with the same `aad` via
    /// [`Self::decrypt_with_aad`]; otherwise the tag will not
    /// validate and decryption will fail closed.
    ///
    /// Empty `aad` is equivalent to [`Self::encrypt`] — the
    /// AES-GCM construction degenerates to "no AAD" and ciphertext
    /// is byte-identical to the no-AAD path (assuming the same
    /// nonce, which is randomly generated per call).
    pub fn encrypt_with_aad<V: AsRef<str>>(
        secrets: &HashMap<String, V>,
        key: &[u8],
        aad: &[u8],
    ) -> Result<Self, String> {
        if key.len() != 32 {
            return Err(format!(
                "WORKER_SHARED_KEY must be 32 bytes, got {}",
                key.len()
            ));
        }

        // Plaintext buffer and subkey are wiped on drop (every return path).
        // The map is serialized through BORROWED values, so a caller holding
        // `Zeroizing<String>` values (security review 2026-10-14, C-10) passes
        // them without a plain copy; the JSON is identical to a String map's.
        let view: HashMap<&str, &str> = secrets
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_ref()))
            .collect();
        let plaintext = zeroize::Zeroizing::new(
            serde_json::to_vec(&view).map_err(|e| format!("serialize secrets: {e}"))?,
        );

        // The AES-GCM key is an HKDF subkey of the root, never the raw
        // root (which is also the HMAC signing key). v2: a non-empty `aad`
        // folds the per-job context into the subkey so the random-nonce
        // budget is per-job. Encrypt and decrypt derive it identically, so
        // the round-trip stays symmetric.
        let aead_key = zeroize::Zeroizing::new(envelope_seal_key(key, aad));
        let cipher = Aes256Gcm::new_from_slice(aead_key.as_slice())
            .map_err(|e| format!("create cipher: {e}"))?;

        // OsRng (CSPRNG via getrandom) for nonce parity with the rest of
        // the Aegix signing surface — see aegix-rpc-protocol/src/rpc_auth.rs's
        // random_nonce. thread_rng() (ChaCha-12) is practically safe at
        // the per-message scale we hit, but using the same source
        // workspace-wide makes audit easier and removes the ChaCha-12
        // birthday-bound footnote from this primitive.
        let mut nonce_bytes = [0u8; 12];
        aegix_random::fill(&mut nonce_bytes);
        let nonce = &Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext.as_slice(),
                    aad,
                },
            )
            .map_err(|e| format!("encrypt secrets: {e}"))?;

        Ok(Self {
            ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Decrypt back into a secrets map.
    ///
    /// `key` must be the same 32-byte key used for encryption.
    /// Backwards-compatible no-AAD wrapper — passes empty AAD.
    /// Use [`Self::decrypt_with_aad`] for new call sites.
    pub fn decrypt(&self, key: &[u8]) -> Result<SecretMap, String> {
        self.decrypt_with_aad(key, &[])
    }

    /// L-1: Decrypt with `aad` bound into the AES-GCM tag check.
    ///
    /// The AAD passed here MUST byte-equal the AAD used at encrypt
    /// time. If they differ, the tag will not validate and this
    /// method returns the standard "wrong key or tampered ciphertext"
    /// error — same fail-closed surface as a bit-flipped ciphertext.
    pub fn decrypt_with_aad(&self, key: &[u8], aad: &[u8]) -> Result<SecretMap, String> {
        if key.len() != 32 {
            return Err(format!(
                "WORKER_SHARED_KEY must be 32 bytes, got {}",
                key.len()
            ));
        }
        if self.nonce.len() != 12 {
            return Err("invalid nonce length".to_string());
        }

        let nonce = <&Nonce<_>>::try_from(self.nonce.as_slice())
            .map_err(|_| "invalid nonce length".to_string())?;

        // The AES-GCM key is an HKDF subkey of the root, never the raw root
        // (which is also the HMAC signing key). A non-empty `aad` (the
        // production per-job path) opens ONLY under the v2 per-job key; an
        // empty `aad` only under the v1 key. Until 2026-10-14 a per-job
        // envelope also tried the v1 static key, for a controller not yet
        // rolled to v2 sealing — every controller has sealed v2 since
        // 2026-06-17 (#237), and the fallback only widened the set of keys
        // that open a per-job envelope back to one static key (security
        // review B-10).
        let candidates: Vec<zeroize::Zeroizing<[u8; 32]>> = if aad.is_empty() {
            vec![zeroize::Zeroizing::new(derive_envelope_aead_key_v1(key))]
        } else {
            vec![zeroize::Zeroizing::new(derive_envelope_aead_key_v2(
                key, aad,
            ))]
        };

        for aead_key in candidates {
            let cipher = Aes256Gcm::new_from_slice(aead_key.as_slice())
                .map_err(|e| format!("create cipher: {e}"))?;
            // The decrypted JSON buffer is wiped once parsed, and the map it
            // parses into holds `Zeroizing` values (a `SecretMap`), so no plain
            // copy of a value outlives this function.
            if let Ok(plaintext) = cipher.decrypt(
                nonce,
                Payload {
                    msg: self.ciphertext.as_ref(),
                    aad,
                },
            ) {
                let plaintext = zeroize::Zeroizing::new(plaintext);
                return serde_json::from_slice(plaintext.as_slice())
                    .map_err(|e| format!("deserialize secrets: {e}"));
            }
        }
        Err("decryption failed — wrong key or tampered ciphertext".to_string())
    }

    /// Decrypt against a [`WorkerKeyRing`] (the decrypt-ring), trying the
    /// signing key first then each staged previous key. Returns the first
    /// success; if all fail, returns the signing-key error.
    ///
    /// This is what the worker should call to decrypt `encrypted_secrets`
    /// during a rolling `WORKER_SHARED_KEY` rotation: the controller may have
    /// already flipped to encrypting under the new root while a not-yet-rolled
    /// worker still treats the old root as current (or vice-versa). Because
    /// the encryptor (controller) and decryptor (worker) are different
    /// processes, rotation is a **two-phase** operator procedure — see
    /// [`WorkerKeyRing`]'s rotation note: first deploy the incoming key as an
    /// *accepted* (previous) key everywhere, then flip the signing key.
    ///
    /// AES-256-GCM's tag makes trial-decryption safe: a wrong key cannot forge
    /// a passing tag, so the worst case is one extra GCM verification per
    /// staged key. AAD binding is preserved across every attempt.
    ///
    /// [`WorkerKeyRing`]: aegix_dispatch_types::WorkerKeyRing
    pub fn decrypt_with_ring(
        &self,
        ring: &aegix_dispatch_types::WorkerKeyRing,
        aad: &[u8],
    ) -> Result<SecretMap, String> {
        let mut keys = ring.verify_keys().iter();
        // INVARIANT: a ring is never empty, so `signing` is always present.
        let signing = keys.next().expect("WorkerKeyRing is never empty");
        let signing_err = match self.decrypt_with_aad(signing.as_bytes(), aad) {
            Ok(map) => return Ok(map),
            Err(e) => e,
        };
        for prev in keys {
            if let Ok(map) = self.decrypt_with_aad(prev.as_bytes(), aad) {
                return Ok(map);
            }
        }
        Err(signing_err)
    }

    /// Returns `true` if no secrets are stored.
    pub fn is_empty(&self) -> bool {
        self.ciphertext.is_empty()
    }
}
