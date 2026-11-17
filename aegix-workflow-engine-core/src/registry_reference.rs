//! What a dispatch commits to as the module's content hash — and what it
//! must NOT.
//!
//! A compiled module row stores `content_hash = sha256(wasm_bytes)`, and a
//! dispatch that routes the bytes by URI (an OCI artifact, an oversized
//! component in Redis) carries it as `expected_wasm_hash`, which the worker
//! checks against the bytes it fetched. A REGISTRY-REFERENCE copy — a row
//! installed in registry mode — holds no bytes, and its `content_hash` is
//! the reference itself, [`registry_reference_hash`] (`oci:<url>`), so that
//! "did a reinstall change what this runs" has the same answer it has for a
//! compiled copy. That string is not a hash of anything, and until
//! 2026-11-04 every dispatch site sent it as one: the worker compared
//! `sha256(bytes)` with `oci:oci://…` and refused every run of a registry
//! copy (`WASM integrity check failed: content hash mismatch`) — on the first
//! deployment to run registry mode, every run, after Sigstore had passed.
//!
//! The one decision lives here: [`expected_wasm_hash`]. A registry reference
//! sends NO expected hash, and the worker's integrity check then requires
//! what the OCI path provides on every run — the Sigstore signature under
//! the policy and the layer digest the signed manifest names, on a fresh
//! pull and on a digest-keyed cache hit alike (`attested_in_this_run`). A
//! compiled row routed by URI still sends its byte hash; inline bytes send
//! none, because the dispatch signature already binds them.

use super::inline_wasm::rides_inline;

/// The prefix a registry-reference copy's `content_hash` carries.
pub const REGISTRY_REFERENCE_HASH_PREFIX: &str = "oci:";

/// The `content_hash` a registry-reference copy stores: the reference
/// itself. The hash differs when the reference does, as a compiled copy's
/// differs when its code does.
pub fn registry_reference_hash(oci_url: &str) -> String {
    format!("{REGISTRY_REFERENCE_HASH_PREFIX}{oci_url}")
}

/// Whether a stored `content_hash` is a registry reference rather than a
/// hash of bytes.
pub fn is_registry_reference_hash(content_hash: &str) -> bool {
    content_hash.starts_with(REGISTRY_REFERENCE_HASH_PREFIX)
}

/// The `expected_wasm_hash` a dispatch for this artifact carries.
///
/// * Bytes that ride inline: `None` — the signature binds them.
/// * A registry reference: `None` — there are no bytes to have hashed, and
///   the worker attests the artifact in-run (signature + layer digest).
/// * Otherwise (a compiled row routed by URI): the row's byte hash.
pub fn expected_wasm_hash(wasm_bytes: &[u8], content_hash: &str) -> Option<String> {
    if rides_inline(wasm_bytes) || is_registry_reference_hash(content_hash) {
        None
    } else {
        Some(content_hash.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BYTE_HASH: &str = "fa897d8af387ec36cb7a08502228727ff3430f76ad2452edb4e790053001c279";

    #[test]
    fn a_registry_reference_is_recognised_by_its_prefix() {
        let h = registry_reference_hash("oci://ghcr.io/o/talos-tools/x:v1@sha256:abc");
        assert_eq!(h, "oci:oci://ghcr.io/o/talos-tools/x:v1@sha256:abc");
        assert!(is_registry_reference_hash(&h));
        assert!(!is_registry_reference_hash(BYTE_HASH));
        assert!(!is_registry_reference_hash(""));
    }

    #[test]
    fn a_registry_reference_dispatch_commits_to_no_hash() {
        // The defect: a registry copy has no bytes, and its content_hash is
        // the reference. Sending it as a hash refused every run.
        let reference = registry_reference_hash("oci://ghcr.io/o/talos-tools/x:v1@sha256:abc");
        assert_eq!(expected_wasm_hash(&[], &reference), None);
    }

    #[test]
    fn a_compiled_row_routed_by_uri_commits_to_its_byte_hash() {
        // Empty bytes route by URI (the OCI and redis:wasm: shapes).
        assert_eq!(
            expected_wasm_hash(&[], BYTE_HASH).as_deref(),
            Some(BYTE_HASH)
        );
        // Oversized bytes route by URI too.
        let budget = super::super::inline_wasm::inline_field_budget();
        let oversized = vec![7u8; budget];
        assert_eq!(
            expected_wasm_hash(&oversized, BYTE_HASH).as_deref(),
            Some(BYTE_HASH)
        );
    }

    #[test]
    fn inline_bytes_commit_to_no_hash() {
        assert_eq!(expected_wasm_hash(&[0u8; 1024], BYTE_HASH), None);
    }
}
