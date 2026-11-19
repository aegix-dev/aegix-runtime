use super::*;

#[test]
fn accepts_random_nonce_output() {
    for _ in 0..100 {
        assert!(
            is_canonical_nonce(&random_nonce()),
            "random_nonce() output must pass canonical check by construction"
        );
    }
}

#[test]
fn rejects_wrong_length() {
    assert!(!is_canonical_nonce(""));
    assert!(!is_canonical_nonce("a")); // too short
    assert!(!is_canonical_nonce(&"a".repeat(31))); // one shy
    assert!(!is_canonical_nonce(&"a".repeat(33))); // one over
    assert!(!is_canonical_nonce(&"a".repeat(1024))); // wildly oversized
    assert!(!is_canonical_nonce(&"a".repeat(1_000_000))); // DoS shape
}

#[test]
fn rejects_non_hex_chars() {
    assert!(!is_canonical_nonce("ABCDEF0123456789ABCDEF0123456789")); // uppercase
    assert!(!is_canonical_nonce("g0000000000000000000000000000000")); // 'g' not hex
    assert!(!is_canonical_nonce("0000000000000000000000000000000-")); // dash
    assert!(!is_canonical_nonce("0000000000000000000000000000000 ")); // space
    assert!(!is_canonical_nonce("0000000000000000000000000000000\0")); // null
}

#[test]
fn rejects_uppercase_hex_canonical_length() {
    // Same logical bytes as a canonical nonce, but uppercase hex.
    // Reject — equality on NonceKey is byte-exact, so admitting
    // uppercase opens a shape-variation gap that lets the same
    // logical value re-land as a fresh cache key.
    assert!(!is_canonical_nonce("1A2B3C4D5E6F7A8B9C0D1E2F3A4B5C6D"));
}

#[test]
fn accepts_canonical_lowercase_hex() {
    assert!(is_canonical_nonce("1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d"));
    assert!(is_canonical_nonce("00000000000000000000000000000000"));
    assert!(is_canonical_nonce("ffffffffffffffffffffffffffffffff"));
}

/// End-to-end: `check_and_record_nonce` rejects non-canonical
/// nonces without polluting the cache (no entry inserted on the
/// rejection path).
#[test]
fn check_and_record_rejects_non_canonical() {
    let _g = nonce_test_lock();
    clear_nonce_cache_for_test();
    let actor = Uuid::new_v4();

    // Non-canonical shape: rejected.
    assert!(!check_and_record_nonce(
        "memory_rpc",
        actor,
        "not-canonical"
    ));
    assert!(!check_and_record_nonce(
        "memory_rpc",
        actor,
        &"a".repeat(1_000_000)
    ));

    // After rejection, a canonical nonce admits cleanly — the
    // rejection path did not insert anything that would shadow it.
    let n = random_nonce();
    assert!(check_and_record_nonce("memory_rpc", actor, &n));
    // Replay of the same canonical nonce: rejected as expected.
    assert!(!check_and_record_nonce("memory_rpc", actor, &n));
}
