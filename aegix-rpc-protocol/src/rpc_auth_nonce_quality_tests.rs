use super::random_nonce;
use std::collections::HashSet;

/// 100k draws from a 128-bit RNG should yield zero collisions
/// with overwhelming probability (birthday-paradox: collision
/// probability ≈ k²/2N ≈ 10¹⁰ / 2¹²⁹ ≈ 10⁻²⁹). The prior
/// implementation, with ~40 bits of effective entropy, would
/// fail this test inside a few thousand draws.
#[test]
fn random_nonce_no_collisions_at_scale() {
    const N: usize = 100_000;
    let mut seen: HashSet<String> = HashSet::with_capacity(N);
    for _ in 0..N {
        let n = random_nonce();
        assert!(
            seen.insert(n.clone()),
            "collision after {} draws — RNG entropy is broken",
            seen.len()
        );
    }
}

/// Output shape: 32 lowercase hex chars, every char in [0-9a-f].
#[test]
fn random_nonce_has_correct_shape() {
    for _ in 0..1000 {
        let n = random_nonce();
        assert_eq!(n.len(), 32, "expected 32-char hex output");
        assert!(
            n.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')),
            "non-hex char in nonce: {n}"
        );
    }
}

/// Sanity check on byte-level distribution: across 10k draws
/// (160k bytes total), every byte value 0x00-0xff should appear
/// at least once. A constant-output RNG (or one with very low
/// entropy) would fail this trivially. Not a proof of uniformity
/// — that requires real statistical tests — but a cheap regression
/// guard.
#[test]
fn random_nonce_byte_coverage() {
    let mut seen_bytes = [false; 256];
    for _ in 0..10_000 {
        let n = random_nonce();
        // Decode back to bytes.
        for chunk in n.as_bytes().chunks(2) {
            let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
            seen_bytes[((hi << 4) | lo) as usize] = true;
        }
    }
    let unseen: Vec<usize> = seen_bytes
        .iter()
        .enumerate()
        .filter_map(|(i, &b)| if !b { Some(i) } else { None })
        .collect();
    assert!(
        unseen.is_empty(),
        "byte values never produced after 160k bytes: {unseen:?} \
             — RNG distribution is suspiciously narrow"
    );
}
