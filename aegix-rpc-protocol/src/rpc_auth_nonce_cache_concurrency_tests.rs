use super::*;
use std::sync::Barrier;
use std::thread;

/// Two threads racing the same nonce must produce exactly one
/// `true` (the winner) and one `false` (the loser). Prior to the
/// `entry()` fix, the `contains_key + insert` pattern allowed
/// both threads to observe `false` from `contains_key` and both
/// to insert, returning `true` from both calls — admitting a
/// replay.
#[test]
fn concurrent_same_nonce_admits_exactly_one() {
    let _g = nonce_test_lock();
    clear_nonce_cache_for_test();
    // Run many trials; race conditions are timing-dependent and
    // a single trial can hide them. 200 trials × 2 threads =
    // 400 racing pairs; even a 1% TOCTOU window would surface.
    for trial in 0..200 {
        clear_nonce_cache_for_test();
        let actor = uuid::Uuid::new_v4();
        // MCP-1137: must be a canonical 32-hex nonce —
        // `is_canonical_nonce` rejects shape variants. Each
        // `random_nonce()` is fresh by construction, so trial
        // uniqueness is already implicit.
        let nonce = random_nonce();
        let barrier = std::sync::Arc::new(Barrier::new(2));

        let n1 = nonce.clone();
        let b1 = barrier.clone();
        let h1 = thread::spawn(move || {
            b1.wait();
            check_and_record_nonce("memory_rpc", actor, &n1)
        });

        let n2 = nonce.clone();
        let b2 = barrier.clone();
        let h2 = thread::spawn(move || {
            b2.wait();
            check_and_record_nonce("memory_rpc", actor, &n2)
        });

        let r1 = h1.join().unwrap();
        let r2 = h2.join().unwrap();
        // Exactly one true, exactly one false.
        assert_ne!(
            r1, r2,
            "trial {trial}: both threads got {r1} — TOCTOU race admitted a replay"
        );
    }
}

/// 100 threads racing 100 distinct nonces should all succeed —
/// no false rejection from cache pressure or shard contention.
#[test]
fn concurrent_distinct_nonces_all_admitted() {
    let _g = nonce_test_lock();
    clear_nonce_cache_for_test();
    let actor = uuid::Uuid::new_v4();
    let barrier = std::sync::Arc::new(Barrier::new(100));
    let mut handles = Vec::with_capacity(100);
    for _ in 0..100 {
        let b = barrier.clone();
        handles.push(thread::spawn(move || {
            // MCP-1137: canonical 32-hex nonces only. Each
            // `random_nonce()` is fresh (16 random bytes hex-
            // encoded) so 100 distinct draws are statistically
            // certain.
            let nonce = random_nonce();
            b.wait();
            check_and_record_nonce("memory_rpc", actor, &nonce)
        }));
    }
    let results: Vec<bool> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let admitted = results.iter().filter(|&&x| x).count();
    assert_eq!(
        admitted, 100,
        "expected all 100 distinct nonces admitted; got {admitted}"
    );
}

/// Replay-coverage invariant (MEDIUM replay-gap fix): an entry must
/// survive at least one FULL rotation cycle so a captured request
/// that is still within the freshness window can never have been
/// evicted from both generations.
///
/// With `rotation_interval == PAST_WINDOW_MS` and two generations,
/// an entry inserted just before a rotation is promoted to
/// `previous` and survives until the next rotation — a guaranteed
/// minimum lifetime of one full `PAST_WINDOW_MS`. We simulate the
/// worst case (insert, then one rotation immediately after) by
/// rewinding the rotation clock so the next call rotates exactly
/// once, then assert the nonce is still detected as a replay.
#[test]
fn nonce_survives_one_full_rotation_cycle() {
    let _g = nonce_test_lock();
    clear_nonce_cache_for_test();
    let actor = uuid::Uuid::new_v4();
    let nonce = random_nonce();

    // First sight: admitted, lands in `current`.
    assert!(
        check_and_record_nonce("memory_rpc", actor, &nonce),
        "first sighting of a fresh nonce must be admitted"
    );

    // Age the cache by one full interval. The NEXT check_and_record
    // will rotate exactly once: `current` (holding our nonce) is
    // promoted to `previous`, a fresh empty `current` is installed.
    // This models a request captured an instant before a rotation —
    // the worst case for entry lifetime.
    force_age_nonce_cache_one_interval_for_test();

    // Replay of the SAME nonce: must still be rejected. It now lives
    // in `previous`; the rotation that happened on this very call
    // moved it there but did NOT drop it. This is the band that the
    // old `PAST_WINDOW_MS / 2` interval failed to cover.
    assert!(
        !check_and_record_nonce("memory_rpc", actor, &nonce),
        "nonce aged just under PAST_WINDOW_MS must still be a replay \
             (survives at least one full rotation cycle)"
    );

    // A different fresh nonce on the same call path is still
    // admitted — the surviving entry didn't block unrelated traffic
    // and the rotation left `current` writable.
    let other = random_nonce();
    assert!(
        check_and_record_nonce("memory_rpc", actor, &other),
        "a distinct fresh nonce must still be admitted after rotation"
    );
}

/// After TWO full rotation cycles, the original entry has aged out
/// of both generations (current → previous → dropped). This pins
/// the UPPER bound of the lifetime so the test for the lower bound
/// above isn't trivially satisfied by an entry that never expires.
#[test]
fn nonce_evicted_after_two_full_rotation_cycles() {
    let _g = nonce_test_lock();
    clear_nonce_cache_for_test();
    let actor = uuid::Uuid::new_v4();
    let nonce = random_nonce();

    assert!(check_and_record_nonce("memory_rpc", actor, &nonce));

    // First rotation: nonce current → previous (still tracked).
    force_age_nonce_cache_one_interval_for_test();
    assert!(
        !check_and_record_nonce("memory_rpc", actor, &nonce),
        "after one rotation the nonce is in `previous`, still a replay"
    );

    // Second rotation: nonce previous → dropped. At this point a
    // real request would also be stale (>= 2 * PAST_WINDOW_MS old)
    // and rejected by verify_freshness, so re-admission here is
    // outside the security-relevant window.
    force_age_nonce_cache_one_interval_for_test();
    assert!(
        check_and_record_nonce("memory_rpc", actor, &nonce),
        "after two full rotations the nonce has aged out of both \
             generations and is re-admitted (upper bound of lifetime)"
    );
}
