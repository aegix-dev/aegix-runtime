//! The caps and the key rule a signed memory operation is held to.
//!
//! Moved here from `aegix-memory`'s crate root on 2026-10-30
//! (`docs/engineering-log/packages/2026-10-30-rpc-protocols-below-the-runtime-boundary.md`)
//! because [`crate::memory_rpc`] validates a `MemoryOp` against them and the
//! worker's `agent-memory` host functions read them before signing: they are
//! part of the wire contract, not of the Postgres service that enforces the
//! same numbers at persist time. `aegix-memory` re-exports every item at its
//! old path, so `aegix_memory::validate_memory_key` is still the one name.

pub const MAX_VALUE_BYTES: usize = 64 * 1024;
/// MCP-656: cap caller-controlled `metadata` JSONB at 16 KiB. Pre-fix
/// the persist_memory_with_metadata path serialized and INSERTed metadata
/// of arbitrary size into a JSONB column with no upper bound — a guest
/// could ship a ~900 KiB metadata blob (NATS max-msg of ~1 MiB minus
/// signing overhead) and bloat the actor_memory table row-by-row. Every
/// in-use label today (`meeting_prep`, `recall`, `daily_brief`) is tens
/// of bytes; 16 KiB leaves room for richer structured tags without
/// inviting payload abuse. Applies to BOTH `persist_memory_with_metadata`
/// and `persist_memory_in_tx_with_metadata` so the cap is uniform across
/// all writers (engine `__memory_write__`, RPC subscriber Set, MCP
/// handlers).
pub const MAX_METADATA_BYTES: usize = 16 * 1024;

pub const MEMORY_TYPES: &[&str] = &["working", "episodic", "semantic", "scratchpad"];

/// CSV rendering of [`MEMORY_TYPES`] for error messages.
///
/// MCP-819 (2026-05-14): single source of truth for the "valid values"
/// suffix in operator-facing memory_type rejection errors. Pre-fix six
/// sites in `aegix-mcp-handlers/src/actor.rs` hardcoded the list as a
/// string literal — a new memory_type added to `MEMORY_TYPES` would
/// silently leave those error messages stale.
pub fn memory_types_csv() -> String {
    MEMORY_TYPES.join(", ")
}

/// Whether `s` is one of the recognised memory types.
///
/// MCP-819 (2026-05-14): companion to `memory_types_csv` — collapses
/// the six drifted `matches!(s, "working" | "episodic" | ...)` arms
/// in `aegix-mcp-handlers/src/actor.rs` into one canonical predicate.
#[inline]
#[must_use]
pub fn is_valid_memory_type(s: &str) -> bool {
    MEMORY_TYPES.contains(&s)
}

/// Maximum byte length of an actor_memory key after trimming.
///
/// Mirrors the cap inside `persist_memory_with_metadata` (lib.rs:396),
/// promoted here so every caller observes the same value. The MCP
/// `validate_memory_key` helper (aegix-mcp-handlers/src/actor.rs:1201)
/// has historically enforced 500; GraphQL `write_actor_memory` enforced
/// 200 — that asymmetry is now closed via [`validate_memory_key`] below.
pub const MAX_MEMORY_KEY_CHARS: usize = 500;

/// Canonical actor_memory key validator.
///
/// Steps mirror MCP `handle_actor_remember` / `handle_actor_forget` (MCP-388):
///   1. Trim leading/trailing whitespace.
///   2. Reject empty-after-trim (`"   "` → operator typo).
///   3. Cap length-after-trim at [`MAX_MEMORY_KEY_CHARS`].
///   4. Reject `\0` and control chars on the ORIGINAL (a key that trims
///      clean but had embedded `\0` still corrupts downstream lookups
///      and crashes `UPDATE ... SET key = $` with opaque Postgres
///      errors — MCP-431 class).
///
/// Returns the trimmed slice so callers can shadow the input variable.
/// Trim parity is critical: pre-MCP-388 `actor_remember(key: "  foo  ")`
/// stored the key with padding while `actor_recall(key: "foo")`
/// (paste-cleaned) missed the lookup.
///
/// MCP-834 (2026-05-14): promoted from `aegix-mcp-handlers::actor::validate_memory_key`
/// so GraphQL `write_actor_memory` / `delete_actor_memory` mutations share
/// the same contract. Same canonicalization pattern as MCP-819
/// (`is_valid_memory_type`).
pub fn validate_memory_key(key: &str) -> Result<&str, &'static str> {
    let trimmed = key.trim();
    if trimmed.is_empty() {
        return Err("key must be a non-empty, non-whitespace string");
    }
    if trimmed.len() > MAX_MEMORY_KEY_CHARS {
        return Err("key must be 1–500 characters");
    }
    if key.contains('\0') || key.chars().any(|c| c.is_control() && c != '\t') {
        return Err("key cannot contain control characters or null bytes");
    }
    Ok(trimmed)
}

/// MCP-437 (2026-05-11): hard upper bound on caller-controlled TTL.
/// 10 years matches the secret-expiry ceiling from MCP-404. Any
/// legitimate use case fits well under this — even long-lived
/// "semantic" actor memories are documented to use None (no expiry)
/// rather than a multi-decade TTL.
///
/// Before this bound existed, a module could emit
/// `__memory_write__: {ttl_hours: 1e30}` from inside a workflow run.
/// The downstream computation was `(hours * 3600.0) as i64` which
/// saturates to i64::MAX, then `Utc::now() + Duration::seconds(i64::MAX)`
/// overflows chrono's DateTime range — depending on chrono version
/// either panicking or wrapping the timestamp into the distant past
/// (effectively expired). Either way the memory's actual expiry is
/// nondeterministic and the operator's TTL intent is destroyed.
///
/// 10 years = 87 600 hours.
pub const MAX_TTL_HOURS: f64 = 87_600.0;

/// Default retention for values written through the `agent_memory::set` host
/// binding (WASM guest KV writes).
///
/// The WIT contract (`wit/aegix.wit`) documents `set` as *persistent* storage.
/// Before 2026-07 the worker binding hardcoded `memory_type = "working"` (1 h
/// TTL), so any state a module wrote via `set` silently vanished before the
/// next scheduled workflow run — a durable-KV API that wasn't durable. `set`
/// now writes `episodic` memory at this ceiling: effectively permanent, and
/// (unlike `scratchpad`, which is filtered out of actor-context injection)
/// first-class for context loading. Equals [`MAX_TTL_HOURS`]; the clamp in
/// [`default_expires_at`] keeps them in lockstep even if the ceiling changes.
pub const SET_KV_TTL_HOURS: f64 = MAX_TTL_HOURS;
