//! A payload whose signed form is the exact text on the wire: `RawSigned`
//! and its `serde_json::Value` spelling, `SignedJson`. This crate is their
//! one home.
//!
//! Moved out of `lib.rs` 2026-11-18, unchanged; every public item is
//! re-exported at the crate root, where it was.

use serde::{Deserialize, Serialize};

/// A payload whose SIGNED representation is the exact text that travels on the
/// wire: produced ONCE on the sending side (in [`From`]) and captured VERBATIM
/// from the received bytes on the verifying side (in `Deserialize`). It is
/// never re-derived, so signer and verifier hash the same bytes by
/// construction.
///
/// `T` is the parsed view handlers read. Two specialisations exist today:
/// [`SignedJson`] (`T = serde_json::Value`) for the dispatch/result payloads
/// in this crate, and `RawSigned<MemoryOp>` / `RawSigned<IntegrationOp>` in
/// `aegix-memory`, which wrap a whole typed RPC op. This is the SINGLE home
/// for the mechanism — `aegix_memory::rpc_auth::RawSigned` re-exports this
/// type rather than reimplementing it, so the two signed-wire surfaces cannot
/// drift apart. The per-caller signing FORMULAS (which envelope fields are
/// concatenated around `raw_bytes()`) deliberately stay in their own crates;
/// only the raw-text binding is shared.
///
/// # Why this type exists
///
/// `serde_json`'s f64 round-trip is NOT idempotent, and no finite number of
/// normalisation passes makes it so — some values CYCLE. The counterexample
/// pinned by `some_floats_have_no_round_trip_fixed_point_known_gap`:
///
/// ```text
///   5.455171886890906e-115   (as written by the controller)
///     -> 5.455171886890905e-115
///     -> 5.4551718868909045e-115
///     -> 5.455171886890905e-115   <- back to the 2nd form: a permanent 2-cycle
/// ```
///
/// Any signature derived by RE-SERIALISING a parsed value therefore depends
/// on how many round trips that particular value happened to have made. The
/// controller hashed `write(x)`; the worker parsed the wire bytes into the
/// drifted f64 and hashed `write(parse(write(x)))`; the two digests differed
/// and the job failed dispatch verification. It presented as a LOTTERY — a job
/// failed only if its payload happened to contain an unstable float — which is
/// why `pa-autonomy-digest` (≈30 computed ratios) failed every run while
/// text-only payloads verified fine for weeks (2026-07-27 incident, #595/#597).
///
/// The memory-RPC twin (#598) had the identical defect one layer down: its
/// predecessor signed a `serde_json::Value` by re-deriving canonical text on
/// each side (`canonical_json_bytes`, now deleted:
/// `Value::Number(n) => n.to_string()`). The sender canonicalised the value it
/// held, the receiver canonicalised its RE-PARSE of the wire JSON, the two
/// byte strings differed, and the signature failed for an entirely honest
/// sender on payload content alone. Actor-memory values are ARBITRARY module
/// output — LLM/agent nodes persist computed ratios routinely — so the class
/// was live, not theoretical.
///
/// Hashing the raw text removes the re-derivation entirely: there is exactly
/// one byte string per payload per direction, and it is the one on the wire.
/// Because the receiver hashes the sender's exact bytes, this ALSO removes any
/// dependence on key ordering or serde enum-tag stability that a fixed-tag
/// canonical concatenation existed to defend.
///
/// # Invariant: `raw` and `parsed` are never supplied independently
///
/// There is deliberately NO constructor that accepts both halves, and NO
/// mutable accessor (`&mut T`, `raw_mut`, …). `raw` is what the signature
/// covers and `parsed` is what handlers act on; a caller who could set — or
/// mutate — them independently could desync them, signing one payload while
/// the module executes another, which is precisely the bug class this type
/// exists to make unrepresentable. Do not add one: mutate the value you own
/// and build a fresh `RawSigned` from it, which re-mints both views together.
/// Construct from a `T` (send side) or by deserialising (receive side).
///
/// Note the two halves are semantically equal but need not be bit-equal: on the
/// send side `parsed` is the caller's original value, and re-parsing `raw`
/// could land one ULP away for an unstable float. That is harmless *because*
/// nothing security-relevant is ever derived from `parsed` — see
/// [`Self::raw_bytes`].
///
/// # Why exotic JSON text is not an attack surface
///
/// `raw` can hold text a round-trip through `T` can never reproduce: duplicate
/// keys (`{"a":1,"a":2}`, which parses last-wins), interior padding,
/// non-shortest float spellings, redundant `\u` escapes. The signature covers
/// that text while every consumer reads the deduplicated parse — so it is
/// worth being explicit about who can put such text there:
///
/// * Both sides only ever MINT raw text through [`From`], i.e.
///   `serde_json::value::to_raw_value(&T)` (for `T = Value` this is exactly
///   `Value::to_string()` — the same compact serializer), which cannot emit
///   duplicate keys or padding.
/// * The only other way raw text enters is deserialisation of a message that
///   ALREADY VERIFIES under a signing key — the digest covers the exact bytes,
///   so an on-path attacker who rewrites the payload text (even into a
///   semantically identical form) invalidates the signature and the message is
///   refused before anything reads `parsed`.
/// * Worker output never becomes controller-signed request text verbatim: the
///   engine takes `into_value()`/`value().clone()` and a fresh `From` re-mints
///   the bytes, so exotic text cannot be laundered across a signing boundary
///   by a keyless component. The same holds for the memory RPCs: a keyless
///   guest supplies only `Value`-semantics to the worker host, which re-mints
///   via [`From`] before signing.
///
/// Consequently duplicate-key smuggling requires the signing key, and a key
/// holder can already send whatever it likes. Pinned by
/// `signature_binds_payload_text_not_meaning`. Corollary worth knowing before
/// anyone "helpfully" normalises: because the binding is textual, ANY
/// semantics-preserving reformatting between signer and verifier now fails
/// closed. Nothing reformats today (NATS delivers bytes verbatim) — do not
/// introduce a JSON-rewriting hop, and do not re-canonicalise to tolerate one.
///
/// # Cost, and deploy ordering
///
/// Memory cost is ≈2× the payload text (raw + parsed view), bounded by the NATS
/// `max_payload` limit that already bounds every message; deserialisation also
/// walks the payload twice (raw capture, then parse), which — like the single
/// parse it replaces — happens BEFORE signature verification. Both are bounded
/// by the transport cap and the worker's own pre-deserialise size check.
///
/// Controllers and workers must roll TOGETHER. A mixed fleet fails closed (a
/// verification error, never an accept or a panic) in both directions — the
/// wire BYTES are unchanged, only the digest formula moved — but it fails MORE
/// often than the pre-fix code did, not less. An old peer hashes the
/// once-normalised form, so a mixed pair diverges for EVERY payload whose float
/// spelling is unstable at all (39_495 + 19_721 of 199_902 sampled f64),
/// whereas the pre-fix pair only diverged for those still unstable after one
/// pass (19_721) — roughly 3× the failure surface. On the memory-RPC side the
/// mixed fleet fails EVERY memory / integration-state RPC until both halves
/// run the new code. Expect elevated dispatch failures for the duration of a
/// staggered rollout, and keep the window short; compose (`make up`) rolls both
/// together.
#[derive(Debug, Clone)]
pub struct RawSigned<T> {
    /// The authoritative form: the exact JSON text that is (or was) on the
    /// wire. Everything security-relevant hashes THIS via
    /// [`raw_bytes`](Self::raw_bytes).
    raw: Box<serde_json::value::RawValue>,
    /// Parsed view for consumers, who overwhelmingly want a typed payload.
    /// Derived ONCE, alongside `raw`, at the single construction point per
    /// side — never re-serialised back into `raw`, which is what would reopen
    /// the desync bug.
    parsed: T,
}

impl<T> RawSigned<T> {
    /// The parsed payload — what module dispatch, judges, RPC handlers, and
    /// every other consumer read. NOT what gets signed; see
    /// [`Self::raw_bytes`].
    pub fn get(&self) -> &T {
        &self.parsed
    }

    /// Consume the wrapper and take the parsed payload (for handlers that
    /// move the payload into an executor).
    pub fn into_inner(self) -> T {
        self.parsed
    }

    /// The bytes covered by the signature: the exact JSON text of this payload
    /// as it appears on the wire. Every `Sha256::digest` / signing /
    /// verification site over a signed payload MUST use this — hashing a
    /// re-serialised form of [`Self::get`] re-introduces the non-idempotent
    /// round trip documented on the type.
    pub fn raw_bytes(&self) -> &[u8] {
        self.raw.get().as_bytes()
    }

    /// Length of [`Self::raw_bytes`]. Used by the signature diagnostics so the
    /// reported length describes the same bytes the signature covers.
    pub fn raw_len(&self) -> usize {
        self.raw.get().len()
    }
}

impl<T: Serialize> From<T> for RawSigned<T> {
    /// The ONLY value constructor — the send-side construction point that
    /// fixes the wire text once and for all.
    ///
    /// `to_raw_value` is infallible for the payload types this wraps.
    /// `serde_json::Value` always serialises (NaN/Inf cannot exist inside one
    /// — `Number::from_f64` rejects them). `MemoryOp` / `IntegrationOp` are
    /// enums over strings, ints, and `Value` fields; the one bare `f64` field,
    /// `ttl_hours`, is validated finite before signing and otherwise
    /// serialises as `null` rather than erroring. The `expect` is therefore
    /// unreachable for these types; it is documented rather than silently
    /// `unwrap`'d.
    fn from(parsed: T) -> Self {
        let raw = serde_json::value::to_raw_value(&parsed)
            .expect("RawSigned payload types always serialise to valid JSON");
        Self { raw, parsed }
    }
}

impl<T> Serialize for RawSigned<T> {
    /// Forwards to the raw text, which `serde_json` emits verbatim — so the
    /// bytes that were signed are the bytes that go out.
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.raw.serialize(serializer)
    }
}

impl<'de, T: serde::de::DeserializeOwned> Deserialize<'de> for RawSigned<T> {
    /// Captures the received text VERBATIM, then derives the parsed view from
    /// it. The verifier consequently hashes exactly what the sender hashed,
    /// whatever the sender's float formatting happened to be.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = Box::<serde_json::value::RawValue>::deserialize(deserializer)?;
        // A parse failure here is a malformed message, not a signing concern:
        // `RawValue` guarantees syntactic JSON, so this only trips on `T`'s
        // shape or on serde_json's built-in 128-deep recursion limit —
        // surface it as a deserialize error rather than panicking on
        // untrusted input.
        let parsed = serde_json::from_str(raw.get()).map_err(serde::de::Error::custom)?;
        Ok(Self { raw, parsed })
    }
}

/// The `serde_json::Value` specialisation of [`RawSigned`] — the dispatch and
/// result payloads carried by [`JobRequest`] and [`JobResult`].
///
/// A type alias, not a distinct type: everything in [`RawSigned`]'s docs
/// applies verbatim, and `value()` / `into_value()` below are the
/// `Value`-flavoured spellings of [`RawSigned::get`] / [`RawSigned::into_inner`].
pub type SignedJson = RawSigned<serde_json::Value>;

impl RawSigned<serde_json::Value> {
    /// The parsed payload — what module dispatch, judges, and every other
    /// consumer read. NOT what gets signed; see [`Self::raw_bytes`].
    ///
    /// Value-typed alias of [`RawSigned::get`]; both are kept because the
    /// dispatch surface reads far better as `input_payload.value()`.
    pub fn value(&self) -> &serde_json::Value {
        &self.parsed
    }

    /// Consume the wrapper and take the parsed payload. Value-typed alias of
    /// [`RawSigned::into_inner`].
    pub fn into_value(self) -> serde_json::Value {
        self.parsed
    }
}
