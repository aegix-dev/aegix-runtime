//! How a module's compiled bytes travel in a job, and whether they fit.
//!
//! A `JobRequest` may carry the module's WASM bytes
//! inline, or name a URI the worker fetches them from (`redis:wasm:…`,
//! `oci://…`). Inline bytes are JSON text on the wire, so what NATS's
//! `max_payload` bounds is the ENCODED message, not the raw byte count.
//! Until 2026-10-30 the inline cap compared the RAW length (4 MiB) with the
//! 8 MiB `max_payload`, while `serde_json` wrote the field as an integer list
//! (`[0,97,115,…]`, 3.57× the raw size on random bytes): a 2.2 MiB module
//! passed the cap and failed to publish (measured, 8 238 698 bytes).
//!
//! This module is the ONE home of three decisions, read by the engine (which
//! decides whether to embed), the registry (which decides whether a module's
//! Redis copy must be written before the fetch returns — the two must agree,
//! or a module the engine routes by URI could race an asynchronous fill) and
//! the job protocol (which writes the field):
//!
//! * [`WasmBytesEncoding`] — the wire spelling of the field. `Base64` is the
//!   default (1.33×); `IntegerList` is the pre-2026-10-30 spelling, kept
//!   behind [`WASM_BYTES_WIRE_ENV`] for a controller that must roll BEFORE
//!   its workers (an old worker cannot decode a string). A worker of this
//!   release decodes both, whatever the controller writes.
//! * [`WasmBytesEncoding::encoded_len`] — the exact JSON text length of the
//!   field under an encoding, so the cap is a check on what goes on the wire.
//! * [`inline_field_budget`] — how much of the message the field may take:
//!   `max_payload − INLINE_HEADROOM_BYTES`, where the headroom covers the
//!   input payload (the worker admits up to `WASM_MAX_INPUT_BYTES`, 1 MB by
//!   default), the secrets envelope and the JSON framing that share the
//!   message. The routing decision uses the reference `max_payload`
//!   (8 MiB, `deploy/nats/nats.conf` and the chart) or the operator's
//!   [`INLINE_WASM_MAX_BYTES_ENV`]; the publisher then checks the whole
//!   encoded message against the limit the connected server actually
//!   announced ([`refuse_over_max_payload`]).
//!
//! The dispatch signature binds `sha256(wasm_bytes)` over the RAW bytes, so
//! none of this touches the signing payload: the same signed request verifies
//! whichever spelling carried it.

use std::fmt;
use std::sync::OnceLock;

/// Selects the wire spelling of `wasm_bytes`: `base64` (default) or
/// `integer-list` (the pre-2026-10-30 form, for a controller rolled before
/// its workers).
pub const WASM_BYTES_WIRE_ENV: &str = "AEGIX_WASM_BYTES_WIRE";

/// Overrides [`inline_field_budget`]: the most bytes the ENCODED `wasm_bytes`
/// field may occupy in a job message before the module routes by URI.
pub const INLINE_WASM_MAX_BYTES_ENV: &str = "AEGIX_INLINE_WASM_MAX_BYTES";

/// The `max_payload` the reference deploys configure on NATS
/// (`deploy/nats/nats.conf`, the chart's NATS `ConfigMap`). The default inline
/// budget derives from it; the publisher reads the live value from the
/// connection.
pub const REFERENCE_NATS_MAX_PAYLOAD: usize = 8 * 1024 * 1024;

/// What the rest of a job message may need beside the inline bytes: the
/// input payload (up to the worker's `WASM_MAX_INPUT_BYTES`, 1 MB default),
/// the secrets envelope, the signature and the JSON framing.
pub const INLINE_HEADROOM_BYTES: usize = 2 * 1024 * 1024;

/// The wire spelling of an inline `wasm_bytes` field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WasmBytesEncoding {
    /// A JSON string holding the standard, padded base64 of the bytes
    /// (4 bytes of text per 3 bytes of module, plus the two quotes).
    Base64,
    /// A JSON array of integers, one per byte (`[0,97,115,109]`): what
    /// `serde_json` writes for a `Vec<u8>`, and what every worker before
    /// 2026-10-30 expects.
    IntegerList,
}

impl WasmBytesEncoding {
    /// The default spelling.
    pub const DEFAULT: Self = Self::Base64;

    /// Parses a [`WASM_BYTES_WIRE_ENV`] value. Empty (or whitespace) means
    /// unset and gives the default; anything but the two spellings is an
    /// error naming them, so a boot gate can refuse a typo instead of a
    /// dispatch silently taking the wrong form.
    pub fn parse(value: &str) -> Result<Self, String> {
        let v = value.trim();
        if v.is_empty() {
            return Ok(Self::DEFAULT);
        }
        match v.to_ascii_lowercase().as_str() {
            "base64" => Ok(Self::Base64),
            "integer-list" | "integer_list" | "legacy" => Ok(Self::IntegerList),
            other => Err(format!(
                "{WASM_BYTES_WIRE_ENV}={other:?} is not a wasm_bytes wire encoding: \
                 use `base64` (default) or `integer-list` (the pre-2026-10-30 form, \
                 for a controller rolled before its workers)"
            )),
        }
    }

    /// Reads [`WASM_BYTES_WIRE_ENV`] from the process environment, every
    /// call (a boot gate calls this; the writer uses [`Self::active`]).
    pub fn from_env() -> Result<Self, String> {
        match std::env::var(WASM_BYTES_WIRE_ENV) {
            Ok(v) => Self::parse(&v),
            Err(_) => Ok(Self::DEFAULT),
        }
    }

    /// The encoding this process writes, read once. An unrecognised value
    /// falls back to the default here because a serialiser cannot refuse;
    /// the controller's configuration validator refuses it at boot, before
    /// any dispatch.
    pub fn active() -> Self {
        static ACTIVE: OnceLock<WasmBytesEncoding> = OnceLock::new();
        *ACTIVE.get_or_init(|| Self::from_env().unwrap_or(Self::DEFAULT))
    }

    /// The spelling [`Self::parse`] accepts for this encoding.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::IntegerList => "integer-list",
        }
    }

    /// The exact length of the JSON text the field's VALUE occupies under
    /// this encoding — quotes or brackets included, the `"wasm_bytes":` key
    /// and the separating comma not. Pinned against `serde_json`'s real output
    /// by the job protocol's tests.
    pub fn encoded_len(self, bytes: &[u8]) -> usize {
        match self {
            Self::Base64 => 2 + bytes.len().div_ceil(3) * 4,
            Self::IntegerList => {
                if bytes.is_empty() {
                    return 2;
                }
                let digits: usize = bytes
                    .iter()
                    .map(|b| match b {
                        0..=9 => 1,
                        10..=99 => 2,
                        _ => 3,
                    })
                    .sum();
                // brackets + digits + a comma between each pair
                2 + digits + bytes.len() - 1
            }
        }
    }
}

impl fmt::Display for WasmBytesEncoding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The budget for the encoded `wasm_bytes` field under a given NATS
/// `max_payload`: the payload less [`INLINE_HEADROOM_BYTES`].
pub fn inline_field_budget_under(max_payload: usize) -> usize {
    max_payload.saturating_sub(INLINE_HEADROOM_BYTES)
}

/// The budget this process routes by: [`INLINE_WASM_MAX_BYTES_ENV`] when set
/// to a positive integer, else [`inline_field_budget_under`] the reference
/// `max_payload` (6 MiB). Read once.
pub fn inline_field_budget() -> usize {
    static BUDGET: OnceLock<usize> = OnceLock::new();
    *BUDGET.get_or_init(|| {
        std::env::var(INLINE_WASM_MAX_BYTES_ENV)
            .ok()
            .and_then(|v| v.trim().parse::<usize>().ok())
            .filter(|v| *v > 0)
            .unwrap_or_else(|| inline_field_budget_under(REFERENCE_NATS_MAX_PAYLOAD))
    })
}

/// Whether these bytes fit inline under `budget` when written with
/// `encoding`: non-empty, and their encoded text within the budget.
pub fn fits_inline(bytes: &[u8], encoding: WasmBytesEncoding, budget: usize) -> bool {
    !bytes.is_empty() && encoding.encoded_len(bytes) <= budget
}

/// Whether these module bytes ride inline in this process: non-empty AND
/// their text under the active encoding fits the process's budget. Empty
/// bytes always route by URI (a registry artifact); oversized bytes route by
/// the `redis:wasm:` URI with `expected_wasm_hash` committed in the
/// signature. The engine's dispatch sites and the registry's pre-warm ask
/// this one function, so they cannot disagree.
pub fn rides_inline(bytes: &[u8]) -> bool {
    fits_inline(bytes, WasmBytesEncoding::active(), inline_field_budget())
}

/// A job message the connected NATS server would refuse: its encoded size is
/// above the `max_payload` the server announced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OversizedMessage {
    /// The whole encoded message, in bytes.
    pub message_bytes: usize,
    /// The server's announced `max_payload`.
    pub max_payload: usize,
    /// The module (its URI) whose job this is.
    pub module_uri: String,
    /// `(raw, encoded)` lengths of the inline bytes, when the message
    /// carries any.
    pub inline_wasm: Option<(usize, usize)>,
}

impl fmt::Display for OversizedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "job message for module {} is {} bytes encoded, above the NATS max_payload of {} bytes",
            self.module_uri, self.message_bytes, self.max_payload
        )?;
        match self.inline_wasm {
            Some((raw, encoded)) => write!(
                f,
                " ({} bytes of inline WASM are {} bytes on the wire as {}). Install the module \
                 as a registry artifact (oci_url) so the worker pulls it, or lower \
                 {INLINE_WASM_MAX_BYTES_ENV} below {} so it routes by URI.",
                raw,
                encoded,
                WasmBytesEncoding::active(),
                encoded
            ),
            None => write!(
                f,
                " and carries no inline WASM: the input payload or the secrets envelope is \
                 too large for this server."
            ),
        }
    }
}

impl std::error::Error for OversizedMessage {}

/// Refuses an encoded job message the connected server's `max_payload` would
/// refuse, naming both numbers and the registry (`oci_url`) alternative.
/// `inline_wasm` is the raw inline bytes the message carries, if any.
pub fn refuse_over_max_payload(
    message_bytes: usize,
    max_payload: usize,
    module_uri: &str,
    inline_wasm: Option<&[u8]>,
) -> Result<(), OversizedMessage> {
    if message_bytes <= max_payload {
        return Ok(());
    }
    Err(OversizedMessage {
        message_bytes,
        max_payload,
        module_uri: module_uri.to_string(),
        inline_wasm: inline_wasm
            .filter(|b| !b.is_empty())
            .map(|b| (b.len(), WasmBytesEncoding::active().encoded_len(b))),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_the_two_spellings_and_refuses_the_rest() {
        assert_eq!(WasmBytesEncoding::parse(""), Ok(WasmBytesEncoding::Base64));
        assert_eq!(
            WasmBytesEncoding::parse("  "),
            Ok(WasmBytesEncoding::Base64)
        );
        assert_eq!(
            WasmBytesEncoding::parse(" Base64 "),
            Ok(WasmBytesEncoding::Base64)
        );
        assert_eq!(
            WasmBytesEncoding::parse("integer-list"),
            Ok(WasmBytesEncoding::IntegerList)
        );
        assert_eq!(
            WasmBytesEncoding::parse("legacy"),
            Ok(WasmBytesEncoding::IntegerList)
        );
        let err = WasmBytesEncoding::parse("json").unwrap_err();
        assert!(err.contains(WASM_BYTES_WIRE_ENV), "{err}");
        assert!(err.contains("integer-list"), "{err}");
    }

    #[test]
    fn encoded_len_matches_the_arithmetic_of_each_form() {
        // base64: 4 chars per 3 bytes, padded, plus quotes.
        assert_eq!(WasmBytesEncoding::Base64.encoded_len(&[]), 2);
        assert_eq!(WasmBytesEncoding::Base64.encoded_len(&[0]), 6);
        assert_eq!(WasmBytesEncoding::Base64.encoded_len(&[0, 1]), 6);
        assert_eq!(WasmBytesEncoding::Base64.encoded_len(&[0, 1, 2]), 6);
        assert_eq!(WasmBytesEncoding::Base64.encoded_len(&[0, 1, 2, 3]), 10);
        // integer list: `[0,97,115,109]` is 14 characters.
        assert_eq!(WasmBytesEncoding::IntegerList.encoded_len(&[]), 2);
        assert_eq!(WasmBytesEncoding::IntegerList.encoded_len(&[0]), 3);
        assert_eq!(
            WasmBytesEncoding::IntegerList.encoded_len(&[0, 97, 115, 109]),
            14
        );
        assert_eq!(WasmBytesEncoding::IntegerList.encoded_len(&[255; 3]), 13);
    }

    #[test]
    fn the_budget_derives_from_the_payload_less_the_headroom() {
        assert_eq!(
            inline_field_budget_under(REFERENCE_NATS_MAX_PAYLOAD),
            6 * 1024 * 1024
        );
        // A server at NATS's own 1 MiB default leaves no inline budget.
        assert_eq!(inline_field_budget_under(1024 * 1024), 0);
    }

    #[test]
    fn fits_inline_is_a_check_on_the_encoded_text() {
        let budget = 6 * 1024 * 1024;
        // 4 MiB of random-looking bytes: 14.98 MB as an integer list (does
        // not fit), 5.59 MB as base64 (fits) — the finding this fixes.
        let four_mib: Vec<u8> = (0..4u64 * 1024 * 1024)
            .map(|i| u8::try_from(i * 7919 % 251).expect("below 251"))
            .collect();
        assert!(fits_inline(&four_mib, WasmBytesEncoding::Base64, budget));
        assert!(!fits_inline(
            &four_mib,
            WasmBytesEncoding::IntegerList,
            budget
        ));
        // 4.5 MiB base64 = 6 291 458 bytes, two over the budget.
        let over: Vec<u8> = vec![1; 4_718_592];
        assert!(!fits_inline(&over, WasmBytesEncoding::Base64, budget));
        assert!(!fits_inline(&[], WasmBytesEncoding::Base64, budget));
        assert!(fits_inline(
            &[0u8; 1024],
            WasmBytesEncoding::IntegerList,
            budget
        ));
    }

    #[test]
    fn an_oversized_message_names_both_numbers_and_the_registry_path() {
        assert_eq!(
            refuse_over_max_payload(100, 100, "redis:wasm:x", None),
            Ok(())
        );
        let err = refuse_over_max_payload(9_000_000, 8_388_608, "redis:wasm:x", Some(&[1u8; 6]))
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("9000000 bytes encoded"), "{text}");
        assert!(text.contains("max_payload of 8388608"), "{text}");
        assert!(text.contains("oci_url"), "{text}");
        assert!(text.contains("redis:wasm:x"), "{text}");
        assert_eq!(err.inline_wasm.map(|(raw, _)| raw), Some(6));
        let none = refuse_over_max_payload(9_000_000, 8_388_608, "oci://m", None).unwrap_err();
        assert!(none.to_string().contains("no inline WASM"), "{none}");
    }
}
