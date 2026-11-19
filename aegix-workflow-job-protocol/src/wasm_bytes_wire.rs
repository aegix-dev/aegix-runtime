//! The wire spelling of an inline `wasm_bytes` field (`#[serde(with)]`).
//!
//! Until 2026-10-30 `JobRequest::wasm_bytes` (and the since-removed
//! `PipelineStep::wasm_bytes`) were plain `Option<Vec<u8>>`, which serde_json writes as an array of
//! integers — 3.57× the raw size on random bytes, 2.8–3.3× on real
//! components (measured; `docs/engineering-log/packages/2026-10-30-wasm-bytes-on-the-wire.md`).
//! `serde_bytes` does not help: serde_json has no binary form and writes a
//! `bytes` value as the same array. This adapter writes standard padded
//! base64 (1.33×) and READS BOTH forms, so a worker of this release accepts a
//! controller of either, and a controller rolled before its workers can keep
//! the old spelling with `AEGIX_WASM_BYTES_WIRE=integer-list`
//! ([`aegix_dispatch_types::inline_wasm::WasmBytesEncoding`] is the
//! one place that decides which is written).
//!
//! The dispatch signature is untouched: both `signing_payload` formulas hash
//! the RAW bytes (`sha256(wasm_bytes)`), never the wire text, so one signed
//! request verifies whichever spelling carried it — pinned by the wire-format
//! snapshots (`job_request_non_empty_wasm_bytes_snapshot` and the legacy
//! round-trip beside it).

use aegix_dispatch_types::inline_wasm::WasmBytesEncoding;
use base64::Engine as _;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserializer, Serializer};
use std::fmt;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// Writes `bytes` under the process's active encoding; `None` is `null`
/// (a field that also carries `skip_serializing_if` never reaches this).
pub fn serialize<S: Serializer>(bytes: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
    serialize_as(WasmBytesEncoding::active(), bytes, s)
}

/// Writes `bytes` under an explicit encoding (the tests pin both forms
/// without touching the environment).
pub fn serialize_as<S: Serializer>(
    encoding: WasmBytesEncoding,
    bytes: &Option<Vec<u8>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    match bytes {
        None => s.serialize_none(),
        Some(b) => match encoding {
            WasmBytesEncoding::Base64 => s.serialize_str(&B64.encode(b)),
            WasmBytesEncoding::IntegerList => s.collect_seq(b.iter()),
        },
    }
}

/// Reads a base64 string, an array of byte integers, or `null`.
pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
    d.deserialize_option(OptionVisitor)
}

struct OptionVisitor;

impl<'de> Visitor<'de> for OptionVisitor {
    type Value = Option<Vec<u8>>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("null, a base64 string or an array of byte integers")
    }

    fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_unit<E: de::Error>(self) -> Result<Self::Value, E> {
        Ok(None)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Self::Value, D::Error> {
        d.deserialize_any(BytesVisitor).map(Some)
    }
}

struct BytesVisitor;

impl<'de> Visitor<'de> for BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a base64 string or an array of byte integers")
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
        B64.decode(v)
            .map_err(|e| E::custom(format!("wasm_bytes is not standard base64: {e}")))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
        Ok(v.to_vec())
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<Self::Value, E> {
        Ok(v)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1 << 20));
        while let Some(b) = seq.next_element::<u8>()? {
            out.push(b);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
    struct Carrier {
        #[serde(default, with = "super")]
        wasm_bytes: Option<Vec<u8>>,
    }

    #[derive(Serialize)]
    struct LegacyCarrier {
        #[serde(serialize_with = "legacy")]
        wasm_bytes: Option<Vec<u8>>,
    }

    #[allow(clippy::ref_option)] // serde's `serialize_with` hands the field over as `&Option<T>`
    fn legacy<S: Serializer>(b: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        serialize_as(WasmBytesEncoding::IntegerList, b, s)
    }

    #[test]
    fn base64_is_written_by_default_and_read_back() {
        let c = Carrier {
            wasm_bytes: Some(vec![0x00, 0x61, 0x73, 0x6D]),
        };
        let text = serde_json::to_string(&c).unwrap();
        assert_eq!(text, r#"{"wasm_bytes":"AGFzbQ=="}"#);
        assert_eq!(serde_json::from_str::<Carrier>(&text).unwrap(), c);
    }

    #[test]
    fn the_integer_list_form_is_still_read() {
        let legacy = serde_json::to_string(&LegacyCarrier {
            wasm_bytes: Some(vec![0x00, 0x61, 0x73, 0x6D]),
        })
        .unwrap();
        assert_eq!(legacy, r#"{"wasm_bytes":[0,97,115,109]}"#);
        let read: Carrier = serde_json::from_str(&legacy).unwrap();
        assert_eq!(
            read.wasm_bytes.as_deref(),
            Some(&[0x00, 0x61, 0x73, 0x6D][..])
        );
    }

    #[test]
    fn null_and_absence_are_none() {
        assert_eq!(
            serde_json::from_str::<Carrier>(r#"{"wasm_bytes":null}"#).unwrap(),
            Carrier { wasm_bytes: None }
        );
        assert_eq!(
            serde_json::from_str::<Carrier>("{}").unwrap(),
            Carrier { wasm_bytes: None }
        );
        assert_eq!(
            serde_json::to_string(&Carrier { wasm_bytes: None }).unwrap(),
            r#"{"wasm_bytes":null}"#
        );
    }

    #[test]
    fn a_string_that_is_not_base64_and_an_integer_over_255_are_refused() {
        let bad = serde_json::from_str::<Carrier>(r#"{"wasm_bytes":"not base64!"}"#).unwrap_err();
        assert!(bad.to_string().contains("not standard base64"), "{bad}");
        assert!(serde_json::from_str::<Carrier>(r#"{"wasm_bytes":[0,256]}"#).is_err());
        assert!(serde_json::from_str::<Carrier>(r#"{"wasm_bytes":[-1]}"#).is_err());
        assert!(serde_json::from_str::<Carrier>(r#"{"wasm_bytes":{"a":1}}"#).is_err());
    }

    #[test]
    fn encoded_len_is_the_exact_wire_length_of_both_forms() {
        // Pseudo-random bytes (xorshift) so every digit count occurs.
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        let bytes: Vec<u8> = (0..200_003)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24).to_le_bytes()[0]
            })
            .collect();
        for (encoding, text) in [
            (
                WasmBytesEncoding::Base64,
                serde_json::to_string(&Carrier {
                    wasm_bytes: Some(bytes.clone()),
                })
                .unwrap(),
            ),
            (
                WasmBytesEncoding::IntegerList,
                serde_json::to_string(&LegacyCarrier {
                    wasm_bytes: Some(bytes.clone()),
                })
                .unwrap(),
            ),
        ] {
            let value_len = text.len() - r#"{"wasm_bytes":}"#.len();
            assert_eq!(encoding.encoded_len(&bytes), value_len, "{encoding}");
        }
    }
}
