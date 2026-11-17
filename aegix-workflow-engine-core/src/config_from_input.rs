//! A config key that may arrive in the node's INPUT instead of its config.
//!
//! A reader that answers a question at run time takes its filter from the
//! node's config OR from a `query` handed in by the trigger or the upstream
//! node (docs/writing-a-template.md, "A query handed in"). Its source says
//! `ok_or("Missing PROPERTY_ADDRESS config")` once both are absent, so a
//! checker that reads only the config called such a node misconfigured when
//! the value arrives in the trigger (observed 2026-10-20 on a parcel lookup
//! driven by an on-demand query).
//!
//! The manifest says so on the key: a `config_schema` property carrying
//! `"x-from-input": "<path in the node's input>"` (for example
//! `"query.property_address"`). This is the ONE reading of that annotation;
//! the validator and the create-time analysis both ask it.

use std::collections::BTreeMap;

/// The `config_schema` property field that names where a key may arrive in
/// the node's input.
pub const FROM_INPUT: &str = "x-from-input";

/// The keys of `config_schema` that may arrive in the node's input, each
/// with the input path its property names. A property whose annotation is
/// not a non-empty string is not listed (it says nothing).
#[must_use]
pub fn keys_from_input(config_schema: &serde_json::Value) -> BTreeMap<String, String> {
    config_schema
        .get("properties")
        .and_then(serde_json::Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(key, spec)| {
            let path = spec.get(FROM_INPUT)?.as_str()?.trim();
            (!path.is_empty()).then(|| (key.clone(), path.to_string()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_a_property_naming_a_path_is_listed() {
        let schema = json!({"properties": {
            "PROPERTY_ADDRESS": {"type": "string", "x-from-input": "query.property_address"},
            "MAX_ITEMS": {"type": "integer"},
            "EMPTY": {"x-from-input": "  "},
            "NOT_TEXT": {"x-from-input": true},
        }});
        assert_eq!(
            keys_from_input(&schema).into_iter().collect::<Vec<_>>(),
            vec![(
                "PROPERTY_ADDRESS".to_string(),
                "query.property_address".to_string()
            )]
        );
        assert!(keys_from_input(&json!({})).is_empty());
        assert!(keys_from_input(&json!({"properties": []})).is_empty());
    }
}
