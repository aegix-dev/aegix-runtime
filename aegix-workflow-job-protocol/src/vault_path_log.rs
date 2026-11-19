//! How a vault path is written to a log, and how the `vault://` references
//! in a value are found.
//!
//! The controller and the worker render a path the same way, so a line in
//! one log can be matched to a line in the other without either holding the
//! path in clear. Moved out of `lib.rs` 2026-11-18, unchanged; every item is
//! re-exported at the crate root, where it was.

use sha2::Sha256;

/// Render a vault key path for a LOG LINE, with the OAuth provider key hashed.
///
/// The OAuth credential paths are `oauth/<provider>/<user_id>/<provider_key>/…`
/// (see `OAuthCredentialService::access_token_path` / `refresh_token_path` in
/// `aegix-oauth`), and for the `gmail` provider `<provider_key>` IS the
/// account's email address — straight PII. MCP-988 (2026-05-15) redacted it in
/// the controller's token-refresh task, in a `pub(crate)` helper that crate
/// alone could reach; the worker's `AuditingProvider` — which logs every
/// `secret.resolve` of every module execution — kept printing the path whole
/// (measured 2026-09-13: 23 email-bearing INFO lines in 25 minutes on a
/// one-user fleet). This is the ONE home now, beside [`vault_path_permitted`]
/// for the same reason that function lives here: both binaries hold vault
/// paths and both must agree on what a vault path means — and on what of it
/// may be printed. Structural check 91 requires every `key_path`/`vault_path`
/// log field to route through it.
///
/// Rules, deliberately narrow so the line stays greppable:
///   - an `oauth/…` path with at least four segments has its FOURTH segment
///     (the provider key) replaced by `<8-hex sha256 prefix>` — whatever the
///     provider keys on (email for gmail, a derived account UUID for
///     google_calendar, a team id for slack), so a new provider keyed on a
///     human identifier is covered the day it ships; the leaf
///     (`access_token`, `refresh_token`, none) does not matter, which is what
///     the MCP-988 helper (exactly five parts, `access_token` only) got wrong;
///   - `<provider>` and `<user_id>` stay visible — a UUID is not directly
///     attributable, and operators correlate on it;
///   - every other path (`anthropic/api_key`, `stripe/live/key`, a bare
///     `oauth/gmail/<uid>` with no provider key) is returned UNCHANGED.
///
/// The hash is a correlation token, not a secret: two log lines for the same
/// credential render the same prefix.
pub fn redact_vault_path_for_log(key_path: &str) -> String {
    let parts: Vec<&str> = key_path.split('/').collect();
    if parts.len() >= 4 && parts[0] == "oauth" {
        let hashed = redact_oauth_provider_key_for_log(parts[3]);
        parts
            .iter()
            .enumerate()
            .map(|(i, seg)| if i == 3 { hashed.as_str() } else { seg })
            .collect::<Vec<&str>>()
            .join("/")
    } else {
        key_path.to_string()
    }
}

/// Replace an OAuth `provider_key` (for gmail the user's email address) with a
/// short sha256 prefix in angle brackets, for the sites that log the key as a
/// bare field rather than embedded in a path. Same token
/// [`redact_vault_path_for_log`] substitutes into the path, so a path line and
/// a bare-key line about one credential correlate.
pub fn redact_oauth_provider_key_for_log(provider_key: &str) -> String {
    use sha2::Digest as _;
    let hash = Sha256::digest(provider_key.as_bytes());
    let prefix: String = hex::encode(hash).chars().take(8).collect();
    format!("<{prefix}>")
}

#[cfg(test)]
mod vault_path_log_redaction_tests {
    use super::{redact_oauth_provider_key_for_log, redact_vault_path_for_log};

    const UID: &str = "11111111-2222-3333-4444-555555555555";

    #[test]
    fn gmail_access_token_path_loses_the_email_and_keeps_the_rest() {
        let out =
            redact_vault_path_for_log(&format!("oauth/gmail/{UID}/alice@example.com/access_token"));
        assert!(!out.contains("alice"), "{out}");
        assert!(!out.contains("example.com"), "{out}");
        assert!(!out.contains('@'), "{out}");
        assert_eq!(
            out.matches('/').count(),
            4,
            "segment count preserved: {out}"
        );
        assert!(out.starts_with(&format!("oauth/gmail/{UID}/<")), "{out}");
        assert!(out.ends_with(">/access_token"), "{out}");
    }

    #[test]
    fn refresh_token_leaf_is_redacted_too() {
        // The MCP-988 helper matched exactly five parts ending in
        // `access_token`; the refresh-token twin of the same credential
        // carries the same email and was invisible to it.
        let out = redact_vault_path_for_log(&format!(
            "oauth/gmail/{UID}/alice@example.com/refresh_token"
        ));
        assert!(!out.contains("alice"), "{out}");
        assert!(out.ends_with(">/refresh_token"), "{out}");
    }

    #[test]
    fn four_segment_prefix_is_redacted() {
        // `oauth/<provider>/<user_id>/<provider_key>` without a leaf — the
        // shape aegix-google-calendar builds before appending `/access_token`.
        let out =
            redact_vault_path_for_log(&format!("oauth/google_calendar/{UID}/alice@example.com"));
        assert!(!out.contains("alice"), "{out}");
        assert_eq!(out.matches('/').count(), 3, "{out}");
    }

    #[test]
    fn non_oauth_paths_pass_through_unchanged() {
        for p in [
            "anthropic/api_key",
            "stripe/live/key",
            "weird/three/parts",
            "",
            "oauth",
            "oauth/gmail",
            // three segments: there is no provider key to hash yet
            &format!("oauth/gmail/{UID}"),
        ] {
            assert_eq!(redact_vault_path_for_log(p), p, "{p:?} must be unchanged");
        }
    }

    #[test]
    fn provider_key_token_is_stable_distinct_and_at_free() {
        let a = redact_oauth_provider_key_for_log("alice@example.com");
        let b = redact_oauth_provider_key_for_log("alice@example.com");
        let c = redact_oauth_provider_key_for_log("bob@example.com");
        assert_eq!(a, b, "same key must render the same token");
        assert_ne!(a, c, "different keys must render different tokens");
        assert!(
            a.starts_with('<') && a.ends_with('>') && a.len() == 10,
            "{a}"
        );
        assert!(!a.contains('@'));
        // and the path form substitutes exactly this token
        let path =
            redact_vault_path_for_log(&format!("oauth/gmail/{UID}/alice@example.com/access_token"));
        assert!(path.contains(&a), "{path} should carry {a}");
    }
}

/// A detected `vault://` reference in a config object: `(config_key, vault_path)`.
///
/// `vault_path` is the path with the `vault://` prefix already stripped,
/// matching the form stored in the vault, accepted by
/// `SecretsManager::get_secrets_by_paths`, and expected by
/// [`vault_path_permitted`].
pub type VaultRef = (String, String);

/// Extract every `vault://<path>` reference from the top-level string values
/// of a JSON config object. Malformed refs (empty path after the marker) are
/// skipped.
///
/// Only scans top-level keys — nested objects are not recursed into, matching
/// the engine's dispatch convention where node config is a flat key/value map.
///
/// # This lives here, next to [`vault_path_permitted`], on purpose
///
/// Reference DETECTION and reference PERMISSION are two halves of one
/// question, and splitting them across crates is how they drifted: the
/// resolvers matched `vault://` anywhere in the value while four separate
/// authoring-time checkers used `strip_prefix`, which matches only a bare
/// prefix. Catalog integration modules carry the reference inside a header
/// template — `AUTH_HEADER = "Bearer vault://oauth/gmail/<uid>/<email>/access_token"`
/// — so the prefix form matched **0 of 45** references on the live fleet
/// (measured 2026-08-28) while both runtime resolvers acted on all 45. A
/// permission check that cannot see the reference reports "clean" for a
/// blocked path.
///
/// The path token runs from `vault://` to the first whitespace (header
/// templates place the token last) or end-of-value, matching
/// `aegix-wasm-host`'s `resolve_vault_header`.
#[must_use]
pub fn extract_vault_refs(config: &serde_json::Value) -> Vec<VaultRef> {
    let mut refs = Vec::new();
    if let Some(obj) = config.as_object() {
        for (k, v) in obj {
            if let Some(val_str) = v.as_str() {
                if let Some(after) = val_str.split("vault://").nth(1) {
                    let path = after.split_whitespace().next().unwrap_or("");
                    if !path.is_empty() {
                        refs.push((k.clone(), path.to_string()));
                    }
                }
            }
        }
    }
    refs
}

#[cfg(test)]
mod vault_ref_extraction_tests {
    use super::extract_vault_refs;

    /// The exact shape carried by every one of the 45 references on the live
    /// fleet. A bare-prefix matcher returns nothing here.
    #[test]
    fn embedded_bearer_reference_is_extracted() {
        let cfg = serde_json::json!({
            "AUTH_HEADER":
                "Bearer vault://oauth/gmail/00000000-0000-4000-8000-000000000001/\
                 user@example.com/access_token"
        });
        let refs = extract_vault_refs(&cfg);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "AUTH_HEADER");
        assert!(refs[0].1.starts_with("oauth/gmail/"));
        assert!(!refs[0].1.contains("Bearer"));
    }

    #[test]
    fn bare_prefix_reference_is_extracted() {
        let cfg = serde_json::json!({"KEY": "vault://anthropic/api_key"});
        assert_eq!(
            extract_vault_refs(&cfg),
            vec![("KEY".to_string(), "anthropic/api_key".to_string())]
        );
    }

    /// A marker with no path yields no ref — callers treat "value mentions
    /// vault:// but produced no ref" as malformed.
    #[test]
    fn empty_path_yields_no_ref() {
        assert!(extract_vault_refs(&serde_json::json!({"K": "vault://"})).is_empty());
        assert!(extract_vault_refs(&serde_json::json!({"K": "vault:// "})).is_empty());
        assert!(extract_vault_refs(&serde_json::json!({"K": "vault://vault://x"})).is_empty());
    }

    #[test]
    fn non_string_and_nested_values_are_ignored() {
        let cfg = serde_json::json!({
            "N": 5,
            "NESTED": {"INNER": "vault://a/b"}
        });
        assert!(extract_vault_refs(&cfg).is_empty());
    }
}
