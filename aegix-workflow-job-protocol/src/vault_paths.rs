//! Which vault paths are whose: the provider-key paths the host keeps for
//! itself, the provider hosts a local-only actor is refused, which tier a
//! provider is, and the one matcher of a module's `allowed_secrets` grant.
//!
//! The controller and the worker read the same rules, which is why they are
//! in the crate both link. They are not part of any message.
//! Moved out of `lib.rs` 2026-11-18, unchanged; every public item is
//! re-exported at the crate root, where it was.

use crate::LlmTier;

//
// These paths name the canonical LLM provider API keys that the controller
// pre-fetches into every worker job's secrets map so the host-side `llm::*`
// functions can resolve them. THE LIST HAS SECURITY IMPLICATIONS:
//
// - Controller-side (`engine::parallel::prefetch_llm_vault_keys` +
//   `secrets::SecretsManager::get_llm_vault_keys`): every job gets a snapshot
//   of these paths injected so LLM host calls can find them without the
//   module declaring them in `allowed_secrets`.
// - Worker-side (`host_impl::check_secret_allowlist`): guest-reachable
//   secret resolution MUST deny these paths even when a module has
//   `allowed_secrets: ["*"]` — otherwise a wildcard-grant module could
//   exfiltrate the user's LLM API keys via `secrets::get_secret` or a
//   `vault://anthropic/api_key` header interpolation.
//
// The list lives here, not per-crate, so adding a provider happens in one
// place and the controller prefetch + cache-invalidation + worker deny-list
// stay in lockstep. If you're adding a new provider (say, Mistral), update
// this constant and the corresponding branch in `worker::host_impl::llm_key_lookup_paths`.
//
// Rules for the list:
// - Entries are literal, case-sensitive vault paths.
// - The worker does a case-sensitive exact match; casing/prefix games can't
//   bypass the deny-list.
// - Add only paths that are genuinely host-only. User-facing secrets
//   (OAuth tokens, per-integration keys) do NOT belong here.
pub const LLM_PROVIDER_VAULT_PATHS: &[&str] =
    &["anthropic/api_key", "openai/api_key", "gemini/api_key"];

/// True iff `path` is one of the canonical LLM provider vault paths that
/// are reserved for host-internal consumption. Consumers use this as:
/// - worker: deny `secrets::get_secret` from returning these to WASM
/// - controller: trigger cache invalidation when the key is rotated
pub fn is_llm_provider_vault_path(path: &str) -> bool {
    LLM_PROVIDER_VAULT_PATHS.contains(&path)
}

/// Map a provider name (case-insensitive) to its data-egress tier.
/// Anthropic / OpenAI / Gemini = Tier 2 (external). Ollama = Tier 1
/// (local). Unknown providers default to Tier 2 (treat as external
/// until proven local) — fail-closed against future providers that
/// haven't been classified yet.
///
/// NB: classification ≠ an implemented client. `aegix-llm` currently ships
/// Anthropic (Tier 2) and Ollama (Tier 1) clients only; OpenAI/Gemini are
/// classified here (and in [`EXTERNAL_LLM_HOSTS`]) purely so the Tier-1 egress
/// gate denies them ahead of any client existing.
pub fn provider_tier(provider_name: &str) -> LlmTier {
    // The explicit Tier2 arm is intentional: it documents which
    // providers we have classified. Unknown providers also fall
    // through to Tier2 (fail-closed against unclassified entries).
    // Removing the explicit arm would lose that documentation.
    #[allow(clippy::match_same_arms)]
    match provider_name.to_ascii_lowercase().as_str() {
        "ollama" => LlmTier::Tier1,
        "anthropic" | "openai" | "gemini" => LlmTier::Tier2,
        _ => LlmTier::Tier2,
    }
}

/// DNS hostnames that belong to external LLM providers. Tier-1 actors
/// must not be allowed to reach these even via the generic
/// `wit_http::fetch` host function — otherwise the `llm::*`-level
/// refusal is trivially bypassed by a guest that writes its own
/// `POST https://api.anthropic.com/v1/messages` + `vault://anthropic/api_key`
/// header.
///
/// Matching is case-insensitive exact-match on the host portion of
/// the URL + suffix match to catch region-specific subdomains (e.g.
/// `generativelanguage.googleapis.com` → also `*.generativelanguage.googleapis.com`).
///
/// Extend this list whenever `LLM_PROVIDER_VAULT_PATHS` grows; the
/// two are parallel (vault-path side deny-lists the key, host-side
/// deny-lists the destination).
pub const EXTERNAL_LLM_HOSTS: &[&str] = &[
    // Anthropic — API endpoint.
    "api.anthropic.com",
    // OpenAI — primary + Azure mirror.
    "api.openai.com",
    // Google Gemini — current + legacy names.
    "generativelanguage.googleapis.com",
    "aiplatform.googleapis.com",
];

/// True iff `host` (already lowercased) matches one of the reserved
/// external LLM hostnames. Uses exact + suffix match so region
/// subdomains (`eu.api.openai.com`) also trigger.
///
/// **Trailing-dot normalisation.** `url::Url::parse("https://api.anthropic.com./...")`
/// returns `"api.anthropic.com."` (the FQDN trailing dot is preserved per
/// RFC 1738 / RFC 3986). DNS resolution treats the trailing dot as
/// equivalent to the dotless form — the same A/AAAA record is returned —
/// so leaving the deny-list strict would let a guest reach
/// `api.anthropic.com.` while the matcher silently passed. We strip the
/// trailing dot defensively at the matcher entry so every one of the five
/// worker enforcement surfaces (`fetch`, `fetch_all`, `graphql::execute`,
/// `webhook::send`, `http_stream::connect`) inherits the fix from one
/// place. Repeating the strip at every call site would be brittle.
pub fn is_external_llm_host(host_lower: &str) -> bool {
    // Defense in depth — callers are documented to pass an already-lowercased
    // host but we normalise here too: an upstream regression that forwards a
    // mixed-case or trailing-dot value shouldn't silently bypass the gate.
    let normalised = host_lower.trim_end_matches('.').to_ascii_lowercase();
    EXTERNAL_LLM_HOSTS
        .iter()
        .any(|reserved| *reserved == normalised || normalised.ends_with(&format!(".{reserved}")))
}

/// True iff `vault_path` references a Tier-2 LLM provider's credentials.
/// Used to block `vault://anthropic/api_key` substitution in HTTP headers
/// for Tier-1 jobs — the tier gate on `llm::*` host fns doesn't help if
/// the guest fetches directly and interpolates the key through
/// `resolve_vault_header`.
pub fn is_tier2_llm_vault_path(vault_path: &str) -> bool {
    is_llm_provider_vault_path(vault_path)
}

/// True iff `path` is consumed by a controller-internal subsystem (LLM
/// client cache, OAuth refresh loop) rather than by any WASM module's
/// `allowed_secrets` grant. Used by the orphaned-secrets hygiene check
/// to suppress false positives — these paths are by-design absent from
/// every module's grant list.
///
/// Recognized patterns:
/// - LLM provider keys: every entry of [`LLM_PROVIDER_VAULT_PATHS`]
/// - OAuth refresh tokens:
///   `oauth/<provider>/<user_id>/<provider_key>/refresh_token`.
///   Access tokens are NOT considered host-internal because workflow
///   modules legitimately read them via `vault://` in node config.
/// - The GCP `google_cloud_full` consent tier: ALL of its tokens
///   (access AND refresh) are host-only. This tier holds a broad
///   `cloud-platform` token used solely CONTROLLER-SIDE to mint
///   short-lived impersonated service-account tokens (Phase D). It is
///   deliberately never handed to a guest — the whole point of
///   impersonation is that a module receives a 10-minute, single-SA
///   token (`gcp/impersonated/<sa>/access_token`, which is NOT reserved),
///   never the broad grant it was minted from.
///
/// Hygiene checks must use this rather than `is_llm_provider_vault_path`
/// alone — flagging an OAuth refresh_token as orphan would suggest an
/// operator delete it, silently breaking the next refresh cycle.
pub fn is_controller_internal_vault_path(path: &str) -> bool {
    if is_llm_provider_vault_path(path) {
        return true;
    }
    // The full-tier GCP consent is host-only in its ENTIRETY (access +
    // refresh). Unlike ordinary providers whose access_token is
    // module-readable via `vault://`, a `cloud-platform` access token is
    // too broad to ever cross to a guest — it exists only to call
    // iamcredentials.generateAccessToken controller-side. Reserve the whole
    // subtree. The minted `gcp/impersonated/*` tokens are a SEPARATE,
    // non-reserved namespace, so this does not block them.
    if path.starts_with("oauth/google_cloud_full/") {
        return true;
    }
    // Defensive: refuse to match shapes like "oauth/refresh_token" that
    // lack the {provider}/{user}/{key} segments — those wouldn't be
    // produced by the canonical refresh_token_path() builder, so they'd
    // be a genuine orphan worth surfacing.
    if let Some(rest) = path.strip_prefix("oauth/") {
        if let Some(prefix) = rest.strip_suffix("/refresh_token") {
            // Require at least three intermediate segments (provider /
            // user_id / provider_key) before the refresh_token suffix.
            if prefix.split('/').filter(|s| !s.is_empty()).count() >= 3 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod llm_provider_path_tests {
    use super::{
        is_controller_internal_vault_path, is_external_llm_host, is_llm_provider_vault_path,
        EXTERNAL_LLM_HOSTS, LLM_PROVIDER_VAULT_PATHS,
    };

    #[test]
    fn canonical_paths_are_recognised() {
        for p in LLM_PROVIDER_VAULT_PATHS {
            assert!(
                is_llm_provider_vault_path(p),
                "canonical path {} not recognised",
                p
            );
        }
    }

    /// Tier-1 (local-Ollama-only) actors are blocked from external LLM egress
    /// by the worker's HTTP-host gate, which keys on `EXTERNAL_LLM_HOSTS`. Key
    /// resolution keys on `LLM_PROVIDER_VAULT_PATHS`. If a provider is added to
    /// the latter but its API host(s) are NOT added to the former, a tier-1
    /// actor can reach the new provider by raw host and exfiltrate data — the
    /// drift CLAUDE.md warns about under "Adding a new LLM provider".
    ///
    /// This is the forcing function: a new provider must be mapped here AND its
    /// host(s) must be present in `EXTERNAL_LLM_HOSTS`, or this test fails at PR
    /// time instead of the gap shipping silently.
    #[test]
    fn every_llm_provider_has_its_egress_host_in_the_deny_list() {
        // provider segment -> API host(s) the provider's traffic uses.
        let provider_hosts: &[(&str, &[&str])] = &[
            ("anthropic", &["api.anthropic.com"]),
            ("openai", &["api.openai.com"]),
            (
                "gemini",
                &[
                    "generativelanguage.googleapis.com",
                    "aiplatform.googleapis.com",
                ],
            ),
        ];

        // 1. Every vault-path provider must be mapped above.
        for path in LLM_PROVIDER_VAULT_PATHS {
            let provider = path
                .split('/')
                .next()
                .expect("vault path has a provider segment");
            assert!(
                provider_hosts.iter().any(|(p, _)| *p == provider),
                "LLM provider `{provider}` (in LLM_PROVIDER_VAULT_PATHS) is unmapped here — add it \
                 + its API host(s) to EXTERNAL_LLM_HOSTS, else a tier-1 actor can reach it by raw \
                 host (CLAUDE.md tier-1 egress invariant)."
            );
        }

        // 2. Every mapped host must be in the tier-1 egress deny-list AND
        //    recognised by the matcher the worker gate actually calls.
        for (provider, hosts) in provider_hosts {
            for host in *hosts {
                assert!(
                    EXTERNAL_LLM_HOSTS.contains(host),
                    "egress host `{host}` for provider `{provider}` is missing from \
                     EXTERNAL_LLM_HOSTS — the tier-1 HTTP-host gate won't deny it."
                );
                assert!(
                    is_external_llm_host(host),
                    "is_external_llm_host(`{host}`) is false despite the deny-list entry."
                );
            }
        }
    }

    #[test]
    fn non_llm_paths_are_not_recognised() {
        assert!(!is_llm_provider_vault_path(""));
        assert!(!is_llm_provider_vault_path("github/pat"));
        assert!(!is_llm_provider_vault_path("oauth/gmail/access_token"));
    }

    #[test]
    fn casing_and_nesting_do_not_bypass() {
        // Case-sensitive exact match only — attackers can't wrap the path
        // in a subpath or alter casing to bypass.
        assert!(!is_llm_provider_vault_path("ANTHROPIC/API_KEY"));
        assert!(!is_llm_provider_vault_path("anthropic/api_key/child"));
        assert!(!is_llm_provider_vault_path("prefix/anthropic/api_key"));
    }

    #[test]
    fn controller_internal_recognises_llm_keys() {
        for p in LLM_PROVIDER_VAULT_PATHS {
            assert!(is_controller_internal_vault_path(p));
        }
    }

    #[test]
    fn controller_internal_recognises_oauth_refresh_tokens() {
        // Canonical shape from oauth/credentials.rs::refresh_token_path:
        // oauth/{provider}/{user_id}/{provider_key}/refresh_token
        assert!(is_controller_internal_vault_path(
            "oauth/google_calendar/1a361562-e551-41aa-9cb4-6f8988b035f7/primary/refresh_token"
        ));
        assert!(is_controller_internal_vault_path(
            "oauth/atlassian/abc123/site/refresh_token"
        ));
    }

    #[test]
    fn controller_internal_rejects_oauth_access_tokens() {
        // Access tokens are consumed by sandbox modules via vault:// in node
        // config (e.g. pa-meeting-fetch). Including them would suppress
        // legitimate orphan warnings.
        assert!(!is_controller_internal_vault_path(
            "oauth/google_calendar/1a361562-e551-41aa-9cb4-6f8988b035f7/primary/access_token"
        ));
    }

    #[test]
    fn controller_internal_rejects_malformed_oauth_paths() {
        // Missing intermediate segments — these wouldn't be produced by the
        // canonical builder, so they're genuine orphans worth surfacing.
        assert!(!is_controller_internal_vault_path("oauth/refresh_token"));
        assert!(!is_controller_internal_vault_path(
            "oauth/provider/refresh_token"
        ));
        assert!(!is_controller_internal_vault_path(
            "oauth/provider/user/refresh_token"
        ));
        // Wrong prefix.
        assert!(!is_controller_internal_vault_path(
            "auth/google/user/key/refresh_token"
        ));
        // Misleading suffix.
        assert!(!is_controller_internal_vault_path(
            "oauth/google/user/key/refresh_token_backup"
        ));
    }

    #[test]
    fn controller_internal_rejects_unrelated_paths() {
        assert!(!is_controller_internal_vault_path(""));
        assert!(!is_controller_internal_vault_path("github/pat"));
        assert!(!is_controller_internal_vault_path("custom/secret"));
    }
}

// ============================================================================
// Wasm-security review 2026-05-23: is_external_llm_host normalisation tests
// ============================================================================
//
// Threat model. The five worker call sites that gate Tier-1 LLM egress —
// `wit_http::fetch` / `fetch_all`, `wit_graphql::execute`,
// `wit_webhook::send`, `wit_http_stream::connect` — feed `host_str()` from a
// `url::Url` into `is_external_llm_host`. `url::Url::parse` preserves the
// trailing dot on an FQDN, so a Tier-1 actor could write
// `https://api.anthropic.com./v1/messages` and the strict equality check
// would silently pass: DNS resolves the trailing-dot form to the same
// record. These tests pin the defensive normalisation at the matcher entry.
#[cfg(test)]
mod external_llm_host_normalisation_tests {
    use super::is_external_llm_host;

    #[test]
    fn bare_host_matches() {
        assert!(is_external_llm_host("api.anthropic.com"));
        assert!(is_external_llm_host("api.openai.com"));
        assert!(is_external_llm_host("generativelanguage.googleapis.com"));
    }

    #[test]
    fn trailing_dot_does_not_bypass() {
        // The exploit shape: `https://api.anthropic.com./v1/messages` —
        // `url::Url::host_str()` returns the trailing-dot form. Pre-fix the
        // matcher returned false; post-fix the strip normalises before
        // compare.
        assert!(is_external_llm_host("api.anthropic.com."));
        assert!(is_external_llm_host("api.openai.com."));
        assert!(is_external_llm_host("generativelanguage.googleapis.com."));
    }

    #[test]
    fn trailing_dot_on_subdomain_does_not_bypass() {
        // Suffix-match limb must also normalise — region subdomains are
        // the documented suffix-match motivator.
        assert!(is_external_llm_host("eu.api.openai.com."));
        assert!(is_external_llm_host("us-east-1.api.anthropic.com."));
    }

    #[test]
    fn mixed_case_does_not_bypass() {
        // Documented as caller-responsibility, but defense-in-depth at the
        // matcher entry guards against an upstream regression that forgets
        // to lowercase. The normalisation must apply BOTH lowercasing AND
        // trailing-dot strip — neither alone is sufficient.
        assert!(is_external_llm_host("API.ANTHROPIC.COM"));
        assert!(is_external_llm_host("API.ANTHROPIC.COM."));
        assert!(is_external_llm_host("Eu.Api.OpenAI.com."));
    }

    #[test]
    fn unrelated_hosts_still_do_not_match() {
        // Negative path — the strip must not be so aggressive that it
        // matches dot-suffixed lookalikes.
        assert!(!is_external_llm_host("example.com"));
        assert!(!is_external_llm_host("example.com."));
        assert!(!is_external_llm_host("anthropic.com")); // bare apex is NOT in deny list
        assert!(!is_external_llm_host("badanthropic.com."));
        assert!(!is_external_llm_host("api.anthropic.com.attacker.example"));
    }

    #[test]
    fn empty_and_dot_only_do_not_match() {
        // Edge cases that the trim could theoretically corrupt — confirm
        // they remain non-matches.
        assert!(!is_external_llm_host(""));
        assert!(!is_external_llm_host("."));
        assert!(!is_external_llm_host(".."));
    }
}

// ============================================================================
// Vault path allowlist matcher — shared between controller and worker
// ============================================================================

/// Returns true if `key_path` is permitted by this module's `allowed_secrets` grant.
///
/// This is the single source of truth for vault path matching semantics. Both
/// the controller (static validation, hygiene reports, engine dispatch) and
/// the worker (runtime enforcement in `secrets::get_secret()`) call this
/// function so they agree on exactly which paths a module can access.
///
/// Semantics:
///   - `[]` (empty)  → deny all (no secret is permitted)
///   - `["*"]`       → grants nothing (until 2026-10-15, any key; operator
///     decision D2-D). A list that holds only `*` denies all
///   - `["prefix"]`  → allow exactly `"prefix"` and any `"prefix/<child>"` subpath
///   - `["pfx/*"]`   → explicit glob form, equivalent to the plain prefix form above
///
/// The separator must be `/` — `["stripe"]` grants `"stripe"` and `"stripe/key"`
/// but NOT `"stripe-live/key"` (different separator).
pub fn vault_path_permitted(allowed: &[String], key_path: &str) -> bool {
    if allowed.is_empty() {
        return false;
    }
    // `*` grants nothing (operator decision D2-D, 2026-10-15): it is refused
    // at every write and stripped from stored rows, and a list that still
    // carries one (a caller-declared rehearsal grant) reads nothing by it.
    allowed.iter().any(|s| {
        s.as_str() == key_path
            || key_path.starts_with(&format!("{}/", s))
            || (s.ends_with("/*") && key_path.starts_with(&s[..s.len() - 1]))
    })
}

/// Returns true if a dispatch will PRE-FETCH `key_path` on the strength of the
/// `allowed_secrets` grant alone.
///
/// The delivery twin of [`vault_path_permitted`], and the two deliberately do
/// NOT agree — that disagreement is the whole reason this function exists.
/// `allowed_secrets` has two jobs:
///
///   1. **Permission** — may this module read this path? Answered by
///      [`vault_path_permitted`], which matches an exact path, a bare
///      prefix and a `/*` glob (and nothing by `*`).
///   2. **Delivery** — which paths does the controller resolve and put on the
///      wire? The engine passes the grant list VERBATIM as `extra_paths` to
///      `resolve_secrets_map_for`, which hands it to
///      `SecretsManager::get_secrets_by_paths`, whose non-wildcard query is
///      `WHERE key_path = ANY($1)` — **exact equality**. Until 2026-10-15
///      the literal `"*"` was special-cased there (expanded to every secret
///      the user can read); it now names nothing, as any other entry that is
///      not a stored path.
///
/// So a prefix or glob entry is a perfectly good permission boundary and
/// prefetches NOTHING: no vault row is literally named `plaid/*`, and an empty
/// result is `Ok`, so nothing logs and nothing fails until the module asks for
/// a secret that was never delivered.
///
/// Semantics — exactly one form delivers:
///   - `["a/b/c"]`    → that path, if a secret is stored at it
///   - `["*"]`        → delivers nothing (until 2026-10-15, every secret the
///     user can read; operator decision D2-D)
///   - `["a/b"]`      → does NOT deliver `"a/b/c"` (permits it; delivers nothing)
///   - `["a/b/*"]`    → delivers nothing, ever
///
/// A path this returns `false` for can still reach the module by the OTHER
/// route: a `vault://<path>` reference in the node's own config, which the
/// engine extracts (`secrets_pipeline::extract_vault_paths`) and resolves
/// separately. That is how every OAuth integration works — a bare `oauth/gmail`
/// grant bounds permission while the node config names the exact token path.
/// So `false` means "the grant alone will not deliver this", never "this module
/// cannot obtain this secret".
pub fn vault_path_prefetched(allowed: &[String], key_path: &str) -> bool {
    allowed.iter().any(|s| s.as_str() == key_path)
}

/// The one home for the sentence every operator surface must say about
/// `allowed_secrets`: a prefix or glob entry PERMITS a path without DELIVERING
/// it. Sibling of [`METHOD_ALLOWLIST_REMEDY`].
///
/// Four surfaces made the opposite claim before 2026-09-24 — two writer tools
/// recommended the prefix form outright, `test_secret_access`'s allowlist gate
/// suggested it as a remedy, and that same tool then returned four PASSes over
/// a path no dispatch would deliver. They agreed on a claim and nothing pinned
/// the words, so this const exists to make a reword of one of them a test
/// failure rather than a silent divergence. See [`vault_path_prefetched`].
/// Which outbound surfaces resolve a `vault://` marker placed in a request
/// BODY, and which deliberately do not.
///
/// Header substitution has always reached every egress surface. BODY
/// substitution reached only `http::fetch` until 2026-09-24, so on
/// `http::fetch_all`, `webhook::send` and `graphql::execute` a marker was
/// neither substituted nor refused — it was sent verbatim, and a vault path
/// names the provider and, for gmail, the account address. All four resolve it
/// now, under one resolver and one set of rules.
///
/// The exclusion is the part worth stating, because it is a DECISION and not a
/// remainder: on surfaces whose body the HOST composes from guest fields —
/// `email::send`'s MIME document, `object_storage`'s signed S3 request, the
/// `llm::*` provider envelopes — a marker is prose the guest chose to send, not
/// a credential placement, and substituting there would inject a secret into an
/// email or an LLM prompt. Those surfaces neither substitute nor refuse.
pub const VAULT_BODY_SUBSTITUTION_SURFACES_NOTE: &str =
    "A `vault://` marker in a request BODY is resolved by the host on the four      guest-composed egress surfaces — http::fetch, http::fetch_all,      webhook::send and graphql::execute — under one rule set: the body must      parse as JSON and declare a JSON content type (a non-JSON body carrying      the marker is REFUSED, never rewritten), only string VALUES are      substituted, never keys, and at most 8 references per request. It is      deliberately NOT resolved where the HOST composes the body from guest      fields (email::send, object_storage, llm::*): a marker there is prose the      guest chose to send, and substituting it would place a credential in an      email body or an LLM prompt.";

pub const SECRET_GRANT_DELIVERY_NOTE: &str =
    "Prefix and glob entries govern PERMISSION ONLY. A dispatch pre-fetches a \
     secret on the strength of this list only when an entry is the EXACT path \
     or \"*\" (the resolver's non-wildcard query is `key_path = ANY($1)`), so a \
     grant like 'oauth/gmail' or 'plaid/*' permits a path and delivers nothing. \
     Either name the exact path here, or reference `vault://<path>` in the \
     node's config, which the engine resolves separately — that second route is \
     how OAuth integrations work and is why a prefix grant is still correct for \
     them.";

#[cfg(test)]
mod vault_matcher_tests {
    use super::{vault_path_permitted, vault_path_prefetched};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn empty_list_denies_everything() {
        assert!(!vault_path_permitted(&[], "anthropic/api_key"));
        assert!(!vault_path_permitted(&[], ""));
    }

    #[test]
    fn a_star_grant_allows_nothing() {
        assert!(!vault_path_permitted(&s(&["*"]), "anthropic/api_key"));
        assert!(!vault_path_permitted(&s(&["*"]), "oauth/gmail/user/access"));
    }

    #[test]
    fn exact_match_allowed() {
        assert!(vault_path_permitted(
            &s(&["anthropic/api_key"]),
            "anthropic/api_key"
        ));
    }

    #[test]
    fn prefix_match_allowed() {
        assert!(vault_path_permitted(
            &s(&["oauth/gmail"]),
            "oauth/gmail/user/access"
        ));
        assert!(vault_path_permitted(&s(&["oauth/gmail"]), "oauth/gmail"));
    }

    #[test]
    fn glob_suffix_allowed() {
        assert!(vault_path_permitted(
            &s(&["oauth/gmail/*"]),
            "oauth/gmail/user/access"
        ));
    }

    #[test]
    fn different_separator_denied() {
        // `stripe` should NOT match `stripe-live/key` — separator must be `/`
        assert!(!vault_path_permitted(&s(&["stripe"]), "stripe-live/key"));
    }

    #[test]
    fn partial_prefix_denied() {
        assert!(!vault_path_permitted(
            &s(&["oauth/gmail"]),
            "oauth/atlassian/token"
        ));
    }

    /// SECURITY INVARIANT (GCP Phase C): a read-tier grant must never match
    /// the write-tier namespace. `oauth/google_cloud/*` and bare
    /// `oauth/google_cloud` grants must NOT resolve
    /// `oauth/google_cloud_write/...` — the distinct provider segment is the
    /// structural boundary keeping the provisioning token out of read-only
    /// modules. Both the glob arm (which strips only the `*`, keeping the
    /// `/`) and the prefix arm (which appends `/` before matching) are
    /// segment-boundary-safe; this test pins that a refactor to raw string
    /// prefixes fails loudly.
    #[test]
    fn read_tier_grant_cannot_name_write_tier_paths() {
        for grant in ["oauth/google_cloud/*", "oauth/google_cloud"] {
            assert!(
                !vault_path_permitted(
                    &s(&[grant]),
                    "oauth/google_cloud_write/1a361562/9c4d/access_token"
                ),
                "grant {grant} must not cross into the write tier"
            );
        }
        // And the write grant still matches its own namespace.
        assert!(vault_path_permitted(
            &s(&["oauth/google_cloud_write/*"]),
            "oauth/google_cloud_write/1a361562/9c4d/access_token"
        ));
    }

    // ── delivery twin ──────────────────────────────────────────────────────
    //
    // Every case below pairs the two matchers, because the finding is the
    // DISAGREEMENT: a grant that permits a path and prefetches nothing reads
    // as correct at every operator surface and delivers no secret at runtime.

    #[test]
    fn a_glob_grant_permits_but_never_prefetches() {
        let grant = s(&["plaid/*"]);
        // Control: permission is granted, which is why this is invisible.
        assert!(vault_path_permitted(&grant, "plaid/client_id"));
        assert!(
            !vault_path_prefetched(&grant, "plaid/client_id"),
            "a glob entry is looked up verbatim by `WHERE key_path = ANY($1)` \
             and no vault row is named `plaid/*`"
        );
    }

    #[test]
    fn a_bare_prefix_grant_permits_but_never_prefetches() {
        // The OAuth shape: this grant is CORRECT — the node config names the
        // exact token path — but the grant alone delivers nothing.
        let grant = s(&["oauth/gmail"]);
        let path = "oauth/gmail/56a7eea7/user@example.com/access_token";
        assert!(vault_path_permitted(&grant, path));
        assert!(!vault_path_prefetched(&grant, path));
    }

    #[test]
    fn an_exact_grant_both_permits_and_prefetches() {
        let grant = s(&["plaid/client_id"]);
        assert!(vault_path_permitted(&grant, "plaid/client_id"));
        assert!(vault_path_prefetched(&grant, "plaid/client_id"));
        // Control: the sibling path in the same namespace does neither.
        assert!(!vault_path_permitted(&grant, "plaid/secret"));
        assert!(!vault_path_prefetched(&grant, "plaid/secret"));
    }

    /// D2-D (2026-10-15): `*` neither permits nor prefetches — until then
    /// it was the one form the resolver expanded to every secret the user
    /// could read.
    #[test]
    fn a_star_grant_neither_permits_nor_prefetches() {
        let grant = s(&["*"]);
        assert!(!vault_path_permitted(&grant, "anything/at/all"));
        assert!(!vault_path_prefetched(&grant, "anything/at/all"));
    }

    #[test]
    fn an_empty_grant_prefetches_nothing() {
        assert!(!vault_path_prefetched(&[], "plaid/client_id"));
        assert!(!vault_path_permitted(&[], "plaid/client_id"));
    }

    /// The invariant that makes the asymmetry SAFE: delivery is strictly
    /// narrower than permission, so a dispatch can never put a secret on the
    /// wire that the grant does not also permit. If this ever inverts, the
    /// prefetch has become an escalation route.
    #[test]
    fn prefetched_is_strictly_narrower_than_permitted() {
        let grants = [
            vec![],
            s(&["*"]),
            s(&["plaid/client_id"]),
            s(&["plaid"]),
            s(&["plaid/*"]),
            s(&["oauth/gmail", "plaid/secret"]),
        ];
        let paths = [
            "plaid/client_id",
            "plaid/secret",
            "plaid/access_token/item-1",
            "oauth/gmail/u/a@b.c/access_token",
            "anthropic/api_key",
            "",
        ];
        let mut narrower_somewhere = false;
        for g in &grants {
            for p in &paths {
                if vault_path_prefetched(g, p) {
                    assert!(
                        vault_path_permitted(g, p),
                        "grant {g:?} prefetches {p:?} without permitting it — \
                         the prefetch has become an escalation route"
                    );
                }
                if vault_path_permitted(g, p) && !vault_path_prefetched(g, p) {
                    narrower_somewhere = true;
                }
            }
        }
        // The corpus must actually exercise the gap, or the loop above is
        // vacuous and would pass against two identical matchers.
        assert!(
            narrower_somewhere,
            "corpus never produced a permits-but-does-not-deliver case"
        );
    }

    /// The operator sentence is the whole remedy, so pin what it must SAY —
    /// a correct pin beside a reworded sentence leaves the operator reading
    /// advice that no longer matches the code.
    #[test]
    fn the_shared_delivery_sentence_names_both_routes() {
        let n = super::SECRET_GRANT_DELIVERY_NOTE;
        assert!(
            n.contains("PERMISSION ONLY"),
            "must name what a prefix does"
        );
        assert!(n.contains("EXACT path"), "must name remedy (a)");
        assert!(
            n.contains("vault://"),
            "must name remedy (b), the config route"
        );
        assert!(
            n.contains("OAuth"),
            "must say why a prefix grant is still correct for OAuth, or a \
             reader will 'fix' every integration's grant"
        );
    }
}

#[cfg(test)]
mod full_tier_reservation_tests {
    use super::{is_controller_internal_vault_path, vault_path_permitted};

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    /// SECURITY INVARIANT (GCP Phase D): the `google_cloud_full` consent
    /// tier holds a broad `cloud-platform` token used only to mint
    /// impersonated tokens controller-side. BOTH its access AND refresh
    /// tokens must be host-reserved — a `cloud-platform` access token is
    /// far too broad to ever reach a guest (unlike ordinary access tokens,
    /// which are module-readable). This is what the worker's
    /// `check_secret_allowlist` and the controller's `retain_wire_safe_secrets`
    /// backstop both inherit from one predicate.
    #[test]
    fn full_tier_tokens_are_entirely_host_reserved() {
        assert!(is_controller_internal_vault_path(
            "oauth/google_cloud_full/1a361562/9c4d/refresh_token"
        ));
        // The distinguishing case: full-tier ACCESS tokens are reserved too,
        // where every other provider's access token is NOT.
        assert!(is_controller_internal_vault_path(
            "oauth/google_cloud_full/1a361562/9c4d/access_token"
        ));
    }

    /// The read/write tiers stay module-readable on their access tokens —
    /// the full-tier reservation must not have widened to them.
    #[test]
    fn read_and_write_tier_access_tokens_stay_module_readable() {
        assert!(!is_controller_internal_vault_path(
            "oauth/google_cloud/1a361562/9c4d/access_token"
        ));
        assert!(!is_controller_internal_vault_path(
            "oauth/google_cloud_write/1a361562/9c4d/access_token"
        ));
    }

    /// The MINTED impersonated token lives in a separate, NON-reserved
    /// namespace so a module's `gcp/impersonated/*` grant can name it —
    /// that's the whole delivery mechanism. It must NOT be swept up by the
    /// full-tier reservation.
    #[test]
    fn minted_impersonated_token_is_not_reserved_and_is_grantable() {
        let minted = "gcp/impersonated/talos-runner@sandbox.iam.gserviceaccount.com/access_token";
        assert!(
            !is_controller_internal_vault_path(minted),
            "minted impersonated token must be deliverable to the guest"
        );
        assert!(
            vault_path_permitted(&s(&["gcp/impersonated/*"]), minted),
            "a gcp/impersonated/* module grant must cover the minted token"
        );
        // And a full-tier grant string must NOT reach the minted namespace
        // (nor vice-versa) — they are unrelated prefixes.
        assert!(!vault_path_permitted(
            &s(&["gcp/impersonated/*"]),
            "oauth/google_cloud_full/1a361562/9c4d/access_token"
        ));
    }
}
