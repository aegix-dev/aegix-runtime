//! The paths a secret is minted at when a job is dispatched, where nothing
//! is ever stored: a GCP impersonated token and a GitHub App token.
//!
//! The recogniser the minting resolver partitions with, and what a tool that
//! reports on secrets asks before it says "not stored".
//! Moved out of `lib.rs` 2026-11-18, unchanged; every public item is
//! re-exported at the crate root, where it was.

/// Where a minted GCP impersonated service-account token is requested
/// (Phase D). A module names one of these paths; nothing is stored under it.
pub const GCP_IMPERSONATED_PREFIX: &str = "gcp/impersonated/";
/// Only `.../access_token` is a mint target, so a typo'd path is never
/// silently treated as a mintable secret.
pub const GCP_IMPERSONATED_SUFFIX: &str = "/access_token";
/// The segment that precedes the connection a mint is made from.
const GCP_IMPERSONATED_VIA: &str = "as";

/// What a `gcp/impersonated/...` path asks for: which service account, and
/// (when it says) which of the requesting user's Google Cloud connections the
/// token is minted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcpImpersonationTarget<'a> {
    pub service_account_email: &'a str,
    /// The connection's key. `None` leaves the choice to the minter, which
    /// may only make it when the user has exactly one such connection.
    pub connection: Option<uuid::Uuid>,
}

/// Read a mint path. Two forms, and nothing else:
///
/// * `gcp/impersonated/<sa_email>/access_token`
/// * `gcp/impersonated/<sa_email>/as/<connection key>/access_token`
///
/// A service-account email holds no `/`, so the segments are exact. The
/// connection key must be a UUID written the one canonical way (lower-case,
/// hyphenated): a path is compared and granted as text, and two spellings of
/// one key would be two paths for one credential.
#[must_use]
pub fn parse_gcp_impersonated_path(path: &str) -> Option<GcpImpersonationTarget<'_>> {
    let inner = path
        .strip_prefix(GCP_IMPERSONATED_PREFIX)?
        .strip_suffix(GCP_IMPERSONATED_SUFFIX)?;
    let mut parts = inner.split('/');
    let service_account_email = parts.next().filter(|sa| !sa.is_empty())?;
    let connection = match (parts.next(), parts.next(), parts.next()) {
        (None, _, _) => None,
        (Some(GCP_IMPERSONATED_VIA), Some(key), None) => {
            let parsed = uuid::Uuid::parse_str(key).ok()?;
            if parsed.hyphenated().to_string() != key {
                return None;
            }
            Some(parsed)
        }
        _ => return None,
    };
    Some(GcpImpersonationTarget {
        service_account_email,
        connection,
    })
}

/// Write a mint path: the inverse of [`parse_gcp_impersonated_path`].
#[must_use]
pub fn gcp_impersonated_path(
    service_account_email: &str,
    connection: Option<uuid::Uuid>,
) -> String {
    match connection {
        None => format!("{GCP_IMPERSONATED_PREFIX}{service_account_email}{GCP_IMPERSONATED_SUFFIX}"),
        Some(key) => format!(
            "{GCP_IMPERSONATED_PREFIX}{service_account_email}/{GCP_IMPERSONATED_VIA}/{}{GCP_IMPERSONATED_SUFFIX}",
            key.hyphenated()
        ),
    }
}

/// The scheme of a GitHub App installation-token path (RFC 0008 B4):
/// `github_app:<owner>`. Nothing is stored under it; the token is minted when
/// a job is dispatched.
pub const GITHUB_APP_SCHEME: &str = "github_app:";

/// Which mint a path belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintScheme {
    /// `gcp/impersonated/…/access_token`.
    GcpImpersonated,
    /// `github_app:<owner>`.
    GithubApp,
}

impl MintScheme {
    /// The path forms the minter reads, for a message.
    #[must_use]
    pub fn forms(self) -> &'static str {
        match self {
            Self::GcpImpersonated => {
                "gcp/impersonated/<service account email>/access_token or \
                 gcp/impersonated/<service account email>/as/<connection key>/access_token"
            }
            Self::GithubApp => "github_app:<owner>",
        }
    }

    /// What a mint of this kind is made from, for a message.
    #[must_use]
    pub fn made_from(self) -> &'static str {
        match self {
            Self::GcpImpersonated => "a Google Cloud (full) connection",
            Self::GithubApp => "a GitHub App installation",
        }
    }
}

/// A secret path whose value is MINTED when a job is dispatched. Nothing is
/// ever stored at such a path, so "is a secret stored there" is the wrong
/// question to ask of it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DispatchMint<'a> {
    /// An impersonated Google Cloud service-account token.
    GcpImpersonated(GcpImpersonationTarget<'a>),
    /// A GitHub App installation token for `owner`.
    GithubApp { owner: &'a str },
    /// The path is taken out of the vault lookup as a mint path, but it is
    /// not a form the minter reads: nothing is minted for it, and nothing
    /// stored at it is read.
    Malformed(MintScheme),
}

impl DispatchMint<'_> {
    /// Which mint this is.
    #[must_use]
    pub fn scheme(&self) -> MintScheme {
        match self {
            Self::GcpImpersonated(_) | Self::Malformed(MintScheme::GcpImpersonated) => {
                MintScheme::GcpImpersonated
            }
            Self::GithubApp { .. } | Self::Malformed(MintScheme::GithubApp) => {
                MintScheme::GithubApp
            }
        }
    }
}

/// Is `path` minted at dispatch? `None` means an ordinary path, read from
/// the vault.
///
/// ONE recogniser, asked by the resolver that mints (which takes exactly
/// these paths out of its vault lookup) and by every tool that tells an
/// operator whether a secret is missing. A tool with its own idea of which
/// paths are stored advises storing a secret where none is ever read.
#[must_use]
pub fn dispatch_mint(path: &str) -> Option<DispatchMint<'_>> {
    if let Some(owner) = path.strip_prefix(GITHUB_APP_SCHEME) {
        // The owner is whatever follows the scheme, as the resolver has
        // always read it: the lookup it feeds is an equality on the
        // requesting user's own installations, so an owner that is not a
        // login finds nothing. Only an empty one is malformed.
        return Some(if owner.is_empty() {
            DispatchMint::Malformed(MintScheme::GithubApp)
        } else {
            DispatchMint::GithubApp { owner }
        });
    }
    if path.starts_with(GCP_IMPERSONATED_PREFIX) && path.ends_with(GCP_IMPERSONATED_SUFFIX) {
        return Some(match parse_gcp_impersonated_path(path) {
            Some(target) => DispatchMint::GcpImpersonated(target),
            None => DispatchMint::Malformed(MintScheme::GcpImpersonated),
        });
    }
    None
}

/// Does an `allowed_secrets` ENTRY reach minted paths? An entry is a path, a
/// prefix or a glob, so this is asked of the entry's text: an exact mint
/// path, or anything in a mint namespace (`gcp/impersonated`,
/// `gcp/impersonated/*`, `gcp/impersonated/<sa>`, `github_app:<owner>`).
///
/// A tool that lists "secrets this workflow needs that are not stored" asks
/// this of an entry no stored path satisfies: such an entry is not missing,
/// it is minted. `*` is not a mint entry.
#[must_use]
pub fn grant_reaches_minted_paths(grant: &str) -> Option<MintScheme> {
    if grant.starts_with(GITHUB_APP_SCHEME) {
        return Some(MintScheme::GithubApp);
    }
    let namespace = GCP_IMPERSONATED_PREFIX.trim_end_matches('/');
    if grant == namespace || grant.starts_with(GCP_IMPERSONATED_PREFIX) {
        return Some(MintScheme::GcpImpersonated);
    }
    None
}

#[cfg(test)]
mod dispatch_mint_tests {
    use super::*;
    use crate::vault_path_permitted;

    const SA: &str = "runner@example-project.iam.gserviceaccount.com";
    const KEY: &str = "0b7b0f0e-4c1d-4a57-9d2e-3f6a1c2b9e10";

    #[test]
    fn a_stored_path_is_not_a_mint() {
        for path in [
            "jira/api_token",
            "oauth/google_calendar/abc/access_token",
            "anthropic/api_key",
            // In the namespace by name, but not what the resolver takes out
            // of the vault lookup: it is read from the vault like any path.
            "gcp/impersonated/someone/refresh_token",
            "gcp/impersonated",
            "github_app",
            "",
        ] {
            assert_eq!(dispatch_mint(path), None, "{path}");
        }
    }

    #[test]
    fn both_gcp_forms_and_the_github_form_are_mints() {
        let plain = gcp_impersonated_path(SA, None);
        let key = uuid::Uuid::parse_str(KEY).unwrap();
        let named = gcp_impersonated_path(SA, Some(key));
        assert_eq!(
            dispatch_mint(&plain),
            Some(DispatchMint::GcpImpersonated(GcpImpersonationTarget {
                service_account_email: SA,
                connection: None,
            }))
        );
        assert_eq!(
            dispatch_mint(&named),
            Some(DispatchMint::GcpImpersonated(GcpImpersonationTarget {
                service_account_email: SA,
                connection: Some(key),
            }))
        );
        assert_eq!(
            dispatch_mint("github_app:example-org"),
            Some(DispatchMint::GithubApp {
                owner: "example-org"
            })
        );
        assert_eq!(
            dispatch_mint(&named).map(|m| m.scheme()),
            Some(MintScheme::GcpImpersonated)
        );
    }

    /// The resolver takes these out of its vault lookup and then mints
    /// nothing for them. They are neither stored nor minted, and a tool must
    /// be able to say so.
    #[test]
    fn a_mint_path_the_minter_cannot_read_is_malformed_not_stored() {
        for path in [
            "gcp/impersonated//access_token".to_string(),
            format!("gcp/impersonated/{SA}/as/not-a-key/access_token"),
            format!(
                "gcp/impersonated/{SA}/as/{}/access_token",
                KEY.to_uppercase()
            ),
            format!("gcp/impersonated/{SA}/extra/access_token"),
        ] {
            assert_eq!(
                dispatch_mint(&path),
                Some(DispatchMint::Malformed(MintScheme::GcpImpersonated)),
                "{path}"
            );
        }
        assert_eq!(
            dispatch_mint("github_app:"),
            Some(DispatchMint::Malformed(MintScheme::GithubApp))
        );
        // Whatever follows the scheme is the owner, as the resolver reads it.
        assert_eq!(
            dispatch_mint("github_app:some_user"),
            Some(DispatchMint::GithubApp { owner: "some_user" })
        );
    }

    #[test]
    fn a_grant_entry_in_a_mint_namespace_reaches_minted_paths() {
        for (grant, scheme) in [
            ("gcp/impersonated", MintScheme::GcpImpersonated),
            ("gcp/impersonated/*", MintScheme::GcpImpersonated),
            (
                "gcp/impersonated/runner@example-project.iam.gserviceaccount.com",
                MintScheme::GcpImpersonated,
            ),
            (
                "gcp/impersonated/runner@example-project.iam.gserviceaccount.com/access_token",
                MintScheme::GcpImpersonated,
            ),
            ("github_app:example-org", MintScheme::GithubApp),
        ] {
            assert_eq!(grant_reaches_minted_paths(grant), Some(scheme), "{grant}");
            // And such an entry really does permit a minted path.
        }
        for grant in [
            "*",
            "gcp",
            "gcp/impersonatedx",
            "jira/api_token",
            "oauth/google_cloud_full/*",
        ] {
            assert_eq!(grant_reaches_minted_paths(grant), None, "{grant}");
        }
        assert!(vault_path_permitted(
            &["gcp/impersonated/*".to_string()],
            &gcp_impersonated_path(SA, None)
        ));
    }
}

#[cfg(test)]
mod gcp_impersonated_path_tests {
    use super::{gcp_impersonated_path, parse_gcp_impersonated_path, GcpImpersonationTarget};

    const SA: &str = "talos-runner@sandbox.iam.gserviceaccount.com";
    const KEY: &str = "63012854-b3ac-dc54-301c-7b5cc9aff819";

    #[test]
    fn both_forms_are_read_and_written_the_same_way() {
        let key = uuid::Uuid::parse_str(KEY).unwrap();
        let plain = format!("gcp/impersonated/{SA}/access_token");
        let named = format!("gcp/impersonated/{SA}/as/{KEY}/access_token");
        assert_eq!(
            parse_gcp_impersonated_path(&plain),
            Some(GcpImpersonationTarget {
                service_account_email: SA,
                connection: None
            })
        );
        assert_eq!(
            parse_gcp_impersonated_path(&named),
            Some(GcpImpersonationTarget {
                service_account_email: SA,
                connection: Some(key)
            })
        );
        assert_eq!(gcp_impersonated_path(SA, None), plain);
        assert_eq!(gcp_impersonated_path(SA, Some(key)), named);
    }

    #[test]
    fn anything_else_is_not_a_mint_target() {
        for bad in [
            // No target, extra segments, the wrong suffix, another namespace.
            "gcp/impersonated//access_token".to_string(),
            "gcp/impersonated/a/b/access_token".to_string(),
            format!("gcp/impersonated/{SA}/refresh_token"),
            "oauth/google_cloud_full/u/k/access_token".to_string(),
            // A connection segment that is not `as/<key>` exactly.
            format!("gcp/impersonated/{SA}/as/access_token"),
            format!("gcp/impersonated/{SA}/as//access_token"),
            format!("gcp/impersonated/{SA}/via/{KEY}/access_token"),
            format!("gcp/impersonated/{SA}/as/{KEY}/extra/access_token"),
            format!("gcp/impersonated//as/{KEY}/access_token"),
            // A key that is not a UUID, or is one spelled another way: upper
            // case, without hyphens, braced. One key, one path.
            format!("gcp/impersonated/{SA}/as/not-a-key/access_token"),
            format!(
                "gcp/impersonated/{SA}/as/{}/access_token",
                KEY.to_uppercase()
            ),
            format!(
                "gcp/impersonated/{SA}/as/{}/access_token",
                KEY.replace('-', "")
            ),
            format!("gcp/impersonated/{SA}/as/{{{KEY}}}/access_token"),
        ] {
            assert_eq!(parse_gcp_impersonated_path(&bad), None, "{bad}");
        }
    }
}
