//! What a module may put in the headers of an outbound request.
//!
//! Every `aegix:core` path that sends a module's headers asks
//! [`request_headers_refusal`] before it resolves a secret or opens a
//! connection: `http::fetch`, each entry of `http::fetch-all`,
//! `graphql::execute`, `webhook::send` and `http-stream::connect`.
//!
//! Until 2026-11-17 those five paths copied a module's headers onto the
//! request by name, whatever the name. `allowed_hosts` and the destination of
//! a `vault://` secret are both decided on the URL's host, and a `Host`
//! header says something else to the server that answers: a module granted
//! one name on a shared front end (an object store's bucket, a CDN's
//! customer) reached another tenant's, and a granted secret went with it.
//! Found by an outside review of 0.1.0.
//!
//! `wasi:http` is not one of the five: its fields refuse the names in
//! `wasmtime_wasi_http::DEFAULT_FORBIDDEN_HEADERS` when the module sets them.
//! The list here holds every one of those (a test keeps it so) and two more.

use super::limits::MAX_OUTBOUND_HEADERS;
use crate::reason_class;

/// Header names a module may not set, in lower case.
///
/// `host` chooses which site answers on the connection the URL opened. The
/// rest are the fields of one connection, not of a request (RFC 9110 §7.6.1,
/// with `trailer`, the proxy pair and `http2-settings`): the client that owns
/// the connection writes them. The worker's connections are pooled per
/// process, so a module that framed its own request (`transfer-encoding`
/// beside the length the client writes) could leave bytes on a connection the
/// next job's request is sent on.
///
/// `content-length` is not here: the client holds a body to the length it
/// declares and closes the connection when they differ.
pub(crate) const REFUSED_REQUEST_HEADERS: [&str; 11] = [
    "host",
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "http2-settings",
];

/// Why a module's request headers were refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequestHeadersRefusal {
    /// More headers than [`MAX_OUTBOUND_HEADERS`].
    TooMany { count: usize },
    /// One of [`REFUSED_REQUEST_HEADERS`], named as the list spells it (never
    /// as the module did, so the name is safe to log).
    Refused { name: &'static str },
}

impl RequestHeadersRefusal {
    /// The reason class the refusal is recorded under.
    pub(crate) fn class(self) -> &'static str {
        match self {
            Self::TooMany { .. } => reason_class::REQUEST_HEADER_CAP,
            Self::Refused { .. } => reason_class::REQUEST_HEADER_REFUSED,
        }
    }
}

impl std::fmt::Display for RequestHeadersRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooMany { count } => write!(
                f,
                "{count} headers, more than the cap of {MAX_OUTBOUND_HEADERS}"
            ),
            Self::Refused { name } => {
                write!(f, "the header '{name}' is not a module's to set")
            }
        }
    }
}

/// Whether `name` is one of [`REFUSED_REQUEST_HEADERS`], compared as header
/// names are (ASCII, case-insensitive).
fn refused_name(name: &str) -> Option<&'static str> {
    REFUSED_REQUEST_HEADERS
        .iter()
        .copied()
        .find(|refused| refused.eq_ignore_ascii_case(name))
}

/// The one rule for a module's outbound request headers: at most
/// [`MAX_OUTBOUND_HEADERS`] of them, and none of
/// [`REFUSED_REQUEST_HEADERS`]. `None` admits the list.
///
/// The count is read first, so a list over the cap is never walked.
pub(crate) fn request_headers_refusal(
    headers: &[(String, String)],
) -> Option<RequestHeadersRefusal> {
    if headers.len() > MAX_OUTBOUND_HEADERS {
        return Some(RequestHeadersRefusal::TooMany {
            count: headers.len(),
        });
    }
    headers
        .iter()
        .find_map(|(name, _)| refused_name(name))
        .map(|name| RequestHeadersRefusal::Refused { name })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(names: &[&str]) -> Vec<(String, String)> {
        names
            .iter()
            .map(|n| ((*n).to_string(), "v".to_string()))
            .collect()
    }

    #[test]
    fn ordinary_headers_are_admitted() {
        assert_eq!(request_headers_refusal(&[]), None);
        assert_eq!(
            request_headers_refusal(&headers(&[
                "Authorization",
                "Content-Type",
                "Content-Length",
                "Accept",
                "User-Agent",
                "X-Forwarded-Host",
                "Hostname",
                "X-Host",
                "Idempotency-Key",
            ])),
            None
        );
    }

    #[test]
    fn host_is_refused_however_it_is_spelled() {
        for spelling in ["host", "Host", "HOST", "hOsT"] {
            assert_eq!(
                request_headers_refusal(&headers(&["Accept", spelling])),
                Some(RequestHeadersRefusal::Refused { name: "host" }),
                "{spelling}"
            );
        }
    }

    #[test]
    fn every_listed_name_is_refused_and_recorded_as_its_own_class() {
        for name in REFUSED_REQUEST_HEADERS {
            let refusal = request_headers_refusal(&headers(&[&name.to_ascii_uppercase()]))
                .unwrap_or_else(|| panic!("{name} was admitted"));
            assert_eq!(refusal, RequestHeadersRefusal::Refused { name });
            assert_eq!(refusal.class(), reason_class::REQUEST_HEADER_REFUSED);
        }
    }

    /// A name that only resembles a refused one is a different header. (A
    /// name with a space or a control character in it is not a header name at
    /// all, and the client refuses to build the request.)
    #[test]
    fn a_near_miss_is_not_refused() {
        assert_eq!(
            request_headers_refusal(&headers(&["host2", "x-host", "hosts", "t", "tee"])),
            None
        );
    }

    #[test]
    fn the_cap_is_read_before_the_names() {
        let mut over = headers(&["Host"]);
        over.extend((0..MAX_OUTBOUND_HEADERS).map(|i| (format!("x-{i}"), "v".to_string())));
        let refusal = request_headers_refusal(&over).expect("refused");
        assert_eq!(
            refusal,
            RequestHeadersRefusal::TooMany {
                count: MAX_OUTBOUND_HEADERS + 1
            }
        );
        assert_eq!(refusal.class(), reason_class::REQUEST_HEADER_CAP);

        let at_cap: Vec<_> = (0..MAX_OUTBOUND_HEADERS)
            .map(|i| (format!("x-{i}"), "v".to_string()))
            .collect();
        assert_eq!(request_headers_refusal(&at_cap), None);
    }

    /// `wasi:http` refuses these names itself. If a wasmtime release adds one,
    /// the `aegix:core` paths must refuse it too, in the same change.
    #[test]
    fn the_list_holds_every_name_wasi_http_refuses() {
        for name in wasmtime_wasi_http::DEFAULT_FORBIDDEN_HEADERS {
            assert!(
                REFUSED_REQUEST_HEADERS.contains(&name.as_str()),
                "wasi:http refuses '{name}' and the aegix:core paths do not"
            );
        }
    }

    /// The list is compared with `eq_ignore_ascii_case` against lower-case
    /// entries, and its names are logged: both need it to stay lower-case
    /// ASCII with no duplicates.
    #[test]
    fn the_list_is_lower_case_and_has_no_duplicate() {
        let mut seen = std::collections::BTreeSet::new();
        for name in REFUSED_REQUEST_HEADERS {
            assert!(
                name.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{name}"
            );
            assert!(seen.insert(name), "{name} is listed twice");
        }
    }

    /// Every path that sends a module's headers asks the one rule, and none
    /// keeps a header check of its own. A list, not a derivation: a sixth
    /// path is added here when it is written.
    #[test]
    fn every_path_that_sends_module_headers_asks_the_one_rule() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/host");
        for (file, calls) in [
            ("http.rs", 2),
            ("graphql.rs", 1),
            ("webhook.rs", 1),
            ("http_stream.rs", 1),
        ] {
            let source = std::fs::read_to_string(dir.join(file)).expect(file);
            assert_eq!(
                source.matches("request_headers_refusal(").count(),
                calls,
                "{file} asks the request-header rule a different number of times"
            );
            let own_cap = source
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .any(|l| l.contains("len() > MAX_OUTBOUND_HEADERS"));
            assert!(
                !own_cap,
                "{file} compares a header count with the cap itself"
            );
        }
    }
}
