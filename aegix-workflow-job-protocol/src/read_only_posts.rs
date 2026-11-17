//! A module's declaration that a POST only reads.
//!
//! Under a dry run the worker answers every non-GET HTTP request with a stub,
//! because GET is the only verb it can call a read. Some services read by
//! POST (Plaid's `/transactions/get`, a search API), and a module that reads
//! one of them could not be rehearsed at all: its reader was handed a stub
//! and every node after it ran on nothing.
//!
//! A module may therefore DECLARE, entry by entry, the POSTs that only read.
//! Under a dry run a POST that an entry names is sent for real, after every
//! ordinary admission check; everything else is stubbed exactly as before.
//!
//! # The rule has one home
//!
//! * [`validate_declaration`] is what every writer of `modules.read_only_posts`
//!   asks. It normalises, bounds and sorts the list, and refuses an entry the
//!   module's own grant does not already reach.
//! * [`is_declared_read`] is what the worker asks before it stubs a request.
//!
//! # What an entry is
//!
//! `<host><path>`: a host name and an absolute path, nothing else. No scheme
//! (https is the only one matched), no port (an explicit port never matches),
//! no query string, no wildcard and no prefix: `api.example.com/v1/search`
//! names exactly that path on exactly that host. A declaration is a statement
//! about what a request DOES, and a pattern would be a statement about
//! requests nobody has read.
//!
//! # What it does not do
//!
//! It grants nothing. A declared POST still needs its host in `allowed_hosts`
//! and `POST` in `allowed_methods`, and is still refused by the write ceiling
//! for a read-only actor. It is read only under a dry run; a real run never
//! consults it.

/// Entries a module may declare.
pub const MAX_ENTRIES: usize = 16;
/// Characters in one entry.
pub const MAX_ENTRY_CHARS: usize = 200;

/// One entry as it is stored and compared: the host lower-cased, the path as
/// written. `Err` says what is wrong with it, in words a caller can be shown.
pub fn normalize_entry(raw: &str) -> Result<String, String> {
    let entry = raw.trim();
    if entry.is_empty() || entry.len() > MAX_ENTRY_CHARS {
        return Err(format!(
            "an entry is a host and a path of 1 to {MAX_ENTRY_CHARS} characters, like api.example.com/v1/search"
        ));
    }
    let Some(slash) = entry.find('/') else {
        return Err(format!(
            "`{entry}` has no path: an entry names one path on one host, like api.example.com/v1/search"
        ));
    };
    let (host, path) = entry.split_at(slash);
    let host_ok = !host.is_empty()
        && host.len() <= 253
        && !host.starts_with(['.', '-'])
        && !host.ends_with(['.', '-'])
        && host.contains('.')
        && host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    if !host_ok {
        return Err(format!(
            "`{entry}` does not begin with a host name: no scheme, no port, no wildcard"
        ));
    }
    // Unreserved path characters only, so the stored text is the text a URL
    // parser hands back and the comparison is byte for byte.
    let path_ok = path.len() > 1
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'.' | b'_' | b'-' | b'~'))
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        && !path.contains("//");
    if !path_ok {
        return Err(format!(
            "`{entry}` does not name one path: letters, digits and / . _ - ~ only, no query string and no wildcard"
        ));
    }
    Ok(format!("{}{path}", host.to_ascii_lowercase()))
}

/// The declaration as it may be stored for a module holding this grant:
/// normalised, deduplicated and sorted. `Err` names the first entry refused.
///
/// An entry must lie inside what the module may already do: its host is one
/// `allowed_hosts` names exactly (a wildcard or a suffix entry names no host),
/// and `POST` is among `allowed_methods`. A declaration about a request the
/// module can never make is a mistake worth saying at write time.
pub fn validate_declaration(
    entries: &[String],
    allowed_hosts: &[String],
    allowed_methods: &[String],
) -> Result<Vec<String>, String> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    if entries.len() > MAX_ENTRIES {
        return Err(format!(
            "a module declares at most {MAX_ENTRIES} read-only POSTs, and {} were given",
            entries.len()
        ));
    }
    if !crate::method_permitted(allowed_methods, "POST") {
        return Err(
            "the module's allowed_methods does not include POST, so it can make none of these requests"
                .to_string(),
        );
    }
    let mut out = Vec::with_capacity(entries.len());
    for raw in entries {
        let entry = normalize_entry(raw)?;
        let host = entry.split('/').next().unwrap_or("");
        if !allowed_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            return Err(format!(
                "`{entry}`: the module's allowed_hosts does not name the host `{host}` exactly"
            ));
        }
        out.push(entry);
    }
    out.sort_unstable();
    out.dedup();
    Ok(out)
}

/// Whether the module declared this request to be a read.
///
/// `host` and `path` are the parsed URL's own; `port` is `None` when the URL
/// names none. Only an https POST to the default port, whose host and path
/// are exactly one entry's, is a declared read.
#[must_use]
pub fn is_declared_read(
    declared: &[String],
    method: &str,
    scheme: &str,
    host: &str,
    port: Option<u16>,
    path: &str,
) -> bool {
    if declared.is_empty()
        || !method.eq_ignore_ascii_case("POST")
        || !scheme.eq_ignore_ascii_case("https")
        || port.is_some_and(|p| p != 443)
    {
        return false;
    }
    declared.iter().any(|entry| {
        entry.split_once('/').is_some_and(|(h, rest)| {
            h.eq_ignore_ascii_case(host) && path.strip_prefix('/').is_some_and(|p| p == rest)
        })
    })
}

/// The declaration as the job's signature binds it: sorted, joined by commas.
/// An entry holds no comma, so the joined text reads back to the same list.
#[must_use]
pub fn signing_text(declared: &[String]) -> String {
    let mut sorted: Vec<&str> = declared.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    sorted.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn an_entry_is_one_host_and_one_path_and_nothing_else() {
        assert_eq!(
            normalize_entry(" Production.Plaid.com/transactions/get ").as_deref(),
            Ok("production.plaid.com/transactions/get")
        );
        assert_eq!(
            normalize_entry("api.example.com/v1/_search.json").as_deref(),
            Ok("api.example.com/v1/_search.json")
        );
        for bad in [
            "",
            "production.plaid.com",
            "production.plaid.com/",
            "https://production.plaid.com/transactions/get",
            "production.plaid.com:8443/transactions/get",
            "*.plaid.com/transactions/get",
            "plaid/transactions/get",
            "production.plaid.com/transactions/*",
            "production.plaid.com/transactions/get?x=1",
            "production.plaid.com/a/../b",
            "production.plaid.com/a//b",
            "production.plaid.com/a b",
            "production.plaid.com/a,b",
            ".plaid.com/x",
            "/transactions/get",
        ] {
            assert!(normalize_entry(bad).is_err(), "{bad:?} was taken");
        }
        assert!(
            normalize_entry(&format!("a.example.com/{}", "x".repeat(MAX_ENTRY_CHARS))).is_err()
        );
    }

    #[test]
    fn a_declaration_lies_inside_the_modules_own_grant() {
        let hosts = list(&["production.plaid.com", "*.example.com"]);
        let post = list(&["POST"]);
        assert_eq!(
            validate_declaration(
                &list(&[
                    "production.plaid.com/transactions/get",
                    "PRODUCTION.plaid.com/accounts/get",
                    "production.plaid.com/accounts/get"
                ]),
                &hosts,
                &post
            ),
            Ok(list(&[
                "production.plaid.com/accounts/get",
                "production.plaid.com/transactions/get"
            ]))
        );
        assert_eq!(
            validate_declaration(&[], &[], &[]),
            Ok(Vec::new()),
            "none is always allowed"
        );
        // A host the grant does not name exactly: a suffix entry names no host.
        assert!(
            validate_declaration(&list(&["api.example.com/search"]), &hosts, &post)
                .unwrap_err()
                .contains("does not name the host")
        );
        assert!(validate_declaration(
            &list(&["sandbox.plaid.com/transactions/get"]),
            &hosts,
            &post
        )
        .is_err());
        // No POST in the grant: the module can make none of them.
        assert!(validate_declaration(
            &list(&["production.plaid.com/transactions/get"]),
            &hosts,
            &list(&["GET"])
        )
        .unwrap_err()
        .contains("does not include POST"));
        assert!(validate_declaration(
            &list(&["production.plaid.com/transactions/get"]),
            &hosts,
            &[]
        )
        .is_err());
        let many: Vec<String> = (0..=MAX_ENTRIES)
            .map(|i| format!("production.plaid.com/p{i}"))
            .collect();
        assert!(validate_declaration(&many, &hosts, &post)
            .unwrap_err()
            .contains("at most"));
        assert!(validate_declaration(&list(&["production.plaid.com/x?y"]), &hosts, &post).is_err());
    }

    #[test]
    fn only_the_exact_https_post_is_a_declared_read() {
        const HOST: &str = "production.plaid.com";
        const PATH: &str = "/transactions/get";
        let d = list(&["production.plaid.com/transactions/get"]);
        let is = |m: &str, s: &str, h: &str, port: Option<u16>, p: &str| {
            is_declared_read(&d, m, s, h, port, p)
        };
        assert!(is("POST", "https", HOST, None, PATH));
        assert!(is("post", "HTTPS", "PRODUCTION.PLAID.COM", Some(443), PATH));
        // Every way of being a different request.
        let different: [(&str, &str, &str, Option<u16>, &str); 11] = [
            ("PUT", "https", HOST, None, PATH),
            ("DELETE", "https", HOST, None, PATH),
            ("POST", "http", HOST, None, PATH),
            ("POST", "https", HOST, Some(8443), PATH),
            ("POST", "https", "sandbox.plaid.com", None, PATH),
            (
                "POST",
                "https",
                "evil.com",
                None,
                "/production.plaid.com/transactions/get",
            ),
            ("POST", "https", HOST, None, "/transactions/get/"),
            ("POST", "https", HOST, None, "/transactions/get2"),
            ("POST", "https", HOST, None, "/transactions"),
            ("POST", "https", HOST, None, "/transfer/create"),
            ("POST", "https", HOST, None, "transactions/get"),
        ];
        for (m, s, h, port, p) in different {
            assert!(!is(m, s, h, port, p), "{m} {s}://{h}:{port:?}{p} was taken");
        }
        // Nothing declared: nothing is a declared read.
        assert!(!is_declared_read(&[], "POST", "https", HOST, None, PATH));
    }

    #[test]
    fn the_signed_text_does_not_depend_on_the_order_given() {
        let a = list(&["b.example.com/y", "a.example.com/x"]);
        let b = list(&["a.example.com/x", "b.example.com/y"]);
        assert_eq!(signing_text(&a), signing_text(&b));
        assert_eq!(signing_text(&a), "a.example.com/x,b.example.com/y");
        assert_eq!(signing_text(&[]), "");
    }
}
