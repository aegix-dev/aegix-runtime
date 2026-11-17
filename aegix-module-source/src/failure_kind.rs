//! Whether a module keeps the KIND of a failed HTTP request in its error.
//!
//! The host hands a module one of four words when a request gets no answer:
//! `Timeout`, `Networkerror`, `Forbiddenhost`, `Invalidurl`. The platform
//! decides from that word whether to try again
//! (`aegix_retry_intelligence::classify_error`): a timeout and a network
//! error are retried, a refused host is not. A module's error message is the
//! only place the word can travel, so a module that maps the error away
//! (`.map_err(|_| "could not be reached")`) turns every network blip into an
//! unretried failure of unknown cause. Observed 2026-10-12: the
//! `github-workflow-run` template did exactly that, unreachable polls in a
//! busy hour failed the CI watcher four times, and the owner was paged about
//! the pager; three other templates had the same line.
//!
//! So, over the module before its `#[cfg(test)]` module, comments out: no
//! statement that calls `http::fetch(` goes on, before its `;`, to a
//! `map_err` whose closure ignores its argument (`|_|`). The fix is
//! `.map_err(|e| format!("… ({e:?})"))`.
//!
//! Limits: the statement is read as the text up to the next `;`, so a call
//! whose result is bound and mapped in a LATER statement is not seen (the
//! kind is then kept in the binding, and it is the later statement's business);
//! a `;` inside a string within the statement ends it early. Until
//! 2026-10-19 this scanner lived in the catalog's gate alone; it is here so
//! the authoring lane holds its modules to the same reading.

use crate::literals::{before_tests, without_comments};
use std::fmt;

/// The call whose failure kind is kept.
pub const CALL: &str = "http::fetch(";

/// One statement of a module that throws the kind of a failed request away.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardedFailureKind {
    /// 1-based line of the source where the call begins.
    pub line: usize,
}

impl fmt::Display for DiscardedFailureKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "line {} maps an HTTP failure to a message without its kind: write \
             `.map_err(|e| format!(\"… ({{e:?}})\"))` so a timeout or a network error is retried",
            self.line
        )
    }
}

/// Every statement of the module (before its tests, comments out) in which
/// the result of [`CALL`] is mapped by a closure that ignores its argument,
/// in source order.
#[must_use]
pub fn discarded_fetch_errors(source: &str) -> Vec<DiscardedFailureKind> {
    let code = without_comments(before_tests(source));
    let mut found = Vec::new();
    let mut from = 0;
    while let Some(at) = code[from..].find(CALL) {
        let start = from + at;
        let end = code[start..].find(';').map_or(code.len(), |i| start + i);
        let statement: String = code[start..end].split_whitespace().collect();
        if statement.contains(".map_err(|_|") {
            found.push(DiscardedFailureKind {
                line: code[..start].lines().count().max(1),
            });
        }
        from = start + CALL.len();
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines(source: &str) -> Vec<usize> {
        discarded_fetch_errors(source)
            .into_iter()
            .map(|d| d.line)
            .collect()
    }

    #[test]
    fn a_discarded_kind_is_found_across_lines_and_a_kept_one_is_not() {
        let discarded =
            "let r = aegix::core::http::fetch(&req)\n        .map_err(|_| \"down\".to_string())?;";
        assert_eq!(lines(discarded), vec![1]);
        let second_line = "x();\nlet r = http::fetch(&req).map_err(|_| \"down\".to_string())?;";
        assert_eq!(lines(second_line), vec![2]);
        let kept = "let r = http::fetch(&req).map_err(|e| format!(\"down ({e:?})\"))?;";
        assert!(lines(kept).is_empty());
        // A later, unrelated statement that ignores an error is not this call's.
        let unrelated = "let r = http::fetch(&req)?;\nlet n = parse(x).map_err(|_| \"bad\")?;";
        assert!(lines(unrelated).is_empty());
    }

    #[test]
    fn a_comment_and_the_tests_are_not_the_module() {
        let commented = "// http::fetch(&req).map_err(|_| \"down\")\nlet r = http::fetch(&req)?;";
        assert!(lines(commented).is_empty());
        let in_tests = "let r = http::fetch(&req)?;\n#[cfg(test)]\nmod t { fn f() { http::fetch(&req).map_err(|_| \"x\"); } }";
        assert!(lines(in_tests).is_empty());
        // Two calls in one module: each is its own finding, with its own line.
        let two = "let a = http::fetch(&a).map_err(|_| \"a\")?;\n\nlet b = http::fetch(&b).map_err(|_| \"b\")?;";
        assert_eq!(lines(two), vec![1, 3]);
    }

    #[test]
    fn the_finding_says_what_to_write() {
        let d = DiscardedFailureKind { line: 7 };
        assert_eq!(d.to_string(), "line 7 maps an HTTP failure to a message without its kind: write `.map_err(|e| format!(\"… ({e:?})\"))` so a timeout or a network error is retried");
    }
}
