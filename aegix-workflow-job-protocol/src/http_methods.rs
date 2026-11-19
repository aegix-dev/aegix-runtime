//! Which HTTP verbs a module may use: the one reading of `allowed_methods`,
//! the five verbs there are, and what a sandbox run gets when it names none.
//!
//! Moved out of `lib.rs` 2026-11-18, unchanged; every public item is
//! re-exported at the crate root, where it was.

/// Returns true if `method` is permitted by this module's `allowed_methods`
/// grant. Sibling of [`vault_path_permitted`], and deliberately the same
/// shape: ONE home, so every enforcement point agrees on what a grant means.
///
/// Semantics:
///   - `[]` (empty)          → **deny all** (no verb is permitted)
///   - `["GET", "POST", …]`  → case-insensitive membership
///
/// # Empty denies, and that is a 2026-09-24 behaviour change
///
/// Until this function existed, all five enforcement points spelled the test
/// `!allowed.is_empty() && !allowed.contains(method)` — so an EMPTY grant
/// admitted every verb. That made `allowed_methods` the one member of the
/// three-part module grant where empty means ALLOW: empty `allowed_hosts`
/// denies (`host/webhook.rs` refuses outright on an empty list) and empty
/// `allowed_secrets` denies (`vault_path_permitted` returns `false`). A
/// module compiled with no method declaration could therefore POST, PUT,
/// PATCH and DELETE anywhere its host allowlist reached.
///
/// Measured on the reference fleet before the flip: of **27** modules in a
/// capability world above `Minimal` (i.e. able to reach the HTTP suite at
/// all) with an empty `allowed_methods`, **ZERO** call any HTTP surface —
/// checked with a deliberately loose predicate (`fetch(`, `::send(`,
/// `execute(`, `connect(`) over `modules.source_code`, with no NULL source
/// to hide in. They are LLM, memory, classify and approval modules that
/// inherit the HTTP imports from their world without using them. So the
/// allow-on-empty behaviour was never load-bearing here, and the flip is
/// latent on this fleet.
///
/// It is NOT latent in general. A deployment holding an undeclared module
/// that does call HTTP loses that call, fail-closed, with a refusal naming
/// `update_module_methods`. That is the same direction as every other gate
/// in this family and is stated rather than softened.
///
/// # No wildcard, deliberately
///
/// `allowed_secrets` needs `["*"]` because the vault key space is unbounded.
/// The method space is **closed at five** — `wit/aegix.wit`'s `enum method`
/// is exactly `get, post, put, delete, patch` — so "every verb" is spelled by
/// listing five strings, which is what the one module on this fleet that uses
/// every verb already does (`{GET,POST,PUT,PATCH,DELETE}`). A wildcard would
/// add a second spelling and a footgun for a bounded set, with no
/// expressiveness gained.
#[must_use]
pub fn method_permitted(allowed: &[String], method: &str) -> bool {
    !allowed.is_empty() && allowed.iter().any(|m| m.eq_ignore_ascii_case(method))
}

/// Every verb the WIT `enum method` can carry, in one place.
///
/// NOT a wildcard and not a default for a MODULE: [`method_permitted`] has no
/// `["*"]` and an installed module must declare what it uses. This exists
/// because the set is CLOSED at five (`wit/aegix.wit`), so "every verb" is
/// spelled by listing five strings — and a spelling repeated by hand is a
/// spelling that drifts.
///
/// The one caller that legitimately wants all five is the SANDBOX
/// (`run_sandbox`), where the operator supplies both the code and the host
/// allowlist in the same call, so the method axis bounds nothing the host axis
/// does not already bound. See [`sandbox_default_methods`].
pub const ALL_HTTP_METHODS: [&str; 5] = ["GET", "POST", "PUT", "PATCH", "DELETE"];

/// The method grant an ephemeral sandbox run gets when the caller names none.
///
/// **Deliberately permissive, and it is the one place in this family that is.**
/// `run_sandbox` compiles and runs operator-supplied code against an
/// operator-supplied `allowed_hosts` list in a single call: there is no third
/// party for the method axis to protect, and the host axis — which still
/// defaults to deny-all — is the bound that matters. Defaulting this closed
/// instead made `run_sandbox` unable to issue ANY request, with no parameter
/// to open it, which is what shipped on 2026-09-24 and is what this repairs.
///
/// An INSTALLED module gets no such default: it inherits its template's
/// declaration, or it declares its own, or it is refused.
#[must_use]
pub fn sandbox_default_methods() -> Vec<String> {
    ALL_HTTP_METHODS.iter().map(|m| (*m).to_string()).collect()
}

/// The one sentence every method refusal gives the module author.
///
/// The refusal has to name the FIX, not just the rule: an author told only
/// "method not allowed" for a module that declares nothing has no way to know
/// that declaring nothing is what denied them.
pub const METHOD_ALLOWLIST_REMEDY: &str =
    "declare the verbs this module uses with update_module_methods (an empty \
     allowed_methods denies every verb, matching allowed_hosts and allowed_secrets)";

/// [`method_permitted`] — the semantics three grants are supposed to share.
#[cfg(test)]
mod method_permitted_tests {
    use super::{method_permitted, METHOD_ALLOWLIST_REMEDY};
    use crate::vault_path_permitted;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    /// The whole point of the function, and the 2026-09-24 behaviour change.
    #[test]
    fn an_empty_grant_denies_every_verb() {
        for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            assert!(!method_permitted(&[], m), "empty must deny {m}");
        }
    }

    /// CONTROL for the above: the same verbs pass once declared, so the
    /// refusal cannot be a function that denies everything.
    #[test]
    fn a_declared_verb_is_permitted() {
        let all = v(&["GET", "POST", "PUT", "PATCH", "DELETE"]);
        for m in ["GET", "POST", "PUT", "PATCH", "DELETE"] {
            assert!(method_permitted(&all, m), "declared must permit {m}");
        }
    }

    #[test]
    fn an_undeclared_verb_is_refused_even_when_others_are_declared() {
        let get_only = v(&["GET"]);
        assert!(method_permitted(&get_only, "GET"));
        for m in ["POST", "PUT", "PATCH", "DELETE"] {
            assert!(!method_permitted(&get_only, m), "{m} is not declared");
        }
    }

    /// Preserved from the four hand-rolled gates this replaced — every one of
    /// them used `eq_ignore_ascii_case`, so a `talos.json` written in lower
    /// case must keep working.
    #[test]
    fn matching_is_case_insensitive_as_all_four_gates_were() {
        assert!(method_permitted(&v(&["get"]), "GET"));
        assert!(method_permitted(&v(&["GeT"]), "get"));
        assert!(method_permitted(&v(&["POST"]), "post"));
    }

    /// Deliberately NO wildcard: the WIT method enum is closed at five, so
    /// "every verb" is spelled by listing five strings. A `["*"]` grant is a
    /// module declaring one verb literally named `*`, which does not exist —
    /// and it must NOT silently mean all, because that would re-create the
    /// allow-by-accident this change removed, under a second spelling.
    #[test]
    fn a_star_is_not_a_wildcard_here_unlike_allowed_secrets() {
        let star = v(&["*"]);
        for m in ["GET", "POST"] {
            assert!(!method_permitted(&star, m), "`*` must not grant {m}");
        }
        // For secrets `*` was the documented wildcard until 2026-10-15; it now
        // grants nothing there either (operator decision D2-D).
        assert!(!vault_path_permitted(&star, "anything/at/all"));
    }

    /// The refusal has to name the FIX, not just the rule.
    #[test]
    fn the_remedy_names_the_tool_and_the_empty_case() {
        assert!(METHOD_ALLOWLIST_REMEDY.contains("update_module_methods"));
        assert!(METHOD_ALLOWLIST_REMEDY.contains("empty"));
        assert!(METHOD_ALLOWLIST_REMEDY.contains("allowed_hosts"));
        assert!(METHOD_ALLOWLIST_REMEDY.contains("allowed_secrets"));
    }
}

#[cfg(test)]
mod sandbox_default_method_tests {
    use super::*;

    /// The five-verb list and the gate must agree: every verb the constant
    /// names must be PERMITTED by a grant of that constant, and a grant of it
    /// must permit nothing else (there is no sixth verb in the WIT enum).
    #[test]
    fn the_constant_is_exactly_what_the_gate_permits() {
        let all = sandbox_default_methods();
        assert_eq!(all.len(), 5, "the WIT method enum is closed at five");
        for verb in ALL_HTTP_METHODS {
            assert!(
                method_permitted(&all, verb),
                "{verb} is in ALL_HTTP_METHODS but the gate refuses it"
            );
        }
        // A control that can fail: a verb OUTSIDE the closed set must not be
        // permitted, so this cannot pass by the gate permitting everything.
        assert!(
            !method_permitted(&all, "HEAD"),
            "HEAD is not in the WIT enum and must not be permitted"
        );
    }

    /// The sandbox default is DELIBERATELY the opposite of a module's.
    ///
    /// If this ever reads equal, `run_sandbox` has silently inherited the
    /// installed-module posture and can issue no request at all — which is
    /// exactly what shipped on 2026-09-24.
    #[test]
    fn the_sandbox_default_is_not_the_module_default() {
        let sandbox = sandbox_default_methods();
        let module: Vec<String> = Vec::new();
        assert_ne!(sandbox, module);
        assert!(method_permitted(&sandbox, "GET"));
        assert!(
            !method_permitted(&module, "GET"),
            "an installed module's empty grant must still DENY"
        );
    }
}
