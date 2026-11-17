//! The closed label set for `aegix_registry_sync_total{outcome}` — one
//! increment per pass of the controller's OCI catalog sync loop
//! (`aegix_registry::sync::start_registry_sync_loop`, every 300 s while
//! `AEGIX_REGISTRY_URL` is set).
//!
//! Why it exists (2026-11-04, `docs/engineering-log/packages/
//! 2026-11-04-registry-sync-failure-is-counted.md`). The production host went
//! registry-only on 2026-11-04 and its read credential died the same morning:
//! the operator regenerated the classic token to add a scope for an image
//! push, which changes its value, and the deployment kept the old one. Every
//! sync after the 10:38Z roll failed with `Registry sync failed: resolve
//! catalog.index digest: Not authorized` — one ERROR line per pass, no series,
//! no alert. It was found by reading the controller log after the roll. A
//! catalog that stops refreshing is quiet by nature (the rows an earlier sync
//! left keep serving), so nothing downstream fails loudly either.
//!
//! The series is SEEDED AT 0 BY THE LOOP, not by `AegixMetrics::new`: it is
//! present exactly when the loop runs, so absence means the controller is in
//! disk-seeding mode (or unscraped, which `TalosControllerDown` owns) and the
//! alert `TalosRegistrySyncFailing` carries no `absent()` arm. A controller
//! that never runs the loop would otherwise export four series nothing can
//! move (CLAUDE.md, "ABSENT and ZERO are different").

/// How one pass of the sync loop ended. Decided in ONE place,
/// `aegix_registry::sync::sync_outcome`, from the loop body's result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegistrySyncOutcome {
    /// The index was read and every template it names was written (a
    /// registry with nothing published yet counts here: nothing failed).
    Ok,
    /// The index was read and at least one named template failed to sync
    /// (its signature, digest or manifest was refused). The rows that
    /// succeeded were written; the rest keep what an earlier sync left.
    Partial,
    /// The registry refused the credential (`OCI_REGISTRY_USERNAME` /
    /// `OCI_REGISTRY_PASSWORD`): an OCI `UNAUTHORIZED` / `DENIED` code, a 401
    /// or 403, or the client's own `Not authorized`. The 2026-11-04 shape.
    Unauthorized,
    /// Any other failure before a template was written: the registry
    /// unreachable, a malformed index, a digest that does not match.
    Error,
}

impl RegistrySyncOutcome {
    pub const ALL: &'static [Self] = &[Self::Ok, Self::Partial, Self::Unauthorized, Self::Error];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Partial => "partial",
            Self::Unauthorized => "unauthorized",
            Self::Error => "error",
        }
    }

    /// Did the catalog come through whole? Everything else is what the
    /// alert's `outcome!="ok"` selector counts.
    #[must_use]
    pub const fn is_ok(self) -> bool {
        matches!(self, Self::Ok)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_values_are_snake_case_words_and_distinct() {
        let mut seen = std::collections::HashSet::new();
        for o in RegistrySyncOutcome::ALL {
            let v = o.as_str();
            assert!(
                !v.is_empty() && v.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{v:?}"
            );
            assert!(seen.insert(v), "{v} listed twice");
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn only_ok_is_ok() {
        for o in RegistrySyncOutcome::ALL {
            assert_eq!(o.is_ok(), *o == RegistrySyncOutcome::Ok, "{}", o.as_str());
        }
    }
}
