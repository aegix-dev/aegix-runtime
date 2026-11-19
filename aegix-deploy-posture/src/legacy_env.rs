//! A process refuses to start while its environment still holds a variable
//! under the project's former prefix.
//!
//! Every variable this workspace reads was renamed from `TALOS_…` to
//! `AEGIX_…` on 2026-11-15, and nothing reads the old names any more. A
//! deployment whose settings file was not renamed would otherwise start
//! with every one of those settings ignored and its default in force: the
//! write ceiling unenforced, signatures not required, the replay guard off.
//! Nothing would say so. So a name left under the old prefix is a refusal,
//! at the top of the controller, the worker and the reference controller.
//!
//! Only names are read. A value is never looked at, logged or returned.
//!
//! `scripts/legacy-env-names.py` finds and renames the keys of a settings
//! file; `docs/renamed-to-aegix.md` is the operator's page.
//!
//! This file is not rewritten by `scripts/rename-to-aegix.py`: it is the one
//! place in the workspace's source that must go on naming the old prefix.

use std::ffi::OsStr;

/// What every variable of this project began with until 2026-11-15.
pub const LEGACY_PREFIX: &str = "TALOS_";

/// What it begins with now.
pub const PREFIX: &str = "AEGIX_";

/// How many names a refusal spells out before it counts the rest.
const NAMES_SHOWN: usize = 20;

/// The names in `names` that begin with [`LEGACY_PREFIX`], sorted, each once.
///
/// A name that is not UTF-8 cannot begin with an ASCII prefix followed by a
/// name this project chose, and is passed over.
pub fn legacy_names<I, S>(names: I) -> Vec<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut found: Vec<String> = names
        .into_iter()
        .filter_map(|name| name.as_ref().to_str().map(str::to_owned))
        .filter(|name| name.starts_with(LEGACY_PREFIX))
        .collect();
    found.sort();
    found.dedup();
    found
}

/// The sentence a process stops with, or `None` when `legacy` is empty.
pub fn refusal_for(legacy: &[String]) -> Option<String> {
    if legacy.is_empty() {
        return None;
    }
    let shown: Vec<String> = legacy
        .iter()
        .take(NAMES_SHOWN)
        .map(|old| format!("{old} -> {PREFIX}{}", &old[LEGACY_PREFIX.len()..]))
        .collect();
    let more = match legacy.len().saturating_sub(NAMES_SHOWN) {
        0 => String::new(),
        rest => format!(", and {rest} more"),
    };
    Some(format!(
        "refusing to start: {count} environment variable(s) still carry the former prefix \
         {LEGACY_PREFIX}. Nothing reads that prefix any more, so each of these settings would \
         be ignored and its default used. Rename them ({shown}{more}); \
         scripts/legacy-env-names.py renames the keys of a settings file.",
        count = legacy.len(),
        shown = shown.join(", "),
    ))
}

/// `Err` with [`refusal_for`]'s sentence when this process's environment
/// holds a name under the former prefix.
///
/// Call it after any settings file has been loaded into the environment, and
/// before the first setting is read.
pub fn refuse_legacy_names() -> Result<(), String> {
    let legacy = legacy_names(std::env::vars_os().map(|(name, _value)| name));
    match refusal_for(&legacy) {
        Some(why) => Err(why),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_names_under_the_former_prefix_are_found() {
        let found = legacy_names([
            "TALOS_FIRST_SETTING",
            "AEGIX_FIRST_SETTING",
            "PATH",
            "MY_TALOS_THING",
            "TALOS",
            "talos_lowercase",
            "TALOS_",
        ]);
        assert_eq!(found, ["TALOS_", "TALOS_FIRST_SETTING"]);
    }

    #[test]
    fn names_are_sorted_and_each_appears_once() {
        let found = legacy_names(["TALOS_B", "TALOS_A", "TALOS_B"]);
        assert_eq!(found, ["TALOS_A", "TALOS_B"]);
    }

    #[test]
    fn an_environment_without_one_is_not_refused() {
        assert_eq!(
            refusal_for(&legacy_names(["AEGIX_FIRST_SETTING", "HOME"])),
            None
        );
    }

    #[test]
    fn the_refusal_names_each_variable_and_what_it_becomes() {
        let why = refusal_for(&legacy_names([
            "TALOS_SECOND_SETTING",
            "TALOS_FIRST_SETTING",
        ]))
        .expect("two legacy names are a refusal");
        assert!(why.contains("2 environment variable(s)"), "{why}");
        assert!(
            why.contains("TALOS_FIRST_SETTING -> AEGIX_FIRST_SETTING"),
            "{why}"
        );
        assert!(
            why.contains("TALOS_SECOND_SETTING -> AEGIX_SECOND_SETTING"),
            "{why}"
        );
    }

    #[test]
    fn a_long_list_is_counted_not_spelled_out() {
        let many: Vec<String> = (0..NAMES_SHOWN + 7)
            .map(|i| format!("TALOS_SETTING_{i:02}"))
            .collect();
        let why = refusal_for(&legacy_names(&many)).expect("a refusal");
        assert!(why.contains("and 7 more"), "{why}");
        assert!(
            !why.contains(&format!("TALOS_SETTING_{:02} ->", NAMES_SHOWN)),
            "{why}"
        );
    }

    /// The function takes names and has no way to be handed a value: what a
    /// refusal prints cannot hold one.
    #[test]
    fn a_refusal_is_built_from_names_alone() {
        let pairs = [("TALOS_FIRST_SETTING", "not-a-real-key-value")];
        let why =
            refusal_for(&legacy_names(pairs.iter().map(|(name, _)| *name))).expect("a refusal");
        assert!(!why.contains("not-a-real-key-value"), "{why}");
    }
}
