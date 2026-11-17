//! Pure readings of a module's source.
//!
//! A module is one Rust source file, compiled for the sandbox by the
//! platform. Several gates ask the same questions of that file: which hosts
//! its string literals address (and whether its grant names them), which
//! config keys it reads (and whether its schema declares them), whether
//! it carries a pattern the compile refuses (`env!()`, `include_str!()`,
//! `#[path]`, `unsafe`), and whether it reads a clock a test cannot set.
//! Each question has ONE answer here:
//!
//! * [`literals`] — the string literals of a source, with comments, char
//!   literals and lifetimes told apart from them; the source with its
//!   comments blanked; the source before its `#[cfg(test)]` module.
//! * [`hosts`] — the hosts a literal addresses with a scheme, whether a
//!   literal names a host whole, and the two rules of the hosts gate.
//! * [`config_keys`] — the keys a typed `…Config` struct or a
//!   `config.get("KEY")` lookup reads, and the rules of the config gate.
//! * [`lint`] — the static lint the platform's compile paths run before they
//!   build, and the subset of its findings that refuses the compile.
//! * [`legacy_names`] — the places a source names the module interface as it
//!   was called before 2026-11-16, the sentence a compile refuses it with,
//!   and the one rewrite of it.
//! * [`clock`] — the lines that read the process's own clock (`Utc::now()`,
//!   `Local::now()`, `SystemTime::now()`) instead of the host's `datetime`.
//! * [`failure_kind`] — the statements that map a failed `http::fetch` to a
//!   message without the kind of the failure, which the retry decision reads.
//! * [`fence`] — whether text shown to a model is wrapped in `<untrusted_data>`
//!   through the one `neutralize_closing_tags` rewrite, and the copy of it a
//!   module carries.
//!
//! The catalog's gates (`aegix-catalog-tests/tests/`), the authoring lane's
//! (through `aegix_module_testkit::source`) and `aegix_compilation`'s
//! `source_lint_errors` all call these; none keeps a copy. No I/O, no
//! platform types: a caller hands in the source text and what its manifest
//! says, and reads back sentences for a person or sets for a program.

pub mod clock;
pub mod config_keys;
pub mod failure_kind;
pub mod fence;
pub mod hosts;
pub mod legacy_names;
pub mod lint;
pub mod literals;
