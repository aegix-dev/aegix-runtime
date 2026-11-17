//! A module's source that names the interface as it was called before
//! 2026-11-16, and the one rewrite of it.
//!
//! Until that date the interface package was `talos:core`, a module reached
//! it as `talos::core::…`, and the macro crate was `talos_sdk_macros` with
//! the macros `talos_node`, `talos_module` and `talos_agent`. They are
//! `aegix:core`, `aegix::core::…`, `aegix_sdk_macros`, `aegix_node`,
//! `aegix_module` and `aegix_agent`, and nothing accepts the former names.
//!
//! A source that still has one would not fail clearly on its own: the
//! compile paths recognise an annotated module by the macro's name, so a
//! `#[talos_node]` reads as "not annotated", a second annotation is added,
//! and the author is shown an error about a crate that does not exist. So
//! the static lint refuses such a source first ([`refusal`], through
//! `lint::lint`), by line, with what each name became; and [`rewrite`] is
//! the one function that changes a source, for a file (`controller
//! rename-module-source`) and for a stored module (`controller
//! recompile-modules`).
//!
//! What is found and what is rewritten are the same places, by
//! construction: both read [`former_names`].
//!
//! This file is not rewritten by `scripts/rename-to-aegix.py`: it must go on
//! naming the former names. `scripts/tests/rename-interface-names-test.sh`
//! holds every name here to that script's list.

/// A name a module's CODE may carry: found outside string literals, as a
/// whole word. (was, is)
pub const RENAMED_IN_CODE: &[(&str, &str)] = &[
    ("talos_sdk_macros", "aegix_sdk_macros"),
    ("talos_node", "aegix_node"),
    ("talos_module", "aegix_module"),
    ("talos_agent", "aegix_agent"),
    ("talos_sdk", "aegix_sdk"),
];

/// The interface as a Rust path: `talos` directly before `::`, outside
/// string literals. (`talos::core::http::fetch`, `crate::talos::core`.)
pub const FORMER_PATH_ROOT: &str = "talos";
/// What [`FORMER_PATH_ROOT`] became.
pub const PATH_ROOT: &str = "aegix";

/// A name found wherever it is written, a string literal or a remark
/// included: the package in an import specifier (`'talos:core/http'`) and
/// the JavaScript annotation that names a module's world, which is a
/// comment. (was, is)
pub const RENAMED_ANYWHERE: &[(&str, &str)] = &[
    ("talos:core", "aegix:core"),
    ("@talos-world", "@aegix-world"),
];

/// On a line that carries this, nothing is found and nothing is rewritten:
/// for the rare line that must name something else by one of these words.
pub const OPT_OUT: &str = "lint-allow: former-interface-name";

/// One place a source names the interface as it was called.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FormerName {
    /// The 1-based line.
    pub line: u32,
    /// Byte offset of the name in the source.
    pub start: usize,
    pub was: &'static str,
    pub is: &'static str,
}

const fn is_word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// For each byte of `src`, whether it is inside a string literal: `"…"` with
/// `\` escapes, and a Rust raw string (`r"…"`, `r#"…"#`, `br#"…"#`). A `"`
/// inside a `//` or `/* */` comment, or a `'"'` character literal, opens
/// nothing.
fn string_mask(src: &str) -> Vec<bool> {
    let b = src.as_bytes();
    let n = b.len();
    let mut mask = vec![false; n];
    let mut i = 0;
    while i < n {
        match b[i] {
            b'/' if b.get(i + 1) == Some(&b'/') => {
                while i < n && b[i] != b'\n' {
                    i += 1;
                }
            }
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 1usize;
                i += 2;
                while i < n && depth > 0 {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
            }
            b'\'' => {
                // `'"'` and `'\"'`: a character, not the start of a string.
                if b.get(i + 1) == Some(&b'"') && b.get(i + 2) == Some(&b'\'') {
                    i += 3;
                } else if b.get(i + 1) == Some(&b'\\')
                    && b.get(i + 2) == Some(&b'"')
                    && b.get(i + 3) == Some(&b'\'')
                {
                    i += 4;
                } else {
                    i += 1;
                }
            }
            b'"' => {
                let start = i;
                i += 1;
                while i < n && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i = (i + 1).min(n);
                mask[start..i].fill(true);
            }
            b'r' | b'b' if i == 0 || !is_word(b[i - 1]) => {
                let mut j = i;
                if b[j] == b'b' {
                    j += 1;
                }
                if b.get(j) == Some(&b'r') {
                    j += 1;
                    let hashes = b[j..].iter().take_while(|&&c| c == b'#').count();
                    j += hashes;
                    if b.get(j) == Some(&b'"') {
                        let body = j + 1;
                        let mut close = None;
                        let mut k = body;
                        while k < n {
                            if b[k] == b'"'
                                && b[k + 1..]
                                    .iter()
                                    .take(hashes)
                                    .filter(|&&c| c == b'#')
                                    .count()
                                    == hashes
                                && k + 1 + hashes <= n
                            {
                                close = Some(k + 1 + hashes);
                                break;
                            }
                            k += 1;
                        }
                        let end = close.unwrap_or(n);
                        mask[i..end].fill(true);
                        i = end;
                        continue;
                    }
                }
                i += 1;
            }
            _ => i += 1,
        }
    }
    mask
}

/// Every place `source` names the interface as it was called, in order.
#[must_use]
pub fn former_names(source: &str) -> Vec<FormerName> {
    if !source.contains(FORMER_PATH_ROOT) {
        return Vec::new();
    }
    let bytes = source.as_bytes();
    let in_string = string_mask(source);
    let mut found: Vec<FormerName> = Vec::new();
    let mut whole_word = |was: &'static str, is: &'static str, code_only: bool| {
        let mut from = 0;
        while let Some(at) = source[from..].find(was) {
            let start = from + at;
            let end = start + was.len();
            from = end;
            let left = start > 0 && is_word(bytes[start - 1]);
            let right = bytes.get(end).is_some_and(|&b| is_word(b));
            if left || right || (code_only && in_string[start]) {
                continue;
            }
            found.push(FormerName {
                line: 0,
                start,
                was,
                is,
            });
        }
    };
    for (was, is) in RENAMED_IN_CODE {
        whole_word(was, is, true);
    }
    for (was, is) in RENAMED_ANYWHERE {
        whole_word(was, is, false);
    }
    // The path root: `talos` as a whole word, directly before `::`.
    let mut from = 0;
    while let Some(at) = source[from..].find(FORMER_PATH_ROOT) {
        let start = from + at;
        let end = start + FORMER_PATH_ROOT.len();
        from = end;
        let left = start > 0 && is_word(bytes[start - 1]);
        if left || in_string[start] || !source[end..].starts_with("::") {
            continue;
        }
        found.push(FormerName {
            line: 0,
            start,
            was: FORMER_PATH_ROOT,
            is: PATH_ROOT,
        });
    }
    found.sort_by_key(|f| f.start);

    // Line numbers, and the lines that opt out.
    let mut line_starts = vec![0usize];
    line_starts.extend(source.match_indices('\n').map(|(i, _)| i + 1));
    found.retain_mut(|f| {
        let index = line_starts.partition_point(|&s| s <= f.start) - 1;
        let end = line_starts.get(index + 1).copied().unwrap_or(source.len());
        f.line = u32::try_from(index + 1).unwrap_or(u32::MAX);
        !source[line_starts[index]..end].contains(OPT_OUT)
    });
    found
}

/// `source` with every former name replaced by what it became, or `None`
/// when it names none. Nothing else in the source changes.
#[must_use]
pub fn rewrite(source: &str) -> Option<String> {
    let found = former_names(source);
    if found.is_empty() {
        return None;
    }
    let mut out = String::with_capacity(source.len());
    let mut at = 0;
    for f in &found {
        out.push_str(&source[at..f.start]);
        out.push_str(f.is);
        at = f.start + f.was.len();
    }
    out.push_str(&source[at..]);
    Some(out)
}

/// The sentence a compile refuses `source` with, or `None` when it names
/// the interface only as it is called now. Each former name once, with the
/// line it is first on and how many places it is in.
#[must_use]
pub fn refusal(source: &str) -> Option<String> {
    let found = former_names(source);
    if found.is_empty() {
        return None;
    }
    let mut names: Vec<(&'static str, &'static str, u32, usize)> = Vec::new();
    for f in &found {
        match names.iter_mut().find(|n| n.0 == f.was) {
            Some(n) => n.3 += 1,
            None => names.push((f.was, f.is, f.line, 1)),
        }
    }
    let listed: Vec<String> = names
        .iter()
        .map(|(was, is, line, count)| {
            let was = if *was == FORMER_PATH_ROOT {
                format!("{FORMER_PATH_ROOT}::")
            } else {
                (*was).to_string()
            };
            let is = if *is == PATH_ROOT {
                format!("{PATH_ROOT}::")
            } else {
                (*is).to_string()
            };
            let places = if *count == 1 {
                format!("line {line}")
            } else {
                format!("{count} places, first on line {line}")
            };
            format!("`{was}` is `{is}` ({places})")
        })
        .collect();
    Some(format!(
        "former-interface-name: this source names the module interface as it was called \
         before 2026-11-16, and nothing accepts those names: {}. Rename them and compile \
         again; `controller rename-module-source <file>` rewrites a source file. A line \
         that must keep one of these words for another reason carries `// {OPT_OUT}`.",
        listed.join("; ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD: &str = r#"use talos_sdk_macros::talos_node;

#[talos_node(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let r = talos::core::http::fetch(&req).map_err(|e| format!("down ({e:?})"))?;
    crate::talos::core::logging::log(talos::core::logging::Level::Info, "ok");
    Ok(input)
}
"#;

    #[test]
    fn a_rust_module_is_rewritten_name_by_name_and_then_names_none() {
        let new = rewrite(OLD).expect("it names the former interface");
        assert_eq!(
            new,
            r#"use aegix_sdk_macros::aegix_node;

#[aegix_node(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let r = aegix::core::http::fetch(&req).map_err(|e| format!("down ({e:?})"))?;
    crate::aegix::core::logging::log(aegix::core::logging::Level::Info, "ok");
    Ok(input)
}
"#
        );
        assert_eq!(rewrite(&new), None);
        assert_eq!(refusal(&new), None);
        assert!(former_names(&new).is_empty());
    }

    #[test]
    fn the_refusal_names_each_former_name_once_with_its_line_and_count() {
        let why = refusal(OLD).expect("a refusal");
        assert!(why.starts_with("former-interface-name:"), "{why}");
        assert!(
            why.contains("`talos_sdk_macros` is `aegix_sdk_macros` (line 1)"),
            "{why}"
        );
        assert!(
            why.contains("`talos_node` is `aegix_node` (2 places, first on line 1)"),
            "{why}"
        );
        assert!(
            why.contains("`talos::` is `aegix::` (3 places, first on line 5)"),
            "{why}"
        );
    }

    /// A word inside a string literal is the module's data, not its code: a
    /// prompt, a field of somebody else's JSON, a message. It is neither
    /// refused nor rewritten, in an ordinary string or a raw one over
    /// several lines.
    #[test]
    fn a_code_name_inside_a_string_literal_is_left() {
        let src = "let field = \"talos_node\";\n\
                   let prompt = r#\"Write a module.\nUse talos_module and talos::core here.\n\"#;\n\
                   let quote = '\"'; let t = talos_node();\n";
        let found = former_names(src);
        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!((found[0].was, found[0].line), ("talos_node", 5));
        let new = rewrite(src).unwrap();
        assert!(new.contains("\"talos_node\""));
        assert!(new.contains("Use talos_module and talos::core here."));
        assert!(new.contains("let t = aegix_node();"));
    }

    /// The package in an import specifier is a string, and the JavaScript
    /// world annotation is a comment: both are found where they are written.
    #[test]
    fn the_package_and_the_js_annotation_are_found_inside_strings_and_remarks() {
        let js = "// @talos-world: http-node\nimport { fetch } from 'talos:core/http';\nconst m = \"talos:core/logging\";\n";
        assert_eq!(
            rewrite(js).unwrap(),
            "// @aegix-world: http-node\nimport { fetch } from 'aegix:core/http';\nconst m = \"aegix:core/logging\";\n"
        );
        let py = "from talos_sdk import talos_module\n\n@talos_module(world=\"http-node\")\ndef run(i):\n    return i\n";
        assert_eq!(
            rewrite(py).unwrap(),
            "from aegix_sdk import aegix_module\n\n@aegix_module(world=\"http-node\")\ndef run(i):\n    return i\n"
        );
    }

    /// Only a whole word: the world marker a compiled module carries, a
    /// name that merely contains one of these, and the bare word `talos`
    /// are not the interface.
    #[test]
    fn a_word_that_only_contains_a_former_name_is_not_one() {
        for src in [
            "static M: &[u8] = b\"x\"; let __talos_world__ = 1;",
            "fn is_talos_node() {} fn talos_node_count() {}",
            "let talos = 1; let x = my_talos::core();",
            "// the Talos platform, talos.memory.op, talos-action:abc",
            "let talos_sdk_macros_dir = 1;",
        ] {
            assert!(former_names(src).is_empty(), "{src}");
            assert_eq!(rewrite(src), None, "{src}");
        }
    }

    #[test]
    fn a_line_that_opts_out_is_neither_found_nor_rewritten() {
        let src = "let a = talos_node; // lint-allow: former-interface-name\nlet b = talos_node;\n";
        let found = former_names(src);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 2);
        assert_eq!(
            rewrite(src).unwrap(),
            "let a = talos_node; // lint-allow: former-interface-name\nlet b = aegix_node;\n"
        );
    }

    /// The rewrite changes the former names and nothing else: every other
    /// byte, a non-ASCII one included, is as it was.
    #[test]
    fn nothing_but_the_names_changes() {
        let src = "// naïve — remark\nuse talos_sdk_macros::talos_module; // ✓\nlet s = \"é talos_module\";\n";
        let new = rewrite(src).unwrap();
        assert_eq!(new.len(), src.len());
        assert_eq!(
            new,
            "// naïve — remark\nuse aegix_sdk_macros::aegix_module; // ✓\nlet s = \"é talos_module\";\n"
        );
    }

    #[test]
    fn a_string_that_is_never_closed_does_not_panic() {
        for src in [
            "let s = \"talos_node",
            "let s = r#\"talos_node",
            "/* talos_node",
            "'",
            "r",
            "br#",
        ] {
            let _ = former_names(src);
            let _ = rewrite(src);
        }
    }
}
