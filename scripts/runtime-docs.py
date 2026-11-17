#!/usr/bin/env python3
"""What the tree's documents are held to.

A document is a Markdown file anywhere in the tree. A document that names
something the tree does not have sends its reader looking for it, so each of
these is a fault, named by file and line:

    runtime-docs.py check
    runtime-docs.py --self-test

* README.md at the root is longer than 100 lines.
* A link to a file leads nowhere.
* A document names a path under one of the tree's directories, or under a
  `talos-…` crate, and the tree has no such file or directory. (A path with a
  `target` directory in it is something a build makes, and is not looked for;
  nor is one written with `*`, `<` or `{` after it.)
* A command in a code span or a code block runs `make <target>` and the
  Makefile has no such target.
* A document names a Rust file and, after a comma, something declared in it
  (`path/to/file.rs`, `name`, or `path/to/file.rs`, `one`, and `another`), and
  the file declares nothing of that name.
  This is how a document says where a rule is decided, so the rule's reader
  lands on it.

`--root DIR` reads another tree (default: the parent of this script's
directory).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

README = "README.md"
README_LINES = 100
# Never part of the tree: what git, a build and a package manager make.
PRUNED = {".git", "target", "node_modules"}

LINK = re.compile(r"\[[^\]\n]*\]\(([^)\s]+)\)")
SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")
FENCE = re.compile(r"^\s*(```|~~~)")
SPAN = re.compile(r"`([^`\n]+)`")
MAKE = re.compile(r"(?:^|[\s;&|(])make\s+([a-z][a-z0-9-]*)")
RULE = re.compile(r"(?m)^([A-Za-z0-9][A-Za-z0-9_.-]*)\s*:(?!=)")
DECLARED_IN = re.compile(r"`([^`\s]+\.rs)`((?:,\s+(?:and\s+)?`[A-Za-z_][A-Za-z0-9_]*`)+)")
NAME = re.compile(r"`([A-Za-z_][A-Za-z0-9_]*)`")
DECLARATION = r"\b(?:fn|struct|enum|union|const|static|type|trait|mod|macro_rules!)\s+{name}\b"


def documents(root: str) -> list[str]:
    found = []
    for directory, names, files in os.walk(root):
        names[:] = sorted(n for n in names if n not in PRUNED)
        for name in sorted(files):
            if name.endswith(".md"):
                found.append(os.path.relpath(os.path.join(directory, name), root).replace(os.sep, "/"))
    return found


def top_directories(root: str) -> list[str]:
    return sorted(n for n in os.listdir(root) if n not in PRUNED and os.path.isdir(os.path.join(root, n)))


def path_pattern(tops: list[str]) -> re.Pattern[str]:
    heads = "|".join([re.escape(t) for t in tops] + [r"(?:aegix|talos)[-_][a-z0-9_-]+"])
    return re.compile(r"(?<![A-Za-z0-9_./-])((?:" + heads + r")/[A-Za-z0-9_./-]*[A-Za-z0-9_])")


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def code_of(text: str) -> list[tuple[int, str]]:
    """Every piece of code in a document: (line, text) for each line of a
    fenced block and each code span outside one."""
    found, fenced = [], False
    for number, line in enumerate(text.split("\n"), 1):
        if FENCE.match(line):
            fenced = not fenced
        elif fenced:
            found.append((number, line))
        else:
            found.extend((number, span) for span in SPAN.findall(line))
    return found


def check(root: str) -> tuple[list[str], int]:
    faults: list[str] = []
    docs = documents(root)
    named = path_pattern(top_directories(root))
    targets: set[str] | None = None
    makefile = os.path.join(root, "Makefile")
    if os.path.isfile(makefile):
        with open(makefile, encoding="utf-8") as handle:
            targets = set(RULE.findall(handle.read()))

    def exists(rel: str) -> bool:
        full = os.path.normpath(os.path.join(root, rel))
        return (full == root or full.startswith(root + os.sep)) and os.path.exists(full)

    for doc in docs:
        with open(os.path.join(root, doc), encoding="utf-8") as handle:
            text = handle.read()
        if doc == README and text.count("\n") > README_LINES:
            faults.append(f"{doc}: {text.count(chr(10))} lines; the tree's first page is at most {README_LINES}")

        linked: list[tuple[int, int]] = []
        for m in LINK.finditer(text):
            linked.append(m.span(1))
            target = m.group(1).split("#", 1)[0]
            if not target or SCHEME.match(target):
                continue
            if not exists(os.path.join(os.path.dirname(doc), target)):
                faults.append(f"{doc}:{line_of(text, m.start())}: the link to {target} leads nowhere")

        for m in named.finditer(text):
            path = m.group(1)
            if text[m.end():m.end() + 1] in ("*", "<", "{") or "target" in path.split("/"):
                continue
            if any(start <= m.start() < end for start, end in linked):
                continue  # a link's target is read above, from the document's own directory
            if not exists(path):
                faults.append(f"{doc}:{line_of(text, m.start())}: names {path}, which this tree does not have")

        for number, code in code_of(text):
            for target in MAKE.findall(code):
                if targets is None or target not in targets:
                    faults.append(f"{doc}:{number}: runs `make {target}`, and the Makefile has no such target")

        for m in DECLARED_IN.finditer(text):
            path = m.group(1)
            if not exists(path) or not os.path.isfile(os.path.join(root, path)):
                continue  # a path the tree lacks is already a fault above, or is not one of its paths
            with open(os.path.join(root, path), encoding="utf-8") as handle:
                source = handle.read()
            for name in NAME.findall(m.group(2)):
                if not re.search(DECLARATION.format(name=re.escape(name)), source):
                    faults.append(f"{doc}:{line_of(text, m.start())}: {path} declares no `{name}`")
    return faults, len(docs)


def self_test() -> int:
    failures: list[str] = []

    def expect(name: str, ok: bool) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            failures.append(name)

    good = {
        "README.md": "# A tree\n\nRun `make demo`. Read [the model](docs/model.md) and `crate-a/src/lib.rs`.\n"
                     "The rule is in `crate-a/src/lib.rs`, `gate`.\n\n```bash\nmake demo\n```\n",
        "docs/model.md": "# Model\n\nBack to [the first page](../README.md#a-tree), or [elsewhere](https://example.com/docs/x.md).\n"
                         "A build leaves `crate-a/target/debug/thing`. Any of `docs/<name>.md`. To make sure, read on.\n",
        "crate-a/src/lib.rs": "pub async fn gate() {}\nconst LIMIT: u32 = 1;\n",
        "Makefile": "demo: ## run it\n\techo demo\nVERSION := 1\n",
    }

    def tree(scratch: str, **changes: str | None) -> str:
        root = tempfile.mkdtemp(dir=scratch)
        for rel, text in {**good, **changes}.items():
            if text is None:
                continue
            full = os.path.join(root, rel)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as handle:
                handle.write(text)
        return root

    with tempfile.TemporaryDirectory() as scratch:
        scratch = os.path.realpath(scratch)

        def refused(name: str, needle: str, **changes: str | None) -> None:
            found = check(tree(scratch, **changes))[0]
            expect(name, len(found) == 1 and needle in found[0])

        faults, count = check(tree(scratch))
        expect("a tree whose documents name only what it has is accepted", faults == [] and count == 2)
        refused("a first page of 101 lines is refused", "README.md: 101 lines",
                **{"README.md": good["README.md"] + "more\n" * (101 - good["README.md"].count("\n"))})
        expect("and one of exactly 100 is not",
               check(tree(scratch, **{"README.md": good["README.md"] + "more\n" * (100 - good["README.md"].count("\n"))}))[0] == [])
        refused("a link that leads nowhere is refused", "README.md:3: the link to docs/gone.md leads nowhere",
                **{"README.md": good["README.md"].replace("(docs/model.md)", "(docs/gone.md)")})
        refused("a link is read from the document's own directory", "docs/model.md:3: the link to README.md leads nowhere",
                **{"docs/model.md": good["docs/model.md"].replace("../README.md", "README.md")})
        refused("a link out of the tree is refused", "leads nowhere",
                **{"docs/model.md": good["docs/model.md"].replace("../README.md", "../../README.md")})
        refused("a named file the tree lacks is refused", "README.md:3: names crate-a/src/gone.rs",
                **{"README.md": good["README.md"].replace("and `crate-a/src/lib.rs`", "and `crate-a/src/gone.rs`")})
        refused("a path under a crate the tree does not carry is refused", "names talos-elsewhere/src/lib.rs",
                **{"docs/model.md": good["docs/model.md"] + "See talos-elsewhere/src/lib.rs:12.\n"})
        refused("a make target the Makefile lacks is refused", "README.md:7: runs `make demos`",
                **{"README.md": good["README.md"].replace("```bash\nmake demo\n", "```bash\nmake demos\n")})
        refused("a make target in a code span is read too", "README.md:3: runs `make up`",
                **{"README.md": good["README.md"].replace("`make demo`", "`make up`")})
        refused("with no Makefile every make target is refused", "runs `make demo`",
                **{"Makefile": None, "README.md": good["README.md"].replace("\n```bash\nmake demo\n```\n", "")})
        refused("a variable assignment is not a target", "runs `make version`",
                **{"docs/model.md": good["docs/model.md"] + "Then `make version`.\n", "Makefile": good["Makefile"] + "version := 2\n"})
        refused("a declaration the file does not make is refused", "README.md:4: crate-a/src/lib.rs declares no `gates`",
                **{"README.md": good["README.md"].replace("`gate`", "`gates`")})
        refused("so is the second name after a file", "crate-a/src/lib.rs declares no `gone`",
                **{"README.md": good["README.md"].replace("`gate`.", "`gate`, and `gone`.")})
        expect("and two names the file declares are accepted",
               check(tree(scratch, **{"README.md": good["README.md"].replace("`gate`.", "`gate`, and `LIMIT`.")}))[0] == [])
        expect("a constant is a declaration",
               check(tree(scratch, **{"README.md": good["README.md"].replace("`gate`", "`LIMIT`")}))[0] == [])
        expect("a build directory is not read for documents",
               check(tree(scratch, **{"target/doc/x.md": "See [nothing](gone.md).\n"}))[0] == [])

    if failures:
        print(f"✗ runtime-docs self-test: {len(failures)} failed", file=sys.stderr)
        return 1
    print("✓ runtime-docs self-test passed")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if len(args) >= 2 and args[0] == "--root":
        root, args = os.path.abspath(args[1]), args[2:]
    if args != ["check"]:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    root = os.path.realpath(root)
    faults, count = check(root)
    for fault in faults:
        print(f"✗ {fault}", file=sys.stderr)
    if faults:
        print(f"✗ {len(faults)} in {count} documents", file=sys.stderr)
        return 1
    print(f"✓ {count} documents name only what this tree has")
    return 0


if __name__ == "__main__":
    sys.exit(main())
