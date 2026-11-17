#!/usr/bin/env python3
"""What a release of the runtime is held to, and the two files made at one.

A release is a tag `v<version>` on a tree whose workspace version, compose
file and changelog all say that version, and three images built from it for
two architectures. This script is the part that can be run anywhere:

    runtime-release.py check [--tag vX.Y.Z] [--repository owner/name]
    runtime-release.py images            the images a release builds: name, Dockerfile,
                                         and the reference compose.yaml pulls it by
    runtime-release.py notes             the changelog's section for this version
    runtime-release.py pin --digests FILE [--out FILE]
    runtime-release.py --self-test

`check` refuses, naming each fault, when

* the workspace has no version, or one that is not `<n>.<n>.<n>` with an
  optional `-<pre-release>`, or `--tag` is not `v<version>`;
* compose.yaml names one of the release's images at another tag, with no tag,
  or under two registry paths; or names any other image without a digest;
* `--repository` is given and compose.yaml's images are not under
  `ghcr.io/<owner>/<name>` (a release is made from the repository whose
  images the compose file pulls);
* CHANGELOG.md's first section is not this version's, or says nothing;
* a crate's manifest gives a `repository` or a `homepage` that is not the
  repository compose.yaml's images are published from (a crate's page would
  send a reader somewhere that is not this tree);
* an image's Dockerfile is missing, or takes a base image by tag alone.

`pin` writes the compose file with each of the release's images held to the
digest that was pushed: `name:tag@sha256:…`. The digests file has one
`<image name> sha256:<64 hex>` per line. An image the compose file names and
the file does not is a refusal; so is a digest that is not one.

`--root DIR` reads another tree (default: the parent of this script's
directory).

It runs on Python 3.9, the interpreter a stock macOS has: `make demo-image`
lists the images with it on a machine that has a container engine and no
toolchain. A test of the repository this script is developed in holds
that.
"""

from __future__ import annotations

import os
import re
import sys
import tempfile

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    # The interpreter a stock macOS has is 3.9. The one thing read from a TOML
    # file here is the workspace version, and `version_line` reads it without
    # a TOML parser; where there is one, `workspace_version` holds the two
    # readings equal.
    tomllib = None

# The images of a release and the file each is built from, at the tree's root.
IMAGES = {
    "worker": "worker/Dockerfile",
    "reference-controller": "aegix-reference-controller/Dockerfile",
    "demo": "scripts/demo/Dockerfile",
}
COMPOSE = "compose.yaml"
CHANGELOG = "CHANGELOG.md"
# What the compose file says until the public repository has a name.
PLACEHOLDER = "ghcr.io/owner/repository"

IMAGE_LINE = re.compile(r"^(\s*image:\s*)(['\"]?)([^'\"\s#]+)(['\"]?)(\s*(?:#.*)?)$")
FROM_LINE = re.compile(r"^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I)
SECTION = re.compile(r"^##\s+\[?v?([0-9]+\.[0-9]+\.[0-9]+[^\]\s]*)\]?(?:\s.*)?$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MANIFEST_LINK = re.compile(r"""^\s*(repository|homepage)\s*=\s*(["'])([^"']*)\2\s*(?:#.*)?$""")


class Refused(Exception):
    pass


def read(root: str, rel: str) -> str | None:
    try:
        with open(os.path.join(root, rel), encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return None


TABLE_LINE = re.compile(r"^\s*\[\[?\s*([^\]]+?)\s*\]\]?\s*(?:#.*)?$")
VERSION_LINE = re.compile(r"""^\s*version\s*=\s*(["'])([^"'\\]+)\1\s*(?:#.*)?$""")


VERSION_SHAPE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?$")


def version_line(text: str) -> str | None:
    """The `version = "…"` line of the `[workspace.package]` table: the one
    spelling this reads. A version written any other way (a dotted key, an
    inline table) is not found, and the caller refuses."""
    table = ""
    for line in text.split("\n"):
        m = TABLE_LINE.match(line)
        if m:
            table = m.group(1)
            continue
        if table == "workspace.package":
            m = VERSION_LINE.match(line)
            if m:
                return m.group(2)
    return None


def workspace_version(root: str) -> str:
    text = read(root, "Cargo.toml")
    if text is None:
        raise Refused("Cargo.toml is missing")
    version = version_line(text)
    if tomllib is not None:
        parsed = tomllib.loads(text).get("workspace", {}).get("package", {}).get("version")
        if parsed != version:
            raise Refused(f"Cargo.toml's workspace version is {parsed!r}, and the `version = \"…\"` line under "
                          f"[workspace.package] reads as {version!r}: write it as that one line")
    if not version:
        raise Refused("Cargo.toml has no `version = \"…\"` line under [workspace.package]")
    # It becomes an image tag and a word on a line a shell reads: digits and
    # dots, with an optional pre-release, and nothing a tag cannot hold.
    if not VERSION_SHAPE.fullmatch(version):
        raise Refused(f"the workspace version {version!r} is not `<n>.<n>.<n>` with an optional `-<pre-release>`")
    return version


def compose_images(text: str) -> list[tuple[int, str]]:
    """(line number, image reference) for every `image:` line."""
    found = []
    for number, line in enumerate(text.split("\n"), 1):
        m = IMAGE_LINE.match(line)
        if m:
            found.append((number, m.group(3)))
    return found


def split_reference(reference: str) -> tuple[str, str, str | None, str | None]:
    """(registry path, name, tag, digest) of `path/name[:tag][@digest]`."""
    rest, _, digest = reference.partition("@")
    path, _, last = rest.rpartition("/")
    name, _, tag = last.partition(":")
    return path, name, tag or None, digest or None


def changelog_sections(text: str) -> list[tuple[str, str]]:
    """(version, body) of each `## <version>` section, in the file's order."""
    sections: list[tuple[str, list[str]]] = []
    for line in text.split("\n"):
        m = SECTION.match(line)
        if m:
            sections.append((m.group(1), []))
        elif line.startswith("## "):
            sections.append(("", []))
        elif sections:
            sections[-1][1].append(line)
    return [(version, "\n".join(body).strip()) for version, body in sections]


def release_images_in_compose(text: str, faults: list[str]) -> list[tuple[int, str, str, str | None, str | None]]:
    """The compose file's lines that name one of the release's images."""
    ours = []
    for number, reference in compose_images(text):
        path, name, tag, digest = split_reference(reference)
        if name in IMAGES and "/" in reference:
            ours.append((number, path, name, tag, digest))
        elif digest is None:
            faults.append(f"{COMPOSE}:{number}: an image that is not this release's is named without a digest")
    return ours


def manifest_links(root: str, home: str) -> list[str]:
    """Every crate manifest's `repository` and `homepage` that is not `home`.

    A crate that was once published from a repository of its own keeps that
    address in its manifest, and a crate's page then sends its reader to a
    tree this one is not."""
    faults = []
    for base, dirs, names in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d != "target" and not d.startswith("."))
        if "Cargo.toml" not in names:
            continue
        rel = os.path.relpath(os.path.join(base, "Cargo.toml"), root).replace(os.sep, "/")
        for number, line in enumerate((read(root, rel) or "").split("\n"), 1):
            m = MANIFEST_LINK.match(line)
            if m and m.group(3).rstrip("/").lower() != home.lower():
                faults.append(f"{rel}:{number}: `{m.group(1)}` is {m.group(3)}; this tree is published from {home}")
    return faults


def check(root: str, tag: str | None, repository: str | None) -> tuple[list[str], list[str], str]:
    """(faults, notes, version)."""
    faults: list[str] = []
    notes: list[str] = []
    version = workspace_version(root)
    if tag is not None and tag != f"v{version}":
        faults.append(f"the tag is {tag}, and the workspace version is {version}: the tag of this tree is v{version}")

    compose = read(root, COMPOSE)
    if compose is None:
        faults.append(f"{COMPOSE} is missing")
    else:
        ours = release_images_in_compose(compose, faults)
        if not ours:
            faults.append(f"{COMPOSE} names none of the release's images ({', '.join(IMAGES)})")
        for number, _path, name, image_tag, _digest in ours:
            if image_tag is None:
                faults.append(f"{COMPOSE}:{number}: {name} has no tag; this tree's is {version}")
            elif image_tag != version:
                faults.append(f"{COMPOSE}:{number}: {name} is at {image_tag}, and the workspace version is {version}")
        paths = sorted({path for _n, path, _name, _t, _d in ours})
        if len(paths) > 1:
            faults.append(f"{COMPOSE} takes the release's images from {len(paths)} registry paths: {', '.join(paths)}")
        elif paths:
            if repository is not None:
                wanted = f"ghcr.io/{repository.lower()}"
                if paths[0] != wanted:
                    faults.append(f"{COMPOSE} takes its images from {paths[0]}; this repository publishes to {wanted}")
            elif paths[0] == PLACEHOLDER:
                notes.append(f"{COMPOSE} names {PLACEHOLDER}, a placeholder: a release is refused until it names "
                             "the repository the images are published from")
            if paths[0] != PLACEHOLDER and paths[0].startswith("ghcr.io/"):
                faults.extend(manifest_links(root, "https://github.com/" + paths[0][len("ghcr.io/"):]))

    changelog = read(root, CHANGELOG)
    if changelog is None:
        faults.append(f"{CHANGELOG} is missing")
    else:
        sections = changelog_sections(changelog)
        if not sections:
            faults.append(f"{CHANGELOG} has no '## <version>' section")
        elif sections[0][0] != version:
            faults.append(f"{CHANGELOG}'s first section is {sections[0][0] or 'not a version'}, "
                          f"and the workspace version is {version}")
        elif not sections[0][1]:
            faults.append(f"{CHANGELOG}'s section for {version} says nothing")

    for name, dockerfile in IMAGES.items():
        text = read(root, dockerfile)
        if text is None:
            faults.append(f"{dockerfile} is missing: the {name} image cannot be built")
            continue
        stages: set[str] = set()
        for number, line in enumerate(text.split("\n"), 1):
            m = FROM_LINE.match(line.strip())
            if not m:
                continue
            base, stage = m.group(1), m.group(2)
            # A stage of the same file, by name or by a name an ARG completes.
            is_stage = base in stages or base.split("-${")[0] in stages or base.split("${")[0].rstrip("-") in stages
            if not is_stage and not re.search(r"@sha256:[0-9a-f]{64}$", base):
                faults.append(f"{dockerfile}:{number}: the base image {base} is not held to a digest")
            if stage:
                stages.add(stage)

    return faults, notes, version


def references(root: str) -> dict[str, str]:
    """The reference each image is pulled by: the compose file's registry path
    (the placeholder when it names none of them) and the workspace version."""
    version = workspace_version(root)
    compose = read(root, COMPOSE) or ""
    paths = [path for _n, path, _name, _t, _d in release_images_in_compose(compose, [])]
    prefix = paths[0] if paths else PLACEHOLDER
    return {name: f"{prefix}/{name}:{version}" for name in IMAGES}


def release_notes(root: str) -> str:
    version = workspace_version(root)
    changelog = read(root, CHANGELOG)
    if changelog is None:
        raise Refused(f"{CHANGELOG} is missing")
    for found, body in changelog_sections(changelog):
        if found == version:
            if not body:
                raise Refused(f"{CHANGELOG}'s section for {version} says nothing")
            return body
    raise Refused(f"{CHANGELOG} has no section for {version}")


def read_digests(path: str) -> dict[str, str]:
    digests: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle.read().split("\n"), 1):
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = line.split()
            if len(parts) != 2 or parts[0] not in IMAGES or not DIGEST.match(parts[1]):
                raise Refused(f"{path}:{number}: expected '<image name> sha256:<64 hex>', "
                              f"with a name from {', '.join(IMAGES)}")
            if parts[0] in digests:
                raise Refused(f"{path}:{number}: {parts[0]} is named twice")
            digests[parts[0]] = parts[1]
    return digests


def pin(root: str, digests: dict[str, str]) -> str:
    compose = read(root, COMPOSE)
    if compose is None:
        raise Refused(f"{COMPOSE} is missing")
    version = workspace_version(root)
    lines = compose.split("\n")
    pinned = 0
    for index, line in enumerate(lines):
        m = IMAGE_LINE.match(line)
        if not m:
            continue
        path, name, tag, digest = split_reference(m.group(3))
        if name not in IMAGES or "/" not in m.group(3):
            continue
        if tag != version or digest is not None:
            raise Refused(f"{COMPOSE}:{index + 1}: {name} is not at the bare tag {version}; run `check` first")
        if name not in digests:
            raise Refused(f"{COMPOSE}:{index + 1}: no digest was given for {name}")
        lines[index] = f"{m.group(1)}{m.group(2)}{path}/{name}:{tag}@{digests[name]}{m.group(4)}{m.group(5)}"
        pinned += 1
    if not pinned:
        raise Refused(f"{COMPOSE} names none of the release's images")
    return "\n".join(lines)


# ── Self-test ───────────────────────────────────────────────────────────────

def self_test() -> int:
    failures: list[str] = []

    def expect(name: str, ok: bool) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            failures.append(name)

    digest = "@sha256:" + "a" * 64
    good = {
        "Cargo.toml": '[workspace]\nmembers = []\n[workspace.package]\nversion = "1.2.3"\n',
        COMPOSE: "services:\n  demo:\n    image: ghcr.io/acme/runtime/demo:1.2.3   # the demo\n"
                 f"  bus:\n    image: nats:2{digest}\n",
        CHANGELOG: "# Changelog\n\n## 1.2.3\n\n- The first one.\n\n## 1.2.2\n\n- Before it.\n",
        "worker/Dockerfile": f"FROM rust:1{digest} AS builder\nFROM debian:slim{digest} AS runtime\n"
                             "FROM runtime AS runtime-amd64\nFROM runtime AS runtime-arm64\nFROM runtime-${TARGETARCH}\n",
        "aegix-reference-controller/Dockerfile": f"FROM rust:1{digest} AS builder\nFROM debian:slim{digest}\n",
        "scripts/demo/Dockerfile": f"FROM rust:1{digest} AS builder\nFROM nats:2{digest} AS nats\nFROM debian:slim{digest}\n",
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
        def faults_of(tag: str | None = None, repository: str | None = None, **changes: str | None) -> list[str]:
            return check(tree(scratch, **changes), tag, repository)[0]

        crate = '[package]\nname = "core"\nversion = "0.3.0"\n'
        expect("a crate's repository that is this tree's passes, whatever its case or last slash",
               faults_of(**{"core/Cargo.toml": crate + 'repository = "https://github.com/Acme/runtime/"\n'}) == [])
        found = faults_of(**{"core/Cargo.toml": crate + 'repository = "https://github.com/acme/engine"\n'
                                                         'homepage = "https://github.com/acme/engine"   # its own\n'})
        expect("a crate's repository and homepage that are another repository's are each refused, by file and line",
               len(found) == 2 and found[0].startswith("core/Cargo.toml:4: `repository` is https://github.com/acme/engine")
               and found[1].startswith("core/Cargo.toml:5: `homepage`") and "https://github.com/acme/runtime" in found[0])
        expect("a manifest in a build directory is not read",
               faults_of(**{"target/package/core/Cargo.toml": crate + 'repository = "https://github.com/acme/engine"\n'}) == [])
        expect("with the placeholder in the compose file there is no repository to hold a manifest to",
               faults_of(**{COMPOSE: f"services:\n  demo:\n    image: {PLACEHOLDER}/demo:1.2.3\n",
                            "core/Cargo.toml": crate + 'repository = "https://github.com/acme/engine"\n'}) == [])

        def refused(name: str, needle: str, tag: str | None = None, repository: str | None = None,
                    **changes: str | None) -> None:
            found = faults_of(tag, repository, **changes)
            expect(name, len(found) == 1 and needle in found[0])

        expect("a tree whose three files agree is accepted", faults_of() == [])
        expect("and with its own tag and repository", faults_of("v1.2.3", "Acme/Runtime") == [])
        refused("a tag that is not the workspace version is refused", "the tag is v1.2.4", tag="v1.2.4")
        refused("a tag without the v is refused", "the tag is 1.2.3", tag="1.2.3")
        refused("a compose file at another tag is refused", "demo is at 1.2.2",
                **{COMPOSE: good[COMPOSE].replace("demo:1.2.3", "demo:1.2.2")})
        refused("a compose file with no tag is refused", "demo has no tag",
                **{COMPOSE: good[COMPOSE].replace("demo:1.2.3", "demo")})
        refused("a release image under another repository is refused", "this repository publishes to ghcr.io/acme/other",
                repository="acme/other")
        refused("release images under two registry paths are refused", "2 registry paths",
                **{COMPOSE: good[COMPOSE] + "  worker:\n    image: ghcr.io/elsewhere/runtime/worker:1.2.3\n"})
        refused("another image without a digest is refused", "without a digest",
                **{COMPOSE: good[COMPOSE].replace(digest, "")})
        refused("a compose file with none of the release's images is refused", "names none of the release's images",
                **{COMPOSE: f"services:\n  bus:\n    image: nats:2{digest}\n"})
        refused("a missing compose file is refused", "compose.yaml is missing", **{COMPOSE: None})
        refused("a changelog whose first section is an older version is refused", "first section is 1.2.2",
                **{CHANGELOG: "## 1.2.2\n\n- Before it.\n"})
        refused("a changelog section that says nothing is refused", "says nothing",
                **{CHANGELOG: "## 1.2.3\n\n## 1.2.2\n\n- Before it.\n"})
        refused("a changelog with an unreleased section on top is refused", "first section is not a version",
                **{CHANGELOG: "## Unreleased\n\n- Soon.\n\n## 1.2.3\n\n- The first one.\n"})
        expect("a bracketed, dated heading is this version's",
               faults_of(**{CHANGELOG: "## [1.2.3] - 2026-01-01\n\n- The first one.\n"}) == [])
        refused("a missing Dockerfile is refused", "scripts/demo/Dockerfile is missing", **{"scripts/demo/Dockerfile": None})
        refused("a base image by tag alone is refused", "worker/Dockerfile:2: the base image debian:slim",
                **{"worker/Dockerfile": good["worker/Dockerfile"].replace(f"debian:slim{digest}", "debian:slim")})
        placeholder = tree(scratch, **{COMPOSE: good[COMPOSE].replace("ghcr.io/acme/runtime", PLACEHOLDER)})
        expect("the placeholder registry path is a note without a repository, and a fault with one",
               check(placeholder, None, None)[0] == [] and len(check(placeholder, None, None)[1]) == 1
               and len(check(placeholder, None, "acme/runtime")[0]) == 1)
        try:
            workspace_version(tree(scratch, **{"Cargo.toml": "[workspace]\nmembers = []\n"}))
            expect("a workspace with no version is refused", False)
        except Refused:
            expect("a workspace with no version is refused", True)
        # The version is read without a TOML parser, so that an interpreter
        # older than 3.11 can list the images.
        expect("the version is the [workspace.package] line, whatever else is called version",
               version_line('[package]\nversion = "9.9.9"\n[workspace.package]\n# version = "8.8.8"\n'
                            'edition = "2021"\nversion = "1.2.3"  # this one\n[workspace.dependencies]\n'
                            'version = "7.7.7"\n') == "1.2.3"
               and version_line("[ workspace.package ]\nversion = '1.2.3'\n") == "1.2.3")
        expect("a version written any other way is not read",
               version_line('[workspace]\npackage = { version = "1.2.3" }\n') is None
               and version_line('[workspace]\npackage.version = "1.2.3"\n') is None
               and version_line('[workspace.package]\nversion.workspace = true\n') is None)
        for bad in ("1.2", "1.2.3 x", "1.2.3+build", "v1.2.3", "1.2.3/../x", "1.2.3-"):
            try:
                workspace_version(tree(scratch, **{"Cargo.toml": f'[workspace.package]\nversion = "{bad}"\n'}))
                expect(f"a version of {bad!r} is refused", False)
            except Refused:
                expect(f"a version of {bad!r} is refused", True)
        expect("a pre-release version is read",
               workspace_version(tree(scratch, **{"Cargo.toml": '[workspace.package]\nversion = "1.2.3-rc.1"\n'})) == "1.2.3-rc.1")
        if tomllib is not None:
            try:
                workspace_version(tree(scratch, **{"Cargo.toml": '[workspace]\npackage = { version = "1.2.3" }\n'}))
                expect("a version the line reading misses and a TOML parser finds is refused", False)
            except Refused as refusal:
                expect("a version the line reading misses and a TOML parser finds is refused",
                       "write it as that one line" in str(refusal))

        root = tree(scratch)
        expect("an image's reference is the compose file's registry path and the workspace version",
               references(root)["worker"] == "ghcr.io/acme/runtime/worker:1.2.3"
               and references(tree(scratch, **{COMPOSE: None}))["demo"] == f"{PLACEHOLDER}/demo:1.2.3")
        expect("the notes are the version's section and nothing else", release_notes(root) == "- The first one.")
        made = pin(root, {"demo": "sha256:" + "b" * 64})
        expect("pin adds the digest after the tag and keeps the rest of the line",
               f"    image: ghcr.io/acme/runtime/demo:1.2.3@sha256:{'b' * 64}   # the demo" in made.split("\n")
               and f"    image: nats:2{digest}" in made.split("\n"))
        for name, digests, needle in (
            ("pin refuses an image with no digest given", {}, "no digest was given for demo"),
        ):
            try:
                pin(root, digests)
                expect(name, False)
            except Refused as refusal:
                expect(name, needle in str(refusal))
        try:
            pin(tree(scratch, **{COMPOSE: good[COMPOSE].replace("demo:1.2.3", "demo:1.2.2")}), {"demo": "sha256:" + "b" * 64})
            expect("pin refuses a compose file that is not at the version", False)
        except Refused:
            expect("pin refuses a compose file that is not at the version", True)
        listing = os.path.join(scratch, "digests")
        for name, text, ok in (
            ("a digests file is read", f"# pushed\ndemo sha256:{'c' * 64}\nworker sha256:{'d' * 64}\n", True),
            ("a digest that is not one is refused", "demo sha256:abc\n", False),
            ("an image the release does not build is refused", f"other sha256:{'c' * 64}\n", False),
            ("an image named twice is refused", f"demo sha256:{'c' * 64}\ndemo sha256:{'d' * 64}\n", False),
        ):
            with open(listing, "w", encoding="utf-8") as handle:
                handle.write(text)
            try:
                got = read_digests(listing)
                expect(name, ok and (len(got) == 2))
            except Refused:
                expect(name, not ok)

    if failures:
        print(f"✗ runtime-release self-test: {len(failures)} failed", file=sys.stderr)
        return 1
    print("✓ runtime-release self-test passed")
    return 0


def main() -> int:
    args = sys.argv[1:]
    if args == ["--self-test"]:
        return self_test()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    options: dict[str, str] = {}
    positional: list[str] = []
    takes_value = {"--root", "--tag", "--repository", "--digests", "--out"}
    while args:
        arg = args.pop(0)
        if arg in takes_value:
            if not args:
                print(f"{arg} needs a value", file=sys.stderr)
                return 2
            options[arg] = args.pop(0)
        elif arg in ("-h", "--help"):
            print(__doc__)
            return 0
        else:
            positional.append(arg)
    root = options.get("--root", root)
    if len(positional) != 1 or positional[0] not in ("check", "images", "notes", "pin"):
        print(__doc__, file=sys.stderr)
        return 2
    command = positional[0]
    try:
        if command == "images":
            pulled_by = references(root)
            for name, dockerfile in IMAGES.items():
                print(f"{name} {dockerfile} {pulled_by[name]}")
            return 0
        if command == "notes":
            print(release_notes(root))
            return 0
        if command == "pin":
            if "--digests" not in options:
                print("pin needs --digests FILE", file=sys.stderr)
                return 2
            made = pin(root, read_digests(options["--digests"]))
            if "--out" in options:
                with open(options["--out"], "w", encoding="utf-8") as handle:
                    handle.write(made)
            else:
                sys.stdout.write(made)
            return 0
        faults, notes, version = check(root, options.get("--tag"), options.get("--repository"))
    except Refused as refusal:
        print(f"✗ {refusal}", file=sys.stderr)
        return 1
    for note in notes:
        print(f"  note: {note}")
    if faults:
        print(f"✗ not a release of {version}: {len(faults)}", file=sys.stderr)
        for fault in faults:
            print(f"  ✗ {fault}", file=sys.stderr)
        return 1
    print(f"✓ the workspace, {COMPOSE} and {CHANGELOG} agree on {version}; "
          f"{len(IMAGES)} images, each from a Dockerfile whose base images are held to a digest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
