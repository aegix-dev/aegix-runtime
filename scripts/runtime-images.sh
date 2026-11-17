#!/usr/bin/env bash
# Build a release's images on this machine, and run each one once.
#
#   scripts/runtime-images.sh build [--platform linux/ARCH] [--profile docker|dist] [image…]
#   scripts/runtime-images.sh smoke [image…]
#
# The images, the Dockerfile each is built from and the reference each is
# tagged with come from scripts/runtime-release.py, the one list. With no image
# named, every one is built or run. An image is built for the architecture of
# the machine unless --platform names another, and an image whose operating
# system and architecture are not the ones asked for is refused: an engine
# that cannot build for a platform has been seen to build for its own and tag
# the result as the other.
#
# `build` tags each image with the reference compose.yaml pulls it by, so a
# `docker compose run` after it uses what was just built. Nothing is pushed
# here; a release's images are pushed by .github/workflows/release.yml.
#
# `smoke` starts each image with no network:
#   worker                it must get as far as refusing to start without its
#                         key (the binary loads and runs; nothing is missing
#                         from the image)
#   reference-controller  it must mint a key pair
#   demo                  the whole refusal demo, in both postures, started as
#                         compose.yaml starts it: a read-only root and every
#                         capability dropped
#
# The engine is docker, or podman where there is no docker;
# AEGIX_CONTAINER_ENGINE names another.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
die() { printf '✗ %s\n' "$*" >&2; exit 1; }

ENGINE="${AEGIX_CONTAINER_ENGINE:-}"
if [ -z "$ENGINE" ]; then
    if command -v docker >/dev/null 2>&1; then ENGINE=docker
    elif command -v podman >/dev/null 2>&1; then ENGINE=podman
    else die "no docker and no podman on PATH (AEGIX_CONTAINER_ENGINE names another engine)"
    fi
fi

COMMAND="${1:-}"
[ $# -gt 0 ] && shift
PLATFORM=""; PROFILE="docker"; WANTED=()
while [ $# -gt 0 ]; do
    case "$1" in
        --platform) PLATFORM="${2:-}"; [ -n "$PLATFORM" ] || die "--platform needs a value"; shift 2 ;;
        --profile) PROFILE="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*) die "unknown argument: $1" ;;
        *) WANTED+=( "$1" ); shift ;;
    esac
done
if [ "$PROFILE" != docker ] && [ "$PROFILE" != dist ]; then die "--profile is docker or dist"; fi
if [ "$COMMAND" != build ] && [ "$COMMAND" != smoke ]; then
    sed -n '2,29p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2
    exit 2
fi

# name, Dockerfile, reference: one line per image.
LISTING="$(python3 -I "$ROOT/scripts/runtime-release.py" --root "$ROOT" images)" \
    || die "scripts/runtime-release.py could not list the images"
for name in ${WANTED[@]+"${WANTED[@]}"}; do
    grep -q "^$name " <<<"$LISTING" || die "$name is not an image of a release ($(cut -d' ' -f1 <<<"$LISTING" | tr '\n' ' '))"
done
wanted() {
    [ "${#WANTED[@]}" -eq 0 ] && return 0
    local name
    for name in "${WANTED[@]}"; do [ "$name" = "$1" ] && return 0; done
    return 1
}

SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/runtime-images.XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

build_one() { # build_one <name> <dockerfile> <reference>
    local name="$1" dockerfile="$2" reference="$3" id built
    local args=( build --file "$ROOT/$dockerfile" --build-arg "CARGO_PROFILE=$PROFILE"
                 --iidfile "$SCRATCH/$name.iid" --tag "$reference" )
    [ -z "$PLATFORM" ] || args+=( --platform "$PLATFORM" )
    printf '▶ %s: %s build of %s\n' "$name" "$ENGINE" "$dockerfile"
    "$ENGINE" "${args[@]}" "$ROOT" || die "$name did not build"
    id="$(cat "$SCRATCH/$name.iid")"
    built="$("$ENGINE" image inspect --format '{{.Os}}/{{.Architecture}}' "$id")"
    if [ -n "$PLATFORM" ] && [ "$built" != "$PLATFORM" ]; then
        "$ENGINE" image rm "$reference" >/dev/null 2>&1 || true
        die "$name was built for $built, and $PLATFORM was asked for; the tag is removed"
    fi
    printf '✓ %s  %s  %s  %s\n' "$name" "$built" "${id#sha256:}" "$reference"
}

smoke_one() { # smoke_one <name> <reference>
    local name="$1" reference="$2" out status=0
    "$ENGINE" image inspect "$reference" >/dev/null 2>&1 \
        || die "$reference is not on this machine (scripts/runtime-images.sh build $name)"
    printf '▶ %s: %s\n' "$name" "$reference"
    if [ "$name" = worker ]; then
        out="$("$ENGINE" run --rm --network none "$reference" 2>&1)" || status=$?
        [ "$status" -ne 0 ] || die "the worker started with no key and no bus"
        grep -q 'WORKER_SHARED_KEY' <<<"$out" \
            || { printf '%s\n' "$out" | tail -5 >&2; die "the worker did not get as far as asking for its key"; }
        printf '✓ worker: it loads, and refuses to start without its key\n'
    elif [ "$name" = reference-controller ]; then
        out="$("$ENGINE" run --rm --network none "$reference" keygen --out-dir /tmp/keys 2>&1)" \
            || { printf '%s\n' "$out" | tail -5 >&2; die "the reference controller did not mint a key pair"; }
        printf '✓ reference-controller: it mints a key pair\n'
    else
        # As compose.yaml starts it.
        "$ENGINE" run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL \
            --security-opt no-new-privileges "$reference" \
            || die "the demo image's run failed"
        printf '✓ demo: both postures, with no network, no capability and a read-only root\n'
    fi
}

while read -r name dockerfile reference; do
    wanted "$name" || continue
    if [ "$COMMAND" = build ]; then
        build_one "$name" "$dockerfile" "$reference"
    else
        smoke_one "$name" "$reference" </dev/null
    fi
done <<<"$LISTING"
