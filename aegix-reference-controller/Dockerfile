# syntax=docker/dockerfile:1
# The reference controller's image: one binary and nothing it does not need.
# Built from the workspace root, for the architecture it is built on:
#
#   docker build -f aegix-reference-controller/Dockerfile -t reference-controller .
#
# docs/reference-controller.md says what the binary does and what it reads.

# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: build the binary
# ══════════════════════════════════════════════════════════════════════════════
# The same base image, linker and flags as worker/Dockerfile, so the two
# binaries of one release are built by one compiler against one libc.
# scripts/check-rust-pins.py holds the release to rust-toolchain.toml.
FROM rust:1.99@sha256:15ad267e7a4cb2dce5905c90c76765adb6714945c5ea6d7c82673897a5e4067b AS builder

WORKDIR /app/talos

RUN apt-get update && apt-get install -y mold && rm -rf /var/lib/apt/lists/*

# `docker` for a build on a developer's machine, `dist` for a published image.
ARG CARGO_PROFILE=docker
ENV CARGO_BUILD_JOBS=8
ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold --cfg rustix_use_libc"

COPY . .

# The cache mounts are the ones worker/Dockerfile names, so the images of one
# release share one registry and one build directory. sharing=locked: two
# builds at once would otherwise race the registry unpack.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/talos/target,sharing=locked \
    cargo build --locked --profile "${CARGO_PROFILE}" --bin aegix-reference-controller 2>&1 && \
    cp "target/${CARGO_PROFILE}/aegix-reference-controller" /app/talos-reference-controller-bin

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: the image
# ══════════════════════════════════════════════════════════════════════════════
# The runtime base is the builder's Debian release (trixie): an older one
# lacks the glibc the binary was linked against.
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

COPY --from=builder /app/talos-reference-controller-bin /usr/local/bin/aegix-reference-controller

# The controller's files are its user's alone: it refuses a secrets file or a
# control directory that anyone else can read or enter. /var/lib/talos is
# where the default command keeps the control directory, so a client command
# run in the same container (`docker exec`) finds it.
RUN groupadd -r talos && useradd -r -g talos -u 1000 -d /home/talos talos \
 && mkdir -p /home/talos /var/lib/talos /etc/talos \
 && chown talos:talos /home/talos /var/lib/talos
USER talos
ENV HOME=/home/talos
ENV AEGIX_REFERENCE_CONTROL_DIR=/var/lib/talos/control
WORKDIR /var/lib/talos

ENTRYPOINT ["aegix-reference-controller"]
CMD ["serve", "--config", "/etc/talos/controller.json"]
