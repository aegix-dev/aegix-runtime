# syntax=docker/dockerfile:1
# The sha256 of the cosign release binary per architecture, from upstream's
# cosign_checksums.txt at COSIGN_VERSION (declared in the runtime stage).
# Global scope, because two stages read them: the runtime stage verifies the
# download against the arch's sum, and the per-arch final stages at the end
# of this file bake the SAME sum into the image as AEGIX_COSIGN_SHA256, the
# pin the worker holds the binary to at boot. Bump COSIGN_VERSION and both
# sums together, here and in controller/Dockerfile.
# docs/engineering-log/packages/2026-11-04-worker-cosign-pin-baked-in.md
ARG COSIGN_SHA256_AMD64=8b24b946dd5809c6bd93de08033bcf6bc0ed7d336b7785787c080f574b89249b
ARG COSIGN_SHA256_ARM64=3b2e2e3854d0356c45fe6607047526ccd04742d20bd44afb5be91fa2a6e7cb4a
# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: Build the worker binary
# ══════════════════════════════════════════════════════════════════════════════
# Base image digest matches controller/Dockerfile so both binaries link
# against the same glibc/OpenSSL versions. Bump together when rotating.
FROM rust:1.99@sha256:15ad267e7a4cb2dce5905c90c76765adb6714945c5ea6d7c82673897a5e4067b AS builder

# All Aegix crates — including the engine + protocol crates folded
# back from the sibling repo in May-2026 — live in this single
# workspace. The Dockerfile no longer needs `additional_contexts` to
# pull the engine from an external path.
WORKDIR /app/talos

# Install mold — a modern linker that is 5-10x faster than GNU ld for the final link step.
RUN apt-get update && apt-get install -y mold && rm -rf /var/lib/apt/lists/*

# Cargo profile — see controller/Dockerfile. `docker` for dev compose,
# `dist` for published images.
ARG CARGO_PROFILE=docker
ENV CARGO_BUILD_JOBS=8
ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold --cfg rustix_use_libc"

# Build-time git SHA + dirty flag passed by docker-compose.yml (and by
# main-publish.yml's build-args, which apply to every matrix service).
# Captured by aegix-build-info (`option_env!`) and composed into the build
# version at compile time so the worker's boot-time self-registration
# reports the deployed commit. MUST mirror controller/Dockerfile exactly —
# if only one side gets the override, a same-tree controller and worker
# report different strings and the build-skew WARN fires on a healthy fleet.
ARG GIT_SHA_OVERRIDE=unknown
ARG GIT_DIRTY_OVERRIDE=false
ENV GIT_SHA_OVERRIDE=${GIT_SHA_OVERRIDE}
ENV GIT_DIRTY_OVERRIDE=${GIT_DIRTY_OVERRIDE}

# Copy the entire workspace in one shot. .dockerignore is the contract:
# it excludes **/target, .env*, private keys, frontend node_modules, .git,
# etc. — keep that file conservative.
#
# Why one COPY instead of the previous two-phase manifest+stub+source
# pattern: that pattern bought slightly tighter Docker layer-cache hits
# at the cost of an explicit hard-coded list of every workspace member,
# which broke the release every time a new talos-* crate was added
# (3+ incidents through r292 — the workspace now has 90+ crates).
# The BuildKit cache mounts on /usr/local/cargo/registry and
# /app/talos/target survive Docker layer-cache invalidation, so cargo's
# incremental compilation still skips unchanged crates on every
# subsequent build. The practical perf delta is small; the maintenance
# burden disappears.
COPY . .

# Final build: cache mounts persist registry + target across builds, so
# only crates with changed source recompile.
# sharing=locked: the controller/migrate/worker images build in PARALLEL
# (compose bake) and share these cache mounts; the default `shared` mode
# lets concurrent cargo processes race the registry unpack ("failed to
# open .cargo-ok … File exists"), and a build killed mid-unpack leaves
# the cache corrupted so every retry fails. Locking serializes the build
# steps — near-free, since cargo's target-dir flock serialized the
# actual compilation anyway.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/talos/target,sharing=locked \
    cargo build --locked --profile "${CARGO_PROFILE}" --bin worker 2>&1 && \
    cp "target/${CARGO_PROFILE}/worker" /app/worker-bin

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: Minimal runtime image
# ══════════════════════════════════════════════════════════════════════════════
# IMPORTANT: The runtime base MUST match the builder's Debian version.
# rust:1.99 is based on Debian trixie (glibc 2.41, OpenSSL 3.5).
# Using bookworm-slim (glibc 2.36, OpenSSL 3.0) causes "GLIBC_2.38 not found"
# and "OPENSSL_3.3.0 not found" crashes at startup.
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132 AS runtime

# `cosign` (~80 MB) is bundled so the worker can verify Sigstore-signed OCI
# template artifacts before executing their WASM. See `verify_oci_signature`
# in worker/src/main.rs and AEGIX_SIGSTORE_REQUIRED env in the Helm chart.
# We pull a pinned release directly from sigstore/cosign rather than apt
# (Debian package lags upstream by months and lacks SLSA-3 attestations).
#
# The downloaded binary is the runtime trust root for every WASM module —
# a poisoned cosign would silently validate attacker-signed artifacts.
# We verify against the upstream-published SHA256 from cosign_checksums.txt
# at the same release tag; bump both COSIGN_SHA256_* (global scope, top of
# this file) in lockstep with COSIGN_VERSION (and controller/Dockerfile's copy).
ARG TARGETARCH
ARG COSIGN_VERSION=v2.4.1
ARG COSIGN_SHA256_AMD64
ARG COSIGN_SHA256_ARM64
RUN case "${TARGETARCH}" in \
      amd64) COSIGN_SHA256="${COSIGN_SHA256_AMD64}" ;; \
      arm64) COSIGN_SHA256="${COSIGN_SHA256_ARM64}" ;; \
      *) echo "unsupported TARGETARCH ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
 && apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl libssl3t64 \
 && curl -fsSL \
      --retry 5 --retry-delay 5 --retry-connrefused \
      --connect-timeout 30 --max-time 180 \
      "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-${TARGETARCH}" \
      -o /usr/local/bin/cosign \
 && echo "${COSIGN_SHA256}  /usr/local/bin/cosign" | sha256sum -c - \
 && chmod +x /usr/local/bin/cosign \
 && /usr/local/bin/cosign version \
 && apt-get purge -y curl && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /app/worker-bin /app/worker

# The talos user has a home (cosign and other Go tools read $HOME for their
# config), and cosign's TUF cache — the Rekor and Fulcio keys it fetches on
# its first keyless verify — goes under /tmp, the one directory the worker
# can write on both deployments: compose's 1777 /tmp, and the chart's emptyDir
# at /tmp under readOnlyRootFilesystem (where the pod runs as uid 10001, not
# talos). Without TUF_ROOT cosign writes $HOME/.sigstore/root, and on
# 2026-11-04 the VPS's first registry-mode run failed every verification with
# "mkdir /home/talos: permission denied": the home did not exist. The
# controller image has the same shape (HOME, caches under /tmp).
# docs/engineering-log/packages/2026-11-04-worker-cosign-cache-dir.md
RUN groupadd -r talos && useradd -r -g talos -u 1000 -d /home/talos talos \
 && mkdir -p /home/talos && chown talos:talos /home/talos /app/worker
USER talos
ENV HOME=/home/talos
ENV TUF_ROOT=/tmp/cosign-tuf
CMD ["/app/worker"]

# ══════════════════════════════════════════════════════════════════════════════
# Stage 3: the cosign pin, baked per architecture
# ══════════════════════════════════════════════════════════════════════════════
# Under AEGIX_SIGSTORE_REQUIRED=required the worker hashes the cosign binary
# at boot and refuses to start on a mismatch, so a swapped-in wrapper that
# always exits 0 cannot pass every other Sigstore gate; without the pin it
# logged the gap on every boot and every pull, and no compose file or chart
# value ever set it. The value is known right here — it is the sum the
# download above was verified against — so the image carries it and no
# deployment keeps a per-image hash by hand. An ENV cannot choose by
# TARGETARCH, so each architecture has a one-line stage and the final FROM
# picks it; the stages add no layer and inherit USER, ENV and CMD from
# `runtime`. A worker run outside this image sets AEGIX_COSIGN_SHA256 itself.
# docs/engineering-log/packages/2026-11-04-worker-cosign-pin-baked-in.md
FROM runtime AS runtime-amd64
ARG COSIGN_SHA256_AMD64
ENV AEGIX_COSIGN_SHA256=${COSIGN_SHA256_AMD64}

FROM runtime AS runtime-arm64
ARG COSIGN_SHA256_ARM64
ENV AEGIX_COSIGN_SHA256=${COSIGN_SHA256_ARM64}

FROM runtime-${TARGETARCH}
