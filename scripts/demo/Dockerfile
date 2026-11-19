# syntax=docker/dockerfile:1
# The refusal demo in one image: a message bus, the reference controller, one
# worker and the hostile module, already built. Running it needs no toolchain,
# no account and no network:
#
#   docker run --rm --network none <image>                 both postures
#   docker run --rm --network none <image> --posture worker-identity
#
# Built from the workspace root, for the architecture it is built on:
#
#   docker build -f scripts/demo/Dockerfile -t demo .
#
# The run is scripts/reference-controller-demo.sh, the script `make demo`
# runs from a checkout. docs/reference-controller.md says what it shows.

# ══════════════════════════════════════════════════════════════════════════════
# Stage 1: build the three binaries and compile the module
# ══════════════════════════════════════════════════════════════════════════════
# The base image, linker and flags of worker/Dockerfile and
# aegix-reference-controller/Dockerfile: the binaries in this image are built
# as the ones in those images are.
FROM rust:1.99@sha256:15ad267e7a4cb2dce5905c90c76765adb6714945c5ea6d7c82673897a5e4067b AS builder

WORKDIR /app/talos

RUN apt-get update && apt-get install -y mold && rm -rf /var/lib/apt/lists/*

# What a module is compiled with, at the version the platform compiles with.
# The registry sources the install fetched are removed in the same step: they
# are not needed again and would stay in the layer.
RUN rustup target add wasm32-wasip2 \
 && cargo install cargo-component --version 0.21.1 --locked \
 && rm -rf /usr/local/cargo/registry

ARG CARGO_PROFILE=docker
ENV CARGO_BUILD_JOBS=8
ENV RUSTFLAGS="-C link-arg=-fuse-ld=mold --cfg rustix_use_libc"

COPY . .

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/talos/target,sharing=locked \
    cargo build --locked --profile "${CARGO_PROFILE}" \
        --bin worker --bin aegix-reference-controller --bin aegix-e2e-probe 2>&1 && \
    mkdir -p /app/out && \
    cp "target/${CARGO_PROFILE}/worker" "target/${CARGO_PROFILE}/aegix-reference-controller" \
       "target/${CARGO_PROFILE}/aegix-e2e-probe" /app/out/

# The module goes through the compile path a controller uses
# (aegix-compilation), not a build of its own. Its flags are the compile
# path's: the linker flags above are for the host binaries.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/app/talos/target,sharing=locked \
    cargo run --locked --profile "${CARGO_PROFILE}" -p aegix-compilation --example compile_module -- \
        scripts/demo/hostile-module.rs agent-node /app/out/hostile.wasm 2>&1

# ══════════════════════════════════════════════════════════════════════════════
# Stage 2: the message bus
# ══════════════════════════════════════════════════════════════════════════════
# nats-server is one static binary. The image is the one the platform's
# compose files pin.
FROM nats:2.10-alpine@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927 AS nats

# ══════════════════════════════════════════════════════════════════════════════
# Stage 3: the image
# ══════════════════════════════════════════════════════════════════════════════
FROM debian:trixie-slim@sha256:d7e12182ce18b85b93007c1dedf31f2d29e01ccf3182cc4017c709b6259bc132

# What the run's script calls: jq, python3 and uuidgen. python3 is the whole
# standard library, not python3-minimal: the judge computes an HMAC, and the
# minimal package has no hmac module. uuid-runtime asks for
# something that can create its system user; named here, the small one is
# taken, and left to apt, the whole of systemd is.
#
# ca-certificates is for the worker: it builds its HTTP client when a job
# starts and will not build one over an empty set of roots, though in this
# image, with no network, it never opens a connection.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates jq python3 uuid-runtime systemd-standalone-sysusers \
 && rm -rf /var/lib/apt/lists/*

COPY --from=nats /usr/local/bin/nats-server /usr/local/bin/nats-server
COPY --from=builder /app/out/ /opt/talos/

# The script, what it starts the bus with, and the source files whose lines
# it names when it says where a refusal was decided. The files are named one
# by one, and never as a directory: an image built from a larger tree than
# this one then carries nothing of it. Where this Dockerfile's tests run,
# they hold the list to what the two scripts read.
WORKDIR /talos
COPY scripts/reference-controller-demo.sh scripts/nats-password.sh scripts/
COPY scripts/demo/refusal-judge.sh scripts/demo/hostile-module.rs scripts/demo/
COPY deploy/nats/nats-shared-worker.conf deploy/nats/worker-permissions.conf deploy/nats/
COPY aegix-reference-controller/src/serve.rs aegix-reference-controller/src/
COPY aegix-rpc-gates/src/dispatch_binding.rs aegix-rpc-gates/src/
COPY worker/src/job_execution.rs worker/src/
COPY aegix-wasm-host/src/context.rs aegix-wasm-host/src/
COPY aegix-wasm-host/src/host/vault.rs aegix-wasm-host/src/host/egress_admission.rs \
     aegix-wasm-host/src/host/egress.rs aegix-wasm-host/src/host/

RUN groupadd -r talos && useradd -r -g talos -u 1000 -d /home/talos talos \
 && mkdir -p /home/talos && chown talos:talos /home/talos
USER talos
ENV HOME=/home/talos
ENV AEGIX_DEMO_CONTROLLER_BIN=/opt/talos/aegix-reference-controller \
    AEGIX_DEMO_WORKER_BIN=/opt/talos/worker \
    AEGIX_DEMO_PROBE_BIN=/opt/talos/aegix-e2e-probe \
    AEGIX_DEMO_HOSTILE_WASM=/opt/talos/hostile.wasm

ENTRYPOINT ["bash", "/talos/scripts/reference-controller-demo.sh", "--no-build"]
CMD ["--posture", "both"]
