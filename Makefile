# This tree is made from a private repository by its export script
# (PROVENANCE.json names the commit). Changes are made there.

.DEFAULT_GOAL := help
.PHONY: help check lint test demo test-e2e-reference images images-smoke demo-image release-check docs-check

help: ## What can be run here
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F ':.*## ' '{printf "  make %-14s %s\n", $$1, $$2}'

check: ## Compile every crate and every test, with the locked dependencies
	cargo check --workspace --all-targets --locked

lint: ## rustfmt and clippy, warnings refused
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --locked -- -D warnings

test: ## Every test that needs no service (KEEP_GOING=1 runs every test binary, whatever an earlier one did)
	cargo test --workspace --locked $(if $(KEEP_GOING),--no-fail-fast)

demo: ## A hostile module against the reference controller and an unmodified worker, in both postures (needs nats-server, cargo-component, the wasm32-wasip2 target, jq, python3, uuidgen)
	@command -v nats-server >/dev/null 2>&1 || [ -n "$$AEGIX_DEMO_NATS_SERVER" ] \
	    || { echo "nats-server is missing: the run starts its own on a free local port"; exit 1; }
	@command -v cargo-component >/dev/null 2>&1 \
	    || { echo "cargo-component is missing: cargo install cargo-component --locked"; exit 1; }
	bash scripts/reference-controller-demo.sh --posture both

# The name the documents under docs/ use for the same run.
test-e2e-reference: demo

# ── Images and releases ─────────────────────────────────────────────────────
# The list of images is in scripts/runtime-release.py; these targets and the
# release workflow all build through scripts/runtime-images.sh.

images: ## Build the release's images for this machine, tagged as compose.yaml names them (ONLY=demo PLATFORM=linux/arm64 PROFILE=dist)
	bash scripts/runtime-images.sh build $(if $(PLATFORM),--platform $(PLATFORM)) $(if $(PROFILE),--profile $(PROFILE)) $(ONLY)

images-smoke: ## Run each built image once with no network; the demo image runs the whole demo (ONLY=demo)
	bash scripts/runtime-images.sh smoke $(ONLY)

demo-image: ## The demo from an image built here: needs a container engine, python3 and the network, and no toolchain
	bash scripts/runtime-images.sh build demo
	bash scripts/runtime-images.sh smoke demo

docs-check: ## Every document names only files, make targets and declarations this tree has
	python3 -I scripts/runtime-docs.py check

release-check: ## The workspace version, compose.yaml and CHANGELOG.md agree (TAG=v0.1.0 REPOSITORY=owner/name)
	python3 -I scripts/runtime-release.py check $(if $(TAG),--tag $(TAG)) $(if $(REPOSITORY),--repository $(REPOSITORY))
