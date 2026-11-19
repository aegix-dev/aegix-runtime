# Wasmtime Version Tracking

Aegix's WASM sandbox is wasmtime. A sandbox-escape CVE in wasmtime is, by
definition, a sandbox-escape CVE in Aegix — there is no defense-in-depth
layer below wasmtime that prevents native code execution from a compromised
guest. This file is the single place that tracks what version we are on,
why, and when the operator should bump.

## Current pin

| Crate                | Version  | Pinned in                                  |
|----------------------|----------|--------------------------------------------|
| `wasmtime`           | 49.0.6   | `Cargo.toml`, `[workspace.dependencies]`   |
| `wasmtime-wasi`      | 49.0.6   | `Cargo.toml`, `[workspace.dependencies]`   |
| `wasmtime-wasi-http` | 49.0.6   | `Cargo.toml`, `[workspace.dependencies]`   |

Since 2026-10-06 the three versions are declared once, in the workspace
manifest. `aegix-wasm-host` (which links all three) and `worker` (whose
tests use `wasmtime` as a dev-dependency) inherit them with
`workspace = true`, so the two manifests can no longer name different
versions.

The runtime library (`AegixRuntime`, the engine config, the AOT cache) was
extracted from `worker/` to `aegix-wasm-host/` in July 2026, so that
crate's manifest is the one that governs which wasmtime the fleet actually
runs — all three production entries live there. The deployable `worker`
binary's own wasmtime entry is a **dev-dependency**: `worker/tests/` builds
guest fixtures and pokes the engine directly, and nothing else in that crate
links wasmtime.

It still has to move in lockstep. Across a major, cargo does not unify the
two specs — it resolves BOTH, so the lockfile grows a second wasmtime +
cranelift family and the worker's integration tests end up validating an
engine the fleet does not ship, with no compile error anywhere.
`fingerprint_wasmtime_version_matches_cargo_toml` fails if the two manifests
disagree, and it reads THIS table too, so a bump that forgets this file
fails the same test rather than leaving a stale CVE-response reference.

Line numbers are deliberately omitted: they rot on every unrelated edit to
those manifests, and the table above is machine-checked by version, not by
location.

## Why this version

Cumulative, newest first. Each row is a bump that happened; the version
column is the version bumped *to*.

| Version  | Identifier             | Class                                    |
|----------|------------------------|------------------------------------------|
| 49.0.6   | RUSTSEC-2026-0566      | `wasmtime-wasi`: unbounded host memory growth via empty writes to `AsyncWriteStream` |
| 49.0.6   | RUSTSEC-2026-0567      | Abort in builds without the `threads` cargo feature |
| 49.0.6   | RUSTSEC-2026-0568      | Stale GC heap base pointer in compiled code lets a guest abort the host process |
| 49.0.6   | RUSTSEC-2026-0569      | Panic in `Caller::get_module_export` when a host function is not called from WebAssembly |
| 49.0.6   | RUSTSEC-2026-0570      | Abort in builds without the `gc` cargo feature |
| 49.0.6   | RUSTSEC-2026-0571      | `wasmtime-wasi-http`: empty body writes can use unbounded heap with HTTP/2 |
| 49.0.6   | RUSTSEC-2026-0572      | Panic when a component cancels a stream or future copy on the wrong end |
| 49.0.6   | RUSTSEC-2026-0573      | Process abort when a GC heap's reservation is not a multiple of the page size |
| 49.0.5   | RUSTSEC-2026-0420      | wasmtime-wasi wasip3: UDP `send` to a receive-only address |
| 49.0.5   | RUSTSEC-2026-0421      | `wasi:http` p2: outgoing content-length can be invalid or mismatch the body |
| 49.0.5   | RUSTSEC-2026-0422      | Typed functions with `i31`/`nullref` arguments may panic the host |
| 49.0.5   | RUSTSEC-2026-0423      | Cross-engine type confusion with host-created struct types that have supertypes |
| 49.0.5   | RUSTSEC-2026-0424      | Unchecked memory usage transferring borrowed resources between components |
| 49.0.4   | RUSTSEC-2026-0379      | Cranelift aarch64 can jump to the wrong target on a large `br_table` (codegen; the fleet's hosts are aarch64 and x86-64) |
| 49.0.4   | RUSTSEC-2026-0378      | Host panic lowering a host-created component-model stream into a guest expecting another payload type |
| 49.0.4   | RUSTSEC-2026-0375      | `wasi:http` p3: a guest can set a wrong content-length on a spliced response body |
| 49.0.4   | RUSTSEC-2026-0376      | `wasi:http`: a guest can add conflicting content-length headers to a message |
| 49.0.4   | RUSTSEC-2026-0377      | `wasi:http` p3: forwarded trailers are not checked against the `is_forbidden_header` hook |
| 49.0.3   | RUSTSEC-2026-0350      | `wasi:http`: guests can send absolute-form requests to a different host (egress bypass) |
| 49.0.3   | RUSTSEC-2026-0352      | Filesystem sandbox escape when renaming symlinks with trailing slashes |
| 49.0.3   | RUSTSEC-2026-0351      | `wasi:http`: a long URL before the query string crashes the host |
| 49.0.3   | RUSTSEC-2026-0353…0362 | Component-model host panics (async-lifted `call`, cancelled `call_async`, stream/future type confusion, realloc call-to-host, zero-length stream writes, yield in a start function, recursive-type drop overflow, fused-adapter transcode, pending calls after a trap, async-entrypoint enforcement) |
| 49.0.3   | RUSTSEC-2026-0363      | Component-model handle tables capped only per instance and charged to no limit |
| 49.0.3   | RUSTSEC-2026-0364      | Exception tags can leave host data structures unaligned |
| 49.0.2   | RUSTSEC-2026-0321      | WASI preview 0 `poll_oneoff` circumvents fuel consumption (GHSA-j366-h8gg-77pm) |
| 49.0.2   | RUSTSEC-2026-0322      | Excessive host memory allocated when a guest has no stdio |
| 49.0.2   | RUSTSEC-2026-0323      | `fd_readdir` copies uninitialized struct padding into guest memory |
| 49.0.2   | RUSTSEC-2026-0324      | Guest can panic the host through a pre-epoch filesystem timestamp on wasip3 |
| 49.0.2   | RUSTSEC-2026-0325      | Mis-typed WebAssembly tag imports can corrupt the GC heap (GHSA-cfhf-m2cr-62wj) |
| 49.0.2   | RUSTSEC-2026-0326      | Missing rooting for GC values live across `try_call` can corrupt the GC heap |
| 49.0.2   | RUSTSEC-2026-0327      | Component async-lifted callback result count unvalidated: native stack buffer overflow (GHSA-32h6-97mm-8q3c) |
| 49.0.2   | RUSTSEC-2026-0320      | `wasi:http` panics on a zero timeout |
| 49.0.1   | (support window)       | 48 stops receiving security backports once 50 ships; 49 also carries RUSTSEC-2026-0313…0316. Needs Rust 1.96 |
| 48.0.3   | RUSTSEC-2026-0313      | `wasi:http` outgoing body write allows guest-driven host memory exhaustion |
| 48.0.3   | RUSTSEC-2026-0314      | Guest can panic the host through a WASI filesystem datetime overflow |
| 48.0.3   | RUSTSEC-2026-0315      | `call_ref` + exception `catch` can drop fuel accounting (exponential fuel amplification) |
| 48.0.3   | RUSTSEC-2026-0316      | Dynamic record lifting can allocate beyond the hostcall fuel limit |
| 47.0.3   | RUSTSEC-2026-0222      | Stores mix up type indices between engines (GHSA-hgjw-h833-99q9) |
| 45.0.3   | RUSTSEC-2026-0188      | WASI hard-link/rename `FilePerms` bypass |
| 44.0.3   | RUSTSEC-2026-0182      | WASIp1 `fd_renumber` memory leak (lockfile-only bump — the manifests stayed `44.0.2`) |
| 44.0.2   | RUSTSEC-2026-0149      | WASI `path_open(TRUNCATE)` bypasses host `FilePerms::WRITE` (HIGH, CVSS 7.5) |
| 43.0.2   | CVE-2026-34971         | Sandbox escape                           |
| 43.0.2   | CVE-2026-27572         | HTTP headers DoS                         |
| 43.0.2   | CVE-2026-27195         | `call_async` DoS                         |
| 43.0.2   | GHSA-6wgr-89rj-399p    | Pooling allocator leak                   |
| 43.0.2   | RUSTSEC-2026-0114      | (43.0.2 fix)                             |

43.x also brought: per-operator fuel costs (`OperatorCost`), `Store::try_new`
(OOM-safe construction), WASIp3 preview.

## Upgrade cadence

* **Monthly.** Bump the three versions in the root `Cargo.toml`'s
  `[workspace.dependencies]` together with the RustSec advisory DB snapshot
  in the builder image. Both ride the monthly image rebuild that operators
  are already doing.

* **Out-of-band.** Bump immediately on any wasmtime release that lists
  a CVE in the sandbox-escape, codegen (Cranelift), or component-model
  classes. Subscribe to:
  - `bytecodealliance/wasmtime` GitHub Security Advisories.
  - the `wasmtime` crate's RustSec page (`cargo audit` will surface
    these too, but a direct subscription gives earlier signal).
  - the `cranelift-*` family in the same advisory feeds.

* **Never silently.** When bumping, append a row to the "Why this
  version" table above with the CVEs the new version closes. The
  table is the audit trail.

## What gets pinned

The `Cargo.toml` line names the full three-part version (a literal `X.Y.Z`, not
`"43"` or `"^43"`). Note what that is and is not: cargo reads `"47.0.3"` as
`^47.0.3`, so it pins the MAJOR and floors the patch — it does not forbid
`cargo update` from resolving 47.0.4 within the 47.x line. `Cargo.lock` is
what makes any given build exact. Both properties are deliberate:

1. Reproducible builds — `cargo audit` runs against `Cargo.lock`, and
   the lockfile records the exact transitive set. An unpinned major
   would let `cargo update` silently shift the version. A patch that
   moves within the line (as RUSTSEC-2026-0182 did, 44.0.2 → 44.0.3) is
   a lockfile change with no manifest change, so it will NOT trip
   `fingerprint_wasmtime_version_matches_cargo_toml` — wasmtime's own
   `Component::deserialize` version check is the backstop there.

2. Auditability — the `THREAT_MODEL.md` references this file by name.
   If wasmtime updates without us noticing, the threat model goes
   stale and we wouldn't know.

3. Forces reviewer attention — bumping wasmtime is a security event,
   not a maintenance task. Naming the full `X.Y.Z` makes the bump a
   deliberate PR action with a diff a reviewer can see.

## What to check at upgrade time

When bumping wasmtime, the following Aegix-side surfaces are most
likely to need a corresponding change:

* `aegix-wasm-host/src/runtime.rs::with_resources` — explicit
  `wasm_threads/simd/memory64/gc/tail_call/multi_memory/function_references(false)`.
  Each disabled proposal removes Cranelift attack surface; verify the
  list still matches what's available in the new wasmtime release.
  Adding a new proposal in a wasmtime point release that defaults to
  ON would silently expand the codegen surface — `lint-structural.sh`
  check **#20** catches the regression. (This said "#8" until 2026-07-31;
  #8 is the unrelated `trigger_type` column-drift check. Check numbers are
  positional, so re-verify against the script rather than trusting a
  number quoted in prose.)

* `OperatorCost` field set — wasmtime occasionally adds new fields
  here. The `..wasmtime::OperatorCost::default()` rest-pattern keeps
  the code compiling, but verify the defaults aren't 1-per-op for an
  expensive new operator (e.g. SIMD lanes, GC barriers).

* `PoolingAllocationConfig` field set — same shape. New tuning knobs
  may need to be set explicitly to retain current behaviour.

* The inspector's parser — `aegix-wit-inspector/Cargo.toml` pins `wasmparser`
  to the version `wasmtime-environ` depends on, so what the inspection reads
  as a component's imports is what wasmtime will link. Move the line with
  the bump; `the_parser_is_the_one_wasmtime_reads_with` fails until it
  matches. Then run `controller audit-module-worlds` against the stored
  modules before a roll: a binary the new parser stops in is refused at
  dispatch.
* Memory protection keys — read what the new release's documentation of
  `PoolingAllocationConfig::memory_protection_keys` says: whether the option
  is still called experimental, and whether its default is still `no`. A
  release that turns it on by default would turn it on here. See "Memory
  protection keys" below.

* `wasmtime-wasi` API drift — `add_to_linker_async`, etc. The async
  vs sync split has moved between wasmtime point releases before.

## Memory protection keys: off, and when to ask again

The pooling allocator is not asked for memory protection keys (wasmtime's
`PoolingAllocationConfig::memory_protection_keys`, "MPK"; Linux calls the
processor feature `pku`). Until 2026-11-18 the engine asked for `auto` on
Linux x86_64 and nowhere else.
`aegix-wasm-host/src/runtime.rs` now leaves it at wasmtime's default,
`no`, and the test `pooling_asks_for_no_memory_protection_keys` holds that.

### What the option does

Each memory slot in the pool is followed by a guard region no module can
touch. With keys, wasmtime gives neighbouring slots different keys and lets
a slot's neighbours stand in for its guard region, so the slots can sit
closer together. The saving is reserved address space and nothing else: it
commits no less memory, and a module runs no faster (the key register is
written on every switch between the host and a module, a small cost).

### Why it is off

* wasmtime 49 documents it as "still experimental--use at your own risk" and
  says "you may observe segmentation faults if anything is misconfigured".
  Its default is `no`.
* With it on, what keeps one module out of the next one's memory is the
  key register, not an unmapped region. That is the sandbox boundary resting
  on an experimental option.
* No gate runs on a processor that has keys. The machines this code is
  developed and tested on are arm64, and the hosted x86_64 runner the public
  tree's CI uses reports no `pku`. It was on for exactly the platform nothing
  tested.
* The first outside review of the runtime (0.1.0, on Linux x86_64) reported
  `cancellation_preempts_a_compute_bound_module` dying of a segmentation
  fault in the pooling allocator, five runs in five. It was not reproduced
  on a processor without keys. Whether keys were the cause is not known.

### What it would save here, measured from the configuration

| | today |
|---|---|
| memory slots (`total_memories`) | 2,000 |
| slot size (`memory_reservation` = `max_memory_size`) | 128 MiB |
| guard region per slot (wasmtime's default, not overridden) | 32 MiB |
| address space reserved by the pool's memories | 2,000 × 160 MiB ≈ 313 GiB |
| address space of a Linux x86_64 process (47 bits) | 128 TiB |
| share used | about 0.24% |

Because a slot here is already cut down to the largest memory a module may
have, the most keys could remove is the guard region: 32 MiB of every
160 MiB, about a fifth. (wasmtime's own example saves far more because it
keeps the default 4 GiB reservation with a 128 MiB maximum, and packs many
memories into one reservation. That is not this configuration.)

### When to ask again

Address space is the only thing the option buys, so the question is whether
one worker process is running out of it:

* **At today's slot size the pool's memories reach the 47-bit limit at
  roughly 800,000 slots** (128 TiB ÷ 160 MiB), not at tens of thousands:
  50,000 slots would reserve about 7.6 TiB, 6% of the space. Other
  mappings (tables, stacks, the compiled code of cached modules) take some
  of the rest.
* **A larger slot moves the limit down in proportion.** If modules were
  allowed 4 GiB memories, a slot with its guard would be about 4 GiB and the
  limit would be near 32,000 slots. That is the case in which this option
  is worth reading about again.
* **A reservation the kernel refuses is how it would show**: the engine
  fails to build at worker start (the pool is reserved up front), or a
  process limit on address space (`ulimit -v`, a container's) is hit. The
  `AEGIX_DISABLE_POOLING=true` (memory on demand, slightly slower to start
  a module) is the way round that today.

Before turning it on, all of these, in one change:

1. **Try more worker processes first.** Each has its own address space,
   the platform already runs several, and it needs no experimental option.
   The pool is sized for 500 instances at once in one process; tens of
   thousands of slots in one process is a different design from the one
   that exists.
2. A gate that runs the worker's tests on a processor with `pku`, and
   passes with the option on. Without one the option is untested on the
   only platform it does anything on, which is the state it was removed
   from.
3. wasmtime no longer calls the option experimental (see "What to check at
   upgrade time").
4. The reported crash is either reproduced and explained, or shown on that
   gate not to happen.
5. The engine fingerprint, its pinned hash and `AOT_VERSION_HDR` move
   together, as for any engine configuration change: a module compiled for
   an engine without keys must not be loaded by one with them.

It is deliberately not a setting. A switch nobody can test is the defect
that was removed.

## Test-runner contract

After bumping, the full worker test suite plus the integration suite
(`cargo test --workspace`) must pass before merging. The lint pass
(`make lint`) runs the structural lints that catch silently-shifted
WASM proposal defaults. Lint check #20 (added 2026-05-22) ensures
every disabled proposal stays in the explicit-opt-out list.

The three edits a wasmtime bump requires, all named by
`fingerprint_wasmtime_version_matches_cargo_toml` when it fails:

1. the `wasmtime_version!` macro in `aegix-wasm-host/src/runtime.rs`
   (the single source — it feeds BOTH the `Engine created` boot log's
   `wasmtime_version` field and `ENGINE_CONFIG_FINGERPRINT`'s `wasmtime=`
   line, so there is nothing else in the code to update);
2. the pinned SHA-256 in `engine_config_fingerprint_is_pinned`, plus an
   `AOT_VERSION_HDR` bump so stale AOT blobs reject with a clean version
   mismatch instead of an HMAC failure;
3. the **Current pin** table at the top of this file.

Item 3 is in the list because it was NOT for the first four wasmtime-family
bumps (44.0.2, 44.0.3, 45.0.3, 47.0.3): this file still said 43.0.2 on a
fleet running 47.0.3, while being the document `THREAT_MODEL.md` names as
the CVE-response reference. It is now read by that same test.

## Reference

The "no formal verification of WASM component model adapter" residual
risk row in `THREAT_MODEL.md` §13 references this file. The acceptance
of that residual risk is conditional on operators following the
monthly upgrade cadence documented above.
