# The demo

One command runs a module written to misbehave and prints, for each thing it
tries, what it asked for, what it was given, the line the worker recorded, and
where in the source the refusal is decided.

```bash
make demo-image                 # builds the image here, then runs it
docker compose run --rm demo    # the image as compose.yaml names it: the one just built, or a release's
make demo                       # from source, with no container
```

`make demo-image` needs a container engine (Docker, or Podman where there is
no `docker`), `make`, `bash`, `python3` (3.9 or later) and the network for
the build. `docker compose run --rm demo` needs only the engine once the
image is on the machine or a release has published it; the first page says
how to tell. `make demo` needs cargo, `cargo-component`, the `wasm32-wasip2`
target, `nats-server`, `jq`, `python3` and `uuidgen`. All three run
`scripts/reference-controller-demo.sh`, twice: once in each of the reference
controller's postures ([reference-controller.md](reference-controller.md)).

## What it starts

A NATS server on a free local port, the reference controller, and one
worker, the binary as it is built. The worker runs in its development
profile with the rules that profile leaves off switched on by hand
(`AEGIX_WRITE_CEILING_ENFORCED=1`, and in the `worker-identity` posture
`AEGIX_ENVELOPE_SEALING=required` and `AEGIX_DISPATCH_REQUIRE_ED25519=1`).
The keys and the broker password are minted for the run in a directory only
the user can read. Nothing listens
on any other address and nothing leaves the machine: every attempt below is
refused before a connection is opened, which is why the container can be
given no network at all.

The module is `scripts/demo/hostile-module.rs`. Nothing in it is special to
the demo. It is compiled for the widest world a module is given (`agent-node`:
HTTP, secrets, models, actor memory) and makes calls any module could contain.
Its actor is held to local models, may reach public hosts, and is read-only.

## What it shows

Two **controls**, which must be served. Without them a refusal could be a
worker that refuses everything.

| Control | What the module does | What must happen |
|---|---|---|
| a granted secret | `get-secret("demo/granted")`, then `hmac-sign` | it is handed an opaque handle and the host computes the MAC. The run checks the MAC against the value it stored: the secret was used and never entered the module |
| a memory read | `agent-memory::get("demo/readable")` | it reads the value the operator left |

Five **attempts**, which must be refused.

| # | Attempt | Given | Decided in |
|---|---|---|---|
| 1 | read a secret that is stored but not in its grant | `Err(unauthorized)` | `aegix-worker-runtime/src/host/vault.rs`, `check_secret_allowlist` |
| 2 | call a host that is not in `allowed_hosts` | `Err(forbiddenhost)` | `aegix-worker-runtime/src/host/egress_admission.rs`, `admit_parsed_url` |
| 3 | call a model provider that is in `allowed_hosts`, as an actor held to local models | `Err(forbiddenhost)` | `aegix-worker-runtime/src/host/egress.rs`, `egress_posture_deny_reason` |
| 4 | write to its actor's memory, as a read-only actor | `Err(not-available)` | `aegix-worker-runtime/src/context.rs`, `write_ceiling_refuses_detailed` |
| 5 | ask the controller for the actor's data after the job has ended | `Unauthorized` | `aegix-rpc-gates/src/dispatch_binding.rs`, `gate` |

Attempts 1 to 4 are made by the module. Attempt 5 is made from outside it, by
`aegix-e2e-probe`: a process that holds what a worker holds signs a read of
the actor's memory, bound to the module's job. It sends the same request
twice, while the module holds its job open and after the job has ended. The
first is served and the second refused. A credential that can sign as a worker
reads an actor's data only through a job that is running.

In the `worker-identity` posture the fifth attempt is two harder ones. A
request signed with the shared worker key is refused at admission both times,
because that controller holds no shared key to believe. A second worker whose
key the controller does list is refused a job it did not claim, while the job
runs.

Then two cases about time:

* **A job that waited past its deadline.** The worker is stopped, a job is
  dispatched with a five-second start deadline, and the worker is let go after
  eight. It refuses to start the job and the module never runs.
* **A job its controller gave up on.** The worker is stopped while a module
  runs. The controller's wait ends, it records the job as `timeout`, and from
  then on a request that names the job is refused, whatever the worker sends
  when it runs again.

The table of attempts has one home, in `scripts/demo/refusal-judge.sh`, which
also judges the run. The `decided in` line is found by searching the source at
run time for the function that decides, so it is the line that function is
declared on, in the tree the demo was built from. The refusal itself is a few
lines below it. The image carries those source files for that reason.

## What a run prints

From `make demo` in the `fleet-key` posture (ids differ per run):

```
What it tried, and was refused

  1. read a secret it was not granted
     asked      secrets::get-secret("demo/not-granted")
     given      Err(unauthorized)
     worker     [host:secret-allowlist] secret-access denied by policy 'secret-allowlist' (target: 9c91897a…)
     decided in aegix-worker-runtime/src/host/vault.rs:703
     ✓ refused

  3. reach an external model as a local-only actor
     asked      http::fetch(GET https://api.anthropic.com/v1/models)
     given      Err(forbiddenhost)
     worker     [host:tier1-llm-egress] http-fetch denied by policy 'tier1-llm-egress' (target: api.anthropic.com)
     decided in aegix-worker-runtime/src/host/egress.rs:159
     ✓ refused

  5. ask for its data after its job has ended
     asked      talos.memory.op Get "demo/readable", signed with the fleet key, bound to job 4ce73d48-…
     job live   served: "left here by the operator"
     job ended  refused: Unauthorized
     controller reference controller, refusals.dispatch_binding["talos.memory.op"].not_live: 0 → 1
     decided in aegix-rpc-gates/src/dispatch_binding.rs:435
     ✓ served while the job ran, refused once it had ended: one request, one key, one difference

▶ Both controls served; 5 of 5 attempts made, every one refused.
```

A secret refusal names the SHA-256 of the path, never the path. The run checks
that it is the hash of `demo/not-granted`.

## When it fails

The run exits 1 and prints `NOT REFUSED` when an attempt is served, when a
request passed the policy and failed on the network, when the error is not the
one the table names, when the worker recorded no line under the policy, when a
control is refused, when the MAC is not the stored value's, and for attempt 5
when the request was never served while the job ran or was served after it
ended.

To see a refusal go away, grant what was refused: add `example.com` to the
hostile module's `allowed_hosts` in `scripts/reference-controller-demo.sh` and
run `make demo` again. Attempt 2 is then given `Ok(status 200)`, and the run
prints `NOT REFUSED` and exits 1. (Checked on 2026-11-14.)

## What it does not show

Five refusals are five refusals: the ones named above, with these grants, on
this build. The demo is evidence that these gates are wired end to end. It is
not a proof that no other route exists. What the runtime defends, and against
whom, is [threat-model.md](threat-model.md); what it does not is
[limits.md](limits.md).

* **Attempt 3 is the gate for a named provider host.** A model reached through
  a host that is not a known provider is stopped by `allowed_hosts` (attempt
  2) or not at all.
* **Attempt 4 is the worker's gate.** The controller's own write-ceiling gate,
  in front of a write a worker signs, is held by the tests of
  `aegix-rpc-gates` and is not exercised by this run.
