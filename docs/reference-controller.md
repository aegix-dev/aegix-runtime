# The reference controller

`aegix-reference-controller` is a controller for Aegix workers in one small
binary. It needs a NATS server and nothing else: no Postgres, no Redis, no
workflow engine, no MCP or GraphQL surface.

An Aegix worker runs a WebAssembly module. It holds a login to the message bus
and its own keys (one to sign with, one to seal what it caches), and no
secret store and no database login. It is sent a
signed job, and whatever the module touches that belongs to somebody (a
secret, an actor's memory) it asks of the controller that signed the job. The
reference controller is the smallest program that keeps that promise:

* It holds the secrets. A job is handed only the ones its module is granted.
* It signs each dispatch, with a deadline after which a worker may not start
  the job.
* It answers a worker's actor-memory calls only when the call names a job it
  is running for that actor, and it lets a module write only where the actor's
  ceiling allows.
* It takes as a job's result only what a worker it believes signed for that
  job.

It does not write these rules itself. Admission and the two gates are
`aegix-rpc-gates`; signatures, the secret envelope and the result checks are
`aegix-workflow-job-protocol`; the claim responder is `aegix-envelope-seal`.
The platform's controller calls the same functions over Postgres. The
reference controller supplies a record held in memory and the order things
happen in.

```bash
make test-e2e-reference       # builds it, a worker and the hostile module; runs both postures
```

## What it does not do

* **Its record is in memory.** A restart forgets every job and every memory
  value that is not in the configuration file. A job that was running when it
  stopped is unknown afterwards, so its data calls are refused.
* **One module per dispatch.** No workflow, no retry, no schedule, no
  sub-workflow.
* **Actor memory is the only data call it serves.** A graph search, a SQL
  query, integration state and model inference are each answered "not
  available". Memory search is by keyword; nothing is embedded.
* **It delivers no model-provider key.** The paths the platform reserves for
  them are never handed to a job, whatever the grant says.
* **It is one process.** Its record of spent request nonces is its own. Two of
  them on one broker would each accept a signed request once.
* **It does not serve the NATS auth callout.** Workers log in to the broker as
  one shared user (`deploy/nats/nats-shared-worker.conf`), so the broker does
  not separate one worker's reply inbox from another's. What a worker may do
  with the controller is still decided by its signature and its job.
* **It has no network API.** It is driven through a Unix socket in a
  directory only its owner can enter.

## Two postures

The configuration names one. A controller never runs in both.

| | `fleet-key` | `worker-identity` |
|---|---|---|
| For | development on one machine | anything else |
| The controller signs with | `WORKER_SHARED_KEY` | its own Ed25519 key |
| A worker is believed when | it holds `WORKER_SHARED_KEY` | its public key is listed in `AEGIX_WORKER_PUBLIC_KEYS` |
| A job's secrets travel | in the dispatch, encrypted under the shared key and bound to the job | sealed to the one worker that claims the job |
| A data call for a job is served to | any holder of the shared key | the worker that claimed the job's secrets; any listed worker when the job was granted none |
| Refused unless `RUST_ENV` is unset, `development`, `dev`, `local` or `test` | yes | no |

Under `fleet-key` every worker holds the one key and can sign as any other.
What still bounds it is the job: a data call must name a job the controller is
running, for the actor it names. Under `worker-identity` the shared key is
never loaded, so a request signed with it fails at admission.

## Running it

Build the controller and a worker:

```bash
cargo build --workspace --bin aegix-reference-controller --bin worker
```

Start a NATS server with the worker permission set. The configuration is
`deploy/nats/nats-shared-worker.conf`, started from its own directory because
it includes `worker-permissions.conf` beside it. It takes the two users'
names and passwords from its environment: `NATS_USER` and `NATS_PASSWORD` for
the controller, `NATS_WORKER_USER` and `NATS_WORKER_PASSWORD` for the
workers. `scripts/nats-password.sh` prints a password of the shape the
configuration reads.

The steps below are the ones `scripts/reference-controller-demo.sh` takes,
for both postures. Its step 2 is the whole environment the bus, the
controller and the worker are each started with, and it is the configuration
that has been run: where this section and the script differ, the script is
right.

Mint the keys for `worker-identity`. The two seeds are written to files only
their owner can read and are not printed:

```bash
target/debug/aegix-reference-controller keygen --out-dir keys --worker-id worker-1
```

It prints the environment each side needs: `AEGIX_CONTROLLER_SIGNING_KEY_FILE`
and `AEGIX_WORKER_PUBLIC_KEYS` for the controller; `AEGIX_WORKER_ID`,
`AEGIX_WORKER_SIGNING_KEY_FILE` and `AEGIX_CONTROLLER_PUBLIC_KEY` for the
worker. Start the worker with `AEGIX_ENVELOPE_SEALING=required` and
`AEGIX_DISPATCH_REQUIRE_ED25519=1` as well, so it refuses a dispatch that is
not signed by that controller key.

Write the configuration. Every grant is written out; there is no default
actor, no default grant, and an unknown field is an error:

```json
{
  "posture": "worker-identity",
  "secrets_file": "secrets.json",
  "pickup_window_secs": 30,
  "actors": [
    { "name": "assistant", "max_llm_tier": "tier1", "egress_scope": "public",
      "max_write_ceiling": "readonly",
      "memory": { "notes/today": "buy milk" } }
  ],
  "modules": [
    { "name": "digest", "wasm": "digest.wasm", "capability_world": "agent-node",
      "allowed_hosts": ["api.example.com"], "allowed_methods": ["GET"],
      "allowed_secrets": ["example/api_key"], "max_fuel": 5000000, "timeout_secs": 30 }
  ]
}
```

* Paths are relative to the file.
* `secrets.json` is a JSON object of `path: value`. It is refused unless only
  its owner can read it (`chmod 600`).
* A module's grants name hosts (an exact host, or `.example.com` for the
  hosts beneath one) and secret paths (a path also grants the paths beneath
  it). `*` and `<prefix>/*` are refused.
* A module is checked against the capability world it declares when the
  controller starts, by the rule the worker links it with.
* `pickup_window_secs` is optional (30 when absent, at most 300).

A module is a compiled component. From this checkout, one source file is
compiled the way the platform compiles it with:

```bash
cargo run -p aegix-compilation --example compile_module -- module.rs agent-node module.wasm
```

Start it, then drive it with the same binary:

```bash
export AEGIX_REFERENCE_CONTROL_DIR=$PWD/control
aegix-reference-controller serve --config controller.json --control-dir control &

aegix-reference-controller status
aegix-reference-controller dispatch --module digest --actor assistant --input '{"config":{}}' --wait
aegix-reference-controller job --job <id>
aegix-reference-controller remember --actor assistant --key notes/today --value '"call the bank"'
aegix-reference-controller actor-status --actor assistant --status suspended
aegix-reference-controller counters
```

A client command exits 0 when it was served (and the job completed, when it
reports one), 3 when the job failed, timed out or has not ended, and 1 when it
was refused.

What `serve` reads from its environment:

| Variable | Read for |
|---|---|
| `NATS_URL` | the broker (default `nats://127.0.0.1:4222`) |
| `NATS_USER`, with `NATS_PASSWORD_FILE` or `NATS_PASSWORD` | the broker login. The file must be readable by its owner only |
| `NATS_JOB_TOPIC` | the subject jobs are published on, when the workers were given another (default `talos.jobs`) |
| `RUST_ENV` | whether the `fleet-key` posture is allowed |
| `WORKER_SHARED_KEY` or `WORKER_SHARED_KEY_FILE`, and `WORKER_SHARED_KEY_PREVIOUS` | `fleet-key`: the shared key, and the one before it during a rotation |
| `AEGIX_CONTROLLER_SIGNING_KEY_FILE` or `AEGIX_CONTROLLER_SIGNING_KEY` | `worker-identity`: the controller's Ed25519 seed |
| `AEGIX_WORKER_PUBLIC_KEYS` | `worker-identity`: `<worker id>=<public key>`, comma separated |
| `AEGIX_REFERENCE_CONTROL_DIR` | the control directory, when `--control-dir` is not given (client commands too) |

`counters` prints every refusal the controller has made, by decision
(`admission`, `dispatch_binding`, `write_ceiling`, `result`), subject and
reason. It is the reference controller's stand-in for the platform's metrics.

The control directory is created with mode 0700, and an existing one is
refused if anyone else can enter it: whoever reaches the socket can dispatch
jobs and write actor memory.

## The deadline

A worker accepts a signed dispatch for up to five minutes after it was signed.
Without a deadline, a job that waited on the bus could start long after its
controller had given up on it, with real side effects.

Every dispatch the reference controller signs carries the last second at which
a worker may start it: `pickup_window_secs` after signing. The deadline is
under the signature. The controller then waits that window, plus the module's
own time limit, plus ten seconds for the result to arrive, and then reads the
job's last log lines for at most half a second however many keep arriving.
When the wait ends it records the job as `timeout` first, and then tells the
workers to stop it.
From that moment (within the two seconds the gate remembers a "yes") a data
call that names the job is refused by the dispatch-binding gate, a claim for its secrets is refused, and nothing a
worker sends later changes the record.

## What the end-to-end run shows

`make test-e2e-reference` (`scripts/reference-controller-demo.sh --posture
both`) starts a NATS server on a free local port, the reference controller and
one unmodified worker, with keys minted for the run in a directory only the
user can read. It then:

* **A.** dispatches the hostile module of [the refusal demo](refusal-demo.md).
  Its two controls are served and its four attempts refused, judged by
  `scripts/demo/refusal-judge.sh` with the rules the full stack is held to.
* **B.** asks for the job's actor's data from outside the module. Under
  `fleet-key` the request is served while the job runs and refused once it has
  ended. Under `worker-identity` a request signed with the worker's shared key
  is refused at admission both times, and a second listed worker is refused a
  job it did not claim.
* **C.** stops the worker, dispatches with a five-second pickup window and
  lets the worker go after it. The worker refuses to start the job, the module
  never runs, and a request that names the job is refused.
* **D.** stops the worker while a module runs. The controller's wait ends, it
  records the job as `timeout`, and from then on a request that names the job
  is refused, including one signed by the worker that claimed it.

The run takes about two minutes after the build.
