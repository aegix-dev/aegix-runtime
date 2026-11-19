# Threat model

What this tree defends, against whom, and where each rule is decided. It
covers the worker, the runtime it embeds, the gates in `aegix-rpc-gates` and
the reference controller, as they are in this tree. It was written by the
author from the code, and nobody outside has audited either.

Where a rule is named as `file`, `function`, `make docs-check` holds that the
file declares it. What is not defended is in [limits.md](limits.md), and each
section here ends with what remains.

## The parts

```
 module ──(the interface in wit/aegix.wit)── worker ──(signed messages on a NATS bus)── controller ──(a Unix socket)── operator
```

* A **module** is a WebAssembly component: code somebody, or some model,
  wrote. It runs inside the worker and can do only what the host functions of
  its capability world let it ask for.
* A **worker** runs modules. It holds a broker login and its own keys: the
  one it signs with, and the one it seals its checkpoints and cached results
  with (under `fleet-key` they are the same key). It holds no secret store
  and no database login.
* The **controller** holds the secrets, the actors' memory, and the record of
  which job is running for which actor. It signs every job.
* The **operator** writes the controller's configuration and drives it.

## What is protected

1. **Secrets** the controller holds: their values, and where they may be sent.
2. **An actor's memory**: who may read it, and who may write it.
3. **The machine and network the worker runs on**: private addresses, the
   worker's own environment and files.
4. **The record**: that a job the controller ended has ended, and that what
   it recorded as a job's result came from the worker that ran it.

## Who is not trusted

* **A. The module.** The case this runtime exists for. Assume it was written
  to do harm, or was talked into it by text it read.
* **B. A worker that has been taken over**, with everything it holds.
* **C. Somebody on the message bus**, with a broker login and no key.

Trusted: the controller process and its machine, its configuration and
secrets file, whoever can reach its control socket, the toolchain that
compiled the module and the machine it compiled on, and wasmtime.

## A. The module

| The module tries to | What stops it | Decided in |
|---|---|---|
| read a secret outside its grant | the job is handed only the secrets its module is granted, and the worker refuses any other path. A grant is a path and covers the paths beneath it; `*` grants nothing | `aegix-reference-controller/src/dispatch.rs`, `granted`; `aegix-wasm-host/src/host/vault.rs`, `check_secret_allowlist` |
| read the value of a secret it is granted | it is given a handle. The host signs with the secret or places it in a request; the value does not enter the module. The one host function that returns a value needs a flag under the job's signature, and the reference controller never sets it | `aegix-wasm-host/src/host/secrets.rs`, `get_secret`, and `expose_secret`; `aegix-reference-controller/src/dispatch.rs`, `prepare` |
| have a secret sent somewhere of its choosing | a `vault://` reference is filled in only for a host the grant names, in a header or a JSON body, never in a URL and never in a message-bus header | `aegix-wasm-host/src/host/vault.rs`, `secret_destination_refusal` |
| call a host that is not on its list, or with a verb it was not given | `allowed_hosts` is exact hosts and `.suffix` entries; empty denies everything, and so does an empty `allowed_methods`. HTTPS only. The worker also takes `*` as every public host; the reference controller refuses to load a module granted it (see [The operator's side](#the-operators-side)) | `aegix-wasm-host/src/host/egress_admission.rs`, `admit_parsed_url`; `aegix-workflow-job-protocol/src/http_methods.rs`, `method_permitted` |
| name another site to the server than the one its URL was admitted for | a `Host` header, and the fields that belong to the connection (`Transfer-Encoding`, `Connection`, `Upgrade` and the rest), are refused on every request path before a secret is filled in or a connection is opened. The worker writes them from the URL | `aegix-wasm-host/src/host/request_headers.rs`, `request_headers_refusal` |
| reach a private address: loopback, the local network, a cloud metadata service | an address literal is refused at admission, and a name is checked when it is resolved for the connection, so a name that changes its answer is checked on the answer that is used. Redirects are not followed | `aegix-wasm-host/src/host/egress.rs`, `denied_ip_literal`; `aegix-wasm-host/src/ssrf_resolver.rs`, `resolved_addr_permitted`; `aegix-ssrf-classify/src/lib.rs`, `classify_private_ip` |
| reach an outside model, as an actor held to local ones | provider hosts are refused whatever the grant says, provider keys are not resolved, and a local model server's cloud-served models are refused | `aegix-wasm-host/src/host/egress.rs`, `egress_posture_deny_reason`; `aegix-wasm-host/src/host/llm.rs`, `decide_llm_tier_access`, and `admit_local_model` |
| write, as a read-only actor | the worker refuses the host call, and the controller refuses the write again when a worker signs one | `aegix-wasm-host/src/context.rs`, `write_ceiling_refuses_detailed`; `aegix-rpc-gates/src/write_ceiling.rs`, `gate` |
| read or write another actor's memory | the actor is the job's, under the controller's signature. The module does not name it | `aegix-reference-controller/src/data_plane.rs`, `memory_op` |
| use a host function outside its world | the module is linked with its declared world's functions only, and a binary that imports more is refused before it starts. The world is under the job's signature | `aegix-wit-inspector/src/lib.rs`, `link_world`, and `imports_outside_world` |
| read the worker's environment or files | no environment is passed in and no directory is opened, except a per-run scratch directory for the worlds that have files | `aegix-wasm-host/src/context.rs`, `capability_world_has_fs_preopen` |
| run for ever, or take the machine's memory | fuel (10 million units when the job names none; the job may name up to 50 million, a ceiling the operator can move with `AEGIX_WORKER_MAX_JOB_FUEL`), 128 MB of memory, a wall-clock limit enforced every 100 ms, and caps on input, output and each kind of call | `worker/src/main.rs`, `clamp_job_fuel`; `aegix-workflow-job-protocol/src/lib.rs`, `MAX_JOB_FUEL` |

**What remains.**

* A host on the list is trusted with everything the module can send it: its
  input, what it read from memory, and any secret granted for that host. A
  host that returns request headers in its response returns the secret to
  the module.
* A header that a host on the list itself reads as a routing instruction
  (`X-Forwarded-Host`, `X-Original-URL`) is sent as the module wrote it. What
  such a host does with it is the host's.
* The provider list has four hosts. A model behind any other host is stopped
  only by `allowed_hosts`.
* `allowed_hosts` is read by the HTTP interfaces and not by the model ones.
  A module in a world with `llm` or `embedding` sends its prompt to the
  model server the worker is configured with, or to a provider the worker
  holds a key for, with an empty list of hosts as with any other
  ([limits.md](limits.md), "Model calls").
* The worker's own write-ceiling check is off unless it is switched on
  ([What a deployment must set](#what-a-deployment-must-set)). The
  controller's is always on in the reference controller.
* The write ceiling covers HTTP verbs other than GET, messages, mail, SQL
  writes, object storage and actor memory. It does not cover a module's own
  state, cache, scratch files or events.
* A module in a world with messaging can publish on any bus subject that is
  not reserved, with the worker's login.
* All of this is about a module that is run. Compiling a module's source is
  not covered: the compile runs on the build machine with the builder's
  rights, and a source can embed that machine's files and environment in
  the module it becomes. The lint that reads the source first is advice
  ([limits.md](limits.md), "Compiling a module's source").
* The sandbox is wasmtime's. A flaw there is a flaw here.

## B. A worker that has been taken over

It holds its broker login, its keys, and each job it was sent while that job
runs: the job's input, its module, and the secrets granted to it. What
follows is the `worker-identity` posture; `fleet-key`, the development
posture, shares one key among all workers and is weaker in every row
([reference-controller.md](reference-controller.md)).

| It tries to | What stops it | Decided in |
|---|---|---|
| read an actor's data when it has no job for that actor | a data call must name a job the controller is running, for the actor it names, and the actor must be active | `aegix-rpc-gates/src/dispatch_binding.rs`, `gate`, and `dispatch_is_live` |
| go on using a job that has ended, or that the controller gave up on | the controller's own timer ends the job in its record, and the record is what the gate reads. Nothing the worker sends afterwards changes it | `aegix-reference-controller/src/serve.rs`, `await_result`; `aegix-rpc-gates/src/dispatch_binding.rs`, `dispatch_is_live` |
| take the secrets of a job sent to another worker | secrets do not travel with the job. The worker that picked it up claims them, signed with its own key; they are sealed to a key made for that one claim, and handed out once | `aegix-envelope-seal/src/lib.rs`, `handle_secret_claim`; `aegix-workflow-job-protocol/src/envelope_seal.rs`, `seal_secrets` |
| use another worker's job | once a job's secrets are claimed, its data calls and its result are taken only from the claimant | `aegix-rpc-gates/src/dispatch_binding.rs`, `dispatch_is_live`; `aegix-workflow-job-protocol/src/envelope_seal.rs`, `sealed_result_refused` |
| write above the actor's ceiling by signing the write itself | the controller reads the ceiling from its own record. An actor it cannot find is refused | `aegix-rpc-gates/src/write_ceiling.rs`, `gate` |
| send a job of its own making to other workers | a job is signed with the controller's Ed25519 key, which no worker holds | `aegix-workflow-job-protocol/src/lib.rs`, `verify_dispatch` |
| send a signed request twice, or an old one | every request carries a nonce the receiver remembers, and a time: 60 seconds old at most for a data call, 5 minutes for a job, and for a job the start deadline its controller signed | `aegix-rpc-protocol/src/rpc_auth.rs`, `check_and_record_nonce`, and `verify_freshness`; `worker/src/job_execution.rs`, `execute_job`, and `run_verified_job` |
| have its result taken for another job | a result names the job, the attempt and the run it answers, under its signature | `aegix-reference-controller/src/dispatch.rs`, `accept_result` |

**What remains.**

* Everything about its own jobs. It can read their inputs and granted
  secrets, read and (within the ceiling) write their actors' memory while
  they run, and report any output, any failure and any fuel figure it likes.
  The controller checks who signed a result. It cannot check that the module
  ran.
* The log lines it publishes while a job runs are not signed, and the
  controller records them before the lines of the signed result. It can
  write lines into the log of any running job whose id it knows: its own,
  and, with the broker login the workers share, any whose claim it saw
  answered.
* A job granted no secret is claimed by nobody, so while it runs any listed
  worker is served its actor's memory.
* A gate's "yes" is remembered for two seconds
  (`aegix-rpc-gates/src/dispatch_binding.rs`, `CACHE_TTL`). A data call can be
  served that long after its job ends.
* A worker accepts a job signed with the shared key as well, unless
  `AEGIX_DISPATCH_REQUIRE_ED25519=1`. Without it, a worker that is taken over
  can sign jobs for the others.
* It can stop doing its work, and it can fill the fixed-size records that
  refuse when full. See C.

## C. Somebody on the message bus

With the workers' broker login and no key.

| They try to | What stops them | Decided in |
|---|---|---|
| send a job, a data call, a result or a cancel | each is refused without a signature the receiver has the key for | `aegix-rpc-gates/src/admission.rs`, `admit_from_bytes`; `aegix-workflow-job-protocol/src/lib.rs`, `verify_dispatch` |
| replay one they saw | the nonce and the time, as above | `aegix-rpc-protocol/src/rpc_auth.rs`, `check_and_record_nonce` |
| read a job's secrets | under `worker-identity` they are sealed to the claiming worker's one-time key. Under `fleet-key` they are encrypted under the shared key, which the login alone does not give | `aegix-workflow-job-protocol/src/envelope_seal.rs`, `seal_secrets` |
| publish a job or a cancel, or into a worker's inbox | the broker's permissions for the worker user | `deploy/nats/worker-permissions.conf` |

**What remains.** This is the weakest of the three, and the demo's broker is
not a deployment.

* **Nothing but a job's secrets is encrypted on the bus.** A job's input, its
  module, its result and the answers to its data calls are readable. Every
  worker logs in as one user, so that user can take a share of the jobs and
  read the answers sent to other workers.
* **An answer to a data call, and a log line, carry no signature.** The
  table's last row is all that keeps a made-up answer out of a worker's
  inbox: with the controller's login, or on a broker without those
  permissions, a worker's module can be given any value as its actor's
  memory. A log line is published on a subject the worker login may publish
  to, and the controller keeps the first 200 it receives for a job
  ([limits.md](limits.md), "The message bus").
* **There is no TLS** in the demo's broker, and the reference controller
  has no setting for a CA. A worker has one (`NATS_CA_FILE`).
* **Availability.** Signed messages are counted in records of fixed size
  that refuse when full, the controller runs at most 64 jobs at once, and
  anyone who can publish can fill a subject. None of that gives data away;
  all of it can stop work.
* With the *controller's* broker login and no key, they can publish a job. A
  worker sends nothing in answer to a job that does not verify, so a job of
  their own making gets them no signed result
  (`worker/src/refused_dispatch.rs`, `refused_dispatch_answer`). What is left is a job
  the controller did sign, sent a second time more than five minutes after
  it was signed, while it is still running. The worker's check of a job's
  age comes before its check of the signature, and a job that is too old but
  is the controller's is told so, under the worker's signature; the
  controller records the running job as failed. When the job's secrets were
  claimed, that answer is taken only from the worker that claimed them.

## The operator's side

Trusted, and the controller still refuses the configurations that are
easiest to get wrong.

| | Decided in |
|---|---|
| a grant of `*` for hosts, or `*` or `<prefix>/*` for secrets, is refused; a module that does not fit the world it declares is refused at start | `aegix-reference-controller/src/config.rs`, `module_from` |
| the secrets file and the key files are refused unless only their owner can read them | `aegix-reference-controller/src/config.rs`, `read_private_file` |
| the control directory is refused if anyone but its owner can enter it. There is no other check on who is asking: whoever reaches the socket can dispatch jobs and write memory | `aegix-reference-controller/src/control.rs`, `prepare_dir` |
| the shared-key posture is refused unless `RUST_ENV` is unset or names a development environment | `aegix-reference-controller/src/keys.rs`, `load` |
| a model-provider key is never handed to a job, whatever the grant says | `aegix-workflow-job-protocol/src/vault_paths.rs`, `is_controller_internal_vault_path` |

## What a deployment must set

A worker runs under one of three profiles
(`aegix-deploy-posture/src/security_profile.rs`, `SecurityProfile`).
`AEGIX_SECURITY_PROFILE` names it: `hardened`, `transitional` or
`development`. Any other value stops the worker at start. Left unset, the
profile follows `RUST_ENV`: **development** when that is unset or is
`development`, `dev`, `local` or `test`, and **hardened** for anything else.
`development` cannot be named under any other `RUST_ENV`.

**Development.** No rule is forced at start, and three of the rules above
are off until they are switched on. The demo switches them on by hand: all
three in its `worker-identity` posture, the first alone in `fleet-key`.

| Variable, on the worker | Without it |
|---|---|
| `AEGIX_WRITE_CEILING_ENFORCED=1` | the worker does not refuse a read-only actor's writes. Only the controller does, and only the ones that reach it |
| `AEGIX_DISPATCH_REQUIRE_ED25519=1` | a job signed with the shared key is accepted |
| `AEGIX_ENVELOPE_SEALING=required` | a job that carries its secrets with it is accepted |

In this profile the worker also honours `WORKER_ALLOW_PRIVATE_HOST_TARGETS`
and `WASM_ALLOW_INSECURE_HTTP`, takes a model-provider key from its own
environment, and does not ask for signatures on a module pulled from a
registry.

**Hardened.** The worker refuses to start unless the rules are on, and
turns only one of them on by itself:

* `AEGIX_WRITE_CEILING_ENFORCED` is on when unset, and a worker that sets it
  to `false` does not start.
* `AEGIX_DISPATCH_REQUIRE_ED25519` and `AEGIX_ENVELOPE_SEALING=required` are
  not turned on for it. A worker without them does not start, and says which
  is missing.
* A worker that sets `WORKER_ALLOW_PRIVATE_HOST_TARGETS` or
  `WASM_ALLOW_INSECURE_HTTP`, or a waiver from the next paragraph, does not
  start. Nor does one with no Redis for its replay record, or with no stated
  choice about signatures on registry modules.

**Transitional.** For a deployment that is moving to hardened. The same
checks run at start, and each rule can be left off by naming it: a job
signed with the shared key, or one that carries its secrets, by listing
`dispatch` or `envelope` in `AEGIX_ALLOW_LEGACY_FLEET_HMAC`; a
model-provider key from the environment by
`AEGIX_WORKER_ALLOW_ENV_PROVIDER_KEYS`. The worker's own write-ceiling check
is off unless it is switched on. Each waiver is logged as an error at each
start. The two development settings for private hosts and plain HTTP
are refused here as they are under hardened, and so is a worker with no
Redis.

This tree has no run of a hardened or a transitional worker against the
reference controller; the demo, a development worker with those switches
on, is the configuration that has been run.

Whatever the profile: give the worker no credential it does not need. The
worker reads `EMAIL_API_KEY` and `S3_*` from its environment when they are
there, and uses them for modules in the worlds that have mail and object
storage.
