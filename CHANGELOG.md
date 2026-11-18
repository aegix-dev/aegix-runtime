# Changelog

One section per release, the newest first. A release is the tag `v<version>`;
`make release-check` holds the workspace version, `compose.yaml` and the first
section here to one another.

## 0.1.1

Answers the first outside review of 0.1.0.

- **Fixed: a module's `Host` header was sent as the module wrote it.** A
  module's list of hosts, and the destination of a secret granted to it, are
  decided on the URL. A `Host` header names another site to the server that
  answers. A module granted one name on a shared front end (a bucket of an
  object store, one customer of a CDN) could reach another's, and a secret
  granted for the first went with the request. `Host` and the fields that
  belong to the connection (`Transfer-Encoding`, `Connection`, `Upgrade` and
  seven more) are now refused on every request path (`http`, `graphql`,
  `webhook`, `http-stream`) before a secret is filled in or a connection is
  opened, under the reason `request-header-refused`. Upgrade a worker that
  runs modules against a host that serves more than one tenant.
- **Every commit is tested on Linux x86_64 and Linux arm64**
  (`.github/workflows/ci.yml`: the documents, rustfmt and clippy, every test
  that needs no service), and a release is refused unless that passed for
  its commit. Until now the tests had only been run on arm64.
- **Fixed: a test of `aegix-metrics` failed on Linux.** It compared the
  lengths of two whole renders, and on Linux a render carries the process
  collector, whose values change width. It now measures its own two metric
  families.
- **The review reported a crash on Linux x86_64** in a worker test
  (`cancellation_preempts_a_compute_bound_module`), in the pooling
  allocator. It could not be reproduced where this release was written,
  which has no x86_64 machine. `ci.yml` now runs that test on x86_64 for
  every commit and prints whether the runner's processor has memory
  protection keys, the path only x86_64 takes. This release exists because
  it passed there.
- **Documents corrected.** `docs/limits.md` and `docs/threat-model.md` said
  the answers to a worker's data calls were signed. They are not: what keeps
  a made-up answer out of a worker's inbox is the broker's permissions. The
  log lines a worker publishes while a job runs are not signed either, and
  the controller keeps the first 200 it receives. And the model interfaces
  (`llm`, `embedding`) do not read `allowed_hosts`. Each is written down
  with what it means.
- **New documents.** `docs/embedding.md`: the runtime in your own program,
  and what a controller of your own must supply. `CONTRIBUTING.md`: how an
  issue and a patch are taken. The first page says what this tree is: a
  runtime to embed with a reference controller to read, not a product to
  deploy as it stands.
- **`deny.toml`** excepts only advisories against crates this tree's lock
  file holds. It carried the exceptions of the repository it is exported
  from, most of them for crates that are not here.

Wire format: a refusal's reason may now be `request-header-refused`. Nothing
else that two processes exchange changed.

## 0.1.0

The first release.

- **The worker.** A WebAssembly host that holds no secret store and no
  database login. It runs a signed job, and what the job's module asks for
  that belongs to somebody (a secret, an actor's memory) it asks of the
  controller that signed the job.
- **The gates.** `aegix-rpc-gates`: admission of a signed request, the
  dispatch-binding gate (a worker's data call is answered only for a job that
  is running, and only as that job's actor) and the write-ceiling gate.
- **A reference controller.** One binary with its record in memory and no
  database, driven over a local socket. It dispatches a module, answers the
  worker's data calls through the gates, and has two postures: one key shared
  by the fleet (development only), and a key pair per worker with sealed
  secrets.
- **The demo.** A hostile module that tries to read a secret it was not
  granted, call a host that is not on its list, reach an external model as a
  local-only actor, write as a read-only actor, and use its job after the job
  has ended. Each attempt is refused, and the run names the source file that
  decided it. `make demo` runs it from this tree; `docker compose run --rm
  demo` runs it from an image.
- **Images** for `linux/amd64` and `linux/arm64`, signed without a stored key
  by the workflow that built them: `worker`, `reference-controller`, `demo`.
- **Documents.** `docs/threat-model.md` (what is defended, against whom, and
  the function that decides each rule), `docs/limits.md` (what is not), and
  `SECURITY.md` (where a flaw is reported). `make docs-check` holds every
  document to the tree.

Limits of this release: WebAssembly components only; the wire format and the
module interface may change before 1.0; a host a module is permitted to call
is still a way out for what the module was given; no outside audit has been
made. `docs/limits.md` has these and the rest.
