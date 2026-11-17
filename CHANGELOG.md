# Changelog

One section per release, the newest first. A release is the tag `v<version>`;
`make release-check` holds the workspace version, `compose.yaml` and the first
section here to one another.

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
