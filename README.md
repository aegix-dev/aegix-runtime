# Aegix Runtime

A runtime for code an AI wrote. A module is a WebAssembly component, and the
worker that runs it holds no secret store and no database login. It is sent a
signed job, and asks for the rest.

**What this is.** A runtime to embed, the worker built on it, and a reference
controller small enough to read. It is not a product to deploy as it stands:
the reference controller keeps its record in memory, and a deployment brings
its own, written against the same gates ([docs/embedding.md](docs/embedding.md)).

## Quick start

With Docker or Podman, `make`, `bash` and `python3` (3.9 or later):

```bash
make demo-image
```

It builds one image from this tree and runs it. The build needs the network
and no toolchain; on an eight-core Apple Silicon laptop, with the base images
pulled, build and run took about six minutes (2026-11-15). The run is given
no network. Inside the one container it starts a message bus, a controller
and one worker, and runs a module written to misbehave. The module tries to:

1. read a secret it was not granted,
2. call a host that is not on its list,
3. reach an external model as an actor held to local models,
4. write as a read-only actor,
5. use its job after the job has ended.

Each attempt is refused, and the run prints what was asked, what was given,
and the source file and line where the deciding function is declared. Two
things the module is entitled to are served first, so a refusal is not a
worker that refuses everything.

Other ways to the same run:

```bash
make images-smoke ONLY=demo    # the image again, without building it
docker compose run --rm demo   # the same; `podman compose` needs a compose provider installed
make demo                      # from source; `make help` says what it needs
```

`docker compose run --rm demo` pulls nothing after `make demo-image`; on a
machine that has not built the image it pulls a release's, from
`ghcr.io/aegix-dev/aegix-runtime`. A release's page carries
`compose.pinned.yaml`, the same file held to the digest that was signed.

What each step shows, and how to make a refusal go away to see that it was
real: [docs/refusal-demo.md](docs/refusal-demo.md).

## How it works

Whatever a module touches that belongs to somebody (a secret, an actor's
memory) it asks of the controller that signed its job. The controller answers
only for a job it is running, and only within what the module and its actor
were granted. A worker that is taken over has the jobs it was sent, while
they run, and the threat model says what else it can and cannot reach.

* [docs/threat-model.md](docs/threat-model.md): what is defended, against
  whom, and the file that decides each rule.
* [docs/limits.md](docs/limits.md): what is not defended.
* [docs/reference-controller.md](docs/reference-controller.md): the controller
  in this tree, its two postures, and how to run your own module under it.
* [docs/embedding.md](docs/embedding.md): the runtime in your own program,
  and what a controller of your own must supply.

## What is here

| Path | What it is |
|---|---|
| `worker/` | the worker binary |
| `aegix-runtime/` | the runtime as one crate to embed |
| `aegix-rpc-gates/` | admission, the dispatch-binding gate and the write-ceiling gate |
| `aegix-reference-controller/` | a controller in one binary, with its record in memory |
| `wit/aegix.wit` | the interface between a module and its host |
| `scripts/demo/`, `module-templates/` | the hostile module and the demo's image; two small modules to read |
| `compose.yaml`, `CHANGELOG.md` | the demo from a release's image; what each release holds |

`make help` lists what can be run; `make docs-check` holds these documents to the tree.

## Limits

* A host a module is permitted to call is a way out for whatever the module
  was given.
* WebAssembly components only.
* Before 1.0: the wire format and the interface may change.
* No outside audit has been made.

Each, with the others and what to do about it: [docs/limits.md](docs/limits.md).

## Changes, flaws, licence

This tree is made from a private repository by a script, one commit at a
time, and carries no history; `PROVENANCE.json` names the commit. Remarks in
the source sometimes name a file of that repository that is not here. Issues
and patches: [CONTRIBUTING.md](CONTRIBUTING.md). A flaw: [SECURITY.md](SECURITY.md).

Licensed under either of Apache-2.0 or MIT, at your option.
