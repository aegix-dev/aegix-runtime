# Limits

What this tree does not do, said before somebody finds out. The first four
are the ones on the first page. [threat-model.md](threat-model.md) says what
is defended; where the two disagree, this page is the one to believe and the
disagreement is a flaw to report ([SECURITY.md](../SECURITY.md)).

## The four on the first page

**1. A host a module is permitted to call is a way out.** The runtime decides
*where* a module may send things, not *what*. A module allowed to call one
host can send that host its input, whatever it read from its actor's memory,
and any secret granted for that host; and a GET is enough, because a URL
carries data. What narrows it:

* Grant exact hosts, and as few as the module needs. The reference
  controller refuses `*`.
* Grant a secret only beside the one host it is for. A `vault://` reference
  is filled in only for a host the grant names.
* Make the actor read-only when it only reads. That stops every verb but
  GET, not GET.
* A host that returns request headers in its response hands a granted secret
  back to the module. Do not grant a secret for a host like that.

**2. WebAssembly components only.** A module is a component compiled against
`wit/aegix.wit`. This tree does not run containers, native code, Python or
JavaScript as they are, or a core WebAssembly module that is not a component.
The sandbox is wasmtime's: its flaws, and those of the processor and kernel
under it, are not defended here. Modules for different actors run in one
worker process.

**3. Before 1.0.** The wire format, the interface in `wit/aegix.wit`, the
configuration file and the environment variables may all change between
releases, and a controller and a worker of different versions are not
promised to work together. `CHANGELOG.md` says what changed.

**4. No outside audit has been made.** The threat model was written by the
person who wrote the code, by reading it. Writing it found two flaws, both
fixed before 0.1.0, and most of what follows on this page. A worker could
hold a timed-out job open by publishing log lines. And a worker signed a
failure for a job it could not verify, so a sender with no key could have a
running job recorded as failed. Expect more to be found.

## Defaults are for development

A worker started without `RUST_ENV`, or with a development one, leaves
several rules off: its own write-ceiling check, the refusal of jobs signed
with the shared key, the refusal of secrets that travel with their job, and
signature checks on modules pulled from a registry. It also honours two
switches that let a module reach private addresses and plain HTTP. The demo
turns the first three on by hand. The threat model lists them under "What a
deployment must set". The hardened profile has not been run against the
reference controller in this tree.

## The message bus

* **Only a job's secrets are encrypted.** Inputs, modules, results and the
  answers to data calls are signed and readable by anyone who can subscribe.
* **Every worker logs in to the broker as one user** in the configuration
  this tree carries (`deploy/nats/nats-shared-worker.conf`), so that login
  can take a share of the jobs and read answers meant for another worker.
* **No TLS** in the demo's broker, and the reference controller has no
  setting for one.
* **A job sent again after five minutes.** Whoever can read the bus and
  publish jobs (the controller's broker login, or anyone on a broker with no
  permissions) can send a job the controller signed a second time. Within
  five minutes a worker that has seen it refuses it and does not answer.
  After that, while the job still runs, the worker answers that it arrived
  too late, and the controller records the job as failed. When the job's
  secrets were claimed, that answer is taken only from the worker that
  claimed them. It needs a job that runs longer than five minutes. Read in
  the code; not exercised by a run.
* For anything but one machine: a broker with TLS, a login per worker, and
  the bus on a network only the controller and the workers reach. None of
  that is set up here.

## The `fleet-key` posture

For development on one machine, and refused elsewhere. Every worker holds
the one key, so any of them can sign as any other, read the secrets of any
job it can see, and send jobs the others accept. What still holds is the
job: a data call must name a job the controller is running.

## What the controller takes on trust

* **A worker's report.** The output, the status, the time taken, the fuel
  spent and the log lines are what the worker said. The controller checks
  who signed them.
* **A job nobody claimed.** A job granted no secret is not claimed, so while
  it runs any listed worker is served its actor's memory. Under `fleet-key`
  any holder of the key is.
* **Two seconds.** A data call can be served up to two seconds after its job
  ends, because a gate's "yes" is remembered that long.
* **The control socket.** Whoever can reach it is the operator: they can
  dispatch jobs and write any actor's memory, with no ceiling. It is guarded
  by the permissions of its directory and nothing else.

## Availability

Not defended. The records that stop replays are of fixed size and refuse new
messages when full; the controller runs at most 64 jobs at once and answers
at most 64 claims at once; a subject can be flooded by anyone who can
publish to it. These fail closed: work stops, data does not leave.

## What the worker can hold

The worker holds no secret store. It can still be handed credentials in its
environment, and it uses them for modules:

* `EMAIL_API_KEY` and `S3_*`, for modules in the worlds that send mail or
  use object storage. One set for every module and actor. Object storage
  goes to the endpoint the operator set and is not checked against
  `allowed_hosts`.
* A model-provider key, in the development profile only.
* `OLLAMA_URL`, taken to be a local model server. Nothing checks that it is.
* Its broker login. A module in a world with messaging publishes with it, on
  any subject that is not reserved.
* A Redis, when one is configured. A module's cache is kept apart by user,
  not by module.

Give a worker none of these unless a module needs it.

## Time zones

A module asks the host for a zone's offset (`local-offset-seconds` in the
`datetime` interface). The answer comes from the IANA time zone database
compiled into the worker, release 2026f, through a library that is still
released with the database (`jiff-tzdb`). The machine's own zone files are
never read, so an image without them, or with old ones, answers the same.
What that leaves:

* New rules arrive by a newer `jiff-tzdb` in `Cargo.lock` and a build, and in
  no other way. A worker built before a government changes its clocks answers
  by the rules it was built with until it is built again. Nothing warns of
  it: the zone is found, and the offset is the old one.
* A zone is a name the database lists, written exactly as it lists it
  (`America/New_York`, not `america/new_york`). An offset such as `-04:00`
  is not a zone.
* An instant after the year 9999 is refused.

`chrono`, the date library the tree uses, is no longer maintained; no
vulnerability is known in it, and it is accepted in `deny.toml` with its
reason.

## The reference controller

It is a reference, the smallest program that keeps the promise, and not a
service to run a business on ([reference-controller.md](reference-controller.md)
has the whole list):

* Its record is in memory. A restart forgets every job and every memory
  value that is not in its configuration file.
* It is one process, and its record of spent nonces is its own. Two on one
  broker would each accept a signed request once.
* It serves actor memory and nothing else. A module's SQL, graph search,
  integration state and model inference are answered "not available", so the
  worlds built on them have not been run in this tree.
* It sends a module's bytes with the job, under the job's signature. It does
  not say who wrote the module or what it does. The worker's registry and
  signature-verification paths are in this tree and are not used by it.

## What the demo shows, and does not

Five refusals and four more cases, with one set of grants, on one machine.
It shows that those gates are wired end to end. It does not show that no
other route exists, and it runs a development profile.

## The tree itself

It is made from a private repository by a script. Remarks in the source
sometimes name files, checks and records of that repository that are not
here, and two crates carry instructions written for its maintainers
(`aegix-workflow-job-protocol/AGENTS.md` and
`aegix-workflow-engine-core/AGENTS.md`). The project is published as
Aegix Runtime, its crates are named `aegix-*`, its environment variables
begin `AEGIX_`, its metric names `aegix_`, and the interface a module is
compiled against is the package `aegix:core`. It was developed as Talos, a
name other projects also use, and some identifiers still say so, in lower
case: the message subjects (`talos.jobs`, `talos.memory.op`), the log
targets that are not a crate's name (`talos_security`, `talos_rpc`,
`talos_audit`), the prefixes of its Redis keys, the labels its keys are
derived with, a module template's manifest (`talos.json`), the marker a
compiled module names its world with, the user and the paths inside the
images, and the names of the compile sandbox's image and containers. Remarks
also cite alerts of the private repository by their names, which begin
`Talos`. All of these name nothing but this runtime. A change to one that
two processes exchange is a change to the wire format, under limit 3. A
process refuses to start while a variable that begins with the former name,
in capitals, is in its environment, since nothing reads one.
