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

The first outside review, of 0.1.0, found a third. A module's `Host` header
was sent as the module wrote it, while its list of hosts and the destination
of its secrets were decided on the URL. A module granted one name on a
shared front end (a bucket of an object store, one customer of a CDN) could
name another to the server, and a secret granted for the first went with
the request. The header is refused now, with the fields that belong to the
connection (`docs/threat-model.md`, section A).

The same review reported a worker test dying of a segmentation fault on
Linux x86_64, in the allocator that hands modules their memory. That has
not been reproduced. The worker asked wasmtime to use memory protection
keys where a processor had them, and no machine this tree is tested on has
such a processor, the hosted x86_64 runner included. The worker no longer
asks, so every platform takes the path the tests take; whether that was the
cause is not known. A test of this tree that crashes on your machine is a
flaw to report.

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
  answers to data calls are readable by anyone who can subscribe.
* **An answer to a data call is not signed.** A job, a result and a data
  call are; the answer the controller sends back is not. A worker takes it
  from its own inbox, and what keeps another party from answering first is
  the broker's rule that the worker login may not publish there
  (`deploy/nats/worker-permissions.conf`). With the controller's login, or
  on a broker without that rule, a worker can be handed a made-up answer,
  and its module reads it as its actor's memory. Until 0.1.1 this page said
  the answers were signed.
* **A log line is not signed.** A worker publishes the lines of a running
  job on a subject named for the job, and the worker login may publish
  there. The controller keeps the first 200 lines it receives, puts the
  lines of the signed result after them, and drops what is past 200. It
  cannot tell who sent a line. Whoever holds that login and learns a
  running job's id can put lines into its record, and with 200 of them
  leave none of the worker's own. The id is not a secret: with the one
  login every worker shares here, it can be read from the answer to another
  worker's claim. Read a job's log as what was said on the bus, not as what
  the module did.
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

* **A worker's report.** The output, the status, the time taken and the
  fuel spent are what the worker said. The controller checks who signed the
  result that carries them. The log lines sent while the job ran are not
  signed at all ([The message bus](#the-message-bus)).
* **A job nobody claimed.** A job granted no secret is not claimed, so while
  it runs any listed worker is served its actor's memory. Under `fleet-key`
  any holder of the key is.
* **Two seconds.** A data call can be served up to two seconds after its job
  ends, because a gate's "yes" is remembered that long.
* **The control socket.** Whoever can reach it is the operator: they can
  dispatch jobs and write any actor's memory, with no ceiling. It is guarded
  by the permissions of its directory and nothing else.

## Compiling a module's source

The threat model is about a module that is **run**. Compiling one is a
different act, and nothing here makes it safe to compile source you did not
write.

* **The compile runs on your machine, as you.** `compile_module`, the
  example in [embedding.md](embedding.md), runs `cargo component build` in a
  scratch project with your user's rights. A source file can read the build
  machine into the module it becomes: `include_bytes!("/path/to/a/file")`
  embeds a file, and `env!("NAME")` embeds a variable of the environment the
  compile ran in. The module can then return what it embedded.
* **The source lint does not stop that.** Before a compile, the source is
  read for `unsafe`, `extern "…"`, `std::process::`, `env!`, `include_str!`,
  `include_bytes!`, `include!` and `#[path = …]`, and a finding refuses the
  compile (`aegix-module-source/src/lint.rs`, `errors`). It reads the text
  line by line. A space before the `!`, a quote earlier on the line or an
  attribute split over two lines gets past it, and each finding has an
  opt-out comment the source's own author writes. It tells an honest author
  early what will not work. It is not a control.
* **The crates a source asks for are code too.** A dependency's build script
  and its procedural macros run during the compile. The list of crates a
  source may ask for (`aegix-compilation/src/dependency_allowlist.rs`) says
  which crates, not what they do.
* **What contains a compile is a container.** `aegix-compilation` can run
  the build in one with no network, a read-only root and an empty
  environment (`AEGIX_COMPILATION_CONTAINER=true`, image named by
  `AEGIX_BUILDER_IMAGE`). This tree carries that code and no image for it:
  you build the image, with the toolchain and the crates a build may use
  already in it. Off the host, a source that reads a file reads the image's.

So: compile source from an author you trust, or in a container or a machine
that holds nothing you would mind a module carrying away. A module you were
given as a compiled component needs none of this; running it is the case the
threat model covers.

## Availability

Not defended. The records that stop replays are of fixed size and refuse new
messages when full; the controller runs at most 64 jobs at once and answers
at most 64 claims at once; a subject can be flooded by anyone who can
publish to it. These fail closed: work stops, data does not leave.

## Model calls

`allowed_hosts` governs a module's HTTP requests: `http`, `graphql`,
`webhook`, `http-stream` and `wasi:http`. The model interfaces (`llm`,
`llm-tools`, `llm-streaming`, `embedding`) do not read it. A module in a
world that has them (`llm-node`, `secrets-node`, `database-node`,
`agent-node`, `automation-node`) sends its prompt to the model server at
`OLLAMA_URL`, or to a provider the worker holds a key for, whatever its
list of hosts says. A module with an empty `allowed_hosts` is therefore not
a module that sends nothing out. What decides is:

* the world the module is linked with;
* the actor's tier: an actor held to local models is refused the providers;
* whether the worker has a key. The reference controller hands a job none,
  and a worker takes one from its own environment only in the development
  profile, or in the transitional one under a named waiver.

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
here, and one crate carries instructions written for its maintainers
(`aegix-workflow-job-protocol/AGENTS.md`). The project is published as
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
