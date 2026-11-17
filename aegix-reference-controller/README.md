# aegix-reference-controller

A controller for Aegix workers in one small binary. It needs a NATS server
and nothing else.

It holds the secrets, signs each dispatch with a start deadline, hands a job
only the secrets its module is granted (encrypted to the job, or sealed to the
worker that claims it), answers a worker's actor-memory calls through the
dispatch-binding and write-ceiling gates, and takes a job's result only from a
worker it believes. Its record is held in memory.

The rules are not in this crate: admission and the gates are
`aegix-rpc-gates`, the signatures and the envelope are
`aegix-workflow-job-protocol`, the claim responder is `aegix-envelope-seal`.
The platform's controller calls the same functions over Postgres.

```bash
make test-e2e-reference    # this controller, an unmodified worker and a hostile module, both postures
```

How to configure and run it, its two postures, what it does not do, and what
the end-to-end run shows: [docs/reference-controller.md](../docs/reference-controller.md).

| Module | What it holds |
|---|---|
| `config` | the configuration file: posture, actors, modules, the secrets file |
| `keys` | the two postures and which keys each signs with and believes |
| `dispatch` | building and signing a request; what a result must pass |
| `ledger` | actors and jobs, and the facts the gates decide on |
| `data_plane` | the memory subject through admission and the gates; the subjects it does not serve |
| `memory` | actor memory, and the write ceiling in front of every mutation |
| `serve` | the order things happen in: dispatch, the wait, the claim recorder |
| `control` | the Unix socket and its commands |
| `counters` | every refusal, by decision, subject and reason |
