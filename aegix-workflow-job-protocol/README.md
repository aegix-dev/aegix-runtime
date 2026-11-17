# aegix-workflow-job-protocol

[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

The signed wire format between a controller and its workers: the job a
controller sends, the result a worker returns, and the envelope a job's
secrets travel in. Used on both sides:

- **A controller** builds a `JobRequest`, signs it and publishes it, and
  verifies the `JobResult` that comes back. `aegix-reference-controller` is
  the smallest one.
- **A worker** verifies the request, opens or claims its secrets, runs the
  module, and replies with a signed `JobResult`.

## What's on the wire

- **`JobRequest`**: one module to run. The module (its bytes or where to
  fetch them, and the capability world it is linked at), the input, the
  module's grants, the actor's ceilings, fuel and time limits, a `job_nonce`,
  and a signature over all of it.
- **`JobResult`**: the reply. Status, output or error, the fuel spent, and
  the attempt and run it answers, under the worker's signature.
- **`EncryptedSecrets`** and **`envelope_seal`**: the two ways a job's
  secrets travel. In the job, AES-256-GCM under a key derived for that job
  from the key the fleet shares; or, where each worker has a key pair of its
  own, held back by the controller and sealed to a key the worker that
  picked the job up made for that one claim.

## Security invariants

- **Every message is signed.** There are two schemes. Ed25519, with a key
  pair per process (`DispatchSigner`, `Verifier`), is the one to deploy.
  HMAC-SHA256 under one key every worker holds (`WORKER_SHARED_KEY`) is for
  development on one machine: any holder of that key can sign as any other.
- **What is signed is what was sent.** Scalar fields are signed as a tagged
  concatenation in a fixed order, and a JSON body as its exact wire text
  (`RawSigned<T>`), so signer and verifier cannot disagree about how a number
  is written. A field added to a message later is appended to the signed
  bytes only when it is set, so a message without it verifies as before.
- **Replay.** The receiver remembers each `job_nonce` and refuses a message
  that is older than its window or more than five seconds in the future.
  `verify` and `verify_dispatch` record the nonce, so a process calls one of
  them once per message; an observer uses the `verify_no_replay` forms.
- **A result names the dispatch it answers** (`JobResult::bind_to_request`),
  and a receiver takes it only when `JobResult::answers` says so. Where the
  job's secrets were claimed, `sealed_result_refused` holds the result to
  the worker that claimed them.
- **Grants have one matcher each**, used by the controller that writes a
  grant and the worker that enforces it: `vault_path_permitted` for secret
  paths (a path covers the paths beneath it; `*` grants nothing) and
  `method_permitted` for HTTP verbs (an empty list denies every verb).
  Model-provider key paths (`LLM_PROVIDER_VAULT_PATHS`) are the host's and
  are never served to a module, whatever its grant.

## Quickstart

```toml
[dependencies]
aegix-workflow-job-protocol = { git = "https://github.com/aegix-dev/aegix-runtime" }
```

The shared-key form, which is the shortest to show. With a key pair per
process the calls are `sign_ed25519` with the controller's
`DispatchSigningKey`, and `verify_dispatch` with the public keys the
receiver believes.

```rust,ignore
use aegix_workflow_job_protocol::{JobRequest, JobResult};

// A controller fills in a JobRequest and signs it in place.
let mut req: JobRequest = build_job_request();
req.sign(&worker_shared_key).expect("sign ok");
let bytes = serde_json::to_vec(&req)?;
// publish `bytes` on your transport

// A worker verifies it against the same key and a freshness window in
// seconds. `verify` records the nonce: call it once per message.
let req: JobRequest = serde_json::from_slice(&bytes)?;
req.verify(&worker_shared_key, 300).expect("verify ok");

// The reply names the request it answers, and is signed.
let mut result: JobResult = run_the_module(&req);
result.bind_to_request(&req);
result.sign(&worker_shared_key).expect("sign ok");
```

The crate is pure types + signing / verification helpers. It doesn't
pick a transport, doesn't pick a serialization format (callers
typically use `serde_json` as above), and doesn't own any I/O.

## Stability

Pre-1.0: the wire format may change between releases, and a controller and
a worker of different versions are not promised to work together. Once
stable: a new optional field is not a breaking change; changing what a field
means, or adding a required one, is.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or
  <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  <https://opensource.org/licenses/MIT>)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual-licensed as above, without any additional terms or
conditions.
