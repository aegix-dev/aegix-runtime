//! `aegix-e2e-probe`: the second identity of the hardened end-to-end leg
//! (scripts/test-e2e.sh, `AEGIX_E2E_LEGS=hardened`; the record is
//! docs/engineering-log/packages/2026-11-06-the-hardened-end-to-end-leg.md).
//!
//! It connects to the LIVE broker exactly as a worker on
//! `AEGIX_WORKER_NATS_AUTH=identity` does (`worker::nats_identity::
//! identity_connect_options`: the worker's Ed25519 key as a user nkey, its id
//! as the connection name, its own inbox prefix), so the broker's auth
//! callout — served by the controller under test — decides it as it decides
//! any worker. It then asks for one of two things that identity must be
//! refused, and exits by what it was given:
//!
//! * `inbox` — subscribe to ANOTHER worker's reply inbox
//!   (`_WINBOX.<target>.>`). Exit 0 when the broker refuses the subscription
//!   (a permissions violation naming it) and its own inbox is admitted;
//!   exit 2 when the foreign inbox was admitted.
//! * `memory-get` — a `talos.memory.op` Get, signed with this identity's key
//!   and bound to a dispatch `(execution, job)` that ANOTHER worker claimed.
//!   Exit 0 on the controller's `Unauthorized`; exit 2 when it was served.
//!   With `--nats-user` and `--nats-password-file` it logs in to the broker by
//!   password instead (a broker with no auth callout, as the reference
//!   controller's is); the request is signed with the identity's key as before.
//!
//! A third command serves the refusal demo (docs/refusal-demo.md; judged by
//! scripts/demo/refusal-judge.sh), on a stack whose workers share one key:
//!
//! * `fleet-memory-get` — the same `talos.memory.op` Get, signed with the
//!   FLEET key (`WORKER_SHARED_KEY`) and sent as the shared worker NATS user,
//!   which is everything a worker on such a stack holds. Exit 0 on
//!   `Unauthorized`; exit 2 when it was served. The demo asks twice, with one
//!   request: while the named job runs (served) and after it has ended
//!   (refused), so the only thing that differs is whether the job is live.
//!
//! Exit 1 is any other failure (the probe could not tell). A key is read
//! from a file (`--key-file`, 64 hex characters; for the fleet key
//! `WORKER_SHARED_KEY_FILE`, the loader every process uses; the NATS password
//! `--nats-password-file`), never from an argument: a process's arguments are
//! readable by every user of the machine.

use std::time::Duration;

use aegix_rpc_protocol::dispatch_binding::DispatchBinding;
use aegix_rpc_protocol::memory_rpc::{
    MemoryOp, MemoryRpcError, MemoryRpcReply, MemoryRpcRequest, SUBJECT_MEMORY_OP,
};
use anyhow::{anyhow, bail, Context, Result};
use uuid::Uuid;

const USAGE: &str = "usage:\n  \
    aegix-e2e-probe inbox --nats <url> --worker-id <id> --key-file <path> --target <worker id>\n  \
    aegix-e2e-probe memory-get --nats <url> --worker-id <id> --key-file <path> \
--actor <uuid> --execution <uuid> --job <uuid> --key <memory key> \
[--nats-user <user> --nats-password-file <path>]\n  \
    WORKER_SHARED_KEY_FILE=<path> aegix-e2e-probe fleet-memory-get --nats <url> --nats-user <user> \
--nats-password-file <path> --actor <uuid> --execution <uuid> --job <uuid> --key <memory key>";

/// Exit status when the identity WAS given what it must be refused.
const ADMITTED: i32 = 2;

struct Args {
    nats: String,
    /// The pinned identity's id; empty for `fleet-memory-get`, which has none.
    worker_id: String,
    rest: std::collections::HashMap<String, String>,
}

fn parse(args: &[String]) -> Result<Args> {
    let mut map = std::collections::HashMap::new();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let name = flag
            .strip_prefix("--")
            .ok_or_else(|| anyhow!("unexpected argument {flag:?}\n{USAGE}"))?;
        let value = it
            .next()
            .ok_or_else(|| anyhow!("{flag} needs a value\n{USAGE}"))?;
        map.insert(name.to_string(), value.clone());
    }
    let nats = map
        .remove("nats")
        .ok_or_else(|| anyhow!("--nats is required\n{USAGE}"))?;
    let worker_id = map.remove("worker-id").unwrap_or_default();
    Ok(Args {
        nats,
        worker_id,
        rest: map,
    })
}

impl Args {
    fn get(&self, k: &str) -> Result<&str> {
        self.rest
            .get(k)
            .map(String::as_str)
            .ok_or_else(|| anyhow!("--{k} is required\n{USAGE}"))
    }
    fn uuid(&self, k: &str) -> Result<Uuid> {
        self.get(k)?
            .parse()
            .with_context(|| format!("--{k} is not a UUID"))
    }
}

/// Connect as `worker_id`, reporting every server error the connection is
/// sent on the returned channel (a refused subscription arrives that way).
async fn connect(
    args: &Args,
    key: &aegix_workflow_job_protocol::DispatchSigningKey,
) -> Result<(
    async_nats::Client,
    tokio::sync::mpsc::UnboundedReceiver<String>,
)> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let base = async_nats::ConnectOptions::new()
        .connection_timeout(Duration::from_secs(10))
        .event_callback(move |event| {
            let tx = tx.clone();
            async move {
                if let async_nats::Event::ServerError(e) = event {
                    let _ = tx.send(e.to_string());
                }
            }
        });
    // A broker with no auth callout (the reference controller's: one shared
    // worker user) is logged in to by password. The request is still signed
    // with this identity's key, which is what the controller decides on.
    if let Some(user) = args.rest.get("nats-user") {
        let password = read_password_file(args.get("nats-password-file")?)?;
        let client = base
            .custom_inbox_prefix(aegix_workflow_job_protocol::nats_permissions::WORKER_INBOX_PREFIX)
            .user_and_password(user.clone(), password)
            .connect(args.nats.as_str())
            .await
            .with_context(|| format!("the broker refused the worker user {user}"))?;
        return Ok((client, rx));
    }
    let opts = worker::nats_identity::identity_connect_options(base, &args.worker_id, key, None)
        .map_err(|e| anyhow!(e))?;
    let client = opts.connect(args.nats.as_str()).await.with_context(|| {
        format!(
            "the broker refused {} (is the callout served?)",
            args.worker_id
        )
    })?;
    Ok((client, rx))
}

/// The NATS password a file holds.
fn read_password_file(path: &str) -> Result<String> {
    Ok(std::fs::read_to_string(path)
        .with_context(|| format!("could not read --nats-password-file {path}"))?
        .trim()
        .to_string())
}

/// Every server error that arrives within `wait`.
async fn errors_within(
    rx: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    wait: Duration,
) -> Vec<String> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    while let Ok(Some(e)) = tokio::time::timeout_at(deadline, rx.recv()).await {
        out.push(e);
    }
    out
}

async fn inbox(args: &Args, key: &aegix_workflow_job_protocol::DispatchSigningKey) -> Result<i32> {
    let target = args.get("target")?;
    let own = format!("_WINBOX.{}.probe", args.worker_id);
    let foreign = format!("_WINBOX.{target}.>");
    let (client, mut rx) = connect(args, key).await?;

    // Positive control: this identity's own inbox is admitted. Without it a
    // refusal below could be a broker that refuses every subscription.
    let _own = client.subscribe(own.clone()).await?;
    client.flush().await?;
    let own_errors = errors_within(&mut rx, Duration::from_secs(2)).await;
    if let Some(e) = own_errors.iter().find(|e| e.contains(&own)) {
        bail!("the broker refused this identity's OWN inbox {own}: {e}");
    }
    println!("admitted: {own} (own inbox)");

    let _foreign = client.subscribe(foreign.clone()).await?;
    client.flush().await?;
    let errors = errors_within(&mut rx, Duration::from_secs(5)).await;
    match errors
        .iter()
        .find(|e| e.to_ascii_lowercase().contains("permissions violation") && e.contains(target))
    {
        Some(e) => {
            println!("refused: {foreign} ({e})");
            Ok(0)
        }
        None => {
            println!(
                "ADMITTED: {} subscribed to {foreign}; server errors seen: {errors:?}",
                args.worker_id
            );
            Ok(ADMITTED)
        }
    }
}

async fn memory_get(
    args: &Args,
    key: std::sync::Arc<aegix_workflow_job_protocol::DispatchSigningKey>,
) -> Result<i32> {
    // Sign as this identity, exactly as the worker's RPC client does.
    aegix_rpc_protocol::rpc_auth::register_ed25519_signing_key(args.worker_id.clone(), key.clone());
    let (client, _rx) = connect(args, &key).await?;
    ask_memory_get(args, &client, &args.worker_id).await
}

/// `fleet-memory-get`: the request a worker on a shared-key stack can make.
/// The fleet key is read by the loader every process uses
/// (`WORKER_SHARED_KEY_FILE`), the NATS password from `--nats-password-file`,
/// and the connection is the shared worker user's, with the worker's inbox
/// prefix, so the broker's permission set is the one a worker is under.
async fn fleet_memory_get(args: &Args) -> Result<i32> {
    let user = args.get("nats-user")?.to_string();
    let password = read_password_file(args.get("nats-password-file")?)?;
    let shared = aegix_workflow_job_protocol::load_worker_shared_key()
        .map_err(|e| anyhow!("the fleet key: {e}"))?;
    aegix_rpc_protocol::rpc_auth::register_hmac_key(std::sync::Arc::new(
        shared.as_bytes().to_vec(),
    ));
    let client = async_nats::ConnectOptions::new()
        .connection_timeout(Duration::from_secs(10))
        .custom_inbox_prefix(aegix_workflow_job_protocol::nats_permissions::WORKER_INBOX_PREFIX)
        .user_and_password(user.clone(), password)
        .connect(args.nats.as_str())
        .await
        .with_context(|| format!("the broker refused the worker user {user}"))?;
    ask_memory_get(args, &client, "the fleet key").await
}

/// One `talos.memory.op` Get bound to `--execution`/`--job`, signed with
/// whatever key this process registered; the exit status is what came back.
async fn ask_memory_get(args: &Args, client: &async_nats::Client, signer: &str) -> Result<i32> {
    let actor_id = args.uuid("actor")?;
    let binding = DispatchBinding {
        execution_id: args.uuid("execution")?,
        job_id: args.uuid("job")?,
    };
    let memory_key = args.get("key")?.to_string();
    let req = MemoryRpcRequest::new_signed_bound(
        actor_id,
        Some(binding),
        MemoryOp::Get {
            key: memory_key.clone(),
        },
    )
    .ok_or_else(|| anyhow!("the request could not be signed"))?;
    let payload = serde_json::to_vec(&req)?;
    let msg = tokio::time::timeout(
        Duration::from_secs(15),
        client.request(SUBJECT_MEMORY_OP, payload.into()),
    )
    .await
    .map_err(|_| anyhow!("no reply from {SUBJECT_MEMORY_OP} in 15 s"))??;
    let reply: MemoryRpcReply =
        serde_json::from_slice(&msg.payload).context("the reply is not a MemoryRpcReply")?;
    match reply.result {
        Err(MemoryRpcError::Unauthorized) => {
            println!(
                "refused: {SUBJECT_MEMORY_OP} Get {memory_key:?} for job {} as {signer} (Unauthorized)",
                binding.job_id
            );
            Ok(0)
        }
        Ok(served) => {
            println!(
                "SERVED: {SUBJECT_MEMORY_OP} Get {memory_key:?} for job {} as {signer}: {served:?}",
                binding.job_id
            );
            Ok(ADMITTED)
        }
        // The controller looked the key up for this signer: admitted.
        Err(MemoryRpcError::KeyNotFound) => {
            println!(
                "SERVED: {SUBJECT_MEMORY_OP} Get {memory_key:?} for job {} as {signer}: no such key",
                binding.job_id
            );
            Ok(ADMITTED)
        }
        Err(other) => {
            bail!("{SUBJECT_MEMORY_OP} answered {other:?}, neither served nor Unauthorized")
        }
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let status = match run(&argv).await {
        Ok(code) => code,
        Err(e) => {
            eprintln!("aegix-e2e-probe: {e:#}");
            1
        }
    };
    std::process::exit(status);
}

async fn run(argv: &[String]) -> Result<i32> {
    let (cmd, rest) = argv.split_first().ok_or_else(|| anyhow!("{USAGE}"))?;
    let args = parse(rest)?;
    if cmd == "fleet-memory-get" {
        return fleet_memory_get(&args).await;
    }
    if args.worker_id.is_empty() {
        bail!("--worker-id is required\n{USAGE}");
    }
    let key_file = args.get("key-file")?;
    let raw = std::fs::read_to_string(key_file)
        .with_context(|| format!("could not read --key-file {key_file}"))?;
    let key = aegix_workflow_job_protocol::parse_ed25519_signing_key_hex(raw.trim())
        .map_err(|e| anyhow!("--key-file does not hold an Ed25519 seed: {e}"))?;
    match cmd.as_str() {
        "inbox" => inbox(&args, &key).await,
        "memory-get" => memory_get(&args, std::sync::Arc::new(key)).await,
        other => bail!("unknown command {other:?}\n{USAGE}"),
    }
}
