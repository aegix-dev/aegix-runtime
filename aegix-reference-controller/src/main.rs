//! `aegix-reference-controller`: serve, or ask a serving controller.

use aegix_reference_controller::{config, control, keys::Keys, serve::Controller};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};

const USAGE: &str = "\
aegix-reference-controller: a small controller for Aegix workers

  serve        --config FILE --control-dir DIR
  keygen       --out-dir DIR [--worker-id ID]

Ask a serving controller (each takes --control-dir DIR, or
AEGIX_REFERENCE_CONTROL_DIR):

  status
  counters
  dispatch     --module NAME --actor NAME [--input JSON | --input-file FILE] [--wait]
  wait         --job ID [--timeout-secs N]
  job          --job ID
  remember     --actor NAME --key KEY --value JSON [--type TYPE] [--ttl-hours H]
  forget       --actor NAME --key KEY
  keys         --actor NAME [--prefix P]
  actor-status --actor NAME --status active|suspended

serve reads NATS_URL (default nats://127.0.0.1:4222), and NATS_USER with
NATS_PASSWORD or NATS_PASSWORD_FILE when the server asks for them.

Exit: 0 served (and the job completed, when one is reported); 3 the job
failed, timed out or has not ended; 1 refused; 2 usage.
";

/// `--name value` pairs and bare `--flag`s after the subcommand.
struct Args {
    pairs: Vec<(String, Option<String>)>,
}

impl Args {
    fn parse(rest: &[String], flags: &[&str]) -> Result<Self, String> {
        let mut pairs = Vec::new();
        let mut it = rest.iter();
        while let Some(arg) = it.next() {
            let Some(name) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument {arg:?}"));
            };
            if flags.contains(&name) {
                pairs.push((name.to_string(), None));
            } else {
                let value = it.next().ok_or_else(|| format!("--{name} needs a value"))?;
                pairs.push((name.to_string(), Some(value.clone())));
            }
        }
        Ok(Self { pairs })
    }

    fn take(&mut self, name: &str) -> Option<String> {
        let at = self.pairs.iter().position(|(n, _)| n == name)?;
        self.pairs.remove(at).1
    }

    fn flag(&mut self, name: &str) -> bool {
        match self.pairs.iter().position(|(n, _)| n == name) {
            Some(at) => {
                self.pairs.remove(at);
                true
            }
            None => false,
        }
    }

    fn need(&mut self, name: &str) -> Result<String, String> {
        self.take(name)
            .ok_or_else(|| format!("--{name} is required"))
    }

    /// Every argument must have been read: a misspelt option is an error,
    /// not a default.
    fn done(self) -> Result<(), String> {
        match self.pairs.first() {
            None => Ok(()),
            Some((name, _)) => Err(format!("unknown option --{name}")),
        }
    }
}

fn control_dir(args: &mut Args) -> Result<PathBuf, String> {
    args.take("control-dir")
        .or_else(|| std::env::var("AEGIX_REFERENCE_CONTROL_DIR").ok())
        .filter(|d| !d.trim().is_empty())
        .map(PathBuf::from)
        .ok_or_else(|| "--control-dir (or AEGIX_REFERENCE_CONTROL_DIR) is required".to_string())
}

fn json_arg(text: &str, what: &str) -> Result<Value, String> {
    serde_json::from_str(text).map_err(|e| format!("{what} is not JSON: {e}"))
}

/// The request a client subcommand sends.
fn request_for(command: &str, args: &mut Args) -> Result<Value, String> {
    Ok(match command {
        "status" => json!({"cmd": "status"}),
        "counters" => json!({"cmd": "counters"}),
        "dispatch" => {
            let input = match (args.take("input"), args.take("input-file")) {
                (Some(_), Some(_)) => return Err("give --input or --input-file, not both".into()),
                (Some(text), None) => json_arg(&text, "--input")?,
                (None, Some(path)) => {
                    let text =
                        std::fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?;
                    json_arg(&text, "--input-file")?
                }
                (None, None) => json!({}),
            };
            json!({
                "cmd": "dispatch",
                "module": args.need("module")?,
                "actor": args.need("actor")?,
                "input": input,
                "wait": args.flag("wait"),
            })
        }
        "wait" => {
            let timeout = match args.take("timeout-secs") {
                Some(t) => Some(
                    t.parse::<u64>()
                        .map_err(|_| "--timeout-secs is a number of seconds".to_string())?,
                ),
                None => None,
            };
            json!({"cmd": "wait", "job_id": args.need("job")?, "timeout_secs": timeout})
        }
        "job" => json!({"cmd": "job", "job_id": args.need("job")?}),
        "remember" => {
            let ttl = match args.take("ttl-hours") {
                Some(t) => Some(
                    t.parse::<f64>()
                        .map_err(|_| "--ttl-hours is a number of hours".to_string())?,
                ),
                None => None,
            };
            json!({
                "cmd": "remember",
                "actor": args.need("actor")?,
                "key": args.need("key")?,
                "value": json_arg(&args.need("value")?, "--value")?,
                "memory_type": args.take("type"),
                "ttl_hours": ttl,
            })
        }
        "forget" => json!({
            "cmd": "forget", "actor": args.need("actor")?, "key": args.need("key")?
        }),
        "keys" => json!({
            "cmd": "keys",
            "actor": args.need("actor")?,
            "prefix": args.take("prefix").unwrap_or_default(),
        }),
        "actor-status" => json!({
            "cmd": "set_actor_status",
            "actor": args.need("actor")?,
            "status": args.need("status")?,
        }),
        other => return Err(format!("unknown command {other:?}")),
    })
}

async fn connect_nats() -> Result<async_nats::Client, String> {
    let url = std::env::var("NATS_URL")
        .ok()
        .filter(|u| !u.trim().is_empty())
        .unwrap_or_else(|| "nats://127.0.0.1:4222".to_string());
    let mut options = async_nats::ConnectOptions::new().name("aegix-reference-controller");
    if let Some(user) = std::env::var("NATS_USER").ok().filter(|u| !u.is_empty()) {
        let password = match std::env::var("NATS_PASSWORD_FILE")
            .ok()
            .filter(|p| !p.trim().is_empty())
        {
            Some(path) => config::read_private_file("NATS password file", Path::new(path.trim()))?
                .trim()
                .to_string(),
            None => std::env::var("NATS_PASSWORD").unwrap_or_default(),
        };
        options = options.user_and_password(user, password);
    }
    options
        .connect(&url)
        .await
        .map_err(|e| format!("NATS at {url}: {e}"))
}

async fn serve(mut args: Args) -> Result<i32, String> {
    let config_path = PathBuf::from(args.need("config")?);
    let dir = control_dir(&mut args)?;
    args.done()?;

    let config = config::load(&config_path)?;
    let keys = Keys::load(config.posture, std::env::var("RUST_ENV").ok().as_deref())?;
    // Bound before anything is served: a second controller on the same
    // directory stops here.
    let listener = control::bind(&dir).await?;
    let nats = connect_nats().await?;
    let posture = config.posture;
    let (actors, modules) = (config.actors.len(), config.modules.len());
    let controller = Controller::start(config, keys, nats).await?;
    tracing::info!(
        posture = posture.as_str(),
        actors,
        modules,
        secrets = controller.secret_paths().len(),
        control = %dir.join(control::SOCKET_NAME).display(),
        "serving"
    );

    tokio::select! {
        () = control::serve(listener, controller) => Err("the control socket stopped".to_string()),
        signal = tokio::signal::ctrl_c() => {
            signal.map_err(|e| e.to_string())?;
            let _ = std::fs::remove_file(dir.join(control::SOCKET_NAME));
            Ok(0)
        }
    }
}

/// Write a controller key pair and a worker key pair into `--out-dir`, and
/// print what to set. The two seeds are written to files only their owner
/// can read and are not printed.
fn keygen(mut args: Args) -> Result<i32, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let dir = PathBuf::from(args.need("out-dir")?);
    let worker_id = args
        .take("worker-id")
        .unwrap_or_else(|| "worker-1".to_string());
    args.done()?;
    aegix_workflow_job_protocol::validate_worker_id(&worker_id)?;
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;

    let write_new = |name: &str, text: &str, mode: u32| -> Result<PathBuf, String> {
        use std::io::Write;
        let path = dir.join(name);
        // `create_new`: an existing key is never overwritten.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&path)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        writeln!(file, "{text}").map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(path)
    };

    let (controller_seed, controller_public) =
        aegix_workflow_job_protocol::generate_ed25519_keypair_hex();
    let (worker_seed, worker_public) = aegix_workflow_job_protocol::generate_ed25519_keypair_hex();
    let controller_key = write_new("controller.key", &controller_seed, 0o600)?;
    let worker_key = write_new("worker.key", &worker_seed, 0o600)?;
    write_new("controller.pub", &controller_public, 0o644)?;
    write_new("worker.pub", &worker_public, 0o644)?;

    println!("# controller");
    println!(
        "AEGIX_CONTROLLER_SIGNING_KEY_FILE={}",
        controller_key.display()
    );
    println!("AEGIX_WORKER_PUBLIC_KEYS={worker_id}={worker_public}");
    println!("# worker");
    println!("AEGIX_WORKER_ID={worker_id}");
    println!("AEGIX_WORKER_SIGNING_KEY_FILE={}", worker_key.display());
    println!("AEGIX_CONTROLLER_PUBLIC_KEY={controller_public}");
    Ok(0)
}

async fn run(argv: Vec<String>) -> Result<i32, String> {
    let Some(command) = argv.first().map(String::as_str) else {
        return Err("a command is required".to_string());
    };
    let rest = &argv[1..];
    match command {
        "serve" => serve(Args::parse(rest, &[])?).await,
        "keygen" => keygen(Args::parse(rest, &[])?),
        _ => {
            let mut args = Args::parse(rest, &["wait"])?;
            let dir = control_dir(&mut args)?;
            let request = request_for(command, &mut args)?;
            args.done()?;
            let answer = control::call(&dir, &request).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&answer).map_err(|e| e.to_string())?
            );
            Ok(control::exit_code(&answer))
        }
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() || argv.iter().any(|a| a == "--help" || a == "-h") {
        print!("{USAGE}");
        std::process::exit(if argv.is_empty() { 2 } else { 0 });
    }
    if let Err(why) = aegix_config::legacy_env::refuse_legacy_names() {
        eprintln!("aegix-reference-controller: {why}");
        std::process::exit(1);
    }
    match run(argv).await {
        Ok(code) => std::process::exit(code),
        Err(why) => {
            eprintln!("aegix-reference-controller: {why}");
            // A usage mistake and a refusal both end here; `1` is "refused".
            std::process::exit(1);
        }
    }
}
