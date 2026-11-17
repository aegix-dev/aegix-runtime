//! How the operator talks to a running controller: a Unix socket in a
//! directory only the operator can enter.
//!
//! There is no network listener and no token. Who may dispatch a job, read
//! an outcome or write an actor's memory is whoever the operating system
//! lets into the control directory, which this process creates with mode
//! 0700 and refuses to use when anyone else can enter it.
//!
//! The protocol is one JSON object per line in, one per line out. Every
//! answer has `"ok"`; a refusal has `"error"`.

use crate::ledger::{ActorStatus, JobRecord, JobState};
use crate::memory;
use crate::serve::Controller;
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use uuid::Uuid;

/// The socket's name inside the control directory.
pub const SOCKET_NAME: &str = "control.sock";

/// The longest request line read.
pub const MAX_REQUEST_BYTES: usize = 256 * 1024;

/// The longest a `wait` holds its connection.
pub const MAX_WAIT_SECS: u64 = 3600;

/// How long a `wait` holds when the request names no time.
pub const DEFAULT_WAIT_SECS: u64 = 120;

/// Keys one `keys` request lists.
pub const MAX_KEYS_LISTED: usize = 1000;

/// One request.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    /// The posture, the actors, the modules, the stored secret paths and
    /// the job counts.
    Status,
    /// Every refusal counted since start.
    Counters,
    /// Send a module to a worker for an actor.
    Dispatch {
        module: String,
        actor: String,
        #[serde(default)]
        input: Value,
        /// Hold the connection until the job ends.
        #[serde(default)]
        wait: bool,
    },
    /// Hold the connection until a job ends.
    Wait {
        job_id: Uuid,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// A job's record as it stands.
    Job { job_id: Uuid },
    /// Write one value to an actor's memory. The operator's write: it is
    /// not put to the actor's write ceiling, which bounds a module.
    Remember {
        actor: String,
        key: String,
        value: Value,
        #[serde(default)]
        memory_type: Option<String>,
        #[serde(default)]
        ttl_hours: Option<f64>,
        #[serde(default)]
        metadata: Option<Value>,
    },
    /// Remove one key from an actor's memory.
    Forget { actor: String, key: String },
    /// List an actor's memory keys.
    Keys {
        actor: String,
        #[serde(default)]
        prefix: String,
    },
    /// Suspend an actor, or make it active again. A suspended actor is
    /// dispatched nothing and its running jobs are served nothing.
    SetActorStatus { actor: String, status: ActorStatus },
}

fn refusal(why: impl std::fmt::Display) -> Value {
    json!({"ok": false, "error": why.to_string()})
}

fn job_json(job: &JobRecord) -> Value {
    json!({"ok": true, "ended": job.state.is_ended(), "job": job})
}

/// The answer to one request.
pub async fn handle(controller: &Arc<Controller>, request: Request) -> Value {
    match request {
        Request::Status => {
            let (running, ended) = controller.ledger.job_counts();
            json!({
                "ok": true,
                "posture": controller.posture().as_str(),
                "actors": controller.ledger.actors(),
                "modules": controller.module_names(),
                "secret_paths": controller.secret_paths(),
                "jobs": {"running": running, "ended": ended},
            })
        }
        Request::Counters => json!({"ok": true, "refusals": controller.refusals.snapshot()}),
        Request::Dispatch {
            module,
            actor,
            input,
            wait,
        } => match controller.dispatch(&module, &actor, input).await {
            Err(e) => refusal(e),
            Ok(job_id) if !wait => json!({"ok": true, "job_id": job_id}),
            Ok(job_id) => wait_for(controller, job_id, MAX_WAIT_SECS).await,
        },
        Request::Wait {
            job_id,
            timeout_secs,
        } => {
            let secs = timeout_secs
                .unwrap_or(DEFAULT_WAIT_SECS)
                .clamp(1, MAX_WAIT_SECS);
            wait_for(controller, job_id, secs).await
        }
        Request::Job { job_id } => match controller.ledger.job(job_id) {
            Some(job) => job_json(&job),
            None => refusal("no such job is recorded"),
        },
        Request::Remember {
            actor,
            key,
            value,
            memory_type,
            ttl_hours,
            metadata,
        } => {
            let Some(actor) = controller.ledger.find_actor(&actor) else {
                return refusal(format!("no actor named {actor:?} is configured"));
            };
            match controller.memory.put(
                actor.id,
                &key,
                value,
                memory_type.as_deref().unwrap_or("episodic"),
                ttl_hours,
                metadata,
                memory::now_unix(),
            ) {
                Ok(()) => json!({"ok": true}),
                Err(e) => refusal(e),
            }
        }
        Request::Forget { actor, key } => {
            let Some(actor) = controller.ledger.find_actor(&actor) else {
                return refusal(format!("no actor named {actor:?} is configured"));
            };
            json!({"ok": true, "removed": controller.memory.remove(actor.id, &key)})
        }
        Request::Keys { actor, prefix } => {
            let Some(actor) = controller.ledger.find_actor(&actor) else {
                return refusal(format!("no actor named {actor:?} is configured"));
            };
            let keys =
                controller
                    .memory
                    .keys(actor.id, &prefix, MAX_KEYS_LISTED, memory::now_unix());
            json!({"ok": true, "keys": keys})
        }
        Request::SetActorStatus { actor, status } => {
            let Some(actor) = controller.ledger.find_actor(&actor) else {
                return refusal(format!("no actor named {actor:?} is configured"));
            };
            json!({"ok": controller.ledger.set_actor_status(actor.id, status)})
        }
    }
}

async fn wait_for(controller: &Arc<Controller>, job_id: Uuid, secs: u64) -> Value {
    match controller
        .ledger
        .wait_ended(job_id, Duration::from_secs(secs))
        .await
    {
        Some(job) => job_json(&job),
        None => match controller.ledger.job(job_id) {
            Some(job) => job_json(&job),
            None => refusal("no such job is recorded"),
        },
    }
}

/// The answer to one request line.
pub async fn handle_line(controller: &Arc<Controller>, line: &[u8]) -> Value {
    match serde_json::from_slice::<Request>(line) {
        Ok(request) => handle(controller, request).await,
        Err(e) => refusal(format!("the request was not understood: {e}")),
    }
}

/// Whether a directory with these permission bits is the operator's alone.
#[must_use]
pub fn dir_is_private(mode: u32) -> bool {
    mode & 0o077 == 0
}

/// Make `dir` the control directory: create it with mode 0700, or accept
/// one that exists only when nobody but its owner can enter it. Returns the
/// socket's path.
pub fn prepare_dir(dir: &Path) -> Result<PathBuf, String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match std::fs::metadata(dir) {
        Ok(meta) if !meta.is_dir() => {
            return Err(format!("{} is not a directory", dir.display()));
        }
        Ok(meta) => {
            let mode = meta.permissions().mode();
            if !dir_is_private(mode) {
                return Err(format!(
                    "control directory {} can be entered by others (mode {:o}): anyone who can \
                     reach the socket can dispatch jobs and write actor memory. `chmod 700` it.",
                    dir.display(),
                    mode & 0o777
                ));
            }
        }
        Err(_) => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("control directory {}: {e}", dir.display()))?;
        }
    }
    Ok(dir.join(SOCKET_NAME))
}

/// Bind the control socket in `dir`. Refuses when another controller is
/// already answering there; a socket nothing answers on is replaced.
pub async fn bind(dir: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::PermissionsExt;
    let path = prepare_dir(dir)?;
    if path.exists() {
        if UnixStream::connect(&path).await.is_ok() {
            return Err(format!(
                "another controller is already serving {}",
                path.display()
            ));
        }
        std::fs::remove_file(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    }
    let listener =
        UnixListener::bind(&path).map_err(|e| format!("bind {}: {e}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(listener)
}

/// Answer requests on `listener` until it fails.
pub async fn serve(listener: UnixListener, controller: Arc<Controller>) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(e) => {
                tracing::error!(error = %e, "the control socket stopped accepting");
                return;
            }
        };
        let controller = controller.clone();
        tokio::spawn(async move {
            let (read, mut write) = stream.into_split();
            let mut read = BufReader::new(read);
            loop {
                let mut line = Vec::new();
                // One byte past the cap, so an over-long line is told apart
                // from one that ends exactly at it.
                let mut limited = (&mut read).take(MAX_REQUEST_BYTES as u64 + 1);
                match limited.read_until(b'\n', &mut line).await {
                    Ok(0) | Err(_) => return,
                    Ok(_) => {}
                }
                let answer = if line.len() > MAX_REQUEST_BYTES {
                    refusal(format!("a request is at most {MAX_REQUEST_BYTES} bytes"))
                } else {
                    handle_line(&controller, &line).await
                };
                let over = line.len() > MAX_REQUEST_BYTES;
                let mut bytes = serde_json::to_vec(&answer).unwrap_or_default();
                bytes.push(b'\n');
                if write.write_all(&bytes).await.is_err() || over {
                    return;
                }
            }
        });
    }
}

/// Send one request to the controller serving `dir` and read its answer.
pub async fn call(dir: &Path, request: &Value) -> Result<Value, String> {
    let path = dir.join(SOCKET_NAME);
    let stream = UnixStream::connect(&path).await.map_err(|e| {
        format!(
            "no controller is answering at {} ({e}); start one with `serve`",
            path.display()
        )
    })?;
    let (read, mut write) = stream.into_split();
    let mut line = serde_json::to_vec(request).map_err(|e| e.to_string())?;
    line.push(b'\n');
    write.write_all(&line).await.map_err(|e| e.to_string())?;
    let mut answer = String::new();
    BufReader::new(read)
        .read_line(&mut answer)
        .await
        .map_err(|e| e.to_string())?;
    serde_json::from_str(&answer).map_err(|_| "the controller closed the connection".to_string())
}

/// The process exit code for an answer: 0 when the request was served and
/// any job it reports completed, 3 when the job ended any other way or has
/// not ended, 1 when the request was refused.
#[must_use]
pub fn exit_code(answer: &Value) -> i32 {
    if answer.get("ok").and_then(Value::as_bool) != Some(true) {
        return 1;
    }
    match answer.pointer("/job/state").and_then(Value::as_str) {
        None => 0,
        Some(state) if state == JobState::Completed.as_str() => 0,
        Some(_) => 3,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_request_is_one_tagged_object_and_an_unknown_field_is_refused() {
        assert!(matches!(
            serde_json::from_str::<Request>(r#"{"cmd":"status"}"#),
            Ok(Request::Status)
        ));
        let dispatch: Request =
            serde_json::from_str(r#"{"cmd":"dispatch","module":"m","actor":"a"}"#).expect("parses");
        assert!(matches!(
            dispatch,
            Request::Dispatch {
                wait: false,
                input: Value::Null,
                ..
            }
        ));
        assert!(matches!(
            serde_json::from_str::<Request>(
                r#"{"cmd":"set_actor_status","actor":"a","status":"suspended"}"#
            ),
            Ok(Request::SetActorStatus {
                status: ActorStatus::Suspended,
                ..
            })
        ));
        for bad in [
            r#"{"cmd":"shutdown"}"#,
            r#"{"cmd":"dispatch","module":"m"}"#,
            r#"{"cmd":"dispatch","module":"m","actor":"a","as_user":"root"}"#,
            r#"{"cmd":"job","job_id":"not-an-id"}"#,
            r#"{"module":"m","actor":"a"}"#,
        ] {
            assert!(serde_json::from_str::<Request>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_control_directory_is_the_operators_alone() {
        use std::os::unix::fs::PermissionsExt;
        assert!(dir_is_private(0o40_700));
        for open in [0o40_750, 0o40_705, 0o40_755, 0o40_770, 0o40_701] {
            assert!(!dir_is_private(open), "{open:o}");
        }

        let root = tempfile::tempdir().expect("a directory");
        let made = root.path().join("made");
        let socket = prepare_dir(&made).expect("created");
        assert_eq!(socket, made.join(SOCKET_NAME));
        let mode = std::fs::metadata(&made)
            .expect("exists")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700, "created private");

        let open = root.path().join("open");
        std::fs::create_dir(&open).expect("mkdir");
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        let err = prepare_dir(&open).expect_err("others can enter");
        assert!(err.contains("chmod 700"), "{err}");

        let file = root.path().join("file");
        std::fs::write(&file, b"").expect("write");
        assert!(prepare_dir(&file).is_err());
    }

    #[test]
    fn the_exit_code_says_whether_the_job_completed() {
        assert_eq!(exit_code(&json!({"ok": true})), 0);
        assert_eq!(exit_code(&json!({"ok": false, "error": "x"})), 1);
        assert_eq!(exit_code(&json!({"error": "x"})), 1);
        assert_eq!(
            exit_code(&json!({"ok": true, "job": {"state": "completed"}})),
            0
        );
        for state in ["failed", "timeout", "running"] {
            assert_eq!(
                exit_code(&json!({"ok": true, "job": {"state": state}})),
                3,
                "{state}"
            );
        }
    }
}
