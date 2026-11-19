//! How the worker authenticates to NATS, and the identity it does it with
//! (2026-11-06, `docs/engineering-log/packages/2026-11-06-per-worker-nats-credentials.md`).
//!
//! * `AEGIX_WORKER_NATS_AUTH=password` (the default): `NATS_USER` /
//!   `NATS_PASSWORD`, the broker's static worker user, shared by every worker.
//!   Its permission set admits every `_WINBOX.>`, so a worker on it can read a
//!   sibling's RPC replies; the shipped shapes no longer configure it.
//! * `AEGIX_WORKER_NATS_AUTH=identity`: the worker connects with its Ed25519
//!   identity as a NATS user nkey and signs the server's nonce with it, names
//!   itself by its worker id, and uses its OWN inbox prefix
//!   (`nats_permissions::worker_inbox_prefix_for`). The broker's auth callout
//!   (served by the controller, `aegix-nats-callout`) mints it a credential
//!   whose only inbox scope is that prefix.
//! * `AEGIX_WORKER_IDENTITY=ephemeral` (`aegix_wasm_host::worker_identity`):
//!   the key is minted here, in memory, at boot, and never written anywhere;
//!   the connect carries `AEGIX_WORKER_REGISTRATION_TOKEN` so the callout can
//!   register it. It requires `identity`.
//!
//! A worker on `identity` whose reconnect is refused as unauthorized
//! [`AUTH_REFUSALS_BEFORE_EXIT`] times in a row, after it had connected,
//! exits: its identity was deactivated (or the controller is down past a
//! credential renewal), and an orchestrator restart gives it a new identity
//! where retrying the dead one would loop forever with no bus.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::OnceLock;

use aegix_wasm_host::worker_identity::IdentityMode;
use aegix_workflow_job_protocol::nats_permissions::worker_inbox_prefix_for;
use aegix_workflow_job_protocol::DispatchSigningKey;

/// How the worker authenticates to NATS: `AEGIX_WORKER_NATS_AUTH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatsAuth {
    Password,
    Identity,
}

/// Parse a `AEGIX_WORKER_NATS_AUTH` value; an unrecognised spelling refuses
/// boot.
pub fn parse_nats_auth(raw: Option<&str>) -> Result<NatsAuth, String> {
    match raw.map(str::trim).filter(|v| !v.is_empty()) {
        None => Ok(NatsAuth::Password),
        Some(v) if v.eq_ignore_ascii_case("password") => Ok(NatsAuth::Password),
        Some(v) if v.eq_ignore_ascii_case("identity") => Ok(NatsAuth::Identity),
        Some(v) => Err(format!(
            "AEGIX_WORKER_NATS_AUTH must be `password` or `identity`, got {v:?}"
        )),
    }
}

/// The two settings, checked together at boot. `ephemeral` needs `identity`
/// (an ephemeral key registers only through the callout) and a registration
/// credential (without one the callout cannot register it, and the worker
/// would retry a refused connect forever).
pub fn check_identity_settings(
    auth: NatsAuth,
    mode: IdentityMode,
    registration_token_present: bool,
) -> Result<(), String> {
    match (mode, auth) {
        (IdentityMode::Ephemeral, NatsAuth::Password) => Err(
            "AEGIX_WORKER_IDENTITY=ephemeral needs AEGIX_WORKER_NATS_AUTH=identity: an \
             ephemeral key is registered by the NATS auth callout on connect"
                .into(),
        ),
        (IdentityMode::Ephemeral, NatsAuth::Identity) if !registration_token_present => Err(
            "AEGIX_WORKER_IDENTITY=ephemeral needs AEGIX_WORKER_REGISTRATION_TOKEN or \
             AEGIX_WORKER_REGISTRATION_TOKEN_FILE: the NATS auth callout registers a new \
             identity only with a registration credential"
                .into(),
        ),
        _ => Ok(()),
    }
}

/// The registration credential an ephemeral worker presents on its connect:
/// `AEGIX_WORKER_REGISTRATION_TOKEN` (a shared or provisioning token), or the
/// contents of `AEGIX_WORKER_REGISTRATION_TOKEN_FILE` — in Kubernetes, the
/// pod's projected ServiceAccount token, the replica's credential of its own
/// (`controller::bootstrap::k8s_registration`). Both set is an error, as is a
/// named file that cannot be read or is empty. Read once, at boot: the
/// credential is consulted only for a first registration.
pub fn registration_credential(
    token: Option<&str>,
    token_file: Option<&str>,
    read: impl Fn(&str) -> std::io::Result<String>,
) -> Result<Option<String>, String> {
    value_or_file("AEGIX_WORKER_REGISTRATION_TOKEN", token, token_file, read)
}

/// A setting given either inline (`NAME`) or as a file (`NAME_FILE`, a
/// compose secret or a mounted Secret, which `docker inspect` does not show).
/// Both set is an error, as is a named file that cannot be read or is empty.
pub fn value_or_file(
    name: &str,
    value: Option<&str>,
    file: Option<&str>,
    read: impl Fn(&str) -> std::io::Result<String>,
) -> Result<Option<String>, String> {
    let value = value.map(str::trim).filter(|v| !v.is_empty());
    let file = file.map(str::trim).filter(|v| !v.is_empty());
    match (value, file) {
        (Some(_), Some(_)) => Err(format!("set {name} or {name}_FILE, not both")),
        (Some(v), None) => Ok(Some(v.to_string())),
        (None, Some(path)) => {
            let raw =
                read(path).map_err(|e| format!("{name}_FILE ({path}) cannot be read: {e}"))?;
            let v = raw.trim();
            if v.is_empty() {
                return Err(format!("{name}_FILE ({path}) is empty"));
            }
            Ok(Some(v.to_string()))
        }
        (None, None) => Ok(None),
    }
}

/// This process's ephemeral Ed25519 key: minted once, kept in memory only.
pub fn ephemeral_signing_key() -> &'static DispatchSigningKey {
    static KEY: OnceLock<DispatchSigningKey> = OnceLock::new();
    KEY.get_or_init(aegix_workflow_job_protocol::generate_dispatch_signing_key)
}

/// The NATS user-nkey seed (`SU…`) of an Ed25519 signing key: the same key,
/// in the encoding async-nats signs the server's nonce with.
pub fn user_nkey_seed(key: &DispatchSigningKey) -> Result<String, String> {
    nkeys::KeyPair::new_from_raw(nkeys::KeyPairType::User, key.to_bytes())
        .and_then(|kp| kp.seed())
        .map_err(|e| format!("could not encode the worker key as an nkey: {e}"))
}

/// The connect options for `identity`: `base` (the worker's event callback),
/// then its key as an nkey, its id as the connection name, its OWN inbox
/// prefix, and — for an ephemeral identity — the registration credential.
pub fn identity_connect_options(
    base: async_nats::ConnectOptions,
    worker_id: &str,
    key: &DispatchSigningKey,
    registration: Option<String>,
) -> Result<async_nats::ConnectOptions, String> {
    let prefix = worker_inbox_prefix_for(worker_id).ok_or_else(|| {
        format!(
            "worker id {worker_id:?} cannot name a NATS inbox (it must be one subject token: \
             no `.`); set AEGIX_WORKER_ID to such an id or use AEGIX_WORKER_IDENTITY=ephemeral"
        )
    })?;
    let mut opts = base
        .nkey(user_nkey_seed(key)?)
        .name(worker_id)
        .custom_inbox_prefix(prefix);
    if let Some(token) = registration {
        opts = opts.token(token);
    }
    Ok(opts)
}

/// Consecutive authorization refusals after a first connect before the worker
/// exits. More than one: a single refusal can be the controller restarting
/// across a credential renewal.
pub const AUTH_REFUSALS_BEFORE_EXIT: u32 = 5;

/// What the worker should do after one connection event, under `identity`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthWatchVerdict {
    Continue,
    Exit,
}

/// Counts authorization refusals between successful connects.
#[derive(Default)]
pub struct AuthRefusalWatch {
    connected_once: AtomicBool,
    refusals: AtomicU32,
}

impl AuthRefusalWatch {
    pub fn on_event(&self, event: &async_nats::Event) -> AuthWatchVerdict {
        match event {
            async_nats::Event::Connected => {
                self.connected_once.store(true, Ordering::SeqCst);
                self.refusals.store(0, Ordering::SeqCst);
                AuthWatchVerdict::Continue
            }
            e if is_authorization_refusal(e) && self.connected_once.load(Ordering::SeqCst) => {
                let n = self.refusals.fetch_add(1, Ordering::SeqCst) + 1;
                if n >= AUTH_REFUSALS_BEFORE_EXIT {
                    AuthWatchVerdict::Exit
                } else {
                    AuthWatchVerdict::Continue
                }
            }
            _ => AuthWatchVerdict::Continue,
        }
    }
}

/// Whether `event` is the broker refusing this connection's credential.
/// async-nats 0.50 reports a REconnect the server refused as
/// `ClientError::Other("authorization violation")` — its reconnect loop turns
/// the connect error's kind into that string and retries (`connector.rs`,
/// `connect`) — and a refusal on an open connection as
/// `ServerError::AuthorizationViolation`. The first is the one revocation
/// produces; `a_deactivated_identity_loses_the_bus_when_its_credential_expires`
/// (aegix-workflow-engine-nats) holds the live broker to that shape.
fn is_authorization_refusal(event: &async_nats::Event) -> bool {
    match event {
        async_nats::Event::ServerError(async_nats::ServerError::AuthorizationViolation) => true,
        async_nats::Event::ClientError(async_nats::ClientError::Other(msg)) => {
            msg.to_ascii_lowercase().contains("authorization violation")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_registration_credential_comes_from_one_place() {
        let read = |p: &str| match p {
            "/t" => Ok("eyJ.a.b\n".to_string()),
            "/empty" => Ok("  \n".to_string()),
            _ => Err(std::io::Error::new(std::io::ErrorKind::NotFound, "no")),
        };
        assert_eq!(registration_credential(None, None, read), Ok(None));
        assert_eq!(
            registration_credential(Some("tok"), None, read),
            Ok(Some("tok".into()))
        );
        assert_eq!(
            registration_credential(None, Some("/t"), read),
            Ok(Some("eyJ.a.b".into()))
        );
        assert!(registration_credential(Some("tok"), Some("/t"), read).is_err());
        assert!(registration_credential(None, Some("/missing"), read).is_err());
        assert!(registration_credential(None, Some("/empty"), read).is_err());
    }

    #[test]
    fn the_auth_mode_is_one_of_two_spellings() {
        assert_eq!(parse_nats_auth(None), Ok(NatsAuth::Password));
        assert_eq!(parse_nats_auth(Some("identity")), Ok(NatsAuth::Identity));
        assert_eq!(parse_nats_auth(Some("Password")), Ok(NatsAuth::Password));
        assert!(parse_nats_auth(Some("nkey")).is_err());
    }

    #[test]
    fn ephemeral_needs_identity_auth_and_a_registration_credential() {
        use IdentityMode::*;
        assert!(check_identity_settings(NatsAuth::Password, Ephemeral, true).is_err());
        assert!(check_identity_settings(NatsAuth::Identity, Ephemeral, false).is_err());
        assert!(check_identity_settings(NatsAuth::Identity, Ephemeral, true).is_ok());
        assert!(check_identity_settings(NatsAuth::Identity, Configured, false).is_ok());
        assert!(check_identity_settings(NatsAuth::Password, Configured, false).is_ok());
    }

    /// The nkey the worker connects with IS its Ed25519 identity: the public
    /// key the callout reads off the CONNECT is the one the controller has
    /// registered for its results, RPCs and claims.
    #[test]
    fn the_nkey_is_the_identity_key() {
        let key = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let seed = user_nkey_seed(&key).unwrap();
        assert!(seed.starts_with("SU"), "{seed}");
        let kp = nkeys::KeyPair::from_seed(&seed).unwrap();
        let raw = nkeys::from_public_key(&kp.public_key()).unwrap().1;
        assert_eq!(raw, key.verifying_key().to_bytes());
    }

    #[test]
    fn an_id_that_is_not_one_token_cannot_connect() {
        let key = aegix_workflow_job_protocol::generate_dispatch_signing_key();
        let err = identity_connect_options(async_nats::ConnectOptions::new(), "a.b", &key, None)
            .unwrap_err();
        assert!(err.contains("one subject token"), "{err}");
        assert!(
            identity_connect_options(async_nats::ConnectOptions::new(), "w-1", &key, None).is_ok()
        );
    }

    /// The reconnect refusal async-nats reports, and the open-connection one,
    /// both count; nothing else does.
    #[test]
    fn both_spellings_of_a_refusal_count_and_nothing_else_does() {
        let reconnect_refused = async_nats::Event::ClientError(async_nats::ClientError::Other(
            "authorization violation".into(),
        ));
        let server_refused =
            async_nats::Event::ServerError(async_nats::ServerError::AuthorizationViolation);
        assert!(is_authorization_refusal(&reconnect_refused));
        assert!(is_authorization_refusal(&server_refused));
        for other in [
            async_nats::Event::ClientError(async_nats::ClientError::Other("io error".into())),
            async_nats::Event::ServerError(async_nats::ServerError::Other(
                "user authentication expired".into(),
            )),
            async_nats::Event::Disconnected,
        ] {
            assert!(!is_authorization_refusal(&other), "{other:?}");
        }
    }

    #[test]
    fn repeated_refusals_after_a_connect_exit_and_a_connect_resets_them() {
        let w = AuthRefusalWatch::default();
        // The shape a refused REconnect arrives in (async-nats 0.50).
        let refused = async_nats::Event::ClientError(async_nats::ClientError::Other(
            "authorization violation".into(),
        ));
        // Before the first connect, refusals are the boot retry loop's.
        for _ in 0..10 {
            assert_eq!(w.on_event(&refused), AuthWatchVerdict::Continue);
        }
        assert_eq!(
            w.on_event(&async_nats::Event::Connected),
            AuthWatchVerdict::Continue
        );
        for _ in 1..AUTH_REFUSALS_BEFORE_EXIT {
            assert_eq!(w.on_event(&refused), AuthWatchVerdict::Continue);
        }
        assert_eq!(
            w.on_event(&async_nats::Event::Connected),
            AuthWatchVerdict::Continue
        );
        for _ in 1..AUTH_REFUSALS_BEFORE_EXIT {
            assert_eq!(w.on_event(&refused), AuthWatchVerdict::Continue);
        }
        assert_eq!(w.on_event(&refused), AuthWatchVerdict::Exit);
    }
}
