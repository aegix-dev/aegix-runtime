//! How the worker connects to the message bus: the options every connect
//! branch starts from (the worker's own inbox prefix, and a callback that
//! turns the broker's asynchronous refusals into log lines), and the connect
//! under a per-worker identity.
//!
//! Moved out of `main.rs` 2026-11-18, unchanged.

use async_nats::Client;
use std::sync::Arc;
use worker::worker_identity;

/// Connection options every worker connect branch starts from.
///
/// Two things the broker-side permission model needs from the CLIENT:
///
/// 1. **The worker's own inbox prefix.** async-nats derives every
///    request/reply inbox from one connection-level prefix (`_INBOX` by
///    default — which the controller keeps). The worker's NATS credential
///    is granted subscribe on `_WINBOX.>` and NOT on `_INBOX.>`
///    (`aegix_workflow_job_protocol::nats_permissions`), so a worker whose
///    requests still used `_INBOX` would never see a reply. Deploy note:
///    a worker built with this prefix against a NATS with no permissions
///    block works unchanged (the prefix is just a subject).
/// 2. **An event callback.** A publish or subscribe the broker refuses is
///    reported as an ASYNCHRONOUS `-ERR Permissions Violation …` on the
///    connection — `publish()` still returns `Ok`, the subscription still
///    exists locally and simply never delivers. Without a callback that is
///    a silent drop; with one it is a WARN naming the subject, which is the
///    only operator-visible signal that a credential and a code path have
///    drifted apart.
pub(crate) fn worker_connect_options() -> async_nats::ConnectOptions {
    worker_connect_options_watched(None)
}

/// [`worker_connect_options`], with the `identity` connection's refusal watch
/// (`worker::nats_identity::AuthRefusalWatch`): a worker whose reconnects are
/// refused as unauthorized, after it had connected, exits (2026-11-06).
pub(crate) fn worker_connect_options_watched(
    watch: Option<Arc<worker::nats_identity::AuthRefusalWatch>>,
) -> async_nats::ConnectOptions {
    async_nats::ConnectOptions::new()
        .custom_inbox_prefix(aegix_workflow_job_protocol::nats_permissions::WORKER_INBOX_PREFIX)
        .event_callback(move |event| {
            let watch = watch.clone();
            async move {
                if let Some(w) = &watch {
                    if w.on_event(&event) == worker::nats_identity::AuthWatchVerdict::Exit {
                        ::tracing::error!(
                            target: "talos_security",
                            worker_id = %worker_identity(),
                            refusals = worker::nats_identity::AUTH_REFUSALS_BEFORE_EXIT,
                            "the broker keeps refusing this worker's identity (deactivated, or no \
                             controller answers the NATS auth callout): exiting so a restart gives \
                             the worker a fresh identity"
                        );
                        std::process::exit(3);
                    }
                }
                match &event {
                    async_nats::Event::ServerError(err) => ::tracing::warn!(
                        target: "talos_nats",
                        error = %err,
                        "NATS server error on the worker connection — a `Permissions Violation` \
                         here means this credential is not granted that subject (see \
                         aegix_workflow_job_protocol::nats_permissions); the operation was \
                         dropped by the broker, not by the worker"
                    ),
                    async_nats::Event::ClientError(err) => ::tracing::warn!(
                        target: "talos_nats",
                        error = %err,
                        "NATS client error on the worker connection"
                    ),
                    async_nats::Event::SlowConsumer(sid) => ::tracing::warn!(
                        target: "talos_nats",
                        subscription = sid,
                        "NATS slow consumer on the worker connection"
                    ),
                    async_nats::Event::Connected => {
                        ::tracing::info!(target: "talos_nats", "NATS connected")
                    }
                    async_nats::Event::Disconnected
                    | async_nats::Event::LameDuckMode
                    | async_nats::Event::Draining
                    | async_nats::Event::Closed => ::tracing::warn!(
                        target: "talos_nats",
                        event = %event,
                        "NATS connection state change on the worker connection"
                    ),
                }
            }
        })
}

/// Connect under `AEGIX_WORKER_NATS_AUTH=identity` (2026-11-06): the worker's
/// Ed25519 identity as an nkey, its id as the connection name, its own inbox
/// prefix, and for an ephemeral identity the registration credential
/// (`worker::nats_identity`). The broker's auth callout is answered by the
/// controller, which may not be up yet when the worker starts, so a refused
/// connect is retried for up to two minutes before the worker gives up.
pub(crate) async fn connect_nats_with_identity(
    nats_url: &str,
    nats_url_safe: &str,
    mode: aegix_wasm_host::worker_identity::IdentityMode,
    registration: Option<String>,
) -> anyhow::Result<Client> {
    const ATTEMPTS: u32 = 40;
    let key = crate::worker_result_signing_key().ok_or_else(|| {
        anyhow::anyhow!(
            "AEGIX_WORKER_NATS_AUTH=identity needs an Ed25519 identity: set \
             AEGIX_WORKER_SIGNING_KEY, or AEGIX_WORKER_IDENTITY=ephemeral"
        )
    })?;
    let worker_id = worker_identity();
    let registration = (mode == aegix_wasm_host::worker_identity::IdentityMode::Ephemeral)
        .then_some(registration)
        .flatten();
    let watch = Arc::new(worker::nats_identity::AuthRefusalWatch::default());
    let mut last_err = String::new();
    for attempt in 1..=ATTEMPTS {
        let opts = worker::nats_identity::identity_connect_options(
            worker_connect_options_watched(Some(watch.clone())),
            worker_id,
            key,
            registration.clone(),
        )
        .map_err(anyhow::Error::msg)?;
        match aegix_nats_tls::apply_nats_ca(opts).connect(nats_url).await {
            Ok(c) => {
                println!(
                    "      Connected to NATS as worker identity {worker_id} (own inbox scope) at {nats_url_safe}"
                );
                return Ok(c);
            }
            Err(e) => {
                last_err = e.to_string();
                ::tracing::warn!(
                    target: "talos_nats",
                    attempt,
                    worker_id = %worker_id,
                    error = %e,
                    "NATS refused this worker's identity connect (is the controller up and \
                     serving the auth callout?); retrying"
                );
                tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            }
        }
    }
    anyhow::bail!(
        "could not connect to NATS at {nats_url_safe} as worker {worker_id} after {ATTEMPTS} \
         attempts: {last_err}"
    )
}

#[cfg(test)]
mod nats_connect_options_tests {
    //! The inbox prefix is the one client-side half of the broker permission
    //! model: the worker credential is granted subscribe on `_WINBOX.>` and
    //! not `_INBOX.>`, so a worker that drifted back to the default prefix
    //! would issue RPCs whose replies it can never receive. `ConnectOptions`
    //! exposes no getter; its `Debug` output names the field, which is the
    //! only observation available short of a live broker (the live check is
    //! `aegix-workflow-engine-nats/tests/nats_worker_permissions.rs`).
    use super::worker_connect_options;
    use aegix_workflow_job_protocol::nats_permissions::{
        CONTROLLER_INBOX_PREFIX, WORKER_INBOX_PREFIX,
    };

    #[test]
    fn worker_connect_options_use_the_worker_inbox_prefix() {
        let dbg = format!("{:?}", worker_connect_options());
        // `ConnectOptions` renders as a map of quoted keys: `"inbox_prefix": "_WINBOX"`.
        assert!(
            dbg.contains(&format!("\"inbox_prefix\": {WORKER_INBOX_PREFIX:?}")),
            "ConnectOptions must carry the worker inbox prefix; got: {dbg}"
        );
        assert!(!dbg.contains(&format!("\"inbox_prefix\": {CONTROLLER_INBOX_PREFIX:?}")));
    }
}
