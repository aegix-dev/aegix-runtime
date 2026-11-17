//! # One place a Redis client is made and a connection opened
//!
//! Every Redis client in the workspace is made by [`client`], and every
//! connection opened by [`multiplexed`] or [`manager`], so the servers a TLS
//! connection trusts and the deadlines a connection carries are decided here,
//! once. `clippy.toml` disallows the `redis` constructors everywhere else.
//!
//! ## Which server a `rediss://` connection trusts
//!
//! The workspace builds `redis` with webpki's bundled roots, so a plain
//! `Client::open` trusts the public certificate authorities and nothing else:
//! not the system store, not `SSL_CERT_FILE`. That is right for a managed
//! Redis with a public certificate and makes a private one (the single-host
//! compose stack's own CA) impossible to verify, leaving `#insecure`, which
//! accepts any certificate. [`client`] reads [`CA_FILE_ENV`]: set, a
//! `rediss://` client trusts exactly the certificates in that file — the
//! public roots are not added — and a plaintext URL is refused rather than
//! silently left unencrypted. Unset, it is `Client::open` (2026-10-29).
//!
//! ## Why this exists
//!
//! `redis` 0.27 put no deadline on an async connection. From 1.0 the library
//! defaults are **500 ms for a response and 1 s to connect**, on every async
//! connection, with no client-wide setting — only a config passed where each
//! connection is opened. When the workspace moved to 1.7 (2026-10-07) it
//! opened connections at 44 call sites in 19 crates, none of which passed
//! one. Taking the bump as it came would have put a 500 ms deadline on every
//! Redis call behind login, rate limiting, replay protection and idempotency,
//! and the module cache's multi-megabyte values, without anyone choosing it.
//!
//! ## The deadlines
//!
//! * [`CONNECT_TIMEOUT`] — 5 s. Connecting was unbounded; it is now bounded
//!   at the workspace's floor for any connect timeout. That floor was set
//!   after a cold name lookup was measured at 2.0–2.1 s inside the
//!   containers, which failed every client with a shorter one; the library's
//!   1 s is below it.
//! * [`RESPONSE_TIMEOUT`] — none, which is what every call site had before.
//!   A caller that needs a deadline on one operation wraps that operation, as
//!   the rate limiter does (3 s). Bounding all of them is a decision to make
//!   with the fleet's Redis latencies in hand; it is this one constant.
//!
//! The reconnect policy of a [`ConnectionManager`] is the library's default,
//! unchanged from 0.27: six attempts, backing off from 100 ms by a factor of
//! two.

use redis::aio::{ConnectionManager, ConnectionManagerConfig, MultiplexedConnection};
use redis::{AsyncConnectionConfig, Client, ErrorKind, RedisError, RedisResult, TlsCertificates};
use std::path::Path;
use std::time::Duration;

/// Names a PEM file of the certificate authorities a `rediss://` connection
/// trusts, in place of the public roots (see the module documentation).
pub const CA_FILE_ENV: &str = "AEGIX_REDIS_CA_FILE";

/// Make a client for `url`, trusting the certificate authorities that
/// [`CA_FILE_ENV`] names, if it is set (see [`client_with_ca`]).
///
/// # Errors
///
/// As [`client_with_ca`].
pub fn client(url: impl AsRef<str>) -> RedisResult<Client> {
    let ca = std::env::var(CA_FILE_ENV)
        .ok()
        .filter(|v| !v.trim().is_empty());
    client_with_ca(url.as_ref(), ca.as_deref().map(Path::new))
}

/// Make a client for `url`. With `ca_file`, the connection is TLS and trusts
/// exactly the certificates in that PEM file; without it, `url` is taken as
/// it is.
///
/// # Errors
///
/// A URL the client cannot parse; with `ca_file`: a URL that is not
/// `rediss://`, a file that cannot be read, and a file holding no certificate
/// (an empty trust store would refuse every server, and say so only at the
/// first connect).
pub fn client_with_ca(url: &str, ca_file: Option<&Path>) -> RedisResult<Client> {
    let Some(path) = ca_file else {
        // disallowed-method: redis::Client::open — the one sanctioned constructor of a client
        #[allow(clippy::disallowed_methods)]
        let client = Client::open(url);
        return client;
    };
    let pem = std::fs::read(path).map_err(|e| {
        RedisError::from((
            ErrorKind::InvalidClientConfig,
            "the Redis CA file could not be read",
            format!("{CA_FILE_ENV}={}: {e}", path.display()),
        ))
    })?;
    if !pem.windows(27).any(|w| w == b"-----BEGIN CERTIFICATE-----") {
        return Err(RedisError::from((
            ErrorKind::InvalidClientConfig,
            "the Redis CA file holds no PEM certificate",
            format!("{CA_FILE_ENV}={}", path.display()),
        )));
    }
    // disallowed-method: redis::Client::build_with_tls — the one sanctioned constructor of a client
    #[allow(clippy::disallowed_methods)]
    let client = Client::build_with_tls(
        url,
        TlsCertificates {
            client_tls: None,
            root_cert: Some(pem),
        },
    );
    client
}

/// How long opening a connection may take, name lookup and handshake included.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long one command may wait for its reply: no library deadline.
pub const RESPONSE_TIMEOUT: Option<Duration> = None;

/// The configuration of a multiplexed connection opened by [`multiplexed`].
#[must_use]
pub fn connection_config() -> AsyncConnectionConfig {
    AsyncConnectionConfig::new()
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_response_timeout(RESPONSE_TIMEOUT)
}

/// The configuration of a connection manager opened by [`manager`].
#[must_use]
pub fn manager_config() -> ConnectionManagerConfig {
    ConnectionManagerConfig::new()
        .set_connection_timeout(Some(CONNECT_TIMEOUT))
        .set_response_timeout(RESPONSE_TIMEOUT)
}

/// Open a multiplexed connection: one socket, safe to clone and share.
///
/// # Errors
///
/// Whatever the connect fails with, a timeout after [`CONNECT_TIMEOUT`]
/// included.
// disallowed-method: redis::Client::get_multiplexed_async_connection_with_config — the one sanctioned opener of a multiplexed connection
#[allow(clippy::disallowed_methods)]
pub async fn multiplexed(client: &Client) -> RedisResult<MultiplexedConnection> {
    client
        .get_multiplexed_async_connection_with_config(&connection_config())
        .await
}

/// Open a connection manager: a multiplexed connection that reconnects.
///
/// # Errors
///
/// Whatever the first connect fails with, once its retries are spent.
// disallowed-method: redis::aio::ConnectionManager::new_with_config — the one sanctioned opener of a connection manager
#[allow(clippy::disallowed_methods)]
pub async fn manager(client: Client) -> RedisResult<ConnectionManager> {
    ConnectionManager::new_with_config(client, manager_config()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A throwaway CA certificate (`openssl req -x509 -newkey ec ...`, made
    /// for this test, its key discarded). Only its parse matters here.
    const TEST_CA: &str = include_str!("../testdata/test-ca.pem");

    /// A file of its own for every call. Two tests write the same
    /// certificate, and under `cargo test` they are threads of one process:
    /// a path named by the process and the contents' length alone was one
    /// file for both, and one test read it while the other had truncated it
    /// to write (11 of 300 runs refused with "no PEM certificate").
    fn ca_file(contents: &str) -> std::path::PathBuf {
        static CALLS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let dir = std::env::temp_dir().join(format!(
            "talos-redis-ca-{}-{}",
            std::process::id(),
            CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ca.pem");
        std::fs::write(&path, contents).unwrap();
        path
    }

    fn tls_params_set(client: &Client) -> Option<bool> {
        match client.get_connection_info().addr() {
            redis::ConnectionAddr::TcpTls {
                insecure,
                tls_params,
                ..
            } => {
                assert!(!insecure, "a CA-verified client must not be insecure");
                Some(tls_params.is_some())
            }
            _ => None,
        }
    }

    #[test]
    fn without_a_ca_file_the_url_is_taken_as_it_is() {
        let plain = client_with_ca("redis://:pw@redis:6379", None).unwrap();
        assert_eq!(
            tls_params_set(&plain),
            None,
            "a redis:// URL stays plaintext"
        );
        let public = client_with_ca("rediss://:pw@redis.example.com:6379", None).unwrap();
        assert_eq!(
            tls_params_set(&public),
            Some(false),
            "public roots: no trust store of its own"
        );
    }

    #[test]
    fn a_ca_file_becomes_the_whole_trust_store_of_a_tls_client() {
        let path = ca_file(TEST_CA);
        let c = client_with_ca("rediss://:pw@redis:6379", Some(&path)).unwrap();
        assert_eq!(
            tls_params_set(&c),
            Some(true),
            "the CA file's certificates are the trust store"
        );
    }

    #[test]
    fn a_ca_file_refuses_a_plaintext_url() {
        let path = ca_file(TEST_CA);
        let err = client_with_ca("redis://:pw@redis:6379", Some(&path)).unwrap_err();
        assert!(err.to_string().contains("rediss://"), "{err}");
    }

    #[test]
    fn an_unreadable_or_empty_ca_file_is_refused() {
        let missing = std::env::temp_dir().join("talos-redis-no-such-ca.pem");
        let err = client_with_ca("rediss://redis:6379", Some(&missing)).unwrap_err();
        assert!(err.to_string().contains("could not be read"), "{err}");
        let path = ca_file("not a certificate\n");
        let err = client_with_ca("rediss://redis:6379", Some(&path)).unwrap_err();
        assert!(err.to_string().contains("no PEM certificate"), "{err}");
    }

    /// The two decisions, stated so that changing either is an edit to a
    /// test as well as to a constant.
    #[test]
    fn the_deadlines_are_the_decided_ones() {
        assert_eq!(CONNECT_TIMEOUT, Duration::from_secs(5));
        assert_eq!(RESPONSE_TIMEOUT, None);
        let manager = manager_config();
        assert_eq!(manager.connection_timeout(), Some(CONNECT_TIMEOUT));
        assert_eq!(manager.response_timeout(), RESPONSE_TIMEOUT);
        // The reconnect policy is the library's, and is what 0.27 had.
        assert_eq!(manager.number_of_retries(), 6);
        assert_eq!(manager.min_delay(), Duration::from_millis(100));
        assert!((manager.exponent_base() - 2.0).abs() < f32::EPSILON);
    }
}
