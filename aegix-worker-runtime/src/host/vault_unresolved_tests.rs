//! A granted `vault://` reference this run was not given is explained in the
//! run's host diagnostics (2026-10-29).
//!
//! The guest sees only `forbiddenhost`, which a module renders as "could not
//! be reached" and an operator reads as an egress refusal. Observed on the
//! hosted box: an impersonated Google Cloud token whose mint Google refused
//! (the service account no longer existed) failed every request that way, the
//! module caught it, the run completed, and nothing in the run said a
//! credential was missing. Driven through the production `fetch`; every case
//! is paired with a control on the same context shape. The host is a
//! TEST-NET-3 literal (public to the SSRF classifier, never routed), so no
//! DNS lookup runs.

use std::collections::HashMap;
use std::sync::Arc;

use aegix_workflow_job_protocol::LlmTier;

use super::vault::unresolved_vault_reference_diagnostic;
use super::{wit_http, AegixContext};
use crate::context::HostDiagSink;
use crate::reason_class;
use crate::wit_inspector::CapabilityWorld;

/// Distinct from every other test module's literal, so the process-global
/// circuit breaker cannot be in a state another test left it in.
const HOST: &str = "203.0.113.151";
const STORED: &str = "test/unresolved-token";
const MINTED: &str = "gcp/impersonated/reader@example-project.iam.gserviceaccount.com/as/0b1c2d3e-4f50-4a61-8b72-9c83d4e5f607/access_token";
const PLAINTEXT: &str = "unresolved-test-plaintext";

/// A context granted `granted`, whose secret map holds `given`.
fn ctx(granted: &[&str], given: &[(&str, &str)]) -> (AegixContext, HostDiagSink) {
    let secrets: HashMap<_, _> = given
        .iter()
        .map(|(k, v)| (k.to_string(), zeroize::Zeroizing::new(v.to_string())))
        .collect();
    let mut c = AegixContext::new(
        CapabilityWorld::Http,
        vec![HOST.to_string()],
        vec!["GET".to_string()],
        128,
        secrets,
        None,
        None,
        false,
        None,
        Arc::new(crate::expose_fallback::ExposeFallback::new()),
        LlmTier::Tier2,
        None,
    )
    .expect("context builds");
    c.allowed_secrets = granted.iter().map(|p| p.to_string()).collect();
    let sink: HostDiagSink = Arc::new(std::sync::Mutex::new(Vec::new()));
    c.host_diag_sink = Some(sink.clone());
    (c, sink)
}

fn diag(sink: &HostDiagSink) -> String {
    sink.lock().unwrap().join("\n")
}

fn latched(c: &AegixContext) -> Option<&'static str> {
    c.network_reason_handle().lock().unwrap().map(|r| r.class)
}

fn get_with(path: &str) -> wit_http::Request {
    wit_http::Request {
        method: wit_http::Method::Get,
        url: format!("https://{HOST}/r"),
        headers: vec![(
            "authorization".to_string(),
            format!("Bearer vault://{path}"),
        )],
        body: vec![],
        timeout_ms: Some(1),
    }
}

#[tokio::test]
async fn a_granted_stored_secret_the_run_was_not_given_is_explained() {
    let (mut c, sink) = ctx(&[STORED], &[]);
    let r = <AegixContext as wit_http::Host>::fetch(&mut c, get_with(STORED)).await;
    assert!(matches!(r, Err(wit_http::Error::Forbiddenhost)), "{r:?}");
    assert_eq!(latched(&c), Some(reason_class::SECRET_LOOKUP));
    let d = diag(&sink);
    assert!(d.contains("[host:secret-lookup]"), "{d}");
    assert!(d.contains("this run was not given"), "{d}");
    assert!(d.contains("nothing is stored at that path"), "{d}");
    assert!(
        !d.contains(STORED),
        "the path stays out of the diagnostic: {d}"
    );
}

#[tokio::test]
async fn a_minted_token_the_controller_could_not_mint_is_named_as_one() {
    let (mut c, sink) = ctx(&[MINTED], &[]);
    let r = <AegixContext as wit_http::Host>::fetch(&mut c, get_with(MINTED)).await;
    assert!(matches!(r, Err(wit_http::Error::Forbiddenhost)), "{r:?}");
    let d = diag(&sink);
    assert!(
        d.contains("Google Cloud impersonated token minted at dispatch"),
        "{d}"
    );
    assert!(d.contains("GCP impersonated-token mint failed"), "{d}");
    assert!(
        !d.contains("reader@example-project"),
        "no service account in it: {d}"
    );
}

/// CONTROL: the same granted reference, given to the run, raises no
/// secret-lookup diagnostic (the call then fails on the 1 ms deadline).
#[tokio::test]
async fn a_given_credential_raises_no_secret_lookup_diagnostic() {
    let (mut c, sink) = ctx(&[STORED], &[(STORED, PLAINTEXT)]);
    let _ = <AegixContext as wit_http::Host>::fetch(&mut c, get_with(STORED)).await;
    assert_ne!(latched(&c), Some(reason_class::SECRET_LOOKUP));
    assert!(!diag(&sink).contains("secret-lookup"), "{}", diag(&sink));
}

#[tokio::test]
async fn a_given_credential_that_cannot_be_a_header_is_explained() {
    let (mut c, sink) = ctx(&[STORED], &[(STORED, "line\r\nbreak")]);
    let r = <AegixContext as wit_http::Host>::fetch(&mut c, get_with(STORED)).await;
    assert!(matches!(r, Err(wit_http::Error::Forbiddenhost)), "{r:?}");
    let d = diag(&sink);
    assert!(d.contains("this run was given"), "{d}");
    assert!(d.contains("line break or NUL"), "{d}");
    assert!(
        !d.contains("line\r\nbreak"),
        "the value stays out of the diagnostic: {d}"
    );
}

#[test]
fn the_diagnostic_tells_each_kind_apart_and_carries_only_the_hash() {
    let github = unresolved_vault_reference_diagnostic("authorization", "github_app:acme", "h1");
    assert!(github.contains("GitHub App installation token"), "{github}");
    let stored = unresolved_vault_reference_diagnostic("authorization", STORED, "h2");
    assert!(stored.contains("nothing is stored"), "{stored}");
    for d in [&github, &stored] {
        assert!(d.contains("vault_path_hash=h"), "{d}");
        assert!(!d.contains("acme") && !d.contains(STORED), "{d}");
    }
}
