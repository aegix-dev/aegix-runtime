//! The controller's reserved RPC identity (2026-10-29): no worker may hold
//! it, the registry resolves it only to the key the controller installed,
//! a dynamic refresh cannot displace it, and the identity key is a derivation
//! of the dispatch seed rather than the seed itself. Its own binary: the
//! registry is process-global.

use aegix_workflow_job_protocol::{
    derive_controller_rpc_identity_key, generate_dispatch_signing_key,
    register_controller_rpc_verifying_key, set_dynamic_worker_public_keys, validate_worker_id,
    worker_public_keys, CONTROLLER_RPC_IDENTITY,
};

#[test]
fn no_worker_may_register_under_the_controllers_identity() {
    let err = validate_worker_id(CONTROLLER_RPC_IDENTITY).unwrap_err();
    assert!(err.contains("reserved"), "{err}");
    validate_worker_id("talos-controller-2").expect("a longer id is an ordinary worker id");
}

#[test]
fn the_registry_resolves_the_identity_only_to_the_installed_key() {
    assert!(
        worker_public_keys(CONTROLLER_RPC_IDENTITY).is_empty(),
        "nothing resolves before the controller installs its key"
    );
    let controller = generate_dispatch_signing_key();
    assert!(register_controller_rpc_verifying_key(
        controller.verifying_key()
    ));
    assert_eq!(
        worker_public_keys(CONTROLLER_RPC_IDENTITY),
        vec![controller.verifying_key()]
    );
    // First wins: a second install changes nothing.
    let other = generate_dispatch_signing_key();
    assert!(!register_controller_rpc_verifying_key(
        other.verifying_key()
    ));
    assert_eq!(
        worker_public_keys(CONTROLLER_RPC_IDENTITY),
        vec![controller.verifying_key()]
    );
    // A dynamic refresh (the DB overlay) neither displaces the identity nor
    // admits a row that claims it.
    let worker = generate_dispatch_signing_key();
    set_dynamic_worker_public_keys([
        ("worker-7".to_string(), worker.verifying_key()),
        (CONTROLLER_RPC_IDENTITY.to_string(), other.verifying_key()),
    ]);
    assert_eq!(
        worker_public_keys(CONTROLLER_RPC_IDENTITY),
        vec![controller.verifying_key()]
    );
    assert_eq!(worker_public_keys("worker-7"), vec![worker.verifying_key()]);
    // And an empty refresh keeps it.
    set_dynamic_worker_public_keys(std::iter::empty());
    assert_eq!(
        worker_public_keys(CONTROLLER_RPC_IDENTITY),
        vec![controller.verifying_key()]
    );
    assert!(worker_public_keys("worker-7").is_empty());
}

#[test]
fn the_identity_key_is_derived_from_the_seed_and_is_not_the_seed() {
    let seed = generate_dispatch_signing_key();
    let a = derive_controller_rpc_identity_key(&seed);
    let b = derive_controller_rpc_identity_key(&seed);
    assert_eq!(
        a.to_bytes(),
        b.to_bytes(),
        "deterministic: every replica derives the same"
    );
    assert_ne!(
        a.verifying_key(),
        seed.verifying_key(),
        "a key of its own, not the dispatch key reused"
    );
    let other = derive_controller_rpc_identity_key(&generate_dispatch_signing_key());
    assert_ne!(a.verifying_key(), other.verifying_key());
}
