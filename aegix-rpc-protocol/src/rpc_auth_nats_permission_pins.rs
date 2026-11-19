//! The seven signed data-RPC subjects are REQUESTS the worker publishes
//! and the controller answers. Their canonical consts live in this crate,
//! ABOVE `aegix-workflow-job-protocol`, so the broker permission model
//! there spells them as literals; this is the cross-pin that keeps those
//! literals honest. Each subject must be a permitted worker PUBLISH
//! (or every RPC dies at the broker) and a refused worker SUBSCRIBE (a
//! worker must not be able to intercept a sibling's request).
use aegix_workflow_job_protocol::nats_permissions::{worker_may_publish, worker_may_subscribe};

const RPC_SUBJECTS: &[&str] = &[
    crate::memory_rpc::SUBJECT_MEMORY_OP,
    crate::graph_rpc::SUBJECT_GRAPH_SEARCH,
    crate::database_rpc::SUBJECT_DATABASE_QUERY,
    crate::state_rpc::SUBJECT_STATE_WRITE,
    crate::integration_state_rpc::SUBJECT_INTEGRATION_STATE_OP,
    crate::ml_rpc::SUBJECT_ML_PREDICT,
    crate::ml_rpc::SUBJECT_ML_FEWSHOT,
];

#[test]
fn every_rpc_subject_is_a_permitted_publish_and_a_refused_subscribe() {
    assert_eq!(
        RPC_SUBJECTS.len(),
        7,
        "a new RPC subject must be added here AND to nats_permissions' tests"
    );
    for s in RPC_SUBJECTS {
        assert!(
            worker_may_publish(s),
            "worker must be able to request on {s}"
        );
        assert!(
            !worker_may_subscribe(s, None) && !worker_may_subscribe(s, Some(s)),
            "worker must not be able to subscribe to {s}"
        );
    }
}
