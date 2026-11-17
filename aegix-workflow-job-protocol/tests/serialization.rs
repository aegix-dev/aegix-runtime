//! Basic serialization / deserialization tests for the shared job protocol.

use aegix_workflow_job_protocol::{
    EncryptedSecrets, JobRequest, JobResult, JobStatus, LlmTier, WriteCeiling,
};
use serde_json::json;
use uuid::Uuid;

#[test]
fn job_request_roundtrip() {
    let req = JobRequest {
        crypto_scheme: 0,
        sealing: 0,
        secret_paths: Vec::new(),
        claim_inbox: None,
        job_id: Uuid::new_v4(),
        workflow_execution_id: Uuid::new_v4(),
        module_uri: "file://tmp/module.wasm".to_string(),
        input_payload: json!({"key": "value"}).into(),
        encrypted_secrets: EncryptedSecrets::empty(),
        timeout_ms: 5000,
        allowed_hosts: vec!["example.com".to_string()],
        allowed_methods: vec!["GET".to_string()],
        allowed_secrets: vec![],
        allowed_sql_operations: vec![],
        allow_tier2_exposure: false,
        priority: 100,
        deadline_unix_secs: 0,
        cancellation_token: None,
        signature: vec![0, 1, 2, 3],
        job_nonce: "0:deadbeef".to_string(),
        actor_id: None,
        wasm_bytes: None,
        capability_world: None,
        expected_wasm_hash: None,
        integration_name: None,
        user_id: Uuid::nil(),
        max_fuel: 0,
        dry_run: false,
        read_only_posts: Vec::new(),
        reply_topic: None,
        idempotency_key: None,
        dispatch_attempt: 0,
        max_llm_tier: LlmTier::default(),
        max_write_ceiling: WriteCeiling::default(),
        egress_scope: None,
        http_verb_ceiling: None,
    };
    let ser = serde_json::to_string(&req).expect("serialize request");
    let de: JobRequest = serde_json::from_str(&ser).expect("deserialize request");
    assert_eq!(req.job_id, de.job_id);
    assert_eq!(req.module_uri, de.module_uri);
}

#[test]
fn job_result_roundtrip() {
    let res = JobResult {
        dispatch_attempt: 0,
        workflow_execution_id: None,
        llm_usage: vec![],
        crypto_scheme: 0,
        job_id: Uuid::new_v4(),
        status: JobStatus::Success,
        output_payload: json!({"out": 42}).into(),
        logs: vec!["log entry".to_string()],
        execution_time_ms: 123,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        fuel: None,
    };
    let ser = serde_json::to_string(&res).expect("serialize result");
    let de: JobResult = serde_json::from_str(&ser).expect("deserialize result");
    assert_eq!(res.job_id, de.job_id);
    assert_eq!(de.status, JobStatus::Success);
}
