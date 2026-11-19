use aegix_workflow_job_protocol::LlmTier;
use serde_json::json;
use std::time::Duration;
use uuid::Uuid;
use worker::runtime::{AegixRuntime, RetryPolicy, SecurityPolicy};

#[tokio::test]
async fn test_runtime_no_nested_block_on() {
    let runtime = AegixRuntime::new().expect("Failed to create runtime");

    // We'll use a dummy buffer that isn't valid WASM.
    // The key is that execute_job_with_full_features is an async function
    // and we are calling it from a tokio::test (which has a runtime).
    // If it internally uses block_on, it will panic before even validating the WASM.
    let wasm = b"\0asm\x01\0\0\0";

    let result = runtime
        .execute_job_with_full_features(aegix_wasm_host::runtime::JobRun {
            wasm_bytes: wasm,
            input: json!({"test": true}),
            allowed_hosts: vec![],
            allowed_methods: vec![],
            secrets: std::collections::HashMap::new(),
            max_memory_mb: 128,
            max_fuel_override: None,
            timeout: Duration::from_secs(1),
            execution_context: None,
            retry_policy: RetryPolicy::none(),
            security_policy: SecurityPolicy::default(),
            capability_world_hint: None,
            dry_run: false,
            actor_id: None,
            user_id: Uuid::nil(),
            max_llm_tier: LlmTier::Tier2,
            max_write_ceiling: aegix_workflow_job_protocol::WriteCeiling::Write,
            http_verb_ceiling: None, // http_verb_ceiling — inherit the ceiling above
            egress_scope: None,      // egress_scope: tier default
            dispatch_attempt: 0,
            // inference_wait (RFC 0014 P2): no controller is timing this call
            options: aegix_wasm_host::runtime::JobRunOptions::default(),
        })
        .await;

    // It should fail with a WASM validation error, NOT a runtime panic.
    assert!(result.is_err());
    let err_str = format!("{:?}", result.err());
    assert!(
        !err_str.contains("Cannot start a runtime from within a runtime"),
        "Detected nested block_on panic!"
    );
}
