use std::sync::Arc;
use worker::runtime::AegixRuntime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Worker is credential-free as of Phase 2.10; database access flows
    // through signed NATS-RPC to the controller. No PgPool here.
    let runtime = Arc::new(AegixRuntime::with_resources(None, None, None)?);

    let wasm_bytes = std::fs::read("/tmp/sandbox.wasm")?;
    let input = serde_json::json!({
        "config": {
            "query": "SELECT 1"
        },
        "input": null
    });

    let input_str = serde_json::to_string(&input)?;
    match runtime.execute_module_string(&wasm_bytes, &input_str).await {
        Ok(res) => println!("Raw Success: '{}'", res),
        Err(e) => println!("Raw Error: {:?}", e),
    }

    // We execute the module using the same function that fails in the controller
    match runtime
        .execute_job_with_full_features(aegix_wasm_host::runtime::JobRun {
            wasm_bytes: &wasm_bytes,
            input,
            allowed_hosts: vec![],
            allowed_methods: vec![],
            secrets: std::collections::HashMap::new(),
            max_memory_mb: 128,
            max_fuel_override: None,
            timeout: std::time::Duration::from_secs(10),
            execution_context: None,
            retry_policy: worker::runtime::RetryPolicy::in_process_transient(),
            security_policy: worker::runtime::SecurityPolicy::default(),
            capability_world_hint: None,
            dry_run: false,
            actor_id: None,
            user_id: uuid::Uuid::nil(),
            max_llm_tier: aegix_workflow_job_protocol::LlmTier::Tier2,
            max_write_ceiling: aegix_workflow_job_protocol::WriteCeiling::Write,
            http_verb_ceiling: None, // http_verb_ceiling — inherit the ceiling above
            egress_scope: None,      // egress_scope: tier default
            dispatch_attempt: 0, // dispatch_attempt — a hand-run example, no controller retry loop
            // inference_wait (RFC 0014 P2): no controller is timing this call
            options: aegix_wasm_host::runtime::JobRunOptions::default(),
        })
        .await
    {
        Ok(res) => println!("Success: {}", res),
        Err(e) => println!("Error: {:?}", e),
    }

    Ok(())
}
