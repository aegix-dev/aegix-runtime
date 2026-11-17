//! Run one WASM component through the Aegix runtime with no controller and
//! no NATS: the runtime alone, a component from disk, a fixed input.
//!
//! ```text
//! cargo run -p aegix-runtime --example embed_worker -- <component.wasm> ['{"json":"input"}']
//! ```
//!
//! The component is any `aegix:core` node (`module-templates/echo-debug`
//! compiled with `cargo component build`, or the fixture `tests/embed.rs`
//! builds). Without a controller there is no actor, no secret and no signed
//! RPC: a host call that needs one (`agent-memory`, `secrets`, `database`)
//! is refused by the runtime exactly as it is refused in production.

use std::time::Duration;

use aegix_runtime::{inspect_component, AegixRuntime, RUNTIME_API_VERSION};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: embed_worker <component.wasm> [input-json]"))?;
    let input = args
        .next()
        .unwrap_or_else(|| r#"{"message":"hello from the embedder"}"#.to_string());
    serde_json::from_str::<serde_json::Value>(&input)
        .map_err(|e| anyhow::anyhow!("the input is not JSON: {e}"))?;

    // 1. Look before linking: which capability world does the binary fit?
    let bytes = std::fs::read(&path)?;
    let inspection = inspect_component(&bytes);
    anyhow::ensure!(
        inspection.is_aegix_node,
        "{path} does not export `run`: it is not an Aegix node"
    );
    eprintln!(
        "aegix-runtime {RUNTIME_API_VERSION}: {path} fits world {:?}, imports {:?}",
        inspection.capability_world, inspection.imported_interfaces
    );

    // 2. The host. `new()` is the production configuration: fuel metering,
    //    the epoch ticker, the pooling allocator, no Redis, no NATS, no
    //    sandbox directory.
    let runtime = AegixRuntime::new()?;

    // 3. Run it. The test entry point collects what the module wrote to its
    //    log beside the result; `execute_module_string` is the plain form.
    let (result, logs) = runtime.execute_test_module_string(&bytes, &input).await;
    for line in &logs {
        eprintln!("module log: {line}");
    }
    let output = result.map_err(anyhow::Error::msg)?;
    println!("{output}");

    // 4. Let in-flight work drain (there is none here) before the process ends.
    runtime.shutdown_gracefully(Duration::from_secs(5)).await?;
    Ok(())
}
