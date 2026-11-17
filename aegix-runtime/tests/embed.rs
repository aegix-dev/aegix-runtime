//! The embed path end to end, with nothing but this crate: a real
//! `minimal-node` component is built from WAT against [`aegix_runtime::WIT`],
//! classified by the inspector, and run by the runtime with no controller,
//! no NATS and no environment. What `examples/embed_worker.rs` does, as a
//! test.

use aegix_runtime::{inspect_component, AegixRuntime, CapabilityWorld, WIT};

/// `run` logs once (so the `aegix:core/logging` import survives and the
/// inspector sees an Aegix node) and returns `ok("{}")`: the
/// `result<string,string>` return area is tag 0, then the string's pointer
/// and length. The same fixture as worker/tests/kill_switch_tests.rs.
const OK_CORE_WAT: &str = r#"
(module
  (import "aegix:core/logging" "log" (func $log (param i32 i32 i32)))
  (memory (export "memory") 1)
  (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (i32.const 200))
  (func (export "run") (param i32 i32) (result i32)
    (call $log (i32.const 1) (i32.const 0) (i32.const 0))
    (i32.store8 (i32.const 100) (i32.const 123)) ;; '{'
    (i32.store8 (i32.const 101) (i32.const 125)) ;; '}'
    (i32.store (i32.const 8) (i32.const 0))       ;; tag = ok
    (i32.store (i32.const 12) (i32.const 100))    ;; str ptr
    (i32.store (i32.const 16) (i32.const 2))      ;; str len
    (i32.const 8)))
"#;

/// Encode a core module as a `minimal-node` component of the WIT the crate
/// ships, the way an embedder's build would.
fn minimal_component(core_wat: &str) -> Vec<u8> {
    let mut core = wat::parse_str(core_wat).expect("core module WAT should parse");
    let mut resolve = wit_parser::Resolve::new();
    let pkg = resolve
        .push_str("aegix.wit", WIT)
        .expect("aegix_runtime::WIT should resolve");
    let world = resolve
        .select_world(pkg, Some("minimal-node"))
        .expect("minimal-node world should exist");
    wit_component::embed_component_metadata(
        &mut core,
        &resolve,
        world,
        wit_component::StringEncoding::UTF8,
    )
    .expect("embed minimal-node metadata");
    wit_component::ComponentEncoder::default()
        .validate(true)
        .module(&core)
        .expect("core module accepted by encoder")
        .encode()
        .expect("component should encode")
}

#[test]
fn a_component_built_against_the_shipped_wit_is_a_minimal_aegix_node() {
    let bytes = minimal_component(OK_CORE_WAT);
    let inspection = inspect_component(&bytes);
    assert!(inspection.is_aegix_node, "{inspection:?}");
    assert_eq!(inspection.capability_world, CapabilityWorld::Minimal);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_runtime_runs_a_component_with_no_controller() {
    let bytes = minimal_component(OK_CORE_WAT);
    let runtime = AegixRuntime::new().expect("runtime");

    let output = runtime
        .execute_module_string(&bytes, r#"{"message":"hello"}"#)
        .await
        .expect("the component returns ok");
    assert_fuel_stamped_empty_object(&output);

    let (result, _logs) = runtime.execute_test_module_string(&bytes, "{}").await;
    assert_fuel_stamped_empty_object(&result.expect("the test entry point returns ok"));
}

/// The module returned `{}`; the runtime stamps the fuel it metered into a
/// JSON-object output (`__fuel_consumed__`, `__fuel_limit__`) and nothing
/// else. Fuel accounting proper reads the signed result, never these keys.
fn assert_fuel_stamped_empty_object(output: &str) {
    let value: serde_json::Value = serde_json::from_str(output).expect("JSON output");
    let object = value.as_object().expect("an object");
    let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(keys, ["__fuel_consumed__", "__fuel_limit__"], "{output}");
    assert!(
        object["__fuel_consumed__"].as_u64().is_some_and(|f| f > 0),
        "{output}"
    );
    assert!(
        object["__fuel_limit__"].as_u64().is_some_and(|f| f > 0),
        "{output}"
    );
}
