//! Compile one module source file to a WebAssembly component, with no
//! controller and no database: the production compile path
//! ([`aegix_compilation::CompilationService::compile_rust_for_world`]) run
//! from the command line.
//!
//! ```text
//! cargo run -p aegix-compilation --example compile_module -- \
//!     <source.rs> <capability world> <out.wasm>
//! ```
//!
//! The source is a module as an author writes one: `pub fn run(input: String)
//! -> Result<String, String>`, with or without the `#[aegix_module]`
//! attribute. A source without it is given the attribute for the world on
//! the command line, as the platform's inline compile does
//! (`wrap_rust_code_with_aegix_module`).
//!
//! It needs what any host-side compile needs: `cargo component` and the
//! `wasm32-wasip2` target. The WIT file and the SDK macros are taken from
//! this checkout unless `AEGIX_WIT_PATH` / `AEGIX_SDK_MACROS_PATH` name
//! others. The build directory is `COMPILE_DIR`, or a directory under the
//! system's temporary directory.

use std::path::PathBuf;

/// The source with `#[aegix_module(world = …)]` placed on `fn run`, unless
/// it already names its macro layer.
fn with_module_attribute(source: &str, world: &str) -> String {
    let wrapped = [
        "wit_bindgen::generate!",
        "#[aegix_node",
        "aegix_sdk_macros::aegix_node",
        "#[aegix_module",
        "aegix_sdk_macros::aegix_module",
    ];
    if wrapped.iter().any(|marker| source.contains(marker)) {
        return source.to_string();
    }
    let run_fn =
        regex::Regex::new(r"(?m)^[ \t]*(pub[ \t]+)?fn[ \t]+run[ \t]*\(").expect("a fixed pattern");
    match run_fn.find(source) {
        Some(m) => format!(
            "{}#[aegix_sdk_macros::aegix_module(world = \"{world}\")]\n{}",
            &source[..m.start()],
            &source[m.start()..]
        ),
        None => source.to_string(),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [source, world, out] = args.as_slice() else {
        anyhow::bail!("usage: compile_module <source.rs> <capability world> <out.wasm>");
    };
    let source_code = with_module_attribute(
        &std::fs::read_to_string(source).map_err(|e| anyhow::anyhow!("{source}: {e}"))?,
        world,
    );

    if std::env::var_os("AEGIX_SDK_MACROS_PATH").is_none() {
        // Before any thread is started: the runtime below is current-thread
        // and nothing else has run.
        let macros = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../aegix_sdk_macros");
        std::env::set_var("AEGIX_SDK_MACROS_PATH", macros);
    }
    let compile_dir = std::env::var_os("COMPILE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("talos-compile-module"));

    let (events, _) = tokio::sync::broadcast::channel(16);
    let service = aegix_compilation::CompilationService::new(compile_dir, events);
    let name = PathBuf::from(source).file_stem().map_or_else(
        || "module".to_string(),
        |s| s.to_string_lossy().into_owned(),
    );
    let result = service
        .compile_rust_for_world(
            uuid::Uuid::nil(),
            uuid::Uuid::new_v4(),
            &name,
            &source_code,
            &serde_json::json!({}),
            None,
            world,
        )
        .await?;

    let Some(wasm) = result.wasm_bytes.filter(|_| result.success) else {
        for error in &result.errors {
            eprintln!("{error:?}");
        }
        anyhow::bail!("{source} did not compile for {world}");
    };
    std::fs::write(out, &wasm).map_err(|e| anyhow::anyhow!("{out}: {e}"))?;
    eprintln!(
        "{out}: {} bytes, world {:?}, sha256 {}",
        wasm.len(),
        result.capability_world,
        result.content_hash
    );
    Ok(())
}
