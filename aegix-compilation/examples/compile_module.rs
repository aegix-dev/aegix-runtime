//! Compile one module to a WebAssembly component, with no controller and
//! no database: the production compile path
//! ([`aegix_compilation::CompilationService::compile_rust_for_world`]) run
//! from the command line.
//!
//! ```text
//! cargo run -p aegix-compilation --example compile_module -- \
//!     <template directory> <out.wasm>
//! cargo run -p aegix-compilation --example compile_module -- \
//!     <source.rs> <capability world> <out.wasm>
//! ```
//!
//! A template directory is read as a controller reads one
//! ([`aegix_compilation::CatalogTemplate`]): its `talos.json` names the
//! capability world and any extra crates the source needs, and its source is
//! `template.rs`, else `src/lib.rs`. The world is never taken from anywhere
//! else for a directory, and a manifest that names none is refused. A bare
//! source file has no manifest, so its world is the second argument and it
//! gets no extra crates.
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

use std::path::{Path, PathBuf};

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

/// What one run compiles, read from the command line.
struct Inputs {
    /// What the messages call the module: the path that was given.
    shown: String,
    name: String,
    source: String,
    world: String,
    dependencies: Option<serde_json::Value>,
    /// The fuel limit a template's manifest recommends, when it states one.
    recommended_fuel: Option<u64>,
    out: String,
}

const USAGE: &str = "usage: compile_module <template directory> <out.wasm>\n       \
                     compile_module <source.rs> <capability world> <out.wasm>";

/// A template directory: the manifest is the one statement of the world and
/// of the extra crates, as it is for a controller.
fn template_inputs(dir: &str, out: &str) -> anyhow::Result<Inputs> {
    use aegix_compilation::CatalogTemplateError as E;
    let template =
        aegix_compilation::CatalogTemplate::load(Path::new(dir)).map_err(|e| match e {
            E::ReadManifest(e) => anyhow::anyhow!("{dir}/talos.json could not be read: {e}"),
            E::ParseManifest(e) => anyhow::anyhow!("{dir}/talos.json is not JSON: {e}"),
            E::ReadSource(e) => {
                anyhow::anyhow!("{dir} has neither template.rs nor src/lib.rs: {e}")
            }
        })?;
    let world = template
        .manifest()
        .get("capability_world")
        .and_then(serde_json::Value::as_str)
        .filter(|w| !w.trim().is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("{dir}/talos.json names no capability_world, and none is assumed")
        })?
        .to_string();
    // Said here so the message names the crate; the compile refuses it too.
    template
        .validate_dependencies()
        .map_err(|e| anyhow::anyhow!("{dir}/talos.json: {e}"))?;
    let recommended_fuel = template
        .recommended_max_fuel()
        .map_err(|e| anyhow::anyhow!("{dir}/talos.json: {e}"))?;
    Ok(Inputs {
        shown: dir.to_string(),
        name: template.slug().unwrap_or("module").to_string(),
        source: with_module_attribute(template.source(), &world),
        world,
        dependencies: template.dependencies().cloned(),
        recommended_fuel,
        out: out.to_string(),
    })
}

/// One source file and the world it is to be held to.
fn source_inputs(source: &str, world: &str, out: &str) -> anyhow::Result<Inputs> {
    let text = std::fs::read_to_string(source).map_err(|e| anyhow::anyhow!("{source}: {e}"))?;
    Ok(Inputs {
        shown: source.to_string(),
        name: Path::new(source).file_stem().map_or_else(
            || "module".to_string(),
            |s| s.to_string_lossy().into_owned(),
        ),
        source: with_module_attribute(&text, world),
        world: world.to_string(),
        dependencies: None,
        recommended_fuel: None,
        out: out.to_string(),
    })
}

fn inputs(args: &[String]) -> anyhow::Result<Inputs> {
    match args {
        [dir, out] if Path::new(dir).is_dir() => template_inputs(dir, out),
        [path, _] => anyhow::bail!(
            "{path} is not a directory: a source file also needs its capability world\n{USAGE}"
        ),
        [dir, _, _] if Path::new(dir).is_dir() => anyhow::bail!(
            "{dir} is a template directory: its world is the one in its talos.json\n{USAGE}"
        ),
        [source, world, out] => source_inputs(source, world, out),
        _ => anyhow::bail!("{USAGE}"),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Inputs {
        shown,
        name,
        source,
        world,
        dependencies,
        recommended_fuel,
        out,
    } = inputs(&args)?;

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
    let result = service
        .compile_rust_for_world(
            uuid::Uuid::nil(),
            uuid::Uuid::new_v4(),
            &name,
            &source,
            &serde_json::json!({}),
            dependencies.as_ref(),
            &world,
        )
        .await?;

    let Some(wasm) = result.wasm_bytes.filter(|_| result.success) else {
        for error in &result.errors {
            eprintln!("{error:?}");
        }
        anyhow::bail!("{shown} did not compile for {world}");
    };
    std::fs::write(&out, &wasm).map_err(|e| anyhow::anyhow!("{out}: {e}"))?;
    eprintln!(
        "{out}: {} bytes, world {:?}, sha256 {}",
        wasm.len(),
        result.capability_world,
        result.content_hash
    );
    if let Some(fuel) = recommended_fuel {
        eprintln!("{shown}: its manifest recommends a fuel limit of {fuel}");
    }
    Ok(())
}
