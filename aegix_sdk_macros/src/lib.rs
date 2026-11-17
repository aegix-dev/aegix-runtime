// This crate cannot inherit the workspace's lint table (its Cargo.toml says
// why), so the one workspace rule that is a safety rule is stated here.
#![forbid(unsafe_code)]

use proc_macro2::TokenStream;
use quote::quote;
use syn::{FnArg, ItemFn, PatType};

/// Extract a named attribute value from an attribute string like
/// `provider = "anthropic", model = "claude-sonnet-4-20250514"`.
///
/// Returns `None` if the key is not present.
fn extract_attr(attr_str: &str, key: &str) -> Option<String> {
    let pattern = format!("{} = \"", key);
    if let Some(start) = attr_str.find(&pattern) {
        let rest = &attr_str[start + pattern.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    // Also try without spaces around `=`
    let pattern_no_space = format!("{}=\"", key);
    if let Some(start) = attr_str.find(&pattern_no_space) {
        let rest = &attr_str[start + pattern_no_space.len()..];
        if let Some(end) = rest.find('"') {
            return Some(rest[..end].to_string());
        }
    }
    None
}

/// Entry-point macro for an Aegix WASM module whose `run` takes typed config
/// fields (one fn argument per `config` key, auto-deserialized).
///
/// # The `world` attribute selects your capabilities — and it is the ONLY thing
/// that does.
///
/// ```ignore
/// #[aegix_node(world = "secrets-node")]   // ← this drives everything
/// fn run(repo: String, token_secret: String) -> Result<String, String> { ... }
/// ```
///
/// The `world` string picks the WIT *capability world* the module is compiled
/// against. The compilation scaffold reads it straight out of this attribute
/// (`aegix-compilation`'s `extract_wit_world`) to generate `bindings.rs`, so it
/// decides which `aegix::core::*` interfaces exist. It is **NOT** read from
/// `talos.json` — `capability_world` there is metadata for the catalog UI and
/// MUST be kept identical to this attribute (enforced by `lint-structural.sh`
/// check 48). If they disagree, the macro wins and you get a confusing
/// `unresolved import aegix::core::http` instead of a clear error.
///
/// **Omitting `world` defaults to `minimal-node`** (least privilege: `logging`,
/// `json`, `datetime`, `crypto`, `env` only — JSON in/out, no `http`/`secrets`).
/// Always declare it explicitly; a bare `#[aegix_node]` that imports
/// `aegix::core::http` will fail to compile because `minimal-node` has no `http`.
///
/// # Available worlds (least → most privileged)
/// | world | adds on top of minimal |
/// |---|---|
/// | `minimal-node` | — (logging, json, datetime, crypto, env) |
/// | `http-node` | `http`, `webhook` |
/// | `secrets-node` | `http`, `secrets` (GitHub/OpenAI tokens via `get_secret`) |
/// | `network-node` | `http`, `graphql`, `email`, `state`, `http-stream`, … |
/// | `database-node` | `database` (sandbox SQL) |
/// | `llm-node` | `llm` host functions |
/// | `cache-node`, `messaging-node`, `filesystem-node`, `governance-node`, `agent-node`, `automation-node` | see `wit/aegix.wit` |
///
/// Pick the *smallest* world that satisfies your imports. The exact interface
/// set per world is the source of truth in `wit/aegix.wit`.
///
/// # Example
/// ```ignore
/// use aegix::core::http::{fetch, Method, Request};
/// use aegix::core::secrets::get_secret;
///
/// #[aegix_node(world = "secrets-node")]
/// fn run(repo: String, token_secret: String) -> Result<String, String> {
///     let token = get_secret(&token_secret)?;
///     // ... fetch + return JSON string ...
///     Ok("{}".into())
/// }
/// ```
///
/// See also [`aegix_module`] (free-form `run(input: String)` signature) and
/// [`aegix_agent`] (LLM agent scaffold).
#[proc_macro_attribute]
pub fn aegix_node(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    expand_aegix_node(attr.into(), item.into()).into()
}

/// What [`macro@aegix_node`] expands to. Apart from the conversions above, the
/// whole macro: tests call this directly and compare its output with a
/// recorded expansion.
fn expand_aegix_node(attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed_fn: ItemFn = match syn::parse2(item) {
        Ok(parsed) => parsed,
        Err(error) => return error.to_compile_error(),
    };

    // Parse the world from #[aegix_node(world = "xxx")]
    // Default to minimal-node (least privilege) if not provided
    let world_str = if attr.is_empty() {
        "minimal-node".to_string()
    } else {
        let attr_str = attr.to_string();
        extract_attr(&attr_str, "world").unwrap_or_else(|| "minimal-node".to_string())
    };

    let world_marker = format!("__talos_world_{}__", world_str);
    let world_marker_bytes =
        syn::LitByteStr::new(world_marker.as_bytes(), proc_macro2::Span::call_site());

    let fn_name = &parsed_fn.sig.ident;
    let inputs = &parsed_fn.sig.inputs;

    let mut deserializers = Vec::new();
    let mut call_args = Vec::new();

    for input in inputs {
        if let FnArg::Typed(PatType { pat, ty, .. }) = input {
            if let syn::Pat::Ident(pat_ident) = &**pat {
                let arg_name = &pat_ident.ident;
                let arg_name_str = arg_name.to_string();

                deserializers.push(quote! {
                    let #arg_name: #ty = match serde_json::from_value(config.get(#arg_name_str).cloned().unwrap_or(serde_json::Value::Null)) {
                        Ok(v) => v,
                        Err(e) => return Err(format!("Invalid '{}' parameter: {}", #arg_name_str, e)),
                    };
                });

                call_args.push(quote! { #arg_name });
            }
        }
    }

    let expanded = quote! {
        // cargo-component 0.21+ auto-generates src/bindings.rs from the WIT file.
        // include!() with CARGO_MANIFEST_DIR finds it regardless of whether the
        // crate root is src/lib.rs or template.rs (both resolve to package_root/src/).
        #[allow(warnings)]
        mod bindings {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings.rs"));
        }

        // Expose crate::bindings::aegix at the top-level `aegix` path so template
        // code can use the idiomatic `use aegix::core::cache` / `aegix::core::secrets`
        // syntax.  All WIT worlds live in the `aegix:core` package, so this alias
        // is always valid regardless of which capability world is selected.
        #[allow(unused_imports)]
        use crate::bindings::aegix as aegix;

        struct AegixGuest;

        impl bindings::Guest for AegixGuest {
            fn run(input_str: String) -> Result<String, String> {
                // catch_unwind is present for future compatibility but is currently
                // unreachable on wasm32-wasip2 component targets: the WASM component
                // model adapter assumes panic = "abort" ABI conventions, so enabling
                // software unwinding breaks the WIT boundary entirely.  Panics are
                // recovered at the host level via WASI stderr capture and
                // extract_panic_message_from_stderr() in worker/src/runtime.rs, which
                // produces the same clean Err("PANIC: ...") presentation.
                match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                    let payload: serde_json::Value = match serde_json::from_str(&input_str) {
                        Ok(p) => p,
                        Err(e) => return Err(format!("Failed to parse workflow input: {}", e)),
                    };

                    let config = payload.get("config").unwrap_or(&serde_json::Value::Null);

                    #(#deserializers)*

                    match #fn_name(#(#call_args),*) {
                        Ok(res) => Ok(res),
                        Err(err) => Err(err),
                    }
                })) {
                    Ok(r) => r,
                    Err(p) => {
                        let msg = p.downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<::std::string::String>().cloned())
                            .unwrap_or_else(|| "panic (non-string payload)".to_string());
                        Err(::std::format!("PANIC: {}", msg))
                    }
                }
            }
        }

        bindings::export!(AegixGuest with_types_in bindings);

        #[used]
        #[no_mangle]
        pub static __TALOS_WORLD: &[u8] = #world_marker_bytes;

        #[export_name = "wizer.initialize"]
        pub extern "C" fn init() {
            let _prime = Vec::<u8>::with_capacity(1024 * 1024);
        }

        #parsed_fn
    };

    expanded
}

/// Entry-point macro for an Aegix WASM module whose `run` takes the raw envelope
/// `String` (you parse `{config, input, ...}` yourself). Use [`aegix_node`]
/// instead if you want typed config arguments.
///
/// # The `world` attribute selects your capabilities
///
/// Identical contract to [`aegix_node`]: the `world = "..."` string picks the
/// WIT capability world the module compiles against (read by the compilation
/// scaffold's `extract_wit_world`), which determines the available
/// `aegix::core::*` interfaces. It is **NOT** taken from `talos.json` — keep
/// `talos.json`'s `capability_world` identical to this attribute
/// (`lint-structural.sh` check 48 enforces the match). Omitting `world` defaults
/// to `minimal-node` (no `http`/`secrets`), so a bare `#[aegix_module]` that
/// imports `aegix::core::http` fails to compile.
///
/// See [`aegix_node`] for the full world table and a worked example.
///
/// # Example
/// ```ignore
/// #[aegix_module(world = "http-node")]
/// fn run(input: String) -> Result<String, String> {
///     use aegix::core::http::{Method, Request};
///     // ... parse `input`, fetch, return JSON string ...
///     Ok("{}".into())
/// }
/// ```
#[proc_macro_attribute]
pub fn aegix_module(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    expand_aegix_module(attr.into(), item.into()).into()
}

/// What [`macro@aegix_module`] expands to. Apart from the conversions above, the
/// whole macro: tests call this directly and compare its output with a
/// recorded expansion.
fn expand_aegix_module(attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed_fn: ItemFn = match syn::parse2(item) {
        Ok(parsed) => parsed,
        Err(error) => return error.to_compile_error(),
    };

    let world_str = if attr.is_empty() {
        "minimal-node".to_string()
    } else {
        let attr_str = attr.to_string();
        extract_attr(&attr_str, "world").unwrap_or_else(|| "minimal-node".to_string())
    };

    let world_marker = format!("__talos_world_{}__", world_str);
    let world_marker_bytes =
        syn::LitByteStr::new(world_marker.as_bytes(), proc_macro2::Span::call_site());

    let fn_name = &parsed_fn.sig.ident;

    let expanded = quote! {
        // cargo-component 0.21+ auto-generates src/bindings.rs from the WIT file.
        // include!() with CARGO_MANIFEST_DIR finds it regardless of whether the
        // crate root is src/lib.rs or template.rs (both resolve to package_root/src/).
        #[allow(warnings)]
        mod bindings {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings.rs"));
        }

        // Expose crate::bindings::aegix at the top-level `aegix` path so template
        // code can use the idiomatic `use aegix::core::cache` / `aegix::core::secrets`
        // syntax.  All WIT worlds live in the `aegix:core` package, so this alias
        // is always valid regardless of which capability world is selected.
        #[allow(unused_imports)]
        use crate::bindings::aegix as aegix;

        struct AegixGuest;

        impl bindings::Guest for AegixGuest {
            fn run(input_str: String) -> Result<String, String> {
                // catch_unwind is present for future compatibility but is currently
                // unreachable on wasm32-wasip2 component targets: the WASM component
                // model adapter assumes panic = "abort" ABI conventions, so enabling
                // software unwinding breaks the WIT boundary entirely.  Panics are
                // recovered at the host level via WASI stderr capture and
                // extract_panic_message_from_stderr() in worker/src/runtime.rs, which
                // produces the same clean Err("PANIC: ...") presentation.
                match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                    #fn_name(input_str)
                })) {
                    Ok(r) => r,
                    Err(p) => {
                        let msg = p.downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<::std::string::String>().cloned())
                            .unwrap_or_else(|| "panic (non-string payload)".to_string());
                        Err(::std::format!("PANIC: {}", msg))
                    }
                }
            }
        }

        bindings::export!(AegixGuest with_types_in bindings);

        #[used]
        #[no_mangle]
        pub static __TALOS_WORLD: &[u8] = #world_marker_bytes;

        #[export_name = "wizer.initialize"]
        pub extern "C" fn init() {
            let _prime = Vec::<u8>::with_capacity(1024 * 1024);
        }

        #parsed_fn
    };

    expanded
}

/// Macro for building LLM-powered agent modules.
///
/// Defaults to the `secrets-node` world which includes LLM, secrets, and HTTP access.
/// Generates boilerplate for deserializing agent input (messages, tools, system prompt)
/// and serializing agent output.
///
/// The annotated function receives an `AgentInput` struct (auto-generated) with fields:
/// - `prompt` — the user's prompt or message
/// - `messages` — conversation history as JSON values
/// - `tools` — tool definitions available to the agent
/// - `system_prompt` — system prompt for the LLM
/// - `config` — module configuration from the workflow
/// - `input` — input data from parent nodes
///
/// and must return `Result<AgentOutput, String>` where `AgentOutput` has:
/// - `response` — the agent's response text
/// - `data` — optional structured data (`Option<serde_json::Value>`)
/// - `tool_calls` — tool calls made during execution (`Vec<serde_json::Value>`)
///
/// # Attributes
/// - `world = "..."` — Override the capability world (default: `secrets-node`)
/// - `provider = "..."` — Default LLM provider hint (default: `anthropic`)
/// - `model = "..."` — Default model hint (default: `claude-sonnet-4-20250514`)
///
/// # Example
/// ```ignore
/// #[aegix_agent(provider = "anthropic", model = "claude-sonnet-4-20250514")]
/// fn run(input: AgentInput) -> Result<AgentOutput, String> {
///     Ok(AgentOutput {
///         response: format!("Processed: {}", input.prompt),
///         data: None,
///         tool_calls: vec![],
///     })
/// }
/// ```
///
/// # Required dependencies in the agent crate
/// The generated code references `serde` and `serde_json` (pre-bundled).
/// `wit-bindgen-rt` is also pre-bundled automatically. No additional deps needed.
#[proc_macro_attribute]
pub fn aegix_agent(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    expand_aegix_agent(attr.into(), item.into()).into()
}

/// What [`macro@aegix_agent`] expands to. Apart from the conversions above, the
/// whole macro: tests call this directly and compare its output with a
/// recorded expansion.
fn expand_aegix_agent(attr: TokenStream, item: TokenStream) -> TokenStream {
    let parsed_fn: ItemFn = match syn::parse2(item) {
        Ok(parsed) => parsed,
        Err(error) => return error.to_compile_error(),
    };

    let attr_str = attr.to_string();

    // Extract world (default: secrets-node — agents need LLM + secrets access)
    let world_str = extract_attr(&attr_str, "world").unwrap_or_else(|| "secrets-node".to_string());

    // Extract provider and model hints for metadata markers
    let provider = extract_attr(&attr_str, "provider").unwrap_or_else(|| "anthropic".to_string());
    let model =
        extract_attr(&attr_str, "model").unwrap_or_else(|| "claude-sonnet-4-20250514".to_string());

    // Build world marker (same scheme as aegix_node / aegix_module)
    let world_marker = format!("__talos_world_{}__", world_str);
    let world_marker_bytes =
        syn::LitByteStr::new(world_marker.as_bytes(), proc_macro2::Span::call_site());

    // Agent metadata markers for binary inspection
    let provider_marker = format!("__talos_agent_provider_{}__", provider);
    let provider_marker_bytes =
        syn::LitByteStr::new(provider_marker.as_bytes(), proc_macro2::Span::call_site());

    let model_marker = format!("__talos_agent_model_{}__", model);
    let model_marker_bytes =
        syn::LitByteStr::new(model_marker.as_bytes(), proc_macro2::Span::call_site());

    let fn_name = &parsed_fn.sig.ident;

    let expanded = quote! {
        /// Agent input deserialized from the workflow engine.
        #[derive(serde::Deserialize, Debug)]
        pub struct AgentInput {
            /// The user's prompt or message.
            #[serde(default)]
            pub prompt: String,
            /// Conversation history (JSON array of messages).
            #[serde(default)]
            pub messages: Vec<serde_json::Value>,
            /// Tool definitions available to the agent (JSON array).
            #[serde(default)]
            pub tools: Vec<serde_json::Value>,
            /// System prompt for the LLM.
            #[serde(default)]
            pub system_prompt: String,
            /// Module configuration from the workflow.
            #[serde(default)]
            pub config: serde_json::Value,
            /// Input data from parent nodes.
            #[serde(default)]
            pub input: serde_json::Value,
        }

        /// Agent output serialized back to the workflow engine.
        #[derive(serde::Serialize, Debug)]
        pub struct AgentOutput {
            /// The agent's response text.
            pub response: String,
            /// Optional structured data.
            #[serde(skip_serializing_if = "Option::is_none")]
            pub data: Option<serde_json::Value>,
            /// Tool calls made during execution (for logging/audit).
            #[serde(skip_serializing_if = "Vec::is_empty")]
            pub tool_calls: Vec<serde_json::Value>,
        }

        // cargo-component 0.21+ auto-generates src/bindings.rs from the WIT file.
        // include!() with CARGO_MANIFEST_DIR finds it regardless of whether the
        // crate root is src/lib.rs or template.rs (both resolve to package_root/src/).
        #[allow(warnings)]
        mod bindings {
            include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bindings.rs"));
        }

        // Expose crate::bindings::aegix at the top-level `aegix` path so template
        // code can use the idiomatic `use aegix::core::cache` / `aegix::core::secrets`
        // syntax.  All WIT worlds live in the `aegix:core` package, so this alias
        // is always valid regardless of which capability world is selected.
        #[allow(unused_imports)]
        use crate::bindings::aegix as aegix;

        struct AegixAgentGuest;

        impl bindings::Guest for AegixAgentGuest {
            fn run(raw_input: String) -> Result<String, String> {
                // catch_unwind is present for future compatibility but is currently
                // unreachable on wasm32-wasip2 component targets: the WASM component
                // model adapter assumes panic = "abort" ABI conventions, so enabling
                // software unwinding breaks the WIT boundary entirely.  Panics are
                // recovered at the host level via WASI stderr capture and
                // extract_panic_message_from_stderr() in worker/src/runtime.rs, which
                // produces the same clean Err("PANIC: ...") presentation.
                match ::std::panic::catch_unwind(::std::panic::AssertUnwindSafe(|| {
                    // Parse agent input from JSON
                    let agent_input: AgentInput = serde_json::from_str(&raw_input)
                        .map_err(|e| format!("Failed to parse agent input: {}", e))?;

                    // Call user's agent function
                    let output = #fn_name(agent_input)?;

                    // Serialize output
                    serde_json::to_string(&output)
                        .map_err(|e| format!("Failed to serialize agent output: {}", e))
                })) {
                    Ok(r) => r,
                    Err(p) => {
                        let msg = p.downcast_ref::<&str>()
                            .map(|s| s.to_string())
                            .or_else(|| p.downcast_ref::<::std::string::String>().cloned())
                            .unwrap_or_else(|| "panic (non-string payload)".to_string());
                        Err(::std::format!("PANIC: {}", msg))
                    }
                }
            }
        }

        bindings::export!(AegixAgentGuest with_types_in bindings);

        // World marker — same scheme as aegix_node / aegix_module
        #[used]
        #[no_mangle]
        pub static __TALOS_WORLD: &[u8] = #world_marker_bytes;

        // Agent metadata markers for tooling / binary inspection
        #[used]
        #[no_mangle]
        pub static __TALOS_AGENT_PROVIDER: &[u8] = #provider_marker_bytes;

        #[used]
        #[no_mangle]
        pub static __TALOS_AGENT_MODEL: &[u8] = #model_marker_bytes;

        // Wizer pre-allocation (same pattern as other macros)
        #[export_name = "wizer.initialize"]
        pub extern "C" fn init() {
            let _prime = Vec::<u8>::with_capacity(1024 * 1024);
        }

        #parsed_fn
    };

    expanded
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── What the macros expand to ────────────────────────────────────────
    //
    // Every user module and every catalog template is wrapped by one of these
    // three macros, so their output is the entry point of everything a worker
    // runs. Each case below is expanded and compared, token for token, with a
    // recorded expansion in `expansions/`. A change to a macro, or a new
    // major of `syn` / `quote`, shows up as a diff in those files.
    //
    //     AEGIX_MACRO_EXPANSION_BLESS=1 cargo test -p aegix_sdk_macros
    //
    // re-records them; the diff is the review.

    /// Tokens only: how they are spaced is the printer's business.
    fn tokens(text: &str) -> String {
        text.split_whitespace().collect()
    }

    /// One statement or brace per line, so a diff of a recording is readable.
    fn readable(expansion: &TokenStream) -> String {
        let mut out = String::new();
        for part in expansion.to_string().split_inclusive([';', '{', '}']) {
            out.push_str(part.trim());
            out.push('\n');
        }
        out
    }

    fn check_expansion(case: &str, expansion: &TokenStream) {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("expansions")
            .join(format!("{case}.txt"));
        let got = readable(expansion);
        if std::env::var("AEGIX_MACRO_EXPANSION_BLESS").is_ok_and(|v| !v.is_empty()) {
            std::fs::create_dir_all(path.parent().expect("a parent")).expect("create expansions/");
            std::fs::write(&path, &got).expect("write the recording");
            return;
        }
        let recorded = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e} — record it with AEGIX_MACRO_EXPANSION_BLESS=1",
                path.display()
            )
        });
        assert!(
            tokens(&recorded) == tokens(&got),
            "the expansion of `{case}` differs from {}.\n\
             Re-record with AEGIX_MACRO_EXPANSION_BLESS=1 and review the diff.\n--- got ---\n{got}",
            path.display()
        );
    }

    #[test]
    fn aegix_node_expands_as_recorded() {
        check_expansion(
            "node_typed_arguments",
            &expand_aegix_node(
                quote! { world = "secrets-node" },
                quote! {
                    fn run(repo: String, limit: Option<u32>, tags: Vec<String>) -> Result<String, String> {
                        let _ = (limit, tags);
                        Ok(repo)
                    }
                },
            ),
        );
        // No attribute at all: the least-privileged world.
        check_expansion(
            "node_default_world",
            &expand_aegix_node(
                TokenStream::new(),
                quote! {
                    fn run() -> Result<String, String> {
                        Ok(String::new())
                    }
                },
            ),
        );
    }

    #[test]
    fn aegix_module_expands_as_recorded() {
        check_expansion(
            "module_network_world",
            &expand_aegix_module(
                quote! { world = "network-node" },
                quote! {
                    /// A doc comment and an attribute travel with the function.
                    #[allow(clippy::needless_pass_by_value)]
                    pub fn run(input: String) -> Result<String, String> {
                        Ok(input)
                    }
                },
            ),
        );
        check_expansion(
            "module_default_world",
            &expand_aegix_module(
                TokenStream::new(),
                quote! {
                    fn run(input: String) -> Result<String, String> {
                        Ok(input)
                    }
                },
            ),
        );
    }

    #[test]
    fn aegix_agent_expands_as_recorded() {
        check_expansion(
            "agent_defaults",
            &expand_aegix_agent(
                TokenStream::new(),
                quote! {
                    fn run(input: AgentInput) -> Result<AgentOutput, String> {
                        Ok(AgentOutput { response: input.prompt, data: None, tool_calls: vec![] })
                    }
                },
            ),
        );
        check_expansion(
            "agent_named_provider_model_world",
            &expand_aegix_agent(
                quote! { world = "agent-node", provider = "ollama", model = "example-model" },
                quote! {
                    fn run(input: AgentInput) -> Result<AgentOutput, String> {
                        Ok(AgentOutput { response: input.prompt, data: None, tool_calls: vec![] })
                    }
                },
            ),
        );
    }

    #[test]
    fn the_world_marker_follows_the_attribute() {
        // The compile path and the worker both read the capability world out
        // of the binary from this marker.
        let world = |attr: TokenStream| {
            let text = expand_aegix_module(
                attr,
                quote! { fn run(input: String) -> Result<String, String> { Ok(input) } },
            )
            .to_string();
            let start = text.find("__talos_world_").expect("a world marker");
            text[start..]
                .split("__")
                .nth(1)
                .expect("a world")
                .to_string()
        };
        assert_eq!(world(TokenStream::new()), "talos_world_minimal-node");
        assert_eq!(
            world(quote! { world = "http-node" }),
            "talos_world_http-node"
        );
        assert_eq!(
            world(quote! { world="database-node" }),
            "talos_world_database-node"
        );
    }

    #[test]
    fn something_that_is_not_a_function_is_a_compile_error_not_a_panic() {
        for expand in [expand_aegix_node, expand_aegix_module, expand_aegix_agent] {
            let out = expand(TokenStream::new(), quote! { struct NotAFunction; }).to_string();
            assert!(out.contains("compile_error"), "{out}");
        }
    }

    #[test]
    fn test_extract_attr_with_spaces() {
        let attr_str = r#"world = "secrets-node", provider = "anthropic""#;
        assert_eq!(
            extract_attr(attr_str, "world"),
            Some("secrets-node".to_string())
        );
        assert_eq!(
            extract_attr(attr_str, "provider"),
            Some("anthropic".to_string())
        );
    }

    #[test]
    fn test_extract_attr_without_spaces() {
        let attr_str = r#"world="minimal-node",provider="openai""#;
        assert_eq!(
            extract_attr(attr_str, "world"),
            Some("minimal-node".to_string())
        );
        assert_eq!(
            extract_attr(attr_str, "provider"),
            Some("openai".to_string())
        );
    }

    #[test]
    fn test_extract_attr_missing() {
        let attr_str = r#"world = "minimal-node""#;
        assert_eq!(extract_attr(attr_str, "model"), None);
        assert_eq!(extract_attr(attr_str, "unknown"), None);
    }

    #[test]
    fn test_extract_attr_empty_string() {
        let attr_str = "";
        assert_eq!(extract_attr(attr_str, "world"), None);
    }

    #[test]
    fn test_extract_attr_partial_match() {
        // Should not match "worlds" when looking for "world"
        let attr_str = r#"worlds = "test", world = "correct""#;
        assert_eq!(extract_attr(attr_str, "world"), Some("correct".to_string()));
    }

    #[test]
    fn test_extract_attr_only_key() {
        // Missing value
        let attr_str = r#"world ="#;
        assert_eq!(extract_attr(attr_str, "world"), None);
    }

    #[test]
    fn test_extract_attr_unclosed_quote() {
        // Unclosed quote returns None - no closing quote found
        let attr_str = r#"world = "secrets-node"#;
        assert_eq!(extract_attr(attr_str, "world"), None);
    }

    #[test]
    fn test_extract_attr_single_quotes_not_supported() {
        // Single quotes should not be recognized
        let attr_str = r#"world = 'secrets-node'"#;
        assert_eq!(extract_attr(attr_str, "world"), None);
    }
}
