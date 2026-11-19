//! The configuration file: the posture, the actors, the modules and where
//! the secrets are.
//!
//! One JSON file. Everything it grants is written out in it: there is no
//! default actor, no default grant, and no key this loader accepts without
//! knowing it (an unknown field is an error, so a misspelt ceiling is never
//! silently the default).
//!
//! ```json
//! {
//!   "posture": "worker-identity",
//!   "secrets_file": "secrets.json",
//!   "actors": [
//!     { "name": "assistant", "max_llm_tier": "tier1", "max_write_ceiling": "write",
//!       "memory": { "notes/today": "buy milk" } }
//!   ],
//!   "modules": [
//!     { "name": "digest", "wasm": "digest.wasm", "capability_world": "agent-node",
//!       "allowed_hosts": ["api.example.com"], "allowed_methods": ["GET"],
//!       "allowed_secrets": ["example/api_key"], "max_fuel": 5000000, "timeout_secs": 30 }
//!   ]
//! }
//! ```
//!
//! `pickup_window_secs` (optional, 30 when absent, at most 300) is how long
//! after a dispatch is signed a worker may still start it.
//!
//! Paths are relative to the file. The secrets file is a JSON object of
//! `path: value`; it is refused when anyone but its owner can read it.

use crate::dispatch::{
    Module, SecretStore, MAX_PICKUP_WINDOW_SECS, MAX_TIMEOUT_SECS, PICKUP_WINDOW_SECS,
};
use crate::keys::Posture;
use crate::ledger::{Actor, ActorStatus};
use aegix_dispatch_types::{EgressScope, LlmTier, SecretMap, WriteCeiling};
use aegix_wit_inspector::WorldFit;
use aegix_workflow_job_protocol::MAX_JOB_FUEL;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;
use zeroize::Zeroizing;

/// The memory type a value seeded from the configuration is stored as: one
/// that does not expire.
pub const SEED_MEMORY_TYPE: &str = "semantic";

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    posture: Posture,
    #[serde(default)]
    secrets_file: Option<PathBuf>,
    /// How long after a dispatch is signed a worker may still start it.
    #[serde(default)]
    pickup_window_secs: Option<u64>,
    #[serde(default)]
    actors: Vec<ActorEntry>,
    #[serde(default)]
    modules: Vec<ModuleEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ActorEntry {
    name: String,
    /// Fixed across restarts when given; random otherwise.
    #[serde(default)]
    id: Option<Uuid>,
    max_llm_tier: LlmTier,
    #[serde(default)]
    egress_scope: Option<EgressScope>,
    max_write_ceiling: WriteCeiling,
    #[serde(default)]
    memory: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ModuleEntry {
    name: String,
    wasm: PathBuf,
    capability_world: String,
    #[serde(default)]
    allowed_hosts: Vec<String>,
    #[serde(default)]
    allowed_methods: Vec<String>,
    #[serde(default)]
    allowed_secrets: Vec<String>,
    max_fuel: u64,
    timeout_secs: u64,
}

/// One value to place in an actor's memory at start.
#[derive(Debug, Clone, PartialEq)]
pub struct Seed {
    pub actor_id: Uuid,
    pub key: String,
    pub value: serde_json::Value,
}

/// A configuration that passed every check.
#[derive(Debug)]
pub struct Config {
    pub posture: Posture,
    /// How long after a dispatch is signed a worker may still start it.
    pub pickup_window_secs: u64,
    pub actors: Vec<Actor>,
    pub seeds: Vec<Seed>,
    pub modules: HashMap<String, Module>,
    pub secrets: SecretStore,
}

/// The pickup window a configuration names, or the default when it names
/// none. Zero would sign a dispatch no worker may start.
fn pickup_window_from(named: Option<u64>) -> Result<u64, String> {
    match named {
        None => Ok(PICKUP_WINDOW_SECS),
        Some(secs) if (1..=MAX_PICKUP_WINDOW_SECS).contains(&secs) => Ok(secs),
        Some(secs) => Err(format!(
            "pickup_window_secs is {secs}: it must be between 1 and {MAX_PICKUP_WINDOW_SECS}"
        )),
    }
}

/// A name an actor or a module may have: lowercase letters, digits, `.`,
/// `_` and `-`, starting with a letter or digit, at most 64 long. It is
/// typed on a command line and written into a subject-safe module URI.
fn valid_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_lowercase() || c.is_ascii_digit())
        && name.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

fn actors_from(entries: Vec<ActorEntry>) -> Result<(Vec<Actor>, Vec<Seed>), String> {
    let mut names = HashSet::new();
    let mut ids = HashSet::new();
    let mut actors = Vec::new();
    let mut seeds = Vec::new();
    for entry in entries {
        if !valid_name(&entry.name) {
            return Err(format!(
                "actor name {:?}: use lowercase letters, digits, '.', '_' and '-', at most 64",
                entry.name
            ));
        }
        // A name that parses as an id could be taken for another actor's id
        // on the command line.
        if Uuid::parse_str(&entry.name).is_ok() {
            return Err(format!(
                "actor name {:?} is an id; give it a name",
                entry.name
            ));
        }
        if !names.insert(entry.name.clone()) {
            return Err(format!("actor {:?} is listed twice", entry.name));
        }
        let id = entry.id.unwrap_or_else(Uuid::new_v4);
        if id.is_nil() || !ids.insert(id) {
            return Err(format!(
                "actor {:?}: its id is nil or another actor's",
                entry.name
            ));
        }
        for (key, value) in entry.memory {
            seeds.push(Seed {
                actor_id: id,
                key,
                value,
            });
        }
        actors.push(Actor {
            id,
            name: entry.name,
            status: ActorStatus::Active,
            max_llm_tier: entry.max_llm_tier,
            egress_scope: entry.egress_scope,
            max_write_ceiling: entry.max_write_ceiling,
        });
    }
    Ok((actors, seeds))
}

/// Check one module entry against its bytes.
fn module_from(entry: ModuleEntry, wasm: Vec<u8>) -> Result<Module, String> {
    let name = entry.name;
    if !valid_name(&name) {
        return Err(format!(
            "module name {name:?}: use lowercase letters, digits, '.', '_' and '-', at most 64"
        ));
    }
    // A grant names what it grants. `*` (every host, every secret) and
    // `<prefix>/*` are how a module ends up holding more than its author
    // meant, and nothing here needs them.
    if aegix_capability_world::grant_list_has_wildcard(&entry.allowed_hosts)
        || aegix_capability_world::secret_grant_list_has_wildcard(&entry.allowed_secrets)
    {
        return Err(format!(
            "module {name:?}: a grant names exact hosts and secret paths; '*' and '<prefix>/*' \
             are not accepted"
        ));
    }
    if entry.max_fuel == 0 || entry.max_fuel > MAX_JOB_FUEL {
        return Err(format!(
            "module {name:?}: max_fuel must be between 1 and {MAX_JOB_FUEL}"
        ));
    }
    if entry.timeout_secs == 0 || entry.timeout_secs > MAX_TIMEOUT_SECS {
        return Err(format!(
            "module {name:?}: timeout_secs must be between 1 and {MAX_TIMEOUT_SECS}"
        ));
    }
    if !wasm.starts_with(b"\0asm") {
        return Err(format!(
            "module {name:?}: {} is not a WebAssembly binary",
            entry.wasm.display()
        ));
    }
    // The world is checked here against the binary's own imports, by the
    // rule the worker links it with: a module that would be refused at every
    // dispatch is refused once, at start.
    match aegix_wit_inspector::world_fit_at_dispatch(&entry.capability_world, &wasm) {
        WorldFit::Links(_) => {}
        WorldFit::UnrecognisedWorld(world) => {
            return Err(format!(
                "module {name:?}: {world:?} is not a capability world"
            ));
        }
        WorldFit::Refused(why) => {
            return Err(format!(
                "module {name:?} does not fit the world {:?}: {why}",
                entry.capability_world
            ));
        }
    }
    Ok(Module {
        name,
        wasm: Arc::new(wasm),
        capability_world: entry.capability_world,
        allowed_hosts: entry.allowed_hosts,
        allowed_methods: entry.allowed_methods,
        allowed_secrets: entry.allowed_secrets,
        max_fuel: entry.max_fuel,
        timeout_secs: entry.timeout_secs,
    })
}

/// Whether a file with these permission bits may hold secrets: nobody but
/// its owner can read, write or execute it.
#[must_use]
pub fn mode_is_private(mode: u32) -> bool {
    mode & 0o077 == 0
}

fn secrets_from(text: &str) -> Result<SecretMap, String> {
    // Parsed straight into wiped strings: no plain copy of a value is made.
    let raw: HashMap<String, Zeroizing<String>> = serde_json::from_str(text)
        .map_err(|_| "the secrets file is not a JSON object of path: value strings".to_string())?;
    for path in raw.keys() {
        if path.trim().is_empty() || path != path.trim() {
            return Err("the secrets file has an empty or padded path".to_string());
        }
    }
    Ok(raw)
}

/// Read a file that holds a secret: refused when anyone but its owner can
/// read it. `what` names the file's role in the error.
pub fn read_private_file(what: &str, path: &Path) -> Result<Zeroizing<String>, String> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| format!("{what} {}: {e}", path.display()))?;
    if !mode_is_private(meta.permissions().mode()) {
        return Err(format!(
            "{what} {} can be read by others (mode {:o}); `chmod 600` it",
            path.display(),
            meta.permissions().mode() & 0o777
        ));
    }
    std::fs::read_to_string(path)
        .map(Zeroizing::new)
        .map_err(|e| format!("{what} {}: {e}", path.display()))
}

fn read_secrets(path: &Path) -> Result<SecretMap, String> {
    secrets_from(&read_private_file("secrets file", path)?)
}

/// Read and check the configuration at `path`.
pub fn load(path: &Path) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("configuration {}: {e}", path.display()))?;
    let file: File = serde_json::from_str(&text)
        .map_err(|e| format!("configuration {}: {e}", path.display()))?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));

    let (actors, seeds) = actors_from(file.actors)?;

    let mut modules = HashMap::new();
    for entry in file.modules {
        let wasm_path = base.join(&entry.wasm);
        let wasm = std::fs::read(&wasm_path)
            .map_err(|e| format!("module {:?}: {}: {e}", entry.name, wasm_path.display()))?;
        let module = module_from(entry, wasm)?;
        if modules.contains_key(&module.name) {
            return Err(format!("module {:?} is listed twice", module.name));
        }
        modules.insert(module.name.clone(), module);
    }

    let secrets = match file.secrets_file {
        Some(rel) => SecretStore::new(read_secrets(&base.join(rel))?),
        None => SecretStore::default(),
    };

    Ok(Config {
        posture: file.posture,
        pickup_window_secs: pickup_window_from(file.pickup_window_secs)?,
        actors,
        seeds,
        modules,
        secrets,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor_entry(json: serde_json::Value) -> Result<ActorEntry, serde_json::Error> {
        serde_json::from_value(json)
    }

    fn module_entry(json: serde_json::Value) -> ModuleEntry {
        serde_json::from_value(json).expect("a module entry")
    }

    fn base_module() -> serde_json::Value {
        serde_json::json!({
            "name": "m", "wasm": "m.wasm", "capability_world": "agent-node",
            "max_fuel": 1_000_000, "timeout_secs": 10
        })
    }

    #[test]
    fn an_actor_must_state_its_ceilings_and_an_unknown_field_is_an_error() {
        assert!(actor_entry(serde_json::json!({"name": "a"})).is_err());
        assert!(actor_entry(serde_json::json!({"name": "a", "max_llm_tier": "tier1"})).is_err());
        assert!(actor_entry(serde_json::json!({
            "name": "a", "max_llm_tier": "tier1", "max_write_ceiling": "write"
        }))
        .is_ok());
        // A misspelt ceiling must not become the default.
        assert!(actor_entry(serde_json::json!({
            "name": "a", "max_llm_tier": "tier1", "max_write_ceiling": "write",
            "max_write_cieling": "read_only"
        }))
        .is_err());
        assert!(actor_entry(serde_json::json!({
            "name": "a", "max_llm_tier": "tier9", "max_write_ceiling": "write"
        }))
        .is_err());
    }

    #[test]
    fn actors_are_unique_named_plainly_and_seeded_under_their_own_id() {
        let entry = |name: &str| {
            actor_entry(serde_json::json!({
                "name": name, "max_llm_tier": "tier1", "max_write_ceiling": "readonly",
                "memory": {"notes/a": "one"}
            }))
            .expect("entry")
        };
        let (actors, seeds) = actors_from(vec![entry("a"), entry("b")]).expect("two actors");
        assert_eq!(actors.len(), 2);
        assert_ne!(actors[0].id, actors[1].id);
        assert_eq!(actors[0].max_write_ceiling, WriteCeiling::ReadOnly);
        assert_eq!(actors[0].status, ActorStatus::Active);
        assert_eq!(seeds.len(), 2);
        assert_eq!(seeds[0].actor_id, actors[0].id);
        assert_eq!(seeds[1].actor_id, actors[1].id);

        assert!(actors_from(vec![entry("a"), entry("a")]).is_err());
        for bad in ["", "Has Caps", "-lead", "a/b", &"x".repeat(65)] {
            assert!(actors_from(vec![entry(bad)]).is_err(), "{bad:?}");
        }
        assert!(actors_from(vec![entry(&Uuid::new_v4().to_string())]).is_err());

        let fixed = Uuid::new_v4();
        let with_id = |name: &str, id: Uuid| {
            actor_entry(serde_json::json!({
                "name": name, "id": id, "max_llm_tier": "tier2", "max_write_ceiling": "write"
            }))
            .expect("entry")
        };
        let (actors, _) = actors_from(vec![with_id("a", fixed)]).expect("fixed id");
        assert_eq!(actors[0].id, fixed);
        assert!(actors_from(vec![with_id("a", fixed), with_id("b", fixed)]).is_err());
        assert!(actors_from(vec![with_id("a", Uuid::nil())]).is_err());
    }

    /// A component that imports the actor-memory interface and nothing else.
    fn memory_component() -> Vec<u8> {
        wat::parse_str(
            r#"(component
                 (import "aegix:core/agent-memory" (instance))
                 (core module (memory 1)))"#,
        )
        .expect("a component")
    }

    #[test]
    fn a_module_grant_names_exact_hosts_and_paths() {
        let with = |field: &str, value: serde_json::Value| {
            let mut json = base_module();
            json[field] = value;
            module_from(module_entry(json), memory_component())
        };
        for (field, value) in [
            ("allowed_hosts", serde_json::json!(["*"])),
            ("allowed_secrets", serde_json::json!(["*"])),
            ("allowed_secrets", serde_json::json!(["team/*"])),
            ("allowed_secrets", serde_json::json!(["ok/path", " * "])),
        ] {
            let err = with(field, value.clone()).expect_err("a wildcard");
            assert!(err.contains("exact"), "{field}={value}: {err}");
        }
        let exact = with("allowed_secrets", serde_json::json!(["ok/path"])).expect("exact");
        assert_eq!(exact.allowed_secrets, ["ok/path"]);
    }

    #[test]
    fn a_module_states_a_bounded_fuel_and_time_limit() {
        let with = |field: &str, value: u64| {
            let mut json = base_module();
            json[field] = serde_json::json!(value);
            module_from(module_entry(json), memory_component()).expect_err("out of bounds")
        };
        assert!(with("max_fuel", 0).contains("max_fuel"));
        assert!(with("max_fuel", MAX_JOB_FUEL + 1).contains("max_fuel"));
        assert!(with("timeout_secs", 0).contains("timeout_secs"));
        assert!(with("timeout_secs", MAX_TIMEOUT_SECS + 1).contains("timeout_secs"));
        let mut missing = base_module();
        missing.as_object_mut().expect("object").remove("max_fuel");
        assert!(serde_json::from_value::<ModuleEntry>(missing).is_err());
    }

    #[test]
    fn a_module_is_checked_against_the_world_it_declares() {
        let declared = |world: &str, wasm: Vec<u8>| {
            let mut json = base_module();
            json["capability_world"] = serde_json::json!(world);
            module_from(module_entry(json), wasm)
        };
        let fits = declared("agent-node", memory_component()).expect("fits its world");
        assert_eq!(fits.capability_world, "agent-node");
        assert_eq!(fits.timeout_secs, 10);

        // The same binary declared at a world without actor memory.
        let err = declared("minimal-node", memory_component()).expect_err("outside its world");
        assert!(err.contains("does not fit"), "{err}");
        assert!(err.contains("agent-memory"), "the import is named: {err}");

        let err = declared("everything-node", memory_component()).expect_err("no such world");
        assert!(err.contains("not a capability world"), "{err}");

        let err = declared("agent-node", b"not wasm".to_vec()).expect_err("not a binary");
        assert!(err.contains("not a WebAssembly binary"), "{err}");
    }

    #[test]
    fn a_secrets_file_is_private_and_a_map_of_strings() {
        assert!(mode_is_private(0o100_600));
        assert!(mode_is_private(0o100_400));
        for open in [0o100_640, 0o100_604, 0o100_660, 0o100_644, 0o100_601] {
            assert!(!mode_is_private(open), "{open:o}");
        }
        let map = secrets_from(r#"{"demo/granted": "s3cr3t", "other/x": "y"}"#).expect("a map");
        assert_eq!(map.len(), 2);
        assert_eq!(map["demo/granted"].as_str(), "s3cr3t");
        // The error must not echo the file.
        let err = secrets_from(r#"{"demo/granted": 12345}"#).expect_err("not a string");
        assert!(!err.contains("12345"), "{err}");
        assert!(secrets_from(r#"{" padded": "v"}"#).is_err());
        assert!(secrets_from("[]").is_err());
    }

    #[test]
    fn the_pickup_window_is_the_default_or_a_named_value_within_its_bounds() {
        assert_eq!(pickup_window_from(None), Ok(PICKUP_WINDOW_SECS));
        assert_eq!(pickup_window_from(Some(1)), Ok(1));
        assert_eq!(
            pickup_window_from(Some(MAX_PICKUP_WINDOW_SECS)),
            Ok(MAX_PICKUP_WINDOW_SECS)
        );
        for refused in [0, MAX_PICKUP_WINDOW_SECS + 1, u64::MAX] {
            assert!(pickup_window_from(Some(refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn a_file_is_loaded_whole_and_an_open_secrets_file_refuses_it() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("a directory");
        let secrets = dir.path().join("secrets.json");
        std::fs::write(&secrets, r#"{"demo/granted": "v"}"#).expect("write");
        let config = dir.path().join("controller.json");
        std::fs::write(
            &config,
            serde_json::json!({
                "posture": "fleet-key",
                "secrets_file": "secrets.json",
                "actors": [{"name": "a", "max_llm_tier": "tier1", "max_write_ceiling": "write"}]
            })
            .to_string(),
        )
        .expect("write");

        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = load(&config).expect_err("an open secrets file");
        assert!(err.contains("chmod 600"), "{err}");

        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let loaded = load(&config).expect("loaded");
        assert_eq!(loaded.posture, Posture::FleetKey);
        assert_eq!(loaded.pickup_window_secs, PICKUP_WINDOW_SECS);
        assert_eq!(loaded.actors.len(), 1);
        assert_eq!(loaded.secrets.paths(), ["demo/granted"]);
        assert!(loaded.modules.is_empty());

        std::fs::write(&config, r#"{"posture": "fleet-key", "actor": []}"#).expect("write");
        assert!(load(&config).is_err(), "an unknown field");
        std::fs::write(&config, r#"{"actors": []}"#).expect("write");
        assert!(load(&config).is_err(), "no posture");
    }
}
