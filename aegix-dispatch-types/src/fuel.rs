//! The names and the one threshold a fuel reading is carried and judged by.
//!
//! A worker stamps what a module spent into its output under two reserved
//! keys, and whoever reads a signed result reads them back
//! (`aegix_workflow_job_protocol::spent_fuel`), so both sides name them from
//! here.

/// Engine-written output marker: accumulated wasmtime fuel consumed
/// by the node.
pub const FUEL_CONSUMED: &str = "__fuel_consumed__";

/// Worker-written output marker beside [`FUEL_CONSUMED`]: the fuel limit the
/// worker enforced for the node. Like [`FUEL_CONSUMED`] it is stamped only
/// into an OBJECT output; the authoritative carrier is the signed
/// `JobResult::fuel` field.
pub const FUEL_LIMIT: &str = "__fuel_limit__";

/// The share of its fuel limit above which a node has too little headroom:
/// a larger payload than the one measured is likely to exhaust it.
///
/// ONE line, drawn in every place that must agree: the compile path's
/// recommended limit (`aegix_compilation::scaffold::HIGH_FUEL_UTILISATION`
/// is this constant) and, on the platform, the fleet gauge, the fuel-usage
/// report's headroom section, the catalog's recorded-run gate and the
/// validator's `fuel-headroom` warning.
pub const HIGH_FUEL_UTILISATION: f64 = 0.80;
