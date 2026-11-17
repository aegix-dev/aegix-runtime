//! How large a stored workflow graph may be: the one home for the node and
//! edge counts, and for the most fuel a node may ask for.
//!
//! The node count was the engine's own load cap
//! (`aegix_workflow_engine::DEFAULT_MAX_WORKFLOW_NODES`, now this constant),
//! and `create_workflow` spelled both numbers as literals. A writer that
//! takes a whole graph (`aegix_workflow_creation_helpers::validate_graph_structure`)
//! reads them here, so a graph a writer accepts is a graph the engine loads.
//!
//! The fuel ceiling was the engine's own (`DEFAULT_MAX_FUEL_PER_NODE`, now
//! [`NODE_FUEL_CEILING`] read from here) and the validator's
//! (`aegix_workflow_validation::NODE_FUEL_CEILING`, now the same constant).
//! Since 2026-10-19 a node's `max_fuel` above it is refused in front of every
//! statement that writes a graph (`aegix_workflow_repository::graph_caps`),
//! so the engine's clamp no longer decides a stored value in silence
//! (`docs/engineering-log/packages/2026-10-19-max-fuel-refused-above-the-ceiling.md`).

/// Most nodes a workflow graph may have. The engine refuses to load more.
pub const MAX_GRAPH_NODES: usize = 500;

/// Most edges a workflow graph may have.
pub const MAX_GRAPH_EDGES: usize = 2000;

/// The refusal for a graph of `nodes` nodes and `edges` edges, or `None` when
/// it is within both limits — the ONE sentence every writer answers with
/// (security review 2026-10-14, I-6: each surface had its own number, and a
/// 1 MiB YAML import of ten thousand nodes was stored).
#[must_use]
pub fn graph_size_refusal(nodes: usize, edges: usize) -> Option<String> {
    if nodes > MAX_GRAPH_NODES {
        return Some(format!("Workflow exceeds {MAX_GRAPH_NODES} node limit"));
    }
    if edges > MAX_GRAPH_EDGES {
        return Some(format!("Workflow exceeds {MAX_GRAPH_EDGES} edge limit"));
    }
    None
}

/// The most fuel any one node is given: the engine clamps every node's budget
/// to it at dispatch (`ParallelWorkflowEngine::max_fuel_per_node`, whose
/// default reads this constant), the worker holds a job to the same number
/// (`aegix_workflow_job_protocol::MAX_JOB_FUEL`, pinned equal by the
/// dispatcher's tests), and nothing in a deployment raises it. 50M is about
/// 5 s of dense numeric work on the reference worker.
pub const NODE_FUEL_CEILING: u64 = 50_000_000;

/// The longest a loop node waits between two iterations (`interval_secs` in
/// its graph `data`). The parser clamps to it, so no graph can ask for more;
/// the validator and the authoring tools read the same constant to say so.
/// Five minutes is long enough to poll a slow job politely and short enough
/// that a mistyped value cannot park a run for hours: the total wait is still
/// bounded by `max_iterations` and by the run's wall clock.
pub const LOOP_INTERVAL_MAX_SECS: u64 = 300;

/// A loop node's `interval_secs` as the engine runs it: a whole number of
/// seconds, at most [`LOOP_INTERVAL_MAX_SECS`]. Absent, null, negative,
/// fractional or not a number is `0` (no wait), which is what a loop written
/// before the field means.
#[must_use]
pub fn loop_interval_secs(data: &serde_json::Value) -> u32 {
    let secs = data
        .get("interval_secs")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0)
        .min(LOOP_INTERVAL_MAX_SECS);
    // At most 300 by the line above.
    u32::try_from(secs).unwrap_or(0)
}

/// The most bytes the engine puts into one node's `__accumulated__` envelope
/// (the outputs of every prior node, keyed by label), measured as the JSON
/// text that is sent. Over it, the envelope keeps the newest entries by label
/// order and the engine writes `__accumulated_truncated__` beside it
/// (`reserved_keys::cap_accumulated_envelope`).
///
/// 256 KiB is a quarter of the worker's input ceiling (`WASM_MAX_INPUT_BYTES`,
/// 1 MB): the envelope alone can no longer take a node over the ceiling, and
/// three quarters stay for the node's own input and config. Measured
/// 2026-10-30 (`docs/engineering-log/packages/2026-10-30-accumulated-envelope-capped.md`,
/// `aegix-workflow-engine/tests/accumulated_envelope_cap.rs`): uncapped, a
/// 200-node chain of 1 KiB outputs sent 20.9 MB of envelope in total and
/// 207 KB to its last node, quadratic in the chain, and a chain of large
/// outputs fails at the node whose envelope crosses the ceiling. Under the
/// cap the total is linear in the chain and no envelope is over 256 KiB.
pub const ACCUMULATED_ENVELOPE_CAP_BYTES: usize = 256 * 1024;

/// The refusal for a graph in which a node's `data.max_fuel` is above
/// [`NODE_FUEL_CEILING`], or `None` when every node is within it — the ONE
/// sentence every graph writer answers with.
///
/// Reads the value the engine reads: an integer `data.max_fuel`. A value that
/// is not a whole number (a float, a string, a negative) is what the engine
/// ignores in favour of the module's own limit, so it is not refused here;
/// the validator's `fuel-sizing` family reports it. Until 2026-10-19 a value
/// above the ceiling was stored as written and clamped at dispatch, and the
/// author learned the ceiling from a fuel-exhausted run (pain point 104,
/// 2026-10-15: 250M asked, 50M run).
#[must_use]
pub fn node_fuel_refusal(graph: &serde_json::Value) -> Option<String> {
    let nodes = graph.get("nodes")?.as_array()?;
    nodes.iter().find_map(|node| {
        let requested = node.get("data")?.get("max_fuel")?.as_u64()?;
        (requested > NODE_FUEL_CEILING).then(|| {
            let id = node
                .get("id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("<unknown>");
            format!(
                "node '{id}' has max_fuel {requested}, above the {NODE_FUEL_CEILING} every node \
                 is capped at: the engine would run it under {NODE_FUEL_CEILING} and never give \
                 the rest. Set max_fuel to at most {NODE_FUEL_CEILING}; a node that needs more \
                 must be made cheaper (less copying, fewer passes over its input) or split into \
                 smaller nodes."
            )
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_node_above_the_fuel_ceiling_is_refused_by_name_and_one_at_it_is_not() {
        let graph = json!({ "nodes": [
            { "id": "fits", "data": { "max_fuel": NODE_FUEL_CEILING } },
            { "id": "check", "data": { "max_fuel": NODE_FUEL_CEILING + 1 } },
        ]});
        let refusal = node_fuel_refusal(&graph).expect("refused");
        assert!(
            refusal.starts_with("node 'check' has max_fuel 50000001, above the 50000000"),
            "{refusal}"
        );
        assert!(refusal.contains("at most 50000000"), "{refusal}");
        assert_eq!(
            node_fuel_refusal(
                &json!({ "nodes": [{ "id": "fits", "data": { "max_fuel": NODE_FUEL_CEILING } }] })
            ),
            None
        );
    }

    #[test]
    fn what_the_engine_does_not_read_as_a_budget_is_not_refused() {
        // A float, a string, a negative and a top-level value are each what the
        // engine ignores (`as_u64` on `data.max_fuel`), so the module's limit
        // applies and nothing here is above the ceiling.
        for node in [
            json!({ "id": "f", "data": { "max_fuel": 60_000_000.5 } }),
            json!({ "id": "s", "data": { "max_fuel": "60000000" } }),
            json!({ "id": "n", "data": { "max_fuel": -1 } }),
            json!({ "id": "t", "max_fuel": 60_000_000u64, "data": {} }),
            json!({ "id": "none" }),
        ] {
            assert_eq!(
                node_fuel_refusal(&json!({ "nodes": [node.clone()] })),
                None,
                "{node}"
            );
        }
        assert_eq!(node_fuel_refusal(&json!({})), None);
        assert_eq!(node_fuel_refusal(&json!({ "nodes": "x" })), None);
    }

    #[test]
    fn a_loop_interval_is_whole_seconds_under_the_cap_or_no_wait() {
        let read = |v: serde_json::Value| loop_interval_secs(&json!({ "interval_secs": v }));
        assert_eq!(read(json!(20)), 20);
        assert_eq!(read(json!(0)), 0);
        assert_eq!(read(json!(LOOP_INTERVAL_MAX_SECS)), 300);
        // Above the cap is the cap, however far above.
        assert_eq!(read(json!(LOOP_INTERVAL_MAX_SECS + 1)), 300);
        assert_eq!(read(json!(u64::MAX)), 300);
        // Anything that is not a whole number of seconds is no wait.
        for bad in [json!(-1), json!(1.5), json!("20"), json!(true), json!(null)] {
            assert_eq!(read(bad.clone()), 0, "{bad}");
        }
        // A loop written before the field.
        assert_eq!(loop_interval_secs(&json!({ "max_iterations": 3 })), 0);
        assert_eq!(loop_interval_secs(&json!("not an object")), 0);
    }

    #[test]
    fn the_limits_are_inclusive_and_say_which() {
        assert_eq!(graph_size_refusal(MAX_GRAPH_NODES, MAX_GRAPH_EDGES), None);
        assert!(graph_size_refusal(MAX_GRAPH_NODES + 1, 0)
            .unwrap()
            .contains("node"));
        assert!(graph_size_refusal(0, MAX_GRAPH_EDGES + 1)
            .unwrap()
            .contains("edge"));
    }
}
