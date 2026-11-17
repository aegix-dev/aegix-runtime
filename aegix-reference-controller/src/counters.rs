//! What this controller refused, counted in memory.
//!
//! The gates return a refusal and write one `talos_audit` line; counting is
//! the caller's. The platform counts on a Prometheus registry. This
//! controller links none, so it keeps the same numbers here and gives them to
//! the operator over the control socket (`counters`). Every key is one of a
//! closed set of static strings: a caller cannot make a new one.

use std::collections::BTreeMap;
use std::sync::Mutex;

/// Which decision refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Decision {
    /// Admission: malformed, unauthorized or a replay.
    Admission,
    /// The dispatch-binding gate.
    DispatchBinding,
    /// The actor write ceiling.
    WriteCeiling,
    /// A job result that was not this dispatch's, did not verify, or came
    /// from a worker that did not claim the job's secrets.
    Result,
}

impl Decision {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::DispatchBinding => "dispatch_binding",
            Self::WriteCeiling => "write_ceiling",
            Self::Result => "result",
        }
    }
}

/// Refusals by decision, subject and reason.
#[derive(Debug, Default)]
pub struct Refusals {
    counts: Mutex<BTreeMap<(Decision, &'static str, &'static str), u64>>,
}

impl Refusals {
    /// Count one refusal.
    pub fn count(&self, decision: Decision, subject: &'static str, reason: &'static str) {
        let mut counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        *counts.entry((decision, subject, reason)).or_insert(0) += 1;
    }

    /// How many refusals of this kind there have been.
    #[must_use]
    pub fn get(&self, decision: Decision, subject: &str, reason: &str) -> u64 {
        let counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        counts
            .iter()
            .find(|((d, s, r), _)| *d == decision && *s == subject && *r == reason)
            .map_or(0, |(_, n)| *n)
    }

    /// Everything counted, as `{decision: {subject: {reason: n}}}`.
    #[must_use]
    pub fn snapshot(&self) -> serde_json::Value {
        let counts = self.counts.lock().unwrap_or_else(|p| p.into_inner());
        let mut out = serde_json::Map::new();
        for ((decision, subject, reason), n) in counts.iter() {
            let by_subject = out
                .entry(decision.as_str())
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            let by_reason = by_subject
                .as_object_mut()
                .expect("an object was inserted")
                .entry(*subject)
                .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
            by_reason
                .as_object_mut()
                .expect("an object was inserted")
                .insert((*reason).to_string(), serde_json::Value::from(*n));
        }
        serde_json::Value::Object(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_is_counted_under_its_decision_subject_and_reason() {
        let refusals = Refusals::default();
        assert_eq!(
            refusals.get(Decision::DispatchBinding, "talos.memory.op", "not_live"),
            0
        );
        refusals.count(Decision::DispatchBinding, "talos.memory.op", "not_live");
        refusals.count(Decision::DispatchBinding, "talos.memory.op", "not_live");
        refusals.count(Decision::WriteCeiling, "talos.memory.op", "policy");
        assert_eq!(
            refusals.get(Decision::DispatchBinding, "talos.memory.op", "not_live"),
            2
        );
        assert_eq!(
            refusals.get(Decision::DispatchBinding, "talos.memory.op", "unbound"),
            0
        );
        assert_eq!(
            refusals.snapshot(),
            serde_json::json!({
                "dispatch_binding": {"talos.memory.op": {"not_live": 2}},
                "write_ceiling": {"talos.memory.op": {"policy": 1}},
            })
        );
    }
}
