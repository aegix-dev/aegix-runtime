//! Job messages the worker dropped without an answer: oversized (> 32 MiB) or
//! undecodable payloads on `talos.jobs`, which never reach verification, and
//! (since 2026-11-15) dispatches that decoded and then failed it.
//!
//! These used to be one ERROR per message and nothing else, so a steady
//! stream of them was invisible to anything but a log grep while the
//! controller simply waited out its dispatch timeout.
//!
//! **Why there is no fail-fast reply.** Nothing in a rejected message is
//! authenticated: its `job_id` and `reply_topic` are exactly as trustworthy
//! as the bytes that failed to decode. A signed failure published to
//! `talos.results.<job_id>` would let any publisher on the job subject make
//! this worker sign a `Failed` result for a job id of its choosing, which the
//! `talos.results.*` observer then finalizes — i.e. kill someone else's
//! in-flight run. Replying to the wire reply subject is ruled out for the
//! same reason (`pick_trusted_reply_topic`). So the drop stays a drop; the
//! counter and a rate-limited WARN make it SAYABLE.
//!
//! A dispatch that decodes and does not VERIFY is in the same position, and
//! until 2026-11-15 it was answered: the reasoning above was applied to the two
//! drops in front of the decode and not to the refusal behind it. Which such
//! dispatch may still be answered is one rule, `refused_dispatch_answer` in
//! `main.rs`; every one it answers with nothing is counted here under the
//! verifier's own class for the refusal (`verify_failure_class`).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;

#[derive(Debug, Clone, Copy)]
pub(crate) enum JobKind {
    Single,
}

impl JobKind {
    const ALL: [JobKind; 1] = [JobKind::Single];
    fn label(self) -> &'static str {
        match self {
            JobKind::Single => "single",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectReason {
    Oversized,
    Undecodable,
    /// Decoded, then refused by `verify_dispatch` and not answered. The class
    /// is the verifier's (`aegix_workflow_job_protocol::verify_failure_class`).
    Unverified(UnverifiedClass),
}

/// The classes `verify_failure_class` can return: a closed set, so every
/// series is seeded and none is named by a sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnverifiedClass {
    Mismatch,
    Replay,
    StaleTimestamp,
    SchemeMismatch,
    KeyConfig,
}

impl UnverifiedClass {
    const ALL: [UnverifiedClass; 5] = [
        UnverifiedClass::Mismatch,
        UnverifiedClass::Replay,
        UnverifiedClass::StaleTimestamp,
        UnverifiedClass::SchemeMismatch,
        UnverifiedClass::KeyConfig,
    ];
    /// The protocol's own token for the class; `class_labels_are_the_protocols`
    /// holds the two together.
    fn label(self) -> &'static str {
        match self {
            UnverifiedClass::Mismatch => "mismatch",
            UnverifiedClass::Replay => "replay",
            UnverifiedClass::StaleTimestamp => "stale_timestamp",
            UnverifiedClass::SchemeMismatch => "scheme_mismatch",
            UnverifiedClass::KeyConfig => "key_config",
        }
    }
}

impl RejectReason {
    const ALL: [RejectReason; 7] = [
        RejectReason::Oversized,
        RejectReason::Undecodable,
        RejectReason::Unverified(UnverifiedClass::Mismatch),
        RejectReason::Unverified(UnverifiedClass::Replay),
        RejectReason::Unverified(UnverifiedClass::StaleTimestamp),
        RejectReason::Unverified(UnverifiedClass::SchemeMismatch),
        RejectReason::Unverified(UnverifiedClass::KeyConfig),
    ];

    /// The reason a dispatch refused by `verify_dispatch` is counted under.
    /// A class this file does not know (a token added to the protocol later)
    /// is counted as `mismatch`, the class that reads as a security event.
    pub(crate) fn unverified(kind: aegix_workflow_job_protocol::VerifyFailureKind) -> Self {
        let token = aegix_workflow_job_protocol::verify_failure_class(kind);
        RejectReason::Unverified(
            UnverifiedClass::ALL
                .into_iter()
                .find(|c| c.label() == token)
                .unwrap_or(UnverifiedClass::Mismatch),
        )
    }

    fn label(self) -> &'static str {
        match self {
            RejectReason::Oversized => "oversized",
            RejectReason::Undecodable => "undecodable",
            RejectReason::Unverified(class) => class.label(),
        }
    }

    /// Position in [`Self::ALL`], which is the WARN slot.
    fn index(self) -> usize {
        Self::ALL
            .iter()
            .position(|r| *r == self)
            .expect("every reason is in ALL")
    }
}

/// One WARN per `(kind, reason)` per this many seconds; the rest are counted.
const WARN_INTERVAL_SECS: u64 = 60;

static COUNTER: LazyLock<Option<prometheus::IntCounterVec>> = LazyLock::new(|| {
    let c = prometheus::IntCounterVec::new(
        prometheus::Opts::new(
            "aegix_worker_rejected_job_messages_total",
            "Job messages dropped without an answer, by kind (single) and reason: \
             oversized|undecodable (never verified) or the class verification refused \
             them with (mismatch|replay|stale_timestamp|scheme_mismatch|key_config). \
             Nothing in such a message is authenticated, so nothing is signed for it \
             and the controller waits out its dispatch timeout.",
        ),
        &["kind", "reason"],
    )
    .ok()?;
    prometheus::default_registry()
        .register(Box::new(c.clone()))
        .ok()?;
    Some(c)
});

/// Last-WARN time (unix secs) per `(kind, reason)`, index
/// `kind * REASONS + reason`.
const REASONS: usize = RejectReason::ALL.len();
static LAST_WARN: [AtomicU64; REASONS] = [const { AtomicU64::new(0) }; REASONS];

fn slot(kind: JobKind, reason: RejectReason) -> usize {
    (kind as usize) * REASONS + reason.index()
}

/// Pre-seed every `(kind, reason)` pair at 0 — its healthy value is 0
/// forever, which an ABSENT series would render identically.
pub(crate) fn seed() {
    if let Some(c) = COUNTER.as_ref() {
        for kind in JobKind::ALL {
            for reason in RejectReason::ALL {
                c.with_label_values(&[kind.label(), reason.label()])
                    .inc_by(0);
            }
        }
    }
}

/// Whether a WARN is due now; claims the slot when it is.
pub(crate) fn warn_due(last: &AtomicU64, now_secs: u64, interval: u64) -> bool {
    let prev = last.load(Ordering::Relaxed);
    (prev == 0 || now_secs.saturating_sub(prev) >= interval)
        && last
            .compare_exchange(prev, now_secs.max(1), Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
}

pub(crate) fn record(kind: JobKind, reason: RejectReason, payload_bytes: usize) {
    if let Some(c) = COUNTER.as_ref() {
        c.with_label_values(&[kind.label(), reason.label()]).inc();
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if warn_due(&LAST_WARN[slot(kind, reason)], now, WARN_INTERVAL_SECS) {
        ::tracing::warn!(
            kind = kind.label(),
            reason = reason.label(),
            payload_bytes,
            "SECURITY: dropped a job message this worker could not vouch for (no reply \
             is sent; further drops of this kind are counted on \
             aegix_worker_rejected_job_messages_total for the next minute)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warn_is_rate_limited_per_slot() {
        let last = AtomicU64::new(0);
        assert!(warn_due(&last, 1_000, 60));
        assert!(!warn_due(&last, 1_030, 60));
        assert!(warn_due(&last, 1_060, 60));
    }

    #[test]
    fn every_pair_is_seeded_and_counted() {
        seed();
        record(JobKind::Single, RejectReason::Undecodable, 3);
        let text = {
            use prometheus::Encoder as _;
            let mut buf = Vec::new();
            prometheus::TextEncoder::new()
                .encode(&prometheus::default_registry().gather(), &mut buf)
                .unwrap();
            String::from_utf8(buf).unwrap()
        };
        for kind in ["single"] {
            for reason in [
                "oversized",
                "undecodable",
                "mismatch",
                "replay",
                "stale_timestamp",
                "scheme_mismatch",
                "key_config",
            ] {
                assert!(
                    text.contains(&format!(
                        "aegix_worker_rejected_job_messages_total{{kind=\"{kind}\",reason=\"{reason}\"}}"
                    )),
                    "{kind}/{reason} must be exported:\n{text}"
                );
            }
        }
        assert!(text.contains(
            "aegix_worker_rejected_job_messages_total{kind=\"single\",reason=\"undecodable\"} "
        ));
    }

    /// Every class the verifier can refuse with has a reason of its own here,
    /// under the protocol's token, and a WARN slot of its own.
    #[test]
    fn class_labels_are_the_protocols() {
        use aegix_workflow_job_protocol::{verify_failure_class, VerifyFailureKind};
        for &kind in VerifyFailureKind::ALL {
            assert_eq!(
                RejectReason::unverified(kind).label(),
                verify_failure_class(kind),
                "{kind:?} is counted under the verifier's own class"
            );
        }
        let mut slots: Vec<usize> = RejectReason::ALL
            .iter()
            .map(|r| slot(JobKind::Single, *r))
            .collect();
        slots.sort_unstable();
        slots.dedup();
        assert_eq!(slots.len(), RejectReason::ALL.len(), "one WARN slot each");
        assert!(slots.iter().all(|s| *s < LAST_WARN.len()));
    }
}
