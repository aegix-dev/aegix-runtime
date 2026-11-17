//! Closed label sets for `aegix_push_dropped_total{integration,reason}` — a
//! push the platform ACCEPTED (answered 2xx, so the transport will not
//! redeliver it) and then could not act on.
//!
//! Why it exists (2026-11-02, `docs/engineering-log/packages/
//! 2026-11-02-push-dropped-counter.md`). From 2026-11-01 19:41Z the personal
//! mailbox's Gmail watch row named a `gmail_integrations` row that a Settings
//! disconnect had hard-deleted. For 22 hours every Pub/Sub push resolved the
//! mailbox to its user, found the watch row, asked for the integration BY THE
//! ID THE WATCH HELD, got `None`, logged one WARN and returned — acked, so
//! Google did not redeliver, and nothing started. The bound workflow's
//! 15-minute schedule hid it. Nothing counted it and nothing alerted.
//!
//! The three push counters that already existed could not see it:
//! `aegix_google_push_refusals_total` counts a push we REJECTED (401),
//! `aegix_google_push_deferred_total` one we could not ANSWER (503), and
//! `aegix_google_push_accepted_total` moved on every one of those pushes,
//! because each one authenticated. The gap is the fourth outcome: accepted
//! and dropped. This counter is that outcome, on every push receiver.
//!
//! Every value is an ENUM so the label set is closed by the compiler, and the
//! pairs that are seeded at 0 are EXACTLY the pairs a live call site writes
//! ([`PushDrop::SITES`], not the cross product): a seeded pair nothing
//! increments implies a wired signal that does not exist (CLAUDE.md,
//! "ABSENT and ZERO are different"), and an unseeded pair reads as absent, so
//! `increase()` loses its first increment. `sites_cover_every_pair_once`
//! holds the list to that.

/// Which push receiver dropped the delivery. The label value is the word
/// the receiver's own log lines and pause-gate path use (`gcal`, not
/// `google_calendar`; `jira`, not `atlassian`).
///
/// The generic webhook router (`aegix-webhooks`) is deliberately not here: it
/// answers 404 when a trigger or workflow is missing or disabled and 200 only
/// for a delivery its author's own `event_filter` excluded, so it has no
/// accepted-but-unactionable outcome to count.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PushReceiver {
    Gmail,
    GoogleCalendar,
    Gcp,
    Jira,
}

impl PushReceiver {
    pub const ALL: &'static [Self] = &[Self::Gmail, Self::GoogleCalendar, Self::Gcp, Self::Jira];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gmail => "gmail",
            Self::GoogleCalendar => "gcal",
            Self::Gcp => "gcp",
            Self::Jira => "jira",
        }
    }
}

/// Why an accepted push started nothing. Every variant is a DETERMINATE
/// answer the receiver acked on: a lookup that did not answer is deferred
/// (503) and counted on `aegix_google_push_deferred_total` instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PushDropReason {
    /// The watch row exists and names an integration row that is gone — the
    /// 2026-11-01 shape. Reachable since #1535 only by a row deleted by hand
    /// or by a provider that still hard-deletes on disconnect.
    IntegrationMissing,
    /// No watch, channel or registration of ours owns the delivery: the
    /// lookup answered `None` (Gmail, Calendar, GCP), or (Jira) the delivery
    /// named no webhook id we registered, or every one it named is another
    /// site's.
    WatchMissing,
    /// The watch exists but the push was signed for a sender it does not
    /// name (GCP: a service account other than the watch's). Answered
    /// exactly as an absent watch; also counted on
    /// `aegix_google_push_refusals_total`.
    WrongSender,
    /// The watch is bound to a workflow and the trigger service refused the
    /// start (`OrchestrationError::push_refusal_reason` has the word; the
    /// channel audit log has the row). Not retried: the cursor has moved.
    WorkflowRefused,
    /// Jira: the delivery's webhook id is registered on more than one site
    /// and a delivery does not say which sent it, or it matched more
    /// registrations than are read. Nothing is started until the channel is
    /// re-created.
    AmbiguousRegistration,
    /// Gmail: the mailbox's access token could not be fetched (a dead
    /// refresh grant, or the credential store unreachable), so the history
    /// could not be read. The cursor does not move, so the NEXT push reads
    /// these messages — but this one started nothing.
    CredentialsUnavailable,
    /// Calendar: the channel's event sync failed for a reason other than a
    /// missing integration row — the access token could not be fetched,
    /// Google's `events.list` refused (an expired sync token, a 4xx, a
    /// network error), or the new sync token could not be stored — so no
    /// event was read (2026-11-04). The stored sync token has not moved, so
    /// the next push reads these changes too; this one started nothing, and
    /// the one ERROR line it leaves carries the whole cause
    /// (`aegix_integration_helpers::error_chain`).
    SyncFailed,
}

impl PushDropReason {
    pub const ALL: &'static [Self] = &[
        Self::IntegrationMissing,
        Self::WatchMissing,
        Self::WrongSender,
        Self::WorkflowRefused,
        Self::AmbiguousRegistration,
        Self::CredentialsUnavailable,
        Self::SyncFailed,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntegrationMissing => "integration_missing",
            Self::WatchMissing => "watch_missing",
            Self::WrongSender => "wrong_sender",
            Self::WorkflowRefused => "workflow_refused",
            Self::AmbiguousRegistration => "ambiguous_registration",
            Self::CredentialsUnavailable => "credentials_unavailable",
            Self::SyncFailed => "sync_failed",
        }
    }
}

/// The `(integration, reason)` pairs with a live call site.
pub struct PushDrop;

impl PushDrop {
    /// Every pair a receiver writes, each once. The pre-seed loop in
    /// `AegixMetrics::new` walks THIS list, not `ALL × ALL`: `gcal` never
    /// writes `wrong_sender` (Google signs no Calendar notification), `jira`
    /// never writes `integration_missing` (a registration row is the
    /// ownership), and a seeded series nothing can move would be a lie.
    /// Adding a call site adds its pair here in the same change. Fourteen
    /// today (twelve on 2026-11-02; Calendar's `integration_missing` and
    /// `sync_failed` on 2026-11-04).
    pub const SITES: &'static [(PushReceiver, PushDropReason)] = &[
        // aegix-gmail/src/handlers.rs: `find_by_email` → None.
        (PushReceiver::Gmail, PushDropReason::WatchMissing),
        // aegix-gmail/src/handlers.rs: `get_integration(row.integration_id)` → None.
        (PushReceiver::Gmail, PushDropReason::IntegrationMissing),
        // aegix-gmail/src/handlers.rs: `get_access_token` → Err.
        (PushReceiver::Gmail, PushDropReason::CredentialsUnavailable),
        // aegix-gmail/src/dispatch.rs: `start_bound_workflow` → NotStarted.
        (PushReceiver::Gmail, PushDropReason::WorkflowRefused),
        // aegix-google-calendar/src/handlers.rs: `find_channel_by_google_id` → None.
        (PushReceiver::GoogleCalendar, PushDropReason::WatchMissing),
        // aegix-google-calendar/src/handlers.rs: `process_webhook_events` → Err
        // whose chain holds `SyncFailure::IntegrationMissing` (the channel
        // row names a `google_calendar_integrations` row that is gone or
        // inactive; the 2026-11-04 shape).
        (
            PushReceiver::GoogleCalendar,
            PushDropReason::IntegrationMissing,
        ),
        // aegix-google-calendar/src/handlers.rs: `process_webhook_events` → Err
        // whose chain holds any other `SyncFailure` (`sync_drop_reason`).
        (PushReceiver::GoogleCalendar, PushDropReason::SyncFailed),
        // aegix-google-calendar/src/handlers.rs: `start_bound_workflow` → Err.
        (
            PushReceiver::GoogleCalendar,
            PushDropReason::WorkflowRefused,
        ),
        // aegix-google-cloud/src/handlers.rs: `find_by_push_token` → None.
        (PushReceiver::Gcp, PushDropReason::WatchMissing),
        // aegix-google-cloud/src/handlers.rs: `require_service_account` → Err.
        (PushReceiver::Gcp, PushDropReason::WrongSender),
        // aegix-google-cloud/src/dispatch.rs: `start_bound_workflow` → NotStarted.
        (PushReceiver::Gcp, PushDropReason::WorkflowRefused),
        // aegix-atlassian/src/push_receiver.rs: no webhook id named, no
        // registration matched, or every match is another site's.
        (PushReceiver::Jira, PushDropReason::WatchMissing),
        // aegix-atlassian/src/push_receiver.rs: `record_ambiguous`, and more
        // registrations than are read.
        (PushReceiver::Jira, PushDropReason::AmbiguousRegistration),
        // aegix-atlassian/src/push_receiver.rs: `run_planned_starts` → Err.
        (PushReceiver::Jira, PushDropReason::WorkflowRefused),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed list is a SET over the closed product: every entry is a real
    /// pair, no pair twice, and every receiver and every reason is written by
    /// at least one site — a reason no receiver writes is dead vocabulary.
    #[test]
    fn sites_cover_every_pair_once() {
        let mut seen = std::collections::HashSet::new();
        for (receiver, reason) in PushDrop::SITES {
            assert!(
                seen.insert((*receiver, *reason)),
                "pair {}/{} is listed twice",
                receiver.as_str(),
                reason.as_str()
            );
        }
        for receiver in PushReceiver::ALL {
            assert!(
                PushDrop::SITES.iter().any(|(r, _)| r == receiver),
                "receiver {} writes no pair",
                receiver.as_str()
            );
        }
        for reason in PushDropReason::ALL {
            assert!(
                PushDrop::SITES.iter().any(|(_, r)| r == reason),
                "reason {} is written by no receiver",
                reason.as_str()
            );
        }
    }

    /// A label value is a Prometheus-safe word: lower snake case, so the
    /// alert's `{{ $labels.reason }}` reads as the doc spells it.
    #[test]
    fn label_values_are_snake_case_words() {
        for v in PushReceiver::ALL
            .iter()
            .map(|r| r.as_str())
            .chain(PushDropReason::ALL.iter().map(|r| r.as_str()))
        {
            assert!(
                !v.is_empty() && v.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{v:?}"
            );
        }
    }
}
