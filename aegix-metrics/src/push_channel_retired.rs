//! The closed label set for `aegix_push_channels_retired_total{integration,reason}`
//! — a push channel the renewal sweep DELETED because the connection it
//! named is gone and no live connection of the same user is on the same
//! account.
//!
//! Why it exists (2026-11-05, `docs/engineering-log/packages/
//! 2026-11-05-a-channel-whose-row-is-gone-is-retired-or-repointed.md`). On
//! 2026-11-02 a re-consent through the generic Settings disconnect
//! hard-deleted two `google_calendar_integrations` rows (#1538 has since made
//! every disconnect keep its row). The eight Calendar channels created on
//! 2026-10-30 kept naming the deleted ids: every push failed inside the sync
//! and every hourly renewal failed with `Integration … not found`, and the
//! rows sat in `integration_state` until an operator deleted them by hand two
//! days later. #1565 made the push failure count on
//! `aegix_push_dropped_total{gcal,integration_missing}`; this counter is the
//! sweep ACTING on the row instead of failing on it every hour.
//!
//! A re-point (the same account has a live row again under a new id) is not
//! counted here: it is the channel continuing, logged at INFO with both ids.
//! A retirement is the channel ending, with a Google-side channel nothing can
//! stop (no row, no token path), so it is the event an operator acts on:
//! `TalosPushChannelRetired` fires on the first one.
//!
//! Every value is an ENUM so the label set is closed by the compiler, and the
//! pairs seeded at 0 are EXACTLY the pairs a live call site writes
//! ([`PushChannelRetire::SITES`]): `increase()` sees the first retirement
//! (CLAUDE.md, "ABSENT and ZERO are different"), and a seeded pair nothing
//! increments would claim a sweep that does not exist — Google Cloud has no
//! renewal sweep (its rows never expire) and Jira's refresher names a
//! connection, not an integration row, so neither is seeded.

use crate::push_dropped::PushReceiver;

/// Why the sweep retired the channel. One reason today; the enum is the
/// closed set an alert's `reason` label may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PushChannelRetireReason {
    /// The channel named an integration row that no longer exists for its
    /// user, and no live row of that user is on the same account (or the
    /// channel was written before it recorded its account, so no sibling
    /// could be named). The row is deleted; Google is not told.
    IntegrationMissing,
}

impl PushChannelRetireReason {
    pub const ALL: &'static [Self] = &[Self::IntegrationMissing];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntegrationMissing => "integration_missing",
        }
    }
}

/// The `(integration, reason)` pairs with a live call site.
pub struct PushChannelRetire;

impl PushChannelRetire {
    /// Every pair the shared sweep step
    /// (`aegix_integration_helpers::orphaned_channel::reconcile_channel`)
    /// writes, by the renewer that calls it. The pre-seed loop in
    /// `AegixMetrics::new` walks THIS list. A renewer that adopts the step
    /// adds its pair here in the same change.
    pub const SITES: &'static [(PushReceiver, PushChannelRetireReason)] = &[
        // aegix-google-calendar/src/scheduler.rs: `GcalRenewer::reconcile_connection`.
        (
            PushReceiver::GoogleCalendar,
            PushChannelRetireReason::IntegrationMissing,
        ),
        // aegix-gmail/src/scheduler.rs: `GmailRenewer::reconcile_connection`.
        (
            PushReceiver::Gmail,
            PushChannelRetireReason::IntegrationMissing,
        ),
    ];
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The seed list is a SET over the closed product, and every reason is
    /// written by at least one site — a reason no renewer writes is dead
    /// vocabulary.
    #[test]
    fn sites_cover_every_reason_once() {
        let mut seen = std::collections::HashSet::new();
        for (receiver, reason) in PushChannelRetire::SITES {
            assert!(
                seen.insert((*receiver, *reason)),
                "pair {}/{} is listed twice",
                receiver.as_str(),
                reason.as_str()
            );
        }
        for reason in PushChannelRetireReason::ALL {
            assert!(
                PushChannelRetire::SITES.iter().any(|(_, r)| r == reason),
                "reason {} has no call site",
                reason.as_str()
            );
        }
    }

    /// The two renewers that run the shared step are the two seeded; the two
    /// receivers with no renewal sweep are not.
    #[test]
    fn only_the_two_renewers_are_seeded() {
        let seeded: Vec<PushReceiver> = PushChannelRetire::SITES.iter().map(|(r, _)| *r).collect();
        assert!(seeded.contains(&PushReceiver::GoogleCalendar));
        assert!(seeded.contains(&PushReceiver::Gmail));
        assert!(
            !seeded.contains(&PushReceiver::Gcp),
            "GCP has no renewal sweep"
        );
        assert!(
            !seeded.contains(&PushReceiver::Jira),
            "Jira names no integration row"
        );
    }
}
