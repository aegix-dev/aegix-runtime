//! Broker-level permission sets for the WORKER's NATS user.
//!
//! Until 2026-09-10 every process on the bus authenticated as ONE NATS user
//! with no `permissions` block, so a worker was indistinguishable from the
//! controller at the broker: it could subscribe to `_INBOX.>` (every reply
//! the controller ever awaits — job results, sealed-secret claim responses,
//! webhook replies), to `talos.results.*` (every other worker's module
//! output), to `wasm.log.*`, to the heartbeat stream, and it could publish
//! forged jobs on `talos.jobs`, forged cancels on `talos.workers.cmd.cancel`
//! and forged approvals on `talos.approvals.wait.<exec>`. Signing stops the
//! forgeries from being ACTED on; nothing stopped the eavesdropping, and a
//! dropped forgery still costs the controller a verify.
//!
//! This module is the ONE home for the sets a worker credential is granted.
//! Since 2026-11-06 a worker's credential is minted per connection by the NATS
//! auth callout (`aegix-nats-callout`), from [`worker_subscribe_allow_for`] and
//! [`WORKER_PUBLISH_DENY`]: the static set with the inbox narrowed to the
//! worker's own. The static set is still RENDERED for the configurations
//! that keep one shared worker user: the chart's rollout values
//! `nats.workerAuth: both|shared` (`deploy/helm/talos/files/nats-worker-permissions.conf`)
//! and the minimal compose stack (`deploy/nats/worker-permissions.conf`,
//! included by `deploy/nats/nats-shared-worker.conf` only — nats-server refuses
//! a defined variable nothing references, so the callout `nats.conf` does not
//! include it). Two copies because Helm's `.Files.Get` cannot read outside the
//! chart and compose cannot read inside it; [`render_worker_permissions_conf`]
//! is what both must be byte-equal to, pinned by
//! `rendered_conf_files_match_the_code`. Edit the arrays here, run that test,
//! copy its output; never edit the `.conf` files by hand.
//!
//! # Shape of the sets, and why they differ
//!
//! * **Subscribe is an ALLOW-list.** The worker's subscribe footprint is a
//!   closed set the code enumerates: the two job queues (and their per-user
//!   edge-routing children), the fleet-wide cancel command, the per-execution
//!   approval-wait reply subject, and its own request inboxes. Everything
//!   else the broker carries — controller inboxes, other workers' results,
//!   logs, heartbeats, token streams, the audit ledger — is refused at the
//!   broker, which is the property signing cannot give.
//! * **Publish is a DENY-list.** The worker's publish footprint is NOT closed:
//!   the `messaging` WIT lets guest modules publish to any subject outside the
//!   runtime's reserved prefixes (`RESERVED_PUBLISH_PREFIXES`), and the
//!   catalog's `message-publisher` template takes its topic from module
//!   config. A publish permission violation is an ASYNCHRONOUS `-ERR` on the
//!   connection, not an error returned to the publisher, so an allow-list
//!   would have made every guest publish to an unlisted subject a silent drop
//!   that `messaging::publish` reported as success. What IS closed is the set
//!   of subjects the worker must never author — the controller-consumed ones
//!   it does not legitimately publish — and those are denied.
//!
//! # The inbox prefix
//!
//! async-nats derives every request inbox from one connection-level prefix
//! (`_INBOX` by default). Giving the worker its own, [`WORKER_INBOX_PREFIX`],
//! is what lets the subscribe allow-list admit the worker's own replies
//! without admitting the controller's: `_WINBOX.>` is allowed, `_INBOX.>` is
//! not. The controller replies to a worker RPC by publishing to the request's
//! reply subject, so a controller credential that is ever given a permissions
//! block MUST allow publish on `_WINBOX.>`.
//!
//! # Per-worker inboxes (2026-11-06)
//!
//! Under the auth callout the prefix is per WORKER: [`worker_inbox_prefix_for`]
//! gives `_WINBOX.<worker id>`, and the minted credential may subscribe only
//! `_WINBOX.<worker id>.>`, so a worker cannot read a sibling's RPC replies
//! (data-plane review 2026-11-06, finding 4;
//! `docs/engineering-log/packages/2026-11-06-per-worker-nats-credentials.md`).
//! A worker id is used as ONE subject token, so the callout refuses an id with
//! a `.` ([`worker_inbox_token_is_valid`]). Two processes that share an id
//! share its inbox scope: the shipped shapes give each process its own id
//! (`AEGIX_WORKER_IDENTITY=ephemeral`).
//!
//! # Stated limits
//!
//! * Under the chart's rollout values `both` and `shared`, and in the minimal
//!   compose stack, the static worker user still exists and its set still
//!   admits every `_WINBOX.>`: a worker holding that credential can read a
//!   sibling's RPC replies. `callout` (the chart default, the development and
//!   production compose stacks) removes it; the minimal stack runs one worker.
//! * The job subjects are QUEUE-ONLY (2026-10-29). A nats-server allow entry
//!   `"subject queue"` admits a subscription on that subject only in that
//!   queue group, and a plain subscription on a subject that appears only
//!   with a queue is refused (verified live against nats-server 2.10 and
//!   2.12: `-ERR 'Permissions Violation for Subscription to "talos.jobs"'`).
//!   Until then a worker could `SUB talos.jobs` without a queue and receive a
//!   COPY of every job on the fleet — every `JobRequest`, with its
//!   `encrypted_secrets` envelope, which under `AEGIX_ENVELOPE_SEALING=off`
//!   any holder of `WORKER_SHARED_KEY` opens. Now a worker sees only the jobs
//!   the broker hands its queue group. What this does NOT give: a worker may
//!   still open several connections, each a member of the group, and so
//!   take a larger SHARE; and the queue name is matched as a subject pattern,
//!   so a worker on `talos.jobs.<user>` may name any `talos.jobs.…` group,
//!   not only its own. The job a worker IS handed is the one it is meant to
//!   run; what it may do with that job's secrets is bounded by claim-based
//!   sealing (`AEGIX_ENVELOPE_SEALING=required`), which seals them to the
//!   claiming worker alone.
//! * The sets are enforced by the BROKER's configuration, not by this crate.
//!   This module makes the sets sayable and pins the rendered files to them;
//!   `aegix-workflow-engine-nats/tests/nats_worker_permissions.rs` drives the
//!   rendered config on a live `nats-server` and checks that the broker's
//!   answer matches [`worker_may_publish`] / [`worker_may_subscribe`] on
//!   every subject in the table.

/// Inbox prefix for the WORKER's NATS connection (`ConnectOptions::
/// custom_inbox_prefix`). Distinct from async-nats' default `_INBOX`, which the
/// controller keeps, so the worker's subscribe permission can admit its own
/// request/reply traffic and nothing else's.
pub const WORKER_INBOX_PREFIX: &str = "_WINBOX";

/// The controller's inbox prefix — async-nats' default. Named here so the
/// deny-list and the tests spell it once.
pub const CONTROLLER_INBOX_PREFIX: &str = "_INBOX";

/// One subscribe allow entry: a subject pattern, and the queue-group pattern
/// the subscription must be a member of — `None` admits a plain subscription
/// (and, as nats-server reads it, any queue group too).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubscribeAllow {
    pub subject: &'static str,
    pub queue: Option<&'static str>,
}

impl SubscribeAllow {
    /// The entry as nats-server's `allow` list spells it: `"subject"` or
    /// `"subject queue"`.
    #[must_use]
    pub fn rendered(self) -> String {
        match self.queue {
            Some(q) => format!("{} {q}", self.subject),
            None => self.subject.to_string(),
        }
    }
}

const fn plain(subject: &'static str) -> SubscribeAllow {
    SubscribeAllow {
        subject,
        queue: None,
    }
}

/// A job queue: the worker's queue group IS the topic
/// (`worker/src/main.rs`: `let queue_group = single_job_topic.clone()`), so
/// the queue pattern is the subject pattern.
const fn queued(subject: &'static str) -> SubscribeAllow {
    SubscribeAllow {
        subject,
        queue: Some(subject),
    }
}

/// Subjects the worker credential may SUBSCRIBE to. Closed set; every entry
/// maps to a `subscribe`/`queue_subscribe` call in `worker/` or
/// `aegix-wasm-host/`, listed in the order the worker takes them at boot.
pub const WORKER_SUBSCRIBE_ALLOW: &[SubscribeAllow] = &[
    // worker/src/main.rs — the single-job queue (`NATS_JOB_TOPIC` default) and
    // its per-user edge-routing children `talos.jobs.<user_id>`, QUEUE-ONLY:
    // a plain subscription (a copy of every job) is refused at the broker.
    // An operator who overrides `NATS_JOB_TOPIC` outside this prefix must
    // widen the set.
    queued("talos.jobs"),
    queued("talos.jobs.>"),
    // worker/src/main.rs `run_cancel_listener` — plain (non-queue) subscribe,
    // fleet-wide, signed body. `talos.workers.cmd.shutdown` is deliberately
    // NOT here: it has zero publishers and zero subscribers
    // (`docs/inert-mechanisms.md`), and an inert subject earns no permission.
    plain("talos.workers.cmd.cancel"),
    // aegix-wasm-host/src/host/governance.rs — the approve/reject reply
    // for a suspended governance node, keyed on the node's exec id.
    plain("talos.approvals.wait.>"),
    // Every `Client::request` the worker issues (the seven signed RPCs, the
    // secret claim, agent orchestration, guest `messaging::request`).
    plain("_WINBOX.>"),
];

/// Subjects the worker credential may NOT PUBLISH to. Everything not listed
/// is permitted (see the module docs for why this is a deny-list). Every
/// entry is a subject the controller authors or the broker owns, and that no
/// line in `worker/` or `aegix-wasm-host/` publishes to.
pub const WORKER_PUBLISH_DENY: &[&str] = &[
    // Job dispatch is the controller's alone. A forged JobRequest fails its
    // signature check on the receiving worker, but the broker refusing it is
    // cheaper than every worker verifying it.
    "talos.jobs",
    "talos.jobs.>",
    // Fleet commands (cancel today; shutdown is inert) are controller → worker.
    "talos.workers.cmd.>",
    // Execution-failure alerts are authored by the controller's result
    // collector and carry NO signature — the one consumer-trusted subject a
    // worker could have written into.
    "talos.alerts.>",
    // The approve/reject reply is published by the controller's webhook
    // handler from a Redis-routed reply subject; a worker publishing here
    // could approve a SIBLING worker's suspended node.
    "talos.approvals.wait.>",
    // Token stream relayed to GraphQL subscribers. No worker publisher exists
    // today (measured 2026-09-10: zero `llm_stream_for` call sites outside the
    // registry and the GraphQL relay); a future worker producer must remove
    // this entry, and `worker_publish_set_is_pinned` will say so.
    "talos.llm.stream.>",
    // Other workers' request inboxes — the worker only ever RECEIVES here.
    "_WINBOX.>",
    // NATS system and JetStream API namespaces. The worker uses no JetStream
    // (zero `jetstream` references in `worker/` and `aegix-wasm-host/`).
    "$SYS.>",
    "$JS.>",
    "$KV.>",
    "$O.>",
];

/// Whether `worker_id` can name a worker's own inbox scope: a valid worker id
/// (`crate::validate_worker_id`, which also refuses the controller's reserved
/// id), non-empty, and ONE subject token — no `.`. A dot would split the id
/// across tokens, and `_WINBOX.a.>` would then cover worker `a.b`'s inbox.
/// The charset already excludes `*`, `>` and whitespace.
#[must_use]
pub fn worker_inbox_token_is_valid(worker_id: &str) -> bool {
    !worker_id.is_empty()
        && !worker_id.contains('.')
        && crate::validate_worker_id(worker_id).is_ok()
}

/// The inbox prefix ONE worker uses under the auth callout
/// (`aegix-nats-callout`, 2026-11-06): `_WINBOX.<worker id>`. async-nats makes
/// every request inbox `<prefix>.<nuid>.<n>`, so all of this worker's replies
/// land under `_WINBOX.<worker id>.>` — the one inbox scope its minted
/// credential may subscribe. `None` when the id cannot be one token.
#[must_use]
pub fn worker_inbox_prefix_for(worker_id: &str) -> Option<String> {
    worker_inbox_token_is_valid(worker_id).then(|| format!("{WORKER_INBOX_PREFIX}.{worker_id}"))
}

/// The subscribe allow-list the auth callout grants ONE worker, in
/// nats-server's spelling (`"subject"` or `"subject queue"`). It is
/// [`WORKER_SUBSCRIBE_ALLOW`] with the shared `_WINBOX.>` narrowed to this
/// worker's own `_WINBOX.<worker id>.>`, so a worker credential cannot read a
/// sibling's RPC replies (data-plane review 2026-11-06, finding 4). `None` when
/// the id cannot be one token. The publish side is [`WORKER_PUBLISH_DENY`]
/// unchanged: it already denies every `_WINBOX.>`.
#[must_use]
pub fn worker_subscribe_allow_for(worker_id: &str) -> Option<Vec<String>> {
    let prefix = worker_inbox_prefix_for(worker_id)?;
    let shared = format!("{WORKER_INBOX_PREFIX}.>");
    Some(
        WORKER_SUBSCRIBE_ALLOW
            .iter()
            .map(|a| {
                if a.subject == shared {
                    debug_assert!(a.queue.is_none(), "the inbox entry is a plain subscription");
                    format!("{prefix}.>")
                } else {
                    a.rendered()
                }
            })
            .collect(),
    )
}

/// Would the broker admit a SUBSCRIBE by the callout-minted credential of
/// `worker_id`? The same reading as [`worker_may_subscribe`], over
/// [`worker_subscribe_allow_for`]. `false` for an id that cannot be one token
/// (the callout mints nothing for it).
#[must_use]
pub fn worker_may_subscribe_as(worker_id: &str, subject: &str, queue: Option<&str>) -> bool {
    let Some(allow) = worker_subscribe_allow_for(worker_id) else {
        return false;
    };
    allow.iter().any(|entry| {
        let (pattern, group) = match entry.split_once(' ') {
            Some((s, q)) => (s, Some(q)),
            None => (entry.as_str(), None),
        };
        subject_matches(pattern, subject)
            && match (group, queue) {
                (None, _) => true,
                (Some(_), None) => false,
                (Some(gp), Some(q)) => subject_matches(gp, q),
            }
    })
}

/// NATS subject matching: tokens are `.`-separated; `*` matches exactly one
/// token, `>` matches one or more trailing tokens. Mirrors the server's own
/// rules so the tests here predict what the broker will do.
#[must_use]
pub fn subject_matches(pattern: &str, subject: &str) -> bool {
    let mut pat = pattern.split('.');
    let mut sub = subject.split('.').peekable();
    loop {
        match (pat.next(), sub.peek()) {
            // Both exhausted together, or `>` with at least one token left.
            (None, None) | (Some(">"), Some(_)) => return true,
            // One side ran out before the other (`>` needs ≥1 token).
            (None, Some(_)) | (Some(_), None) => return false,
            (Some("*"), Some(_)) => {
                sub.next();
            }
            (Some(p), Some(&s)) => {
                if p != s {
                    return false;
                }
                sub.next();
            }
        }
    }
}

/// Would the broker admit a worker SUBSCRIBE on `subject`, plain (`None`) or
/// as a member of `queue`? A plain entry admits both; a queued entry admits
/// only a queue subscription whose group matches its queue pattern (the
/// server matches the queue name with the same token rules as a subject).
#[must_use]
pub fn worker_may_subscribe(subject: &str, queue: Option<&str>) -> bool {
    WORKER_SUBSCRIBE_ALLOW
        .iter()
        .filter(|a| subject_matches(a.subject, subject))
        .any(|a| match (a.queue, queue) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(qp), Some(q)) => subject_matches(qp, q),
        })
}

/// Would the broker admit a worker PUBLISH to `subject`?
#[must_use]
pub fn worker_may_publish(subject: &str) -> bool {
    !WORKER_PUBLISH_DENY
        .iter()
        .any(|p| subject_matches(p, subject))
}

/// The nats-server configuration fragment defining `WORKER_PERMISSIONS`, for
/// `include` from a `nats.conf` whose `authorization { users = [...] }` binds
/// it to the worker credential. Both checked-in copies must equal this
/// byte-for-byte (`rendered_conf_files_match_the_code`).
#[must_use]
pub fn render_worker_permissions_conf() -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    out.push_str(
        "# GENERATED — do not edit. Source: aegix-workflow-job-protocol/src/nats_permissions.rs\n\
         # (`render_worker_permissions_conf`). `cargo test -p aegix-workflow-job-protocol \\\n\
         #   nats_permissions` fails when this file and the Rust sets disagree; regenerate with\n\
         # `AEGIX_NATS_PERMISSIONS_WRITE=1` set on that same test run.\n\
         #\n\
         # Permission set for the WORKER's NATS user. Subscribe is an allow-list (the\n\
         # worker's subscribe footprint is closed); publish is a deny-list (guest modules\n\
         # may publish to any non-reserved subject, and a publish permission violation is\n\
         # an async -ERR the publisher never sees, so an allow-list would silently drop\n\
         # guest messages). The controller's credential carries no permissions block; if\n\
         # it ever does, it must allow publish on `_WINBOX.>` — that is where it replies\n\
         # to worker RPCs. A `\"subject queue\"` entry admits a subscription on that subject\n\
         # only as a member of that queue group: the job queues are queue-only, so no\n\
         # worker receives a copy of every job.\n\
         WORKER_PERMISSIONS = {\n  subscribe: {\n    allow: [\n",
    );
    for a in WORKER_SUBSCRIBE_ALLOW {
        let _ = writeln!(out, "      \"{}\",", a.rendered());
    }
    out.push_str("    ]\n  }\n  publish: {\n    deny: [\n");
    for s in WORKER_PUBLISH_DENY {
        let _ = writeln!(out, "      \"{s}\",");
    }
    out.push_str("    ]\n  }\n}\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subjects;

    /// The seven signed data-RPC subjects. Their canonical consts live in
    /// `aegix-memory` (`SUBJECT_*`), a crate ABOVE this one, so they are
    /// spelled here as literals and cross-pinned from that crate's own tests
    /// (`aegix_memory::rpc_auth::nats_permission_pins`).
    const RPC_SUBJECTS: &[&str] = &[
        "talos.memory.op",
        "talos.graph.search",
        "talos.database.query",
        "talos.state.write",
        "talos.integration_state.op",
        "talos.ml.predict",
        "talos.ml.fewshot",
    ];

    #[test]
    fn matcher_follows_nats_token_rules() {
        assert!(subject_matches("talos.jobs", "talos.jobs"));
        assert!(!subject_matches("talos.jobs", "talos.jobs.u1"));
        assert!(subject_matches("talos.jobs.>", "talos.jobs.u1"));
        assert!(subject_matches("talos.jobs.>", "talos.jobs.u1.priority"));
        assert!(!subject_matches("talos.jobs.>", "talos.jobs"));
        assert!(subject_matches("talos.results.*", "talos.results.j1"));
        assert!(!subject_matches("talos.results.*", "talos.results.j1.x"));
        assert!(!subject_matches("talos.results.*", "talos.results"));
        assert!(subject_matches("$JS.>", "$JS.API.INFO"));
        assert!(!subject_matches("$JS.>", "$JSX.API"));
        assert!(!subject_matches("_INBOX.>", "_WINBOX.a.1"));
    }

    #[test]
    fn inbox_prefixes_are_distinct_single_tokens() {
        assert_ne!(WORKER_INBOX_PREFIX, CONTROLLER_INBOX_PREFIX);
        for p in [WORKER_INBOX_PREFIX, CONTROLLER_INBOX_PREFIX] {
            assert!(p.starts_with('_'), "{p} should be underscore-prefixed");
            assert!(!p.contains('.'), "{p} must be a single token");
            assert!(!p.contains('*') && !p.contains('>'));
        }
        assert!(WORKER_SUBSCRIBE_ALLOW.contains(&plain("_WINBOX.>")));
        assert_eq!(format!("{WORKER_INBOX_PREFIX}.>"), "_WINBOX.>");
    }

    /// Every subject the worker SUBSCRIBES to (one entry per call site), the
    /// way the call site subscribes: the job queues as `queue_subscribe`
    /// with the topic as the group, everything else plain.
    #[test]
    fn every_worker_subscribe_site_is_allowed() {
        let queued = [subjects::JOBS.to_string(), subjects::jobs_for("user-1")];
        for s in queued {
            assert!(
                worker_may_subscribe(&s, Some(&s)),
                "worker must be able to queue-subscribe to {s} in group {s}"
            );
        }
        let plain = [
            subjects::WORKERS_CMD_CANCEL.to_string(),
            subjects::approvals_wait_for("exec-1"),
            format!("{WORKER_INBOX_PREFIX}.abcdef.1"),
        ];
        for s in plain {
            assert!(
                worker_may_subscribe(&s, None),
                "worker must be able to subscribe to {s}"
            );
        }
    }

    /// The job queues are queue-only: a plain subscription — a copy of every
    /// job on the fleet — is refused, and so is a queue group outside the
    /// topic's own pattern. Mutation: make `queued` return `plain` and the
    /// first assertion fails.
    #[test]
    fn a_plain_subscription_on_a_job_queue_is_refused() {
        for s in [subjects::JOBS.to_string(), subjects::jobs_for("user-1")] {
            assert!(
                !worker_may_subscribe(&s, None),
                "a plain subscription on {s} must be refused"
            );
            assert!(
                !worker_may_subscribe(&s, Some("other")),
                "a foreign queue group on {s} must be refused"
            );
        }
        // The per-user child's group is matched as a pattern: its own name
        // passes; so does another child's (stated limit), but not the parent's.
        assert!(worker_may_subscribe(
            &subjects::jobs_for("user-1"),
            Some(&subjects::jobs_for("user-2"))
        ));
        assert!(!worker_may_subscribe(
            &subjects::jobs_for("user-1"),
            Some(subjects::JOBS)
        ));
        // A plain entry admits any queue group (nats-server reads it so).
        assert!(worker_may_subscribe(
            subjects::WORKERS_CMD_CANCEL,
            Some("g")
        ));
    }

    /// Subjects the worker has NO business reading. The allow-list is what
    /// makes these refusals; this test is the record of what it refuses.
    #[test]
    fn eavesdropping_subjects_are_refused_on_subscribe() {
        let refused = [
            format!("{CONTROLLER_INBOX_PREFIX}.abcdef.1"),
            subjects::results_for("job-1"),
            "wasm.log.exec-1".to_string(),
            subjects::worker_heartbeat_for("w-1"),
            subjects::AUDIT_LEDGER.to_string(),
            subjects::APPROVALS_PENDING.to_string(),
            subjects::llm_stream_for("exec-1"),
            subjects::agent_invoke_for("t"),
            subjects::workflow_event_for("e", "done"),
            subjects::ALERTS_EXECUTION_FAILED.to_string(),
            subjects::WORKERS_CMD_SHUTDOWN.to_string(),
            "$SYS.REQ.SERVER.PING".to_string(),
            "$JS.API.INFO".to_string(),
        ];
        for s in refused.iter().chain(
            RPC_SUBJECTS
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .iter(),
        ) {
            assert!(
                !worker_may_subscribe(s, None) && !worker_may_subscribe(s, Some(s)),
                "worker must NOT be able to subscribe to {s}"
            );
        }
    }

    /// Every subject the worker PUBLISHES to (one entry per call site), plus
    /// two guest-shaped topics the `messaging` host would forward.
    #[test]
    fn every_worker_publish_site_is_permitted() {
        let mut sites = vec![
            subjects::results_for("job-1"),
            format!("{CONTROLLER_INBOX_PREFIX}.abcdef.1"), // reply_topic + claim_inbox
            // RFC 0014 P2: job progress rides the signed reply inbox.
            subjects::job_progress_for(&format!("{CONTROLLER_INBOX_PREFIX}.abcdef.1")),
            subjects::AUDIT_LEDGER.to_string(),
            subjects::APPROVALS_PENDING.to_string(),
            subjects::worker_heartbeat_for("w-1"),
            "wasm.log.exec-1".to_string(),
            subjects::agent_invoke_for("target"),
            subjects::agent_message_for("target"),
            subjects::workflow_event_for("exec-1", "node_done"),
            "orders.created".to_string(),
            "acme.team.notifications".to_string(),
        ];
        sites.extend(RPC_SUBJECTS.iter().map(|s| s.to_string()));
        for s in sites {
            assert!(
                worker_may_publish(&s),
                "worker must be able to publish to {s}"
            );
        }
    }

    /// Controller-authored and broker-owned subjects the worker must never
    /// write into. Adding a worker publisher for one of these means removing
    /// it from `WORKER_PUBLISH_DENY` here, in a reviewed commit.
    #[test]
    fn worker_publish_set_is_pinned() {
        let denied = [
            subjects::JOBS.to_string(),
            subjects::jobs_for("user-1"),
            format!("{}.priority", subjects::JOBS),
            subjects::WORKERS_CMD_CANCEL.to_string(),
            subjects::WORKERS_CMD_SHUTDOWN.to_string(),
            subjects::ALERTS_EXECUTION_FAILED.to_string(),
            subjects::approvals_wait_for("exec-1"),
            subjects::llm_stream_for("exec-1"),
            format!("{WORKER_INBOX_PREFIX}.abcdef.1"),
            "$SYS.REQ.SERVER.PING".to_string(),
            "$JS.API.STREAM.INFO.x".to_string(),
            "$KV.bucket.key".to_string(),
            "$O.bucket.x".to_string(),
        ];
        for s in denied {
            assert!(
                !worker_may_publish(&s),
                "worker must NOT be able to publish to {s}"
            );
        }
    }

    /// The allow-list never admits a controller inbox and the deny-list never
    /// covers the worker's own — the two prefixes must not be confusable by a
    /// wildcard.
    #[test]
    fn inbox_isolation_is_asymmetric() {
        assert!(worker_may_subscribe("_WINBOX.x.1", None));
        assert!(!worker_may_subscribe("_INBOX.x.1", None));
        assert!(worker_may_publish("_INBOX.x.1"));
        assert!(!worker_may_publish("_WINBOX.x.1"));
    }

    /// The callout-minted set narrows ONLY the inbox: every other entry is the
    /// static one, and the worker's own inbox is admitted while a sibling's
    /// (and the shared prefix itself) is refused. Mutation: return the static
    /// `_WINBOX.>` from `worker_subscribe_allow_for` and the sibling assertion
    /// fails.
    #[test]
    fn a_minted_worker_set_admits_its_own_inbox_and_no_sibling() {
        let allow = worker_subscribe_allow_for("w-a").expect("valid id");
        assert_eq!(allow.len(), WORKER_SUBSCRIBE_ALLOW.len());
        assert!(allow.contains(&"_WINBOX.w-a.>".to_string()));
        assert!(!allow.iter().any(|e| e == "_WINBOX.>"));
        for a in WORKER_SUBSCRIBE_ALLOW {
            if a.subject != "_WINBOX.>" {
                assert!(allow.contains(&a.rendered()), "{} dropped", a.rendered());
            }
        }
        assert_eq!(
            worker_inbox_prefix_for("w-a").as_deref(),
            Some("_WINBOX.w-a")
        );
        assert!(worker_may_subscribe_as("w-a", "_WINBOX.w-a.nuid.1", None));
        assert!(!worker_may_subscribe_as("w-a", "_WINBOX.w-b.nuid.1", None));
        // Token boundaries: `w-a` does not cover `w-ab`.
        assert!(!worker_may_subscribe_as("w-a", "_WINBOX.w-ab.nuid.1", None));
        // Everything else is the static model's answer.
        for (s, q) in [
            (subjects::JOBS.to_string(), Some(subjects::JOBS.to_string())),
            (subjects::JOBS.to_string(), None),
            (subjects::WORKERS_CMD_CANCEL.to_string(), None),
            (subjects::approvals_wait_for("e"), None),
            (subjects::results_for("j"), None),
            ("_INBOX.x.1".to_string(), None),
        ] {
            assert_eq!(
                worker_may_subscribe_as("w-a", &s, q.as_deref()),
                worker_may_subscribe(&s, q.as_deref()),
                "{s} {q:?}"
            );
        }
    }

    /// An id that is not ONE subject token names no inbox scope, and the
    /// controller's reserved identity names none either.
    #[test]
    fn an_id_that_is_not_one_token_names_no_inbox() {
        for bad in ["", "a.b", "a*", "a>", "a b", crate::CONTROLLER_RPC_IDENTITY] {
            assert!(!worker_inbox_token_is_valid(bad), "{bad:?}");
            assert!(worker_inbox_prefix_for(bad).is_none(), "{bad:?}");
            assert!(worker_subscribe_allow_for(bad).is_none(), "{bad:?}");
            assert!(!worker_may_subscribe_as(bad, "_WINBOX.a.b.1", None));
        }
        let long = "x".repeat(crate::MAX_WORKER_ID_LEN + 1);
        assert!(!worker_inbox_token_is_valid(&long));
        assert!(worker_inbox_token_is_valid(
            "talos-worker-7f9c-0123456789abcdef"
        ));
    }

    #[test]
    fn no_pattern_is_malformed() {
        let subscribe_patterns = WORKER_SUBSCRIBE_ALLOW
            .iter()
            .flat_map(|a| std::iter::once(a.subject).chain(a.queue));
        for p in subscribe_patterns.chain(WORKER_PUBLISH_DENY.iter().copied()) {
            assert!(!p.is_empty());
            assert!(!p.contains(' '), "{p} contains whitespace");
            assert!(
                !p.starts_with('.') && !p.ends_with('.'),
                "{p} has an empty token"
            );
            if let Some(i) = p.find('>') {
                assert_eq!(i, p.len() - 1, "{p}: `>` must be the last token");
            }
        }
    }

    /// The two checked-in fragments are DERIVED from this module. A drift
    /// fails here with the regenerated text, so the fix is copy-paste — or
    /// run once with `AEGIX_NATS_PERMISSIONS_WRITE=1`, which rewrites both
    /// files from the render before asserting (the snapshot-update idiom).
    fn rendered_conf_file_matches_the_code(rel: &str) {
        let rendered = render_worker_permissions_conf();
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let write = std::env::var("AEGIX_NATS_PERMISSIONS_WRITE").is_ok_and(|v| !v.is_empty());
        let path = root.join(rel);
        if write {
            std::fs::write(&path, &rendered).expect("write rendered fragment");
        }
        let on_disk = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e}\n--- expected content ---\n{rendered}",
                path.display()
            )
        });
        assert!(
            on_disk == rendered,
            "{rel} is out of date. Replace its contents with:\n--- 8< ---\n{rendered}--- >8 ---"
        );
    }

    #[test]
    fn rendered_conf_files_match_the_code() {
        rendered_conf_file_matches_the_code("deploy/nats/worker-permissions.conf");
    }

    #[test]
    fn rendered_conf_names_every_entry_once() {
        let rendered = render_worker_permissions_conf();
        // A queued entry renders as `"subject queue"`, the server's spelling.
        assert!(
            rendered.contains("\"talos.jobs talos.jobs\","),
            "{rendered}"
        );
        assert!(
            rendered.contains("\"talos.jobs.> talos.jobs.>\","),
            "{rendered}"
        );
        let subscribe_entries = WORKER_SUBSCRIBE_ALLOW.iter().map(|a| a.rendered());
        for s in subscribe_entries.chain(WORKER_PUBLISH_DENY.iter().map(|s| s.to_string())) {
            let needle = format!("\"{s}\"");
            let n = rendered.matches(&needle).count();
            // `talos.jobs` etc. appear in BOTH lists by design.
            assert!(n >= 1, "{s} missing from the rendered fragment");
        }
        assert!(rendered.contains("WORKER_PERMISSIONS = {"));
        assert!(rendered.contains("subscribe: {\n    allow: ["));
        assert!(rendered.contains("publish: {\n    deny: ["));
    }
}
