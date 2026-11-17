//! # The dispatch a data-plane RPC is made for
//!
//! A worker makes its memory, graph, database, model and integration-state
//! calls on behalf of ONE dispatch: the `module_executions` row the controller
//! wrote before it published the job (its id is the job id), under one run
//! (`workflow_executions`, the job's `workflow_execution_id`) or, for a
//! module-bound dispatch (webhook, push channel), under no run at all.
//!
//! Until 2026-10-29 none of those requests named it. The controller executed
//! each one for the `actor_id` the request carried, and the signature proved
//! only that the sender held a worker key — the fleet-shared `WORKER_SHARED_KEY`
//! or one worker's Ed25519 key. So any holder of any worker key could read and
//! write any actor's memory and run guest SQL as any tenant, with no dispatch
//! live for it (the 2026-10-29 review's first finding). `talos.state.write`
//! was taken to be bound already (security review 2026-10-14 B-3), but its
//! statement checked only that the run was live; since 2026-11-09 it carries
//! this binding too (`state_rpc`).
//!
//! [`DispatchBinding`] is the signed statement "this call is made by the job
//! `job_id` of run `execution_id`". The controller admits a bound request only
//! while that row is `pending` or `running` (a push integration's
//! module-bound row stays `pending` until its result), owned by the request's
//! actor, that actor is `active` (2026-11-06) and, for a workflow node, under
//! a run that is live (`dispatch_binding` in `aegix-rpc-subscribers`). Until
//! 2026-11-06 this sentence said `running` alone, which the SQL never was.
//! A job whose secrets a worker claimed (`module_executions.claimed_by_worker_id`)
//! is admitted only for a request Ed25519-signed under that worker's id
//! (2026-11-06); the binding names no worker or attempt, the row does. The worker fills it from the two ids its
//! execution context already holds ([`DispatchBinding::from_context`]), the
//! same ids `state_rpc::durable_state_run` reads.
//!
//! ## Wire shape
//!
//! Every request type carries it as `#[serde(default, skip_serializing_if =
//! Option::is_none)] dispatch: Option<DispatchBinding>`, so a request with no
//! binding serialises to the bytes it did before, and its signed body ends
//! with [`append_signed`]'s 33 bytes ONLY when the binding is present
//! (conditional append, the job protocol's idiom): the signature of an unbound
//! request is byte-identical to what it was. An unbound request is not
//! thereby admitted — the controller refuses it unless it was signed by the
//! controller's own rehearsal identity (`run_sandbox`, `test_module`, which
//! run no dispatch) or the operator turned the requirement off.
//!
//! A controller older than this field ignores it on parse and rebuilds the
//! body without it, so a bound request from a newer worker fails its
//! signature there: **controllers roll before workers**, as for every signed
//! wire change (`make up` rolls both together).

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The dispatch a request is made for. Both ids are the ones the worker's
/// execution context holds: `execution_id` is the job's
/// `workflow_execution_id` (the run; for a module-bound dispatch it equals the
/// job id), `job_id` the job's own `module_executions` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DispatchBinding {
    pub execution_id: Uuid,
    pub job_id: Uuid,
}

/// Domain tag in front of the binding's bytes in a signed body. A fixed tag
/// before fixed-width ids, appended after a protocol's own bytes.
const TAG_DISPATCH_BINDING: u8 = b'D';

/// The bytes a present binding adds to a signed body: `TAG (1B) ||
/// execution_id (16B) || job_id (16B)`.
pub const SIGNED_LEN: usize = 1 + 16 + 16;

impl DispatchBinding {
    /// The binding of the job whose execution context holds these two ids
    /// (`AegixContext::workflow_id`, which carries the job's
    /// `workflow_execution_id`, and `AegixContext::execution_id`, which
    /// carries its job id). `None` when either is absent or is not a UUID:
    /// a rehearsal (`execution_context: None`) is unbound by construction.
    #[must_use]
    pub fn from_context(workflow_execution_id: Option<&str>, job_id: Option<&str>) -> Option<Self> {
        let execution_id = Uuid::parse_str(workflow_execution_id?).ok()?;
        let job_id = Uuid::parse_str(job_id?).ok()?;
        Some(Self {
            execution_id,
            job_id,
        })
    }

    /// Whether this is a module-bound dispatch, which runs under no
    /// `workflow_executions` row and names its own job id in both places
    /// (the same fact `state_rpc::durable_state_run` reads as "no run").
    #[must_use]
    pub fn is_module_bound(self) -> bool {
        self.execution_id == self.job_id
    }
}

/// Append a present binding to a protocol's signed body; an absent one
/// appends nothing, so an unbound request signs the bytes it always did.
/// Every request type's `sign_body_bytes` ends with this call, after its own
/// bytes — never before them, never in the middle.
pub fn append_signed(buf: &mut Vec<u8>, binding: Option<&DispatchBinding>) {
    if let Some(b) = binding {
        buf.reserve(SIGNED_LEN);
        buf.push(TAG_DISPATCH_BINDING);
        buf.extend_from_slice(b.execution_id.as_bytes());
        buf.extend_from_slice(b.job_id.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_binding_adds_no_bytes() {
        let mut buf = vec![1, 2, 3];
        append_signed(&mut buf, None);
        assert_eq!(buf, vec![1, 2, 3]);
    }

    #[test]
    fn a_present_binding_adds_the_tag_and_both_ids_in_order() {
        let b = DispatchBinding {
            execution_id: Uuid::from_u128(0xA),
            job_id: Uuid::from_u128(0xB),
        };
        let mut buf = vec![9];
        append_signed(&mut buf, Some(&b));
        assert_eq!(buf.len(), 1 + SIGNED_LEN);
        assert_eq!(buf[1], b'D');
        assert_eq!(&buf[2..18], Uuid::from_u128(0xA).as_bytes());
        assert_eq!(&buf[18..34], Uuid::from_u128(0xB).as_bytes());
    }

    #[test]
    fn the_two_ids_are_not_interchangeable() {
        let ab = DispatchBinding {
            execution_id: Uuid::from_u128(0xA),
            job_id: Uuid::from_u128(0xB),
        };
        let ba = DispatchBinding {
            execution_id: Uuid::from_u128(0xB),
            job_id: Uuid::from_u128(0xA),
        };
        let (mut x, mut y) = (Vec::new(), Vec::new());
        append_signed(&mut x, Some(&ab));
        append_signed(&mut y, Some(&ba));
        assert_ne!(x, y);
    }

    #[test]
    fn the_binding_is_read_from_the_contexts_two_ids() {
        let run = Uuid::new_v4();
        let job = Uuid::new_v4();
        let b = DispatchBinding::from_context(Some(&run.to_string()), Some(&job.to_string()))
            .expect("two uuids bind");
        assert_eq!((b.execution_id, b.job_id), (run, job));
        assert!(!b.is_module_bound());
        let own = job.to_string();
        assert!(DispatchBinding::from_context(Some(&own), Some(&own))
            .unwrap()
            .is_module_bound());
    }

    #[test]
    fn a_rehearsal_with_no_context_is_unbound() {
        let run = Uuid::new_v4().to_string();
        assert_eq!(DispatchBinding::from_context(None, None), None);
        assert_eq!(DispatchBinding::from_context(Some(&run), None), None);
        assert_eq!(DispatchBinding::from_context(None, Some(&run)), None);
        assert_eq!(
            DispatchBinding::from_context(Some(&run), Some("exec-1")),
            None
        );
    }

    #[test]
    fn the_wire_field_is_absent_when_none() {
        #[derive(Serialize)]
        struct Carrier {
            #[serde(default, skip_serializing_if = "Option::is_none")]
            dispatch: Option<DispatchBinding>,
        }
        assert_eq!(
            serde_json::to_string(&Carrier { dispatch: None }).unwrap(),
            "{}"
        );
    }
}
