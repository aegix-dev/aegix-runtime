//! The dispatch binding is SIGNED on every data-plane request type
//! (2026-10-29): a bound request verifies, and a request whose binding is
//! stripped, or moved to another job or another run, does not. Each case
//! builds a FRESH request (a new nonce), so a failure is the signature's and
//! never the replay cache's.

use aegix_rpc_protocol::database_rpc::DatabaseRpcRequest;
use aegix_rpc_protocol::dispatch_binding::DispatchBinding;
use aegix_rpc_protocol::graph_rpc::GraphSearchRequest;
use aegix_rpc_protocol::integration_state_rpc::{IntegrationOp, IntegrationStateRequest};
use aegix_rpc_protocol::memory_rpc::{MemoryOp, MemoryRpcRequest};
use aegix_rpc_protocol::ml_rpc::{MlFewShotRequest, MlPredictRequest};
use aegix_rpc_protocol::rpc_auth;
use aegix_rpc_protocol::state_rpc::StateWriteRequest;
use std::sync::Arc;
use uuid::Uuid;

fn key() {
    rpc_auth::register_hmac_key(Arc::new(vec![0x5a; 32]));
}

fn binding() -> DispatchBinding {
    DispatchBinding {
        execution_id: Uuid::new_v4(),
        job_id: Uuid::new_v4(),
    }
}

/// The four requests every case needs: honest, stripped, moved to another
/// job, moved to another run. Each is signed over ITS OWN binding and then
/// altered, so only the honest one's bytes match its signature.
fn tampered<T>(
    build: impl Fn(Option<DispatchBinding>) -> T,
    set: impl Fn(&mut T, Option<DispatchBinding>),
) -> [(&'static str, T, bool); 4] {
    let b = binding();
    let honest = build(Some(b));
    let mut stripped = build(Some(b));
    set(&mut stripped, None);
    let mut other_job = build(Some(b));
    set(
        &mut other_job,
        Some(DispatchBinding {
            execution_id: b.execution_id,
            job_id: Uuid::new_v4(),
        }),
    );
    let mut other_run = build(Some(b));
    set(
        &mut other_run,
        Some(DispatchBinding {
            execution_id: Uuid::new_v4(),
            job_id: b.job_id,
        }),
    );
    [
        ("the honest request", honest, true),
        ("a stripped binding", stripped, false),
        ("a binding moved to another job", other_job, false),
        ("a binding moved to another run", other_run, false),
    ]
}

macro_rules! bound_is_signed {
    ($name:ident, $ty:ty, $build:expr) => {
        #[test]
        fn $name() {
            key();
            let actor = Uuid::new_v4();
            let build = |d: Option<DispatchBinding>| -> $ty { ($build)(actor, d) };
            for (what, req, ok) in tampered(build, |r: &mut $ty, d| r.dispatch = d) {
                assert_eq!(req.verify().is_ok(), ok, "{}: {what}", stringify!($ty));
            }
            // Unbound (the controller's rehearsal runtime) still verifies, and
            // carries no `dispatch` key on the wire at all.
            let unbound = build(None);
            unbound.verify().expect("an unbound request verifies");
            assert!(!serde_json::to_string(&unbound)
                .unwrap()
                .contains("\"dispatch\""));
            let bound = build(Some(binding()));
            assert!(serde_json::to_string(&bound)
                .unwrap()
                .contains("\"dispatch\":{"));
        }
    };
}

bound_is_signed!(memory_op, MemoryRpcRequest, |actor, d| {
    MemoryRpcRequest::new_signed_bound(actor, d, MemoryOp::Get { key: "k".into() }).unwrap()
});
bound_is_signed!(graph_search, GraphSearchRequest, |actor, d| {
    GraphSearchRequest::new_signed_bound(actor, d, "q".into(), 1, 5).unwrap()
});
bound_is_signed!(database_query, DatabaseRpcRequest, |actor, d| {
    DatabaseRpcRequest::new_signed_bound(actor, d, "SELECT 1".into(), vec![], true).unwrap()
});
bound_is_signed!(ml_predict, MlPredictRequest, |actor, d| {
    MlPredictRequest::new_signed_bound(actor, d, Uuid::new_v4(), "m".into(), vec!["x".into()])
        .unwrap()
});
bound_is_signed!(ml_fewshot, MlFewShotRequest, |actor, d| {
    MlFewShotRequest::new_signed_bound(actor, d, Uuid::new_v4(), "m".into(), 3).unwrap()
});
bound_is_signed!(integration_state, IntegrationStateRequest, |actor, d| {
    IntegrationStateRequest::new_signed_bound(
        "gmail".into(),
        actor,
        d,
        Uuid::new_v4(),
        IntegrationOp::Get { key: "k".into() },
    )
    .unwrap()
});
bound_is_signed!(state_write, StateWriteRequest, |actor, d| {
    StateWriteRequest::new_signed_bound(Uuid::new_v4(), actor, d, "k".into(), "v".into(), false)
        .unwrap()
});
