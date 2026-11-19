//! The data calls a worker makes while it runs a job, and what this
//! controller answers.
//!
//! One call is served: `talos.memory.op`, the actor's memory. A request is
//! answered in three steps, and a refusal at any of them does no work:
//!
//! 1. **Admission** ([`aegix_rpc_gates::admission`]): the message's length,
//!    its parse, its signature by a key this posture registered, and its
//!    nonce, which is recorded so the same request is never served twice.
//! 2. **The dispatch-binding gate**: the request names a job this controller
//!    is running, for the actor the request names, and (when the worker
//!    signed with its own key) one that worker may act for. A signature
//!    proves who holds a key. This is what proves the holder was given work
//!    for that actor.
//! 3. **The op** ([`crate::memory::execute`]), where a mutation is also put
//!    to the actor's write ceiling.
//!
//! Every other data subject a worker may call (the entity graph, sandbox
//! SQL, integration state, model inference) is answered at once with that
//! protocol's "not available", so a module that calls one fails in
//! milliseconds and not at the worker's timeout. Those answers are constants:
//! the request is not read.
//!
//! [`DataPlane::answer_memory_op`] is the whole decision for one message and
//! has no network in it; [`serve`] carries messages to it.

use crate::counters::{Decision, Refusals};
use crate::ledger::Ledger;
use crate::memory::{self, MemoryStore};
use aegix_deploy_posture::dispatch_binding::Requirement;
use aegix_rpc_gates::admission::{self, AdmitError, OneController};
use aegix_rpc_gates::dispatch_binding::{self, BindingDecision};
use aegix_rpc_protocol::memory_rpc::{MemoryRpcError, MemoryRpcReply, SUBJECT_MEMORY_OP};
use aegix_workflow_job_protocol::subjects::CONTROLLER_RPC_QUEUE_GROUP;
use futures::StreamExt;
use std::sync::Arc;

/// Memory requests handled at once. A request beyond it waits its turn.
pub const MEMORY_OPS_IN_FLIGHT: usize = 16;

/// What a caller is told when a request is not admitted or names no live
/// dispatch. One answer for every reason: the reason is counted and logged
/// for the operator, and a caller that could tell them apart could probe for
/// which actors exist and which jobs are running.
const REFUSED: MemoryRpcError = MemoryRpcError::Unauthorized;

/// The record and the store a data call is decided against.
#[derive(Clone)]
pub struct DataPlane {
    pub ledger: Arc<Ledger>,
    pub memory: Arc<MemoryStore>,
    pub refusals: Arc<Refusals>,
}

impl DataPlane {
    /// Decide and answer one `talos.memory.op` message.
    pub async fn answer_memory_op(&self, payload: &[u8]) -> MemoryRpcReply {
        MemoryRpcReply {
            result: self.memory_op(payload).await,
        }
    }

    async fn memory_op(
        &self,
        payload: &[u8],
    ) -> Result<aegix_rpc_protocol::memory_rpc::MemoryOpResult, MemoryRpcError> {
        let admitted =
            match admission::admit_from_bytes(&admission::memory_op(), &OneController, payload)
                .await
            {
                Ok(admitted) => admitted,
                Err(AdmitError::Malformed(_)) => {
                    self.refusals
                        .count(Decision::Admission, SUBJECT_MEMORY_OP, "malformed");
                    return Err(MemoryRpcError::InvalidInput(
                        "the request could not be read".to_string(),
                    ));
                }
                Err(AdmitError::Unauthorized { reason }) => {
                    self.refusals
                        .count(Decision::Admission, SUBJECT_MEMORY_OP, reason.as_str());
                    tracing::warn!(
                        target: "talos_audit",
                        subject = SUBJECT_MEMORY_OP,
                        reason = reason.as_str(),
                        "data call refused at admission"
                    );
                    return Err(REFUSED);
                }
                Err(AdmitError::Replay) => {
                    self.refusals
                        .count(Decision::Admission, SUBJECT_MEMORY_OP, "replay");
                    tracing::warn!(
                        target: "talos_audit",
                        subject = SUBJECT_MEMORY_OP,
                        reason = "replay",
                        "data call refused at admission"
                    );
                    return Err(REFUSED);
                }
            };
        let request = admitted.into_inner();

        // A binding is required of every worker key, always: this controller
        // has no setting that waives it.
        if let BindingDecision::Refuse(reason) = dispatch_binding::gate(
            self.ledger.as_ref(),
            Requirement::Required,
            SUBJECT_MEMORY_OP,
            request.actor_id,
            request.crypto_scheme,
            &request.worker_id,
            request.dispatch.as_ref(),
        )
        .await
        {
            self.refusals.count(
                Decision::DispatchBinding,
                SUBJECT_MEMORY_OP,
                reason.metric_label(),
            );
            return Err(REFUSED);
        }

        let actor_id = request.actor_id;
        memory::execute(
            &self.memory,
            self.ledger.as_ref(),
            &self.refusals,
            actor_id,
            request.op.into_inner(),
        )
        .await
    }
}

/// A data subject this controller does not serve, and the bytes it answers
/// with.
struct Unserved {
    subject: &'static str,
    reply: Vec<u8>,
}

/// The subjects answered "not available", each with its own protocol's
/// reply so the worker reads a refusal and not a parse error.
fn unserved() -> Vec<Unserved> {
    use aegix_rpc_protocol::{database_rpc, graph_rpc, integration_state_rpc, ml_rpc};
    fn bytes<T: serde::Serialize>(reply: &T) -> Vec<u8> {
        // A reply type is plain data; it serialises.
        serde_json::to_vec(reply).unwrap_or_default()
    }
    vec![
        Unserved {
            subject: graph_rpc::SUBJECT_GRAPH_SEARCH,
            reply: bytes(&graph_rpc::GraphSearchReply {
                result: Err(graph_rpc::GraphRpcError::NotAvailable),
            }),
        },
        Unserved {
            subject: database_rpc::SUBJECT_DATABASE_QUERY,
            reply: bytes(&database_rpc::DatabaseRpcReply {
                result: Err(database_rpc::DatabaseRpcError::ConnectionFailed(
                    "this controller has no database".to_string(),
                )),
            }),
        },
        Unserved {
            subject: integration_state_rpc::SUBJECT_INTEGRATION_STATE_OP,
            reply: bytes(&integration_state_rpc::IntegrationStateReply {
                result: Err(integration_state_rpc::IntegrationStateError::NotAvailable),
            }),
        },
        Unserved {
            subject: ml_rpc::SUBJECT_ML_PREDICT,
            reply: bytes(&ml_rpc::MlPredictResponse::Err(
                ml_rpc::MlRpcError::NotAvailable,
            )),
        },
        Unserved {
            subject: ml_rpc::SUBJECT_ML_FEWSHOT,
            reply: bytes(&ml_rpc::MlFewShotResponse::Err(
                ml_rpc::MlRpcError::NotAvailable,
            )),
        },
    ]
}

/// The subjects [`serve`] answers "not available".
#[must_use]
pub fn unserved_subjects() -> Vec<&'static str> {
    unserved().into_iter().map(|u| u.subject).collect()
}

/// Serve the data plane until `nats` closes: the memory subject through
/// [`DataPlane::answer_memory_op`], and every unserved subject with its
/// constant answer. Returns when the memory subscription ends.
pub async fn serve(nats: async_nats::Client, plane: DataPlane) -> Result<(), String> {
    for Unserved { subject, reply } in unserved() {
        let mut sub = nats
            .queue_subscribe(subject, CONTROLLER_RPC_QUEUE_GROUP.to_string())
            .await
            .map_err(|e| format!("subscribe {subject}: {e}"))?;
        let nats = nats.clone();
        let refusals = plane.refusals.clone();
        tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                refusals.count(Decision::Admission, subject, "not_served");
                if let Some(to) = msg.reply {
                    let _ = nats.publish(to, reply.clone().into()).await;
                }
            }
        });
    }

    let mut sub = nats
        .queue_subscribe(SUBJECT_MEMORY_OP, CONTROLLER_RPC_QUEUE_GROUP.to_string())
        .await
        .map_err(|e| format!("subscribe {SUBJECT_MEMORY_OP}: {e}"))?;
    let slots = Arc::new(tokio::sync::Semaphore::new(MEMORY_OPS_IN_FLIGHT));
    while let Some(msg) = sub.next().await {
        // Taken before the task is spawned, so a flood queues on the
        // subscription and does not become a flood of tasks.
        let Ok(slot) = slots.clone().acquire_owned().await else {
            break;
        };
        let nats = nats.clone();
        let plane = plane.clone();
        tokio::spawn(async move {
            let _slot = slot;
            let reply = plane.answer_memory_op(&msg.payload).await;
            let Some(to) = msg.reply else { return };
            match serde_json::to_vec(&reply) {
                Ok(bytes) => {
                    let _ = nats.publish(to, bytes.into()).await;
                }
                Err(e) => tracing::error!(error = %e, "memory reply did not serialise"),
            }
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::testing::fleet_keys;
    use crate::ledger::testing::{actor, outcome};
    use crate::ledger::{ActorStatus, JobState};
    use aegix_dispatch_types::WriteCeiling;
    use aegix_rpc_protocol::dispatch_binding::DispatchBinding;
    use aegix_rpc_protocol::memory_rpc::{MemoryOp, MemoryOpResult, MemoryRpcRequest};
    use uuid::Uuid;

    struct Fixture {
        plane: DataPlane,
        actor: Uuid,
        read_only: Uuid,
        job: Uuid,
        read_only_job: Uuid,
    }

    fn fixture() -> Fixture {
        // Registers the test fleet key as one a request may be signed with.
        let _ = fleet_keys();
        let ledger = Arc::new(Ledger::default());
        let a = actor("writer", WriteCeiling::Write);
        let ro = actor("reader", WriteCeiling::ReadOnly);
        ledger.put_actor(a.clone());
        ledger.put_actor(ro.clone());
        let job = Uuid::new_v4();
        let read_only_job = Uuid::new_v4();
        ledger
            .record_dispatch(job, a.id, "m", 100, 130)
            .expect("recorded");
        ledger
            .record_dispatch(read_only_job, ro.id, "m", 100, 130)
            .expect("recorded");
        Fixture {
            plane: DataPlane {
                ledger,
                memory: Arc::new(MemoryStore::default()),
                refusals: Arc::new(Refusals::default()),
            },
            actor: a.id,
            read_only: ro.id,
            job,
            read_only_job,
        }
    }

    fn bound(job: Uuid) -> Option<DispatchBinding> {
        Some(DispatchBinding {
            execution_id: job,
            job_id: job,
        })
    }

    fn signed(actor: Uuid, binding: Option<DispatchBinding>, op: MemoryOp) -> Vec<u8> {
        let request =
            MemoryRpcRequest::new_signed_bound(actor, binding, op).expect("a signed request");
        serde_json::to_vec(&request).expect("serialise")
    }

    fn get(key: &str) -> MemoryOp {
        MemoryOp::Get {
            key: key.to_string(),
        }
    }

    fn set(key: &str) -> MemoryOp {
        MemoryOp::Set {
            key: key.to_string(),
            value: serde_json::json!({"n": 1}),
            memory_type: "episodic".to_string(),
            ttl_hours: Some(1.0),
            metadata: None,
        }
    }

    impl Fixture {
        async fn answer(&self, payload: &[u8]) -> Result<MemoryOpResult, MemoryRpcError> {
            self.plane.answer_memory_op(payload).await.result
        }

        fn refused(&self, decision: Decision, reason: &str) -> u64 {
            self.plane.refusals.get(decision, SUBJECT_MEMORY_OP, reason)
        }

        fn holds(&self, actor: Uuid, key: &str) -> bool {
            self.plane
                .memory
                .keys(actor, "", 100, memory::now_unix())
                .iter()
                .any(|k| k == key)
        }
    }

    #[tokio::test]
    async fn a_call_that_names_its_running_job_is_served() {
        let f = fixture();
        assert!(matches!(
            f.answer(&signed(f.actor, bound(f.job), set("notes/a")))
                .await,
            Ok(MemoryOpResult::Ok)
        ));
        assert!(matches!(
            f.answer(&signed(f.actor, bound(f.job), get("notes/a")))
                .await,
            Ok(MemoryOpResult::GetValue { .. })
        ));
    }

    #[tokio::test]
    async fn a_call_that_names_no_job_is_refused_whoever_signed_it() {
        let f = fixture();
        f.plane
            .memory
            .put(
                f.actor,
                "notes/private",
                serde_json::json!("x"),
                "episodic",
                None,
                None,
                memory::now_unix(),
            )
            .expect("stored");
        // Correctly signed with the fleet key, for a real actor: the
        // signature is not what is missing.
        let payload = signed(f.actor, None, get("notes/private"));
        assert!(matches!(
            f.answer(&payload).await,
            Err(MemoryRpcError::Unauthorized)
        ));
        assert_eq!(f.refused(Decision::DispatchBinding, "unbound"), 1);
        assert_eq!(f.refused(Decision::Admission, "bad_signature"), 0);
    }

    #[tokio::test]
    async fn a_call_for_another_actors_memory_is_refused_though_its_own_job_is_live() {
        let f = fixture();
        f.plane
            .memory
            .put(
                f.read_only,
                "notes/theirs",
                serde_json::json!("x"),
                "episodic",
                None,
                None,
                memory::now_unix(),
            )
            .expect("stored");
        // The signer names its OWN live job and ANOTHER actor.
        let payload = signed(f.read_only, bound(f.job), get("notes/theirs"));
        assert!(matches!(
            f.answer(&payload).await,
            Err(MemoryRpcError::Unauthorized)
        ));
        assert_eq!(f.refused(Decision::DispatchBinding, "not_live"), 1);
    }

    #[tokio::test]
    async fn a_call_that_names_an_ended_or_unknown_job_is_refused() {
        let f = fixture();
        assert!(f.plane.ledger.finish(f.job, JobState::Completed, outcome()));
        let payload = signed(f.actor, bound(f.job), set("notes/late"));
        assert!(matches!(
            f.answer(&payload).await,
            Err(MemoryRpcError::Unauthorized)
        ));
        let unknown = signed(f.actor, bound(Uuid::new_v4()), get("notes/a"));
        assert!(matches!(
            f.answer(&unknown).await,
            Err(MemoryRpcError::Unauthorized)
        ));
        assert_eq!(f.refused(Decision::DispatchBinding, "not_live"), 2);
        assert!(
            !f.holds(f.actor, "notes/late"),
            "a late write must not land"
        );
    }

    #[tokio::test]
    async fn a_suspended_actors_running_job_is_served_nothing() {
        let f = fixture();
        assert!(f
            .plane
            .ledger
            .set_actor_status(f.actor, ActorStatus::Suspended));
        let payload = signed(f.actor, bound(f.job), get("notes/a"));
        assert!(matches!(
            f.answer(&payload).await,
            Err(MemoryRpcError::Unauthorized)
        ));
        assert_eq!(f.refused(Decision::DispatchBinding, "not_live"), 1);
    }

    #[tokio::test]
    async fn a_read_only_actors_bound_call_may_read_and_may_not_write() {
        let f = fixture();
        f.plane
            .memory
            .put(
                f.read_only,
                "notes/seed",
                serde_json::json!("x"),
                "episodic",
                None,
                None,
                memory::now_unix(),
            )
            .expect("stored");
        let read = signed(f.read_only, bound(f.read_only_job), get("notes/seed"));
        assert!(matches!(
            f.answer(&read).await,
            Ok(MemoryOpResult::GetValue { .. })
        ));
        let write = signed(f.read_only, bound(f.read_only_job), set("notes/new"));
        assert!(matches!(
            f.answer(&write).await,
            Err(MemoryRpcError::WriteCeiling)
        ));
        assert!(!f.holds(f.read_only, "notes/new"));
        assert_eq!(
            f.plane
                .refusals
                .get(Decision::WriteCeiling, SUBJECT_MEMORY_OP, "policy"),
            1
        );
    }

    #[tokio::test]
    async fn the_same_request_is_served_once() {
        let f = fixture();
        let payload = signed(f.actor, bound(f.job), set("notes/once"));
        assert!(matches!(f.answer(&payload).await, Ok(MemoryOpResult::Ok)));
        assert!(matches!(
            f.answer(&payload).await,
            Err(MemoryRpcError::Unauthorized)
        ));
        assert_eq!(f.refused(Decision::Admission, "replay"), 1);
    }

    #[tokio::test]
    async fn a_request_changed_after_signing_is_refused_before_the_ledger_is_read() {
        let f = fixture();
        let mut request = MemoryRpcRequest::new_signed_bound(f.actor, bound(f.job), get("notes/a"))
            .expect("signed");
        // Re-point a correctly signed request at another actor.
        request.actor_id = f.read_only;
        let payload = serde_json::to_vec(&request).expect("serialise");
        assert!(matches!(
            f.answer(&payload).await,
            Err(MemoryRpcError::Unauthorized)
        ));
        assert_eq!(f.refused(Decision::Admission, "bad_signature"), 1);
        assert_eq!(f.refused(Decision::DispatchBinding, "not_live"), 0);
    }

    #[tokio::test]
    async fn a_message_that_is_not_a_request_is_invalid_and_counted() {
        let f = fixture();
        assert!(matches!(
            f.answer(b"{\"hello\":1}").await,
            Err(MemoryRpcError::InvalidInput(_))
        ));
        assert_eq!(f.refused(Decision::Admission, "malformed"), 1);
    }

    #[test]
    fn every_unserved_subject_has_an_answer_its_protocol_can_read() {
        use aegix_rpc_protocol::{database_rpc, graph_rpc, integration_state_rpc, ml_rpc};
        let all = unserved();
        assert_eq!(all.len(), 5);
        for u in &all {
            assert!(!u.reply.is_empty(), "{} has no answer", u.subject);
            assert_ne!(u.subject, SUBJECT_MEMORY_OP);
        }
        let reply = |subject: &str| -> &[u8] {
            &all.iter()
                .find(|u| u.subject == subject)
                .expect("listed")
                .reply
        };
        assert!(serde_json::from_slice::<graph_rpc::GraphSearchReply>(reply(
            graph_rpc::SUBJECT_GRAPH_SEARCH
        ))
        .expect("parses")
        .result
        .is_err());
        assert!(
            serde_json::from_slice::<database_rpc::DatabaseRpcReply>(reply(
                database_rpc::SUBJECT_DATABASE_QUERY
            ))
            .expect("parses")
            .result
            .is_err()
        );
        assert!(
            serde_json::from_slice::<integration_state_rpc::IntegrationStateReply>(reply(
                integration_state_rpc::SUBJECT_INTEGRATION_STATE_OP
            ))
            .expect("parses")
            .result
            .is_err()
        );
        assert!(matches!(
            serde_json::from_slice::<ml_rpc::MlPredictResponse>(reply(ml_rpc::SUBJECT_ML_PREDICT))
                .expect("parses"),
            ml_rpc::MlPredictResponse::Err(ml_rpc::MlRpcError::NotAvailable)
        ));
        assert!(matches!(
            serde_json::from_slice::<ml_rpc::MlFewShotResponse>(reply(ml_rpc::SUBJECT_ML_FEWSHOT))
                .expect("parses"),
            ml_rpc::MlFewShotResponse::Err(ml_rpc::MlRpcError::NotAvailable)
        ));
    }
}
