//! The two gates a controller puts in front of a worker's signed data-plane
//! RPC, with no database in them.
//!
//! A request on `talos.memory.op` and its sibling subjects is signed with a
//! key the whole worker fleet holds, or with one worker's own key. The
//! signature proves who holds a key. It does not prove that the signer was
//! given a job for the actor it names, or that it ran any check before it
//! asked. A controller therefore decides two things itself, after the
//! request has been admitted ([`admission`]: its length, its parse, its
//! signature and its nonce, in that order) and before it does any work:
//!
//! * [`dispatch_binding`]: the request names a dispatch that is live, the
//!   signed actor's, and the signer's to act for;
//! * [`write_ceiling`]: the actor a mutation names may be written to.
//!
//! Both read the controller's own record through one small trait,
//! [`ledger::GateLedger`], which returns facts and no verdict. The rule is
//! here, once: `aegix-rpc-subscribers` implements the trait over Postgres for
//! the platform, and a controller with no database implements it over
//! whatever it keeps.
//!
//! # What this crate does not do
//!
//! It reads no environment: whether a binding is required
//! ([`aegix_config::dispatch_binding::Requirement`]) and whether the ceiling
//! is enforced are arguments, so the process that calls a gate says what it
//! runs under. It registers no metric: a refusal is returned to the caller,
//! which counts it, and written once to the `talos_audit` log target. It
//! links no database driver, no metrics registry and no engine, held by
//! structural check 109 (`scripts/lint-runtime-boundary.py`).

pub mod admission;
pub mod dispatch_binding;
pub mod ledger;
pub mod write_ceiling;

pub use ledger::{DispatchFacts, GateLedger};
