//! A small controller for the Aegix runtime.
//!
//! An Aegix worker runs a WebAssembly module and holds no credentials: it is
//! handed a signed job, and everything the module touches that belongs to
//! somebody (a secret, an actor's memory) is asked of the controller that
//! signed the job. This crate is the smallest controller that keeps that
//! promise:
//!
//! * it holds the secrets, and hands a job only the ones its module is
//!   granted, encrypted to the job or sealed to the worker that claims it
//!   ([`dispatch`]);
//! * it signs each dispatch, with a deadline after which a worker may not
//!   start it ([`dispatch`]);
//! * it answers a worker's actor-memory calls only when the call names a job
//!   it is running for that actor, and lets a module write only where the
//!   actor's ceiling allows ([`data_plane`], [`memory`]);
//! * it takes as a job's result only what a worker it believes signed for
//!   that job ([`dispatch::accept_result`]).
//!
//! The rules themselves are not here. Admission and the two gates are
//! `aegix-rpc-gates`; the signatures, the envelope and the result checks are
//! `aegix-workflow-job-protocol`; the claim responder is
//! `aegix-envelope-seal`. The platform's controller calls the same
//! functions over Postgres. This crate supplies a record held in memory
//! ([`ledger`]) and the order things happen in ([`serve`]).
//!
//! # What it is not
//!
//! Its record is in memory: a restart forgets every job and every memory
//! value not in the configuration. It runs one module per dispatch, with no
//! workflow, no retry and no schedule. It serves actor memory and no other
//! data call. It delivers no model-provider key. It is one process: there is
//! no second replica to share a replay record with. It links no database
//! driver, no metrics registry, no workflow engine and no API server, which
//! structural check 109 holds.

pub mod config;
pub mod control;
pub mod counters;
pub mod data_plane;
pub mod dispatch;
pub mod keys;
pub mod ledger;
pub mod memory;
pub mod serve;
