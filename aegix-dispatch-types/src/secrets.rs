//! The two aliases a resolved secret travels under.

use std::collections::HashMap;

/// Type-erased error returned across a trait boundary of this data model
/// (a secrets resolver, a [`SecretEnvelope`](crate::SecretEnvelope), a
/// store).
///
/// The trait is agnostic about the concrete error type an implementation
/// uses — a boxed `std::error::Error` lets impls propagate their own
/// error types (`sqlx::Error`, OAuth errors, etc.) without the trait
/// crate having to know about them.
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// A resolved secret map: path → plaintext value, each value wiped from
/// memory when it is dropped (security review 2026-10-14, C-10). The map
/// travels from the store through the resolver and the dispatch
/// pipeline to the envelope encrypt without a plain `String` copy.
pub type SecretMap = HashMap<String, zeroize::Zeroizing<String>>;
