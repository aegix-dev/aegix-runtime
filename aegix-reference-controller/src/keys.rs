//! Which keys this controller signs with and which it believes.
//!
//! There are two postures and the configuration names one. Nothing here
//! chooses for the operator, and a controller never runs in both.
//!
//! * [`Posture::FleetKey`] is the development posture. The controller and
//!   every worker hold one symmetric key (`WORKER_SHARED_KEY`). The
//!   controller signs dispatches with it, encrypts a job's secrets under it,
//!   and believes a result or a data call signed with it. A worker that holds
//!   the key can therefore sign as any worker, and the dispatch-binding gate
//!   is what still bounds it: a data call must name a job this controller is
//!   running for the actor it names. The posture is refused where
//!   `RUST_ENV` says the deployment faces users.
//!
//! * [`Posture::WorkerIdentity`] is the posture to deploy. The controller
//!   signs with its own Ed25519 key, and believes only a worker whose public
//!   key the operator listed (`AEGIX_WORKER_PUBLIC_KEYS`). The fleet key is
//!   never loaded and never registered, so a request signed with it fails at
//!   admission. A job's secrets are sealed to the one worker that claims the
//!   job, and only that worker's result is taken.

use aegix_workflow_engine_core::{WorkerKeyRing, WorkerSharedKey};
use aegix_workflow_job_protocol::{DispatchSigner, DispatchSigningKey};
use std::sync::Arc;

/// The posture's name in the configuration file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Posture {
    FleetKey,
    WorkerIdentity,
}

impl Posture {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::FleetKey => "fleet-key",
            Self::WorkerIdentity => "worker-identity",
        }
    }
}

/// The keys of one posture.
pub struct Keys {
    posture: Posture,
    signer: DispatchSigner,
    /// The ring a fleet-key result is verified against. Under
    /// `WorkerIdentity` it is one random key that nothing else holds: a
    /// fleet-key result is refused before the ring is read, and if that
    /// refusal were ever lost the result would still match no key.
    result_ring: WorkerKeyRing,
    controller_key: Option<Arc<DispatchSigningKey>>,
}

// Never render key material.
impl std::fmt::Debug for Keys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Keys")
            .field("posture", &self.posture)
            .finish_non_exhaustive()
    }
}

impl Keys {
    /// The development posture over `ring`.
    #[must_use]
    pub fn fleet_key(ring: WorkerKeyRing) -> Self {
        let signer = DispatchSigner::Hmac(Arc::new(ring.signing_key().as_bytes().to_vec()));
        Self {
            posture: Posture::FleetKey,
            signer,
            result_ring: ring,
            controller_key: None,
        }
    }

    /// The deployed posture, signing with `controller_key`.
    #[must_use]
    pub fn worker_identity(controller_key: Arc<DispatchSigningKey>) -> Self {
        let unheld = WorkerSharedKey::new(aegix_random::bytes::<32>().to_vec());
        Self {
            posture: Posture::WorkerIdentity,
            signer: DispatchSigner::Ed25519(controller_key.clone()),
            result_ring: WorkerKeyRing::single(unheld),
            controller_key: Some(controller_key),
        }
    }

    /// Read the posture's keys from the environment. `rust_env` is the
    /// process's `RUST_ENV`, an argument so the refusal below is testable.
    ///
    /// * `fleet-key`: `WORKER_SHARED_KEY` (or `WORKER_SHARED_KEY_FILE`), and
    ///   `WORKER_SHARED_KEY_PREVIOUS` during a rotation.
    /// * `worker-identity`: `AEGIX_CONTROLLER_SIGNING_KEY` and at least one
    ///   worker in `AEGIX_WORKER_PUBLIC_KEYS`.
    pub fn load(posture: Posture, rust_env: Option<&str>) -> Result<Self, String> {
        match posture {
            Posture::FleetKey => {
                if aegix_auth_types::hardening_required_for(rust_env) {
                    return Err(
                        "posture `fleet-key` is for development: every worker holds the one key \
                         and can sign as any other. RUST_ENV names a deployment that faces users; \
                         use posture `worker-identity`."
                            .to_string(),
                    );
                }
                let ring = aegix_workflow_job_protocol::load_worker_key_ring()?;
                Ok(Self::fleet_key(ring))
            }
            Posture::WorkerIdentity => {
                let key = controller_signing_key()?;
                if aegix_workflow_job_protocol::static_worker_ring().is_empty() {
                    return Err(
                        "posture `worker-identity` needs at least one worker in \
                         AEGIX_WORKER_PUBLIC_KEYS (`<worker id>=<public key hex>`, comma \
                         separated): with none listed no worker's result or data call is believed"
                            .to_string(),
                    );
                }
                Ok(Self::worker_identity(key))
            }
        }
    }

    /// Make this posture the process's: under `FleetKey`, register the fleet
    /// key as one a data call may be signed with. Under `WorkerIdentity`
    /// nothing is registered, which is what refuses a fleet-key data call.
    /// Call once, before the data plane is served.
    pub fn install(&self) {
        if self.posture == Posture::FleetKey {
            let previous = self
                .result_ring
                .verify_keys()
                .iter()
                .skip(1)
                .map(|k| Arc::new(k.as_bytes().to_vec()))
                .collect();
            aegix_rpc_protocol::rpc_auth::register_hmac_key_ring(
                Arc::new(self.result_ring.signing_key().as_bytes().to_vec()),
                previous,
            );
        }
    }

    #[must_use]
    pub fn posture(&self) -> Posture {
        self.posture
    }

    #[must_use]
    pub fn signer(&self) -> &DispatchSigner {
        &self.signer
    }

    /// The ring a fleet-key result is checked against.
    #[must_use]
    pub fn result_ring(&self) -> &WorkerKeyRing {
        &self.result_ring
    }

    /// Whether a result signed with the fleet key is believed.
    #[must_use]
    pub fn accepts_fleet_key_results(&self) -> bool {
        self.posture == Posture::FleetKey
    }

    /// The key a job's secrets are encrypted under when they travel in the
    /// dispatch itself. `None` under `WorkerIdentity`, where they never do.
    #[must_use]
    pub fn inline_envelope_key(&self) -> Option<&[u8]> {
        (self.posture == Posture::FleetKey).then(|| self.result_ring.signing_key().as_bytes())
    }

    /// The controller's own key, which signs the sealed reply to a worker's
    /// claim. `None` under `FleetKey`.
    #[must_use]
    pub fn controller_key(&self) -> Option<&Arc<DispatchSigningKey>> {
        self.controller_key.as_ref()
    }
}

/// The file form of `AEGIX_CONTROLLER_SIGNING_KEY`: a path to the seed.
pub const CONTROLLER_SIGNING_KEY_FILE_ENV: &str = "AEGIX_CONTROLLER_SIGNING_KEY_FILE";

/// The controller's Ed25519 seed: from the file `AEGIX_CONTROLLER_SIGNING_KEY_FILE`
/// names (which only its owner may read), else from
/// `AEGIX_CONTROLLER_SIGNING_KEY`.
fn controller_signing_key() -> Result<Arc<DispatchSigningKey>, String> {
    let from_file = std::env::var(CONTROLLER_SIGNING_KEY_FILE_ENV)
        .ok()
        .filter(|p| !p.trim().is_empty());
    if let Some(path) = from_file {
        let seed = crate::config::read_private_file(
            "controller signing key",
            std::path::Path::new(path.trim()),
        )?;
        return aegix_workflow_job_protocol::parse_ed25519_signing_key_hex(&seed).map(Arc::new);
    }
    aegix_workflow_job_protocol::configured_controller_signing_key().ok_or_else(|| {
        format!(
            "posture `worker-identity` needs the controller's Ed25519 seed: set \
             {CONTROLLER_SIGNING_KEY_FILE_ENV} to its file, or AEGIX_CONTROLLER_SIGNING_KEY to \
             its 64 hex characters (`aegix-reference-controller keygen` writes one)"
        )
    })
}

#[cfg(test)]
pub(crate) mod testing {
    use super::*;

    /// The fleet key every test in this crate shares. Registration is
    /// process-wide, so there is one.
    pub(crate) const FLEET_KEY: [u8; 32] = [0x5a; 32];

    pub(crate) fn fleet_keys() -> Keys {
        let keys = Keys::fleet_key(WorkerKeyRing::single(WorkerSharedKey::new(
            FLEET_KEY.to_vec(),
        )));
        keys.install();
        keys
    }

    pub(crate) fn identity_keys() -> (Keys, Arc<DispatchSigningKey>) {
        let key = Arc::new(aegix_workflow_job_protocol::generate_dispatch_signing_key());
        (Keys::worker_identity(key.clone()), key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fleet_key_posture_is_refused_where_the_deployment_faces_users() {
        for env in ["production", "staging", "prod", "anything-else"] {
            let err = Keys::load(Posture::FleetKey, Some(env)).expect_err(env);
            assert!(err.contains("worker-identity"), "{env}: {err}");
        }
    }

    #[test]
    fn worker_identity_holds_no_fleet_key_and_believes_no_fleet_result() {
        let (keys, _) = testing::identity_keys();
        assert!(!keys.accepts_fleet_key_results());
        assert!(keys.inline_envelope_key().is_none());
        assert!(keys.controller_key().is_some());
        assert_eq!(keys.signer().scheme(), 1);
        // The stand-in ring is random per controller: two never agree.
        let (other, _) = testing::identity_keys();
        assert_ne!(
            keys.result_ring().signing_key().as_bytes(),
            other.result_ring().signing_key().as_bytes()
        );
    }

    #[test]
    fn the_fleet_key_posture_signs_seals_and_verifies_with_the_one_key() {
        let keys = testing::fleet_keys();
        assert!(keys.accepts_fleet_key_results());
        assert_eq!(keys.inline_envelope_key(), Some(&testing::FLEET_KEY[..]));
        assert!(keys.controller_key().is_none());
        assert_eq!(keys.signer().scheme(), 0);
    }

    #[test]
    fn a_posture_is_named_in_kebab_case() {
        for posture in [Posture::FleetKey, Posture::WorkerIdentity] {
            let text = serde_json::to_string(&posture).expect("serialise");
            assert_eq!(text, format!("\"{}\"", posture.as_str()));
        }
    }
}
