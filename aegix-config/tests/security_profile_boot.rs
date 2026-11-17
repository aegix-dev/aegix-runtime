//! `enforce_at_boot`, from the process ENVIRONMENT (2026-11-06).
//!
//! The library's unit tests drive the pure verdicts and never touch the
//! environment, so nothing there shows that `enforce_at_boot` reads the
//! development-only settings at all. This binary does: its own process, so the
//! variables it sets are seen by no other test, and ONE test function, so no
//! two legs race on the environment.

use aegix_config::security_profile::{enforce_at_boot, Process};

const VARS: [&str; 6] = [
    "RUST_ENV",
    "AEGIX_SECURITY_PROFILE",
    "WORKER_ALLOW_PRIVATE_HOST_TARGETS",
    "WASM_ALLOW_INSECURE_HTTP",
    "WASM_RESULT_CACHE_TTL_SECS",
    "AEGIX_SQL_PERMISSIVE_EMPTY_ALLOWLIST",
];

fn clear() {
    for v in VARS {
        std::env::remove_var(v);
    }
}

/// Mutation target: an `enforce_at_boot` that did not ask
/// `development_only_verdict` boots every enforcing leg below.
#[test]
fn an_enforcing_profile_refuses_a_development_only_setting_at_boot() {
    for process in [Process::Worker, Process::Controller] {
        for (name, value) in [
            ("WORKER_ALLOW_PRIVATE_HOST_TARGETS", "true"),
            ("WASM_ALLOW_INSECURE_HTTP", "1"),
            ("WASM_RESULT_CACHE_TTL_SECS", "300"),
        ] {
            // `RUST_ENV=staging` defaults to `hardened`: the compose
            // production shape (review 2026-11-06, finding 9).
            for profile in [None, Some("transitional")] {
                clear();
                std::env::set_var("RUST_ENV", "staging");
                if let Some(p) = profile {
                    std::env::set_var("AEGIX_SECURITY_PROFILE", p);
                }
                std::env::set_var(name, value);
                let err = enforce_at_boot(process).expect_err(&format!(
                    "{process:?} booted under {profile:?} with {name}={value}"
                ));
                assert!(err.contains(name), "{err}");
                assert!(err.contains("development-only"), "{err}");
            }

            // `development` reads it.
            clear();
            std::env::set_var(name, value);
            assert!(
                enforce_at_boot(process).is_ok(),
                "{process:?} refused {name} under development"
            );
        }

        // Values that turn nothing on are not refused.
        clear();
        std::env::set_var("RUST_ENV", "staging");
        std::env::set_var("WORKER_ALLOW_PRIVATE_HOST_TARGETS", "false");
        std::env::set_var("WASM_RESULT_CACHE_TTL_SECS", "0");
        assert!(enforce_at_boot(process).is_ok(), "{process:?}");

        // The permissive SQL allowlist is an acknowledgement: `hardened`
        // refuses it, `transitional` honours it.
        clear();
        std::env::set_var("RUST_ENV", "staging");
        std::env::set_var("AEGIX_SQL_PERMISSIVE_EMPTY_ALLOWLIST", "1");
        let err = enforce_at_boot(process).expect_err("hardened honoured the SQL acknowledgement");
        assert!(
            err.contains("AEGIX_SQL_PERMISSIVE_EMPTY_ALLOWLIST"),
            "{err}"
        );
        std::env::set_var("AEGIX_SECURITY_PROFILE", "transitional");
        assert!(enforce_at_boot(process).is_ok(), "{process:?}");
    }
    clear();
}
