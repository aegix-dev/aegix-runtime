#[cfg(test)]
// `module_inception` — file-named-after-its-mod is conventional for
// our `*_tests.rs` companion files.
#[allow(clippy::module_inception)]
mod tests {
    use crate::provider::{SecretProvider, SlotHandle};
    use crate::AegixVaultProvider;
    use crate::AuditingProvider;
    use std::collections::HashMap;

    // A simple mock provider for testing the AuditingProvider wrapper
    struct MockProvider {
        resolved: HashMap<String, String>,
    }

    #[async_trait::async_trait]
    impl SecretProvider for MockProvider {
        async fn resolve(
            &self,
            path: &str,
            _execution_id: uuid::Uuid,
        ) -> anyhow::Result<SlotHandle> {
            if self.resolved.contains_key(path) {
                Ok(SlotHandle(1))
            } else {
                Err(anyhow::anyhow!("not found"))
            }
        }

        fn into_auth_header(
            &self,
            _handle: SlotHandle,
            _header_name: &str,
        ) -> anyhow::Result<zeroize::Zeroizing<String>> {
            Ok(zeroize::Zeroizing::new("Bearer test-token".to_string()))
        }

        fn sign(&self, _handle: SlotHandle, _payload: &[u8]) -> anyhow::Result<Vec<u8>> {
            Ok(vec![1, 2, 3, 4])
        }

        fn decrypt(
            &self,
            _handle: SlotHandle,
            _ciphertext: &[u8],
        ) -> anyhow::Result<zeroize::Zeroizing<Vec<u8>>> {
            Ok(zeroize::Zeroizing::new(vec![5, 6, 7, 8]))
        }

        async fn release(&self, _handle: SlotHandle) -> anyhow::Result<()> {
            Ok(())
        }

        async fn health_check(&self) -> anyhow::Result<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn auditing_provider_passes_through_resolve() {
        let mut map = HashMap::new();
        map.insert("test/key".to_string(), "secret".to_string());

        let inner = MockProvider { resolved: map };
        let provider = AuditingProvider::new(inner);

        let handle = provider
            .resolve("test/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        assert_eq!(handle.0, 1);
    }

    /// What this test binary has logged, for the tests that read their own
    /// lines.
    ///
    /// One capturing subscriber serves the whole binary, installed on first
    /// use as the process's default. A subscriber a test sets for its own
    /// thread (`tracing::subscriber::set_default`) loses lines: `tracing`
    /// decides once, for the process, whether a log statement has any
    /// listener, and while one subscriber is registered it asks the thread
    /// that reached the statement first. From a neighbour's thread, which has
    /// none, the answer is "never", and the capturing test then sees nothing
    /// from that statement. Under `cargo test` every test here shares one
    /// process, and that lost the `secret.resolve` line in 153 runs of 400 at
    /// four threads (2026-11-18,
    /// `docs/engineering-log/packages/2026-11-18-public-ci-second-run.md`).
    #[derive(Clone, Default)]
    struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for LogCapture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCapture;
        fn make_writer(&'a self) -> LogCapture {
            self.clone()
        }
    }

    impl LogCapture {
        /// The lines logged so far that contain `marker`: something only the
        /// calling test wrote, so a neighbour's lines are not read as its own.
        fn lines_naming(&self, marker: &str) -> Vec<String> {
            let bytes = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            String::from_utf8_lossy(&bytes)
                .lines()
                .filter(|line| line.contains(marker))
                .map(str::to_owned)
                .collect()
        }
    }

    fn log_capture() -> &'static LogCapture {
        static CAPTURE: std::sync::OnceLock<LogCapture> = std::sync::OnceLock::new();
        CAPTURE.get_or_init(|| {
            let capture = LogCapture::default();
            let subscriber = tracing_subscriber::fmt()
                .with_writer(capture.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::INFO)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .expect("this binary's tests install one subscriber, and it is this one");
            // A statement another thread reached while the subscriber was
            // being installed was told nothing listens. Ask again, now that
            // one does.
            tracing::callsite::rebuild_interest_cache();
            capture
        })
    }

    /// The decorator's `secret.resolve` / `secret.resolve.failed` lines fire on
    /// every secret a module resolves, and an OAuth path carries the account's
    /// provider key — for gmail, the user's email — in its fourth segment.
    /// Drive the REAL decorator under the binary's capturing subscriber and
    /// read the lines it wrote: the message and the correlation token must be
    /// there, the address must not. (Check 91 is the textual gate; this is
    /// the half that proves the rendered field, not the named function.)
    #[tokio::test]
    async fn resolve_log_lines_carry_the_hashed_provider_key_not_the_email() {
        let log = log_capture();
        // Both calls carry this id, and nothing else in the binary does: it
        // is how this test finds its own lines among its neighbours'.
        let execution_id = uuid::Uuid::new_v4();

        let uid = "11111111-2222-3333-4444-555555555555";
        let ok_path = format!("oauth/gmail/{uid}/alice@example.com/access_token");
        let mut map = HashMap::new();
        map.insert(ok_path.clone(), "secret".to_string());
        let provider = AuditingProvider::new(MockProvider { resolved: map });

        provider.resolve(&ok_path, execution_id).await.unwrap();
        let missing = format!("oauth/gmail/{uid}/bob@example.com/refresh_token");
        assert!(provider.resolve(&missing, execution_id).await.is_err());

        let lines = log.lines_naming(&execution_id.to_string());
        assert_eq!(
            lines.len(),
            3,
            "a line for each resolve and one for the failure: {lines:#?}"
        );
        let out = lines.join("\n");
        assert!(out.contains("secret.resolve"), "{out}");
        assert!(out.contains("secret.resolve.failed"), "{out}");
        assert!(out.contains("key_path="), "field is `key_path`: {out}");
        assert!(!out.contains("alice"), "email leaked into the log: {out}");
        assert!(
            !out.contains("bob"),
            "email leaked into the failure log: {out}"
        );
        assert!(!out.contains('@'), "an address survived redaction: {out}");
        let token =
            aegix_workflow_job_protocol::redact_oauth_provider_key_for_log("alice@example.com");
        assert!(
            out.contains(&token),
            "correlation token {token} absent: {out}"
        );
        assert!(
            out.contains(&format!("oauth/gmail/{uid}/")),
            "provider + user id stay visible: {out}"
        );
    }

    #[tokio::test]
    async fn auditing_provider_passes_through_resolve_error() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        let result = provider.resolve("unknown/key", uuid::Uuid::new_v4()).await;
        assert!(result.is_err());
    }

    #[test]
    fn auditing_provider_passes_through_auth_header() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        let header = provider
            .into_auth_header(SlotHandle(1), "Authorization")
            .unwrap();
        assert_eq!(header.as_str(), "Bearer test-token");
    }

    #[test]
    fn auditing_provider_passes_through_sign() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        let sig = provider.sign(SlotHandle(1), b"payload").unwrap();
        assert_eq!(sig, vec![1, 2, 3, 4]);
    }

    #[test]
    fn auditing_provider_passes_through_decrypt() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        let plaintext = provider.decrypt(SlotHandle(1), b"ciphertext").unwrap();
        assert_eq!(plaintext.as_slice(), &[5u8, 6, 7, 8]);
    }

    #[tokio::test]
    async fn auditing_provider_passes_through_release() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        // Should not panic
        provider.release(SlotHandle(1)).await.unwrap();
    }

    #[tokio::test]
    async fn auditing_provider_passes_through_health_check() {
        let inner = MockProvider {
            resolved: HashMap::new(),
        };
        let provider = AuditingProvider::new(inner);

        provider.health_check().await.unwrap();
    }

    #[tokio::test]
    async fn auditing_provider_with_talos_vault_integration() {
        // Integration test: wrap an actual AegixVaultProvider
        let mut map = HashMap::new();
        map.insert(
            "vault/key".to_string(),
            zeroize::Zeroizing::new("my-secret".to_string()),
        );

        let inner = AegixVaultProvider::from_resolved(map);
        let provider = AuditingProvider::new(inner);

        let handle = provider
            .resolve("vault/key", uuid::Uuid::new_v4())
            .await
            .unwrap();
        let value = provider.into_auth_header(handle, "X-Api-Key").unwrap();
        assert_eq!(value.as_str(), "my-secret");

        // Sign should work
        let sig = provider.sign(handle, b"data").unwrap();
        assert!(!sig.is_empty());

        // Release should work
        provider.release(handle).await.unwrap();
    }
}
