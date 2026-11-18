//! Reading a build's output back into the controller.
//!
//! The sandboxed build writes into directories the controller then reads
//! from — the workspace and the per-user target cache, both mounted
//! read-write into the container. Whatever is at the artifact's path is
//! therefore the build's choice, not ours: a regular file of any size, a
//! symlink to `/dev/zero`, a FIFO. A plain `fs::read` follows the link and
//! reads until memory runs out, and the size check that follows it never runs.
//!
//! [`read_artifact`] is the one way an artifact is read: it stays inside the
//! directories the build was given, does not follow a symlink at the final
//! component, takes only a regular file, refuses on the opened file's size
//! BEFORE reading a byte, and reads at most one byte past the cap whatever the
//! file does afterwards.

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};

/// Open `path` for reading without following a symlink at its final
/// component.
fn open_nofollow(path: &Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK so opening a FIFO with no writer returns instead of
        // hanging; it has no effect on the regular file this goes on to
        // require.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(not(unix))]
    if !std::fs::symlink_metadata(path)?.file_type().is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    options.open(path)
}

/// Open `path` as a regular file inside one of `roots`.
///
/// Containment is checked on the canonical path, so a symlinked PARENT
/// directory cannot lead outside the build's directories either; the final
/// component is covered by [`open_nofollow`].
fn open_contained(path: &Path, roots: &[&Path]) -> Result<std::fs::File> {
    let canonical_parent = path
        .parent()
        .and_then(|p| p.canonicalize().ok())
        .context("build artifact has no resolvable parent directory")?;
    let contained = roots.iter().any(|root| {
        root.canonicalize()
            .map(|r| canonical_parent.starts_with(r))
            .unwrap_or(false)
    });
    if !contained {
        bail!("build artifact path is outside the build's own directories");
    }
    let file_name = path
        .file_name()
        .context("build artifact has no file name")?;
    let file = open_nofollow(&canonical_parent.join(file_name))
        .context("build artifact could not be opened as a regular file")?;
    if !file.metadata()?.file_type().is_file() {
        bail!("build artifact is not a regular file");
    }
    Ok(file)
}

/// Read the artifact at `path`, which must be a regular file under one of
/// `roots` and at most `cap` bytes. Blocking; see [`read_artifact`].
pub(crate) fn read_artifact_blocking(path: &Path, roots: &[&Path], cap: usize) -> Result<Vec<u8>> {
    let file = open_contained(path, roots)?;
    let len = file.metadata()?.len();
    if len > cap as u64 {
        bail!("Compiled component is {len} bytes, over the {cap}-byte limit for this language");
    }
    // The size above is a snapshot; the build may still hold the file open.
    // `take` makes the cap hold regardless of what the file grows to.
    let mut bytes = Vec::with_capacity(len as usize);
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        bail!("Compiled component grew past the {cap}-byte limit for this language while read");
    }
    Ok(bytes)
}

/// [`read_artifact_blocking`] off the async executor.
pub(crate) async fn read_artifact(
    path: PathBuf,
    roots: Vec<PathBuf>,
    cap: usize,
) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let roots: Vec<&Path> = roots.iter().map(PathBuf::as_path).collect();
        read_artifact_blocking(&path, &roots, cap)
    })
    .await
    .context("build artifact read task did not complete")?
}

/// Whether the file at `path` (a regular file under `roots`) starts with the
/// component-model magic. Reads eight bytes.
pub(crate) fn has_component_magic(path: &Path, roots: &[&Path]) -> bool {
    let Ok(mut file) = open_contained(path, roots) else {
        return false;
    };
    let mut buf = [0u8; 8];
    matches!(
        file.read(&mut buf),
        Ok(n) if n >= 8 && &buf[0..4] == b"\0asm" && buf[4] == 0x0d
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMPONENT: &[u8] = b"\0asm\x0d\0\x01\0rest-of-the-component";

    fn dir_with(name: &str, bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).expect("write");
        (dir, path)
    }

    #[test]
    fn a_regular_file_within_the_cap_is_read_whole() {
        let (dir, path) = dir_with("module.wasm", COMPONENT);
        let bytes = read_artifact_blocking(&path, &[dir.path()], 1024).expect("read");
        assert_eq!(bytes, COMPONENT);
        assert!(has_component_magic(&path, &[dir.path()]));
    }

    #[test]
    fn a_file_over_the_cap_is_refused_on_its_size() {
        let (dir, path) = dir_with("module.wasm", &vec![0u8; 4097]);
        let err = read_artifact_blocking(&path, &[dir.path()], 4096).expect_err("over cap");
        assert!(
            err.to_string().contains("over the 4096-byte limit"),
            "{err}"
        );
        // Exactly the cap is accepted.
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        assert_eq!(
            read_artifact_blocking(&path, &[dir.path()], 4096)
                .unwrap()
                .len(),
            4096
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_is_not_followed_even_to_a_file_inside_the_root() {
        let (dir, real) = dir_with("real.wasm", COMPONENT);
        let link = dir.path().join("module.wasm");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert!(read_artifact_blocking(&link, &[dir.path()], 1024).is_err());
        assert!(!has_component_magic(&link, &[dir.path()]));
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_an_endless_device_is_refused_without_reading_it() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("module.wasm");
        std::os::unix::fs::symlink("/dev/zero", &link).unwrap();
        // Returns at all: a followed link would read until memory ran out.
        assert!(read_artifact_blocking(&link, &[dir.path()], 1024).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_parent_directory_cannot_lead_outside_the_roots() {
        let (outside, _file) = dir_with("module.wasm", COMPONENT);
        let root = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), root.path().join("release")).unwrap();
        let through_link = root.path().join("release").join("module.wasm");
        let err = read_artifact_blocking(&through_link, &[root.path()], 1024).expect_err("escaped");
        assert!(err.to_string().contains("outside"), "{err}");
    }

    #[test]
    fn a_path_outside_every_root_is_refused() {
        let (_elsewhere, path) = dir_with("module.wasm", COMPONENT);
        let root = tempfile::tempdir().unwrap();
        assert!(read_artifact_blocking(&path, &[root.path()], 1024).is_err());
        assert!(!has_component_magic(&path, &[root.path()]));
    }

    #[test]
    fn a_directory_and_a_missing_file_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("module.wasm")).unwrap();
        assert!(read_artifact_blocking(&dir.path().join("module.wasm"), &[dir.path()], 8).is_err());
        assert!(read_artifact_blocking(&dir.path().join("absent.wasm"), &[dir.path()], 8).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("module.wasm");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !made {
            return; // no mkfifo, or a filesystem without FIFO support
        }
        assert!(read_artifact_blocking(&fifo, &[dir.path()], 8).is_err());
    }

    #[tokio::test]
    async fn the_async_wrapper_reads_the_same_bytes() {
        let (dir, path) = dir_with("module.wasm", COMPONENT);
        let bytes = read_artifact(path, vec![dir.path().to_path_buf()], 1024)
            .await
            .expect("read");
        assert_eq!(bytes, COMPONENT);
    }
}
