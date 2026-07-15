//! Atomic **ciphertext** commit for encrypted secrets-file rewrites.
//!
//! CLI-local (`pub(crate)`) first cut. **Do not** route plaintext document
//! serialization through this writer — temps may be orphaned on crash, and the
//! contract requires ciphertext / encrypted JSON only.
//!
//! # Contract
//!
//! - Temp file: unique `create_new` in the **same directory** as the target
//! - Content: ciphertext / encrypted inline JSON only (caller responsibility)
//! - Permissions: Unix fresh files `0600`; rewrites preserve existing mode
//! - Durability: `sync_all` temp before replace; parent-dir sync on Unix
//!   (errors propagate where supported)
//! - CAS: expected prior bytes re-read via a **fresh open** immediately before
//!   replace (bounded read: at most `expected.len() + 1`); mismatch fails loud
//! - Unix: atomic rename; create-new uses no-clobber persist
//! - Windows: `ReplaceFileW` for existing targets (preserves DACL/attributes);
//!   create-new uses no-clobber path
//!
//! Orphan temps are never trusted as state; randomized names only.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

use crate::error::{CliError, CliResult};

/// Options for an atomic ciphertext replace of `path` with `content`.
#[derive(Debug, Clone, Default)]
pub(crate) struct AtomicWriteOptions {
    /// When set, the on-disk target must still equal these bytes immediately
    /// before replace (CAS). Use the exact bytes loaded at classify/read time.
    ///
    /// `Some(empty)` means an empty file was loaded — if the path is missing at
    /// commit time, that is concurrent modification (not a free create).
    pub expected_prior_bytes: Option<Vec<u8>>,
    /// When true, refuse if `path` already exists (no-clobber commit).
    pub create_new: bool,
}

/// Test-only fault injection points for durability seams.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg(test)]
pub(crate) enum AtomicFault {
    /// Fail after temp create, before writing content.
    BeforeWrite,
    /// Fail after content write, before temp sync.
    AfterWriteBeforeSync,
    /// Fail after temp sync, before CAS/replace.
    AfterSyncBeforeReplace,
    /// Force CAS mismatch even when bytes match.
    ForceCasMismatch,
    /// Fail the replace step itself.
    ReplaceFail,
    /// Fail parent directory sync (Unix).
    DirSyncFail,
}

#[cfg(test)]
thread_local! {
    static TEST_FAULT: std::cell::Cell<Option<AtomicFault>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn inject_fault(fault: Option<AtomicFault>) {
    TEST_FAULT.with(|c| c.set(fault));
}

#[cfg(test)]
fn take_fault() -> Option<AtomicFault> {
    TEST_FAULT.with(|c| c.get())
}

/// Atomically write **ciphertext** `content` to `path`.
///
/// Callers must not pass plaintext secrets documents. Prefer
/// [`atomic_write_ciphertext`] as the named entry point.
pub(crate) fn atomic_write_ciphertext(
    path: &Path,
    content: &[u8],
    options: AtomicWriteOptions,
) -> CliResult<()> {
    atomic_write_bytes(path, content, options)
}

/// Backward-compatible name for [`atomic_write_ciphertext`].
pub(crate) fn atomic_write_bytes(
    path: &Path,
    content: &[u8],
    options: AtomicWriteOptions,
) -> CliResult<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if options.create_new && path.exists() {
        return Err(CliError::Message(format!(
            "refusing to create {}: path already exists",
            path.display()
        )));
    }

    // Unique temp in same directory (randomized; never predictable .tmp alone).
    let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(CliError::Io)?;

    apply_permissions(path, temp.as_file())?;

    #[cfg(test)]
    if take_fault() == Some(AtomicFault::BeforeWrite) {
        return Err(CliError::Message("fault: before write".into()));
    }

    temp.as_file_mut()
        .write_all(content)
        .map_err(CliError::Io)?;

    #[cfg(test)]
    if take_fault() == Some(AtomicFault::AfterWriteBeforeSync) {
        return Err(CliError::Message("fault: after write before sync".into()));
    }

    temp.as_file().sync_all().map_err(CliError::Io)?;

    #[cfg(test)]
    if take_fault() == Some(AtomicFault::AfterSyncBeforeReplace) {
        return Err(CliError::Message("fault: after sync before replace".into()));
    }

    // CAS: fresh open + bounded full-content compare (not a retained fd).
    if let Some(expected) = options.expected_prior_bytes.as_ref() {
        #[cfg(test)]
        if take_fault() == Some(AtomicFault::ForceCasMismatch) {
            return Err(CliError::ConcurrentModification {
                path: path.display().to_string(),
            });
        }

        if !path_matches_expected(path, expected)? {
            return Err(CliError::ConcurrentModification {
                path: path.display().to_string(),
            });
        }
    }

    #[cfg(test)]
    if take_fault() == Some(AtomicFault::ReplaceFail) {
        return Err(CliError::Message("fault: replace fail".into()));
    }

    commit_replace(temp, path, options.create_new)?;

    #[cfg(unix)]
    {
        #[cfg(test)]
        if take_fault() == Some(AtomicFault::DirSyncFail) {
            return Err(CliError::Message("fault: dir sync fail".into()));
        }
        // Parent directory fsync for rename durability — fail loud on error.
        let dir = File::open(parent).map_err(CliError::Io)?;
        dir.sync_all().map_err(CliError::Io)?;
    }

    Ok(())
}

fn apply_permissions(target: &Path, temp: &File) -> CliResult<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if target.exists() {
            let meta = fs::metadata(target).map_err(CliError::Io)?;
            temp.set_permissions(meta.permissions())
                .map_err(CliError::Io)?;
        } else {
            temp.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(CliError::Io)?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (target, temp);
        // Windows: fresh-file ACL inherits parent directory defaults (documented
        // residual). ReplaceFileW preserves target DACL on rewrite.
    }
    Ok(())
}

/// Fresh open + bounded compare: read at most `expected.len() + 1` bytes.
///
/// Missing path always fails (including when `expected` is empty — an empty
/// file was loaded and must still exist).
fn path_matches_expected(path: &Path, expected: &[u8]) -> CliResult<bool> {
    let mut file = match OpenOptions::new().read(true).open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(err) => return Err(CliError::Io(err)),
    };

    let mut buf = vec![0u8; expected.len().saturating_add(1)];
    let mut total = 0usize;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(err) => return Err(CliError::Io(err)),
        }
    }

    if total != expected.len() {
        return Ok(false);
    }
    Ok(&buf[..total] == expected)
}

fn commit_replace(temp: tempfile::NamedTempFile, path: &Path, create_new: bool) -> CliResult<()> {
    #[cfg(windows)]
    {
        if path.exists() {
            if create_new {
                return Err(CliError::Message(format!(
                    "refusing to create {}: path already exists",
                    path.display()
                )));
            }
            return windows_replace_file(temp, path);
        }
    }

    if create_new {
        // No-clobber: fail if a racing creator appeared after the early exists check.
        temp.persist_noclobber(path)
            .map_err(|e| CliError::Io(e.error))?;
    } else {
        // Unix atomic rename, or Windows create when target is absent.
        temp.persist(path).map_err(|e| CliError::Io(e.error))?;
    }
    Ok(())
}

#[cfg(windows)]
fn windows_replace_file(temp: tempfile::NamedTempFile, path: &Path) -> CliResult<()> {
    // Persist temp to a sibling path first so ReplaceFileW has a real source.
    let source = unique_sibling_path(path, ".seclusor-replace-src-")?;
    temp.persist(&source).map_err(|e| CliError::Io(e.error))?;

    let result = replace_file_w(&source, path);
    // Always try to clean the source temp; ignore cleanup errors.
    let _ = fs::remove_file(&source);
    result
}

#[cfg(windows)]
fn unique_sibling_path(path: &Path, prefix: &str) -> CliResult<std::path::PathBuf> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp = tempfile::Builder::new()
        .prefix(prefix)
        .tempfile_in(parent)
        .map_err(CliError::Io)?;
    let p = tmp.path().to_path_buf();
    drop(tmp);
    Ok(p)
}

/// Call `ReplaceFileW` to replace `target` with `source`, preserving attributes.
///
/// # Safety
///
/// Both paths must be valid Win32 paths owned by this process for the duration
/// of the call. `source` and `target` must exist. `REPLACEFILE_IGNORE_MERGE_ERRORS`
/// is **not** set — ACL merge failures fail loud.
#[cfg(windows)]
fn replace_file_w(source: &Path, target: &Path) -> CliResult<()> {
    use std::os::windows::ffi::OsStrExt;
    use std::ptr;

    #[link(name = "kernel32")]
    extern "system" {
        fn ReplaceFileW(
            lpReplacedFileName: *const u16,
            lpReplacementFileName: *const u16,
            lpBackupFileName: *const u16,
            dwReplaceFlags: u32,
            lpExclude: *mut core::ffi::c_void,
            lpReserved: *mut core::ffi::c_void,
        ) -> i32;
    }

    const REPLACEFILE_WRITE_THROUGH: u32 = 0x00000001;

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    let replaced = to_wide(target);
    let replacement = to_wide(source);

    // SAFETY: paths are NUL-terminated wide strings; no backup; flags exclude
    // IGNORE_MERGE_ERRORS so ACL failures surface. Pointers valid for call.
    let ok = unsafe {
        ReplaceFileW(
            replaced.as_ptr(),
            replacement.as_ptr(),
            ptr::null(),
            REPLACEFILE_WRITE_THROUGH,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };

    if ok == 0 {
        return Err(CliError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Diagnose orphan seclusor temps in `dir` on stderr (never trusted as state).
#[allow(dead_code)] // Available for encrypted commit handlers.
pub(crate) fn diagnose_orphan_temps(dir: &Path) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with(".seclusor-") {
            eprintln!(
                "warning: ignoring orphan temp file {} (not trusted as secrets state)",
                entry.path().display()
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    const SENTINEL: &str = "SECLUSOR_PLAINTEXT_SENTINEL_7f3a";

    #[test]
    fn atomic_write_replaces_and_preserves_content() {
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        let original = b"age-encryption.org/v1\nold";
        fs::write(&path, original).expect("seed");

        let next = b"age-encryption.org/v1\nnew";
        atomic_write_ciphertext(
            &path,
            next,
            AtomicWriteOptions {
                expected_prior_bytes: Some(original.to_vec()),
                create_new: false,
            },
        )
        .expect("atomic write");

        assert_eq!(fs::read(&path).expect("read"), next);
    }

    #[test]
    fn cas_refuses_concurrent_modification() {
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"v1").expect("seed");

        let err = atomic_write_ciphertext(
            &path,
            b"v2",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"stale".to_vec()),
                create_new: false,
            },
        )
        .expect_err("CAS must fail");
        assert!(matches!(err, CliError::ConcurrentModification { .. }));
        assert_eq!(fs::read(&path).expect("unchanged"), b"v1");
        assert!(!err.to_string().contains(SENTINEL));
        assert!(!format!("{err:?}").contains(SENTINEL));
    }

    #[test]
    fn cas_refuses_when_empty_loaded_file_vanishes() {
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("empty.age");
        // No file on disk, but CAS token says we loaded empty content.
        let err = atomic_write_ciphertext(
            &path,
            b"new",
            AtomicWriteOptions {
                expected_prior_bytes: Some(Vec::new()),
                create_new: false,
            },
        )
        .expect_err("vanished empty must CAS-fail");
        assert!(matches!(err, CliError::ConcurrentModification { .. }));
        assert!(!path.exists());
    }

    #[test]
    fn cas_refuses_when_file_grows_beyond_expected() {
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"abcdef").expect("seed");

        let err = atomic_write_ciphertext(
            &path,
            b"new",
            AtomicWriteOptions {
                // Expected shorter than on-disk — bounded read must detect growth.
                expected_prior_bytes: Some(b"abc".to_vec()),
                create_new: false,
            },
        )
        .expect_err("growth must CAS-fail");
        assert!(matches!(err, CliError::ConcurrentModification { .. }));
    }

    #[test]
    fn create_new_noclobber_when_target_exists() {
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new.age");
        fs::write(&path, b"existing").expect("seed");

        let err = atomic_write_ciphertext(
            &path,
            b"clobber-attempt",
            AtomicWriteOptions {
                expected_prior_bytes: None,
                create_new: true,
            },
        )
        .expect_err("must refuse existing");
        assert!(err.to_string().contains("already exists"));
        assert_eq!(fs::read(&path).unwrap(), b"existing");
    }

    #[test]
    fn force_cas_mismatch_fault() {
        inject_fault(Some(AtomicFault::ForceCasMismatch));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"v1").expect("seed");
        let err = atomic_write_ciphertext(
            &path,
            b"v2",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"v1".to_vec()),
                create_new: false,
            },
        )
        .expect_err("forced CAS");
        assert!(matches!(err, CliError::ConcurrentModification { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"v1");
        inject_fault(None);
    }

    #[test]
    fn fault_after_sync_before_replace_leaves_target() {
        inject_fault(Some(AtomicFault::AfterSyncBeforeReplace));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"original").expect("seed");
        let err = atomic_write_ciphertext(
            &path,
            b"new-ct",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"original".to_vec()),
                create_new: false,
            },
        )
        .expect_err("fault");
        assert!(err.to_string().contains("fault"));
        assert_eq!(fs::read(&path).unwrap(), b"original");
        inject_fault(None);
    }

    #[test]
    fn fault_replace_fail_leaves_target() {
        inject_fault(Some(AtomicFault::ReplaceFail));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"original").expect("seed");
        let _ = atomic_write_ciphertext(
            &path,
            b"new-ct",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"original".to_vec()),
                create_new: false,
            },
        )
        .expect_err("fault");
        assert_eq!(fs::read(&path).unwrap(), b"original");
        inject_fault(None);
    }

    #[cfg(unix)]
    #[test]
    fn fault_dir_sync_fail_surfaces() {
        inject_fault(Some(AtomicFault::DirSyncFail));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"original").expect("seed");
        // DirSyncFail is injected after successful replace — target may be new.
        let err = atomic_write_ciphertext(
            &path,
            b"new-ct",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"original".to_vec()),
                create_new: false,
            },
        )
        .expect_err("dir sync fault");
        assert!(err.to_string().contains("fault: dir sync"));
        inject_fault(None);
    }

    #[test]
    fn fault_before_write_leaves_target_intact() {
        inject_fault(Some(AtomicFault::BeforeWrite));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"original").expect("seed");

        let err = atomic_write_ciphertext(
            &path,
            SENTINEL.as_bytes(),
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"original".to_vec()),
                create_new: false,
            },
        )
        .expect_err("fault");
        assert!(err.to_string().contains("fault"));
        assert_eq!(fs::read(&path).expect("intact"), b"original");
        inject_fault(None);
    }

    #[test]
    fn fault_after_write_before_sync_leaves_target_intact() {
        inject_fault(Some(AtomicFault::AfterWriteBeforeSync));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"original").expect("seed");

        let _ = atomic_write_ciphertext(
            &path,
            b"new-ct",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"original".to_vec()),
                create_new: false,
            },
        )
        .expect_err("fault");
        assert_eq!(fs::read(&path).expect("intact"), b"original");
        inject_fault(None);
    }

    #[test]
    fn successful_write_with_ciphertext_leaves_no_sentinel() {
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("bundle.age");
        let ct = b"age-encryption.org/v1\n-> fake ciphertext body";
        fs::write(&path, b"old").expect("seed");
        atomic_write_ciphertext(
            &path,
            ct,
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"old".to_vec()),
                create_new: false,
            },
        )
        .expect("write");
        assert_no_sentinel_in_dir(dir.path());
        assert_eq!(fs::read(&path).unwrap(), ct);
    }

    #[test]
    fn diagnose_orphan_temps_does_not_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        fs::write(dir.path().join(".seclusor-orphan-test"), b"ct").expect("orphan");
        diagnose_orphan_temps(dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn rewrite_preserves_mode() {
        use std::os::unix::fs::PermissionsExt;
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secrets.age");
        fs::write(&path, b"v1").expect("seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("mode");

        atomic_write_ciphertext(
            &path,
            b"v2",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"v1".to_vec()),
                create_new: false,
            },
        )
        .expect("write");

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o640);
    }

    #[cfg(unix)]
    #[test]
    fn fresh_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("new.age");
        atomic_write_ciphertext(
            &path,
            b"age-encryption.org/v1\n",
            AtomicWriteOptions {
                expected_prior_bytes: None,
                create_new: true,
            },
        )
        .expect("create");
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    fn assert_no_sentinel_in_dir(dir: &Path) {
        for entry in fs::read_dir(dir).unwrap().flatten() {
            let data = fs::read(entry.path()).unwrap_or_default();
            assert!(
                !data
                    .windows(SENTINEL.len())
                    .any(|w| w == SENTINEL.as_bytes()),
                "sentinel found in {}",
                entry.path().display()
            );
        }
    }

    /// Native Windows behavior: `ReplaceFileW`, CAS, no-clobber, DACL posture.
    ///
    /// Runs on CI native-test Windows cells (`windows-latest`, `windows-latest-arm64-s`).
    #[cfg(windows)]
    mod windows_behavior {
        use super::*;
        use std::process::Command;

        /// Capture a stable ACL summary via `icacls` for DACL preservation checks.
        fn icacls_summary(path: &Path) -> String {
            let output = Command::new("icacls")
                .arg(path)
                .output()
                .expect("icacls must be available on Windows CI");
            assert!(
                output.status.success(),
                "icacls failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            // Normalize newlines; drop the success trailer line if present.
            String::from_utf8_lossy(&output.stdout)
                .lines()
                .filter(|line| !line.contains("Successfully processed"))
                .collect::<Vec<_>>()
                .join("\n")
        }

        #[test]
        fn replace_existing_preserves_dacl() {
            inject_fault(None);
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("secrets.age");
            fs::write(&path, b"v1").expect("seed");

            // Grant a distinctive ACE so preservation is observable.
            let grant = Command::new("icacls")
                .arg(&path)
                .arg("/grant")
                .arg("Users:(R)")
                .output()
                .expect("icacls grant");
            assert!(
                grant.status.success(),
                "grant failed: {}",
                String::from_utf8_lossy(&grant.stderr)
            );

            let dacl_before = icacls_summary(&path);

            atomic_write_ciphertext(
                &path,
                b"v2-ciphertext",
                AtomicWriteOptions {
                    expected_prior_bytes: Some(b"v1".to_vec()),
                    create_new: false,
                },
            )
            .expect("ReplaceFileW path");

            assert_eq!(fs::read(&path).unwrap(), b"v2-ciphertext");
            let dacl_after = icacls_summary(&path);
            assert_eq!(
                dacl_before, dacl_after,
                "ReplaceFileW must preserve target DACL\nbefore:\n{dacl_before}\nafter:\n{dacl_after}"
            );
        }

        #[test]
        fn replace_existing_with_cas_success_and_failure() {
            inject_fault(None);
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("secrets.age");
            fs::write(&path, b"original-ct").expect("seed");

            atomic_write_ciphertext(
                &path,
                b"new-ct",
                AtomicWriteOptions {
                    expected_prior_bytes: Some(b"original-ct".to_vec()),
                    create_new: false,
                },
            )
            .expect("CAS match replace");
            assert_eq!(fs::read(&path).unwrap(), b"new-ct");

            let err = atomic_write_ciphertext(
                &path,
                b"other",
                AtomicWriteOptions {
                    expected_prior_bytes: Some(b"stale".to_vec()),
                    create_new: false,
                },
            )
            .expect_err("CAS mismatch");
            assert!(matches!(err, CliError::ConcurrentModification { .. }));
            assert_eq!(fs::read(&path).unwrap(), b"new-ct");
        }

        #[test]
        fn create_new_noclobber_on_existing() {
            inject_fault(None);
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("new.age");
            fs::write(&path, b"existing").expect("seed");
            let err = atomic_write_ciphertext(
                &path,
                b"clobber",
                AtomicWriteOptions {
                    expected_prior_bytes: None,
                    create_new: true,
                },
            )
            .expect_err("noclobber");
            assert!(err.to_string().contains("already exists"));
            assert_eq!(fs::read(&path).unwrap(), b"existing");
        }

        #[test]
        fn create_new_when_absent() {
            inject_fault(None);
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("fresh.age");
            atomic_write_ciphertext(
                &path,
                b"age-encryption.org/v1\n",
                AtomicWriteOptions {
                    expected_prior_bytes: None,
                    create_new: true,
                },
            )
            .expect("create");
            assert_eq!(fs::read(&path).unwrap(), b"age-encryption.org/v1\n");
        }

        #[test]
        fn orphan_diagnose_does_not_trust_temps() {
            let dir = tempfile::tempdir().expect("tempdir");
            fs::write(dir.path().join(".seclusor-orphan"), b"ct").expect("orphan");
            diagnose_orphan_temps(dir.path());
            assert!(dir.path().join(".seclusor-orphan").exists());
        }
    }
}
