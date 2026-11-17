//! Atomic commits for ciphertext and integrity-sensitive public data.
//!
//! CLI-local (`pub(crate)`) first cut. Callers must choose the named entry point
//! matching the data class. **Do not** route plaintext secrets through the
//! public-data writer.
//!
//! # Contract
//!
//! - Temp file: unique `create_new` in the **same directory** as the target
//! - Content: ciphertext/encrypted JSON or explicitly public data
//! - Permissions: Unix fresh ciphertext `0600`; fresh public data `0644`
//!   respecting umask; rewrites preserve existing mode
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

use zeroize::Zeroizing;

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

/// Snapshot of an existing output target captured before a `--force` or
/// in-place private ciphertext replace.
#[derive(Debug, Clone)]
pub(crate) struct PrivateCiphertextPriorSnapshot {
    pub bytes: Zeroizing<Vec<u8>>,
    #[cfg(unix)]
    pub identity: (u64, u64, u32),
    #[cfg(windows)]
    pub file_id: (u64, u64),
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
    /// Fail parent directory sync (Unix-only path; variant is cfg-gated so
    /// Windows test builds do not see an unconstructed dead variant under
    /// `-D warnings`).
    #[cfg(unix)]
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
    atomic_write_with_permissions(path, content, options, None, PermissionPolicy::Ciphertext)
}

/// Atomically write **private ciphertext** `content` to `path`, tightening
/// any existing group/other permission bits on rewrite and clearing inherited
/// or existing extended ACLs on the temporary file before writing.
///
/// If an existing target had group or other permissions set (`mode & 0o077 != 0`),
/// its mode is tightened to `mode & !0o077` (preserving stricter owner-only
/// modes such as `0400`) and a notice is emitted on `stderr` after the commit
/// succeeds.
pub(crate) fn atomic_write_private_ciphertext(
    path: &Path,
    content: &[u8],
    prior: Option<PrivateCiphertextPriorSnapshot>,
) -> CliResult<()> {
    atomic_write_with_permissions(
        path,
        content,
        AtomicWriteOptions {
            expected_prior_bytes: None,
            create_new: prior.is_none(),
        },
        prior,
        PermissionPolicy::CiphertextTightenPrivate,
    )
}

/// Atomically write integrity-sensitive **public** data.
///
/// Fresh Unix files are created with mode `0644` subject to the process umask.
/// Rewrites preserve the existing target mode. This entry point must never
/// receive plaintext secrets, identities, passphrases, or ciphertext.
pub(crate) fn atomic_write_public_data(
    path: &Path,
    content: &[u8],
    options: AtomicWriteOptions,
) -> CliResult<()> {
    atomic_write_with_permissions(path, content, options, None, PermissionPolicy::PublicData)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PermissionPolicy {
    Ciphertext,
    CiphertextTightenPrivate,
    PublicData,
}

fn atomic_write_with_permissions(
    path: &Path,
    content: &[u8],
    options: AtomicWriteOptions,
    prior_snapshot: Option<PrivateCiphertextPriorSnapshot>,
    permission_policy: PermissionPolicy,
) -> CliResult<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    if permission_policy == PermissionPolicy::CiphertextTightenPrivate {
        seclusor_crypto::acl::reject_writable_directory_acl(parent).map_err(CliError::Io)?;
    }

    if options.create_new && fs::symlink_metadata(path).is_ok() {
        return Err(CliError::Message(format!(
            "refusing to create {}: path already exists",
            path.display()
        )));
    }

    // Unique temp in the same directory. Setting the creation mode on the
    // builder lets the OS apply umask for fresh public files; chmod-after-create
    // would incorrectly widen a restrictive umask.
    let mut builder = tempfile::Builder::new();
    builder.prefix(".seclusor-");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let fresh_mode = match permission_policy {
            PermissionPolicy::Ciphertext | PermissionPolicy::CiphertextTightenPrivate => 0o600,
            PermissionPolicy::PublicData => 0o644,
        };
        builder.permissions(fs::Permissions::from_mode(fresh_mode));
    }
    let mut temp = builder.tempfile_in(parent).map_err(CliError::Io)?;

    let tightened_mode = apply_target_permissions(
        path,
        temp.as_file(),
        temp.path(),
        prior_snapshot.as_ref(),
        permission_policy,
    )?;

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

    // CAS: fresh open + bounded full-content compare, holding an advisory
    // exclusive lock on the target descriptor across `commit_replace` on Unix
    // and an exclusive sibling lockfile across check-and-replace on Windows
    // so cooperating writers serialize across the check-and-replace window.
    let expected_slice = prior_snapshot
        .as_ref()
        .map(|s| s.bytes.as_slice())
        .or(options.expected_prior_bytes.as_deref());
    let _cas_guard = if let Some(expected) = expected_slice {
        #[cfg(test)]
        if take_fault() == Some(AtomicFault::ForceCasMismatch) {
            return Err(CliError::ConcurrentModification {
                path: path.display().to_string(),
            });
        }

        match verify_and_lock_expected_target(
            path,
            expected,
            #[cfg(unix)]
            prior_snapshot.as_ref().map(|s| s.identity),
            #[cfg(windows)]
            prior_snapshot.as_ref().map(|s| s.file_id),
        )? {
            Some(guard) => Some(guard),
            None => {
                return Err(CliError::ConcurrentModification {
                    path: path.display().to_string(),
                });
            }
        }
    } else {
        None
    };

    #[cfg(test)]
    if take_fault() == Some(AtomicFault::ReplaceFail) {
        return Err(CliError::Message("fault: replace fail".into()));
    }

    commit_replace(temp, path, options.create_new, expected_slice.is_some())?;
    #[cfg(unix)]
    if prior_snapshot.is_some() {
        if let Some(ref guard) = _cas_guard {
            use std::os::unix::fs::MetadataExt;
            let displaced_meta =
                guard
                    .file
                    .metadata()
                    .map_err(|err| CliError::PostCommitFailure {
                        path: path.display().to_string(),
                        step: "displaced ciphertext link count check",
                        source: Box::new(CliError::Io(err)),
                    })?;
            if displaced_meta.nlink() != 0 {
                return Err(CliError::PostCommitFailure {
                    path: path.display().to_string(),
                    step: "displaced ciphertext link count verification",
                    source: Box::new(CliError::Message(
                        "displaced ciphertext inode retained unexpected hardlink after replacement"
                            .to_string(),
                    )),
                });
            }
        }
    }
    drop(_cas_guard);

    if let Some((old_mode, new_mode)) = tightened_mode {
        eprintln!(
            "warning: tightened permissions on {} from {:04o} to {:04o}",
            path.display(),
            old_mode,
            new_mode
        );
    }

    #[cfg(unix)]
    {
        #[cfg(test)]
        if take_fault() == Some(AtomicFault::DirSyncFail) {
            return Err(CliError::PostCommitFailure {
                path: path.display().to_string(),
                step: "parent directory sync",
                source: Box::new(CliError::Message("fault: dir sync fail".into())),
            });
        }
        // Parent directory fsync for rename durability — fail loud on error.
        let dir = File::open(parent).map_err(|err| CliError::PostCommitFailure {
            path: path.display().to_string(),
            step: "parent directory open for sync",
            source: Box::new(CliError::Io(err)),
        })?;
        dir.sync_all().map_err(|err| CliError::PostCommitFailure {
            path: path.display().to_string(),
            step: "parent directory sync",
            source: Box::new(CliError::Io(err)),
        })?;
    }

    Ok(())
}

fn apply_target_permissions(
    target: &Path,
    temp: &File,
    temp_path: &Path,
    prior_snapshot: Option<&PrivateCiphertextPriorSnapshot>,
    permission_policy: PermissionPolicy,
) -> CliResult<Option<(u32, u32)>> {
    #[cfg(unix)]
    let mut tightened = None;
    #[cfg(not(unix))]
    let tightened = None;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        match permission_policy {
            PermissionPolicy::CiphertextTightenPrivate => {
                if let Some(snapshot) = prior_snapshot {
                    let meta = match fs::symlink_metadata(target) {
                        Ok(m) => m,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                            return Err(CliError::ConcurrentModification {
                                path: target.display().to_string(),
                            });
                        }
                        Err(err) => return Err(CliError::Io(err)),
                    };
                    if meta.file_type().is_symlink() {
                        return Err(CliError::Message(format!(
                            "refusing to overwrite symlink output path {}",
                            target.display()
                        )));
                    }
                    if !meta.is_file() {
                        return Err(CliError::Message(format!(
                            "output path {} must be a regular file",
                            target.display()
                        )));
                    }
                    let (expected_dev, expected_ino, old_mode) = snapshot.identity;
                    if meta.dev() != expected_dev
                        || meta.ino() != expected_ino
                        || meta.nlink() != 1
                        || (meta.permissions().mode() & 0o777) != old_mode
                    {
                        return Err(CliError::ConcurrentModification {
                            path: target.display().to_string(),
                        });
                    }
                    if old_mode & 0o077 != 0 {
                        let new_mode = old_mode & !0o077;
                        temp.set_permissions(fs::Permissions::from_mode(new_mode))
                            .map_err(CliError::Io)?;
                        tightened = Some((old_mode, new_mode));
                    } else {
                        temp.set_permissions(fs::Permissions::from_mode(old_mode))
                            .map_err(CliError::Io)?;
                    }
                }
            }
            PermissionPolicy::Ciphertext | PermissionPolicy::PublicData => {
                match fs::symlink_metadata(target) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            let target_meta = fs::metadata(target).map_err(CliError::Io)?;
                            temp.set_permissions(target_meta.permissions())
                                .map_err(CliError::Io)?;
                        } else {
                            temp.set_permissions(meta.permissions())
                                .map_err(CliError::Io)?;
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
                    Err(err) => return Err(CliError::Io(err)),
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if permission_policy == PermissionPolicy::CiphertextTightenPrivate {
            if let Some(snapshot) = prior_snapshot {
                match fs::symlink_metadata(target) {
                    Ok(meta) => {
                        if meta.file_type().is_symlink() {
                            return Err(CliError::Message(format!(
                                "refusing to overwrite symlink output path {}",
                                target.display()
                            )));
                        }
                        if !meta.is_file() {
                            return Err(CliError::Message(format!(
                                "output path {} must be a regular file",
                                target.display()
                            )));
                        }
                        #[cfg(windows)]
                        {
                            const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
                            use std::os::windows::fs::MetadataExt;
                            if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
                                return Err(CliError::Message(format!(
                                    "refusing to overwrite symlink output path {}",
                                    target.display()
                                )));
                            }
                            let (actual_id, actual_nlink) =
                                windows_path_identity_and_nlink_nofollow(target)
                                    .map_err(CliError::Io)?;
                            if actual_id != snapshot.file_id || actual_nlink != 1 {
                                return Err(CliError::ConcurrentModification {
                                    path: target.display().to_string(),
                                });
                            }
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                        return Err(CliError::ConcurrentModification {
                            path: target.display().to_string(),
                        });
                    }
                    Err(err) => return Err(CliError::Io(err)),
                }
            }
        }
        // Windows: fresh-file ACL inherits parent directory defaults (documented
        // residual). ReplaceFileW preserves target DACL on rewrite.
    }

    if permission_policy == PermissionPolicy::CiphertextTightenPrivate {
        seclusor_crypto::acl::prepare_private_file(temp, temp_path).map_err(CliError::Io)?;
    }

    Ok(tightened)
}

struct LockedTargetGuard {
    file: File,
}

#[cfg(unix)]
impl Drop for LockedTargetGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: `file` is an open file descriptor owned by `self`.
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(windows)]
impl Drop for LockedTargetGuard {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;

        #[repr(C)]
        struct Overlapped {
            internal: usize,
            internal_high: usize,
            offset: u32,
            offset_high: u32,
            event: *mut core::ffi::c_void,
        }

        #[link(name = "kernel32")]
        extern "system" {
            fn UnlockFileEx(
                hFile: *mut core::ffi::c_void,
                dwReserved: u32,
                nNumberOfBytesToUnlockLow: u32,
                nNumberOfBytesToUnlockHigh: u32,
                lpOverlapped: *mut Overlapped,
            ) -> i32;
        }

        let mut overlapped = Overlapped {
            internal: 0,
            internal_high: 0,
            offset: u32::MAX,
            offset_high: u32::MAX,
            event: core::ptr::null_mut(),
        };
        // SAFETY: `self.file` is an open file handle owned by `self` and
        // `overlapped` is valid for the duration of the `UnlockFileEx` call.
        unsafe {
            let _ = UnlockFileEx(self.file.as_raw_handle(), 0, 1, 0, &mut overlapped);
        }
    }
}

#[cfg(windows)]
pub(crate) fn windows_file_identity_and_nlink(file: &File) -> std::io::Result<((u64, u64), u64)> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct FileTime {
        low_date_time: u32,
        high_date_time: u32,
    }

    #[repr(C)]
    struct ByHandleFileInformation {
        file_attributes: u32,
        creation_time: FileTime,
        last_access_time: FileTime,
        last_write_time: FileTime,
        volume_serial_number: u32,
        file_size_high: u32,
        file_size_low: u32,
        number_of_links: u32,
        file_index_high: u32,
        file_index_low: u32,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn GetFileInformationByHandle(
            hFile: *mut core::ffi::c_void,
            lpFileInformation: *mut ByHandleFileInformation,
        ) -> i32;
    }

    let mut info = ByHandleFileInformation {
        file_attributes: 0,
        creation_time: FileTime {
            low_date_time: 0,
            high_date_time: 0,
        },
        last_access_time: FileTime {
            low_date_time: 0,
            high_date_time: 0,
        },
        last_write_time: FileTime {
            low_date_time: 0,
            high_date_time: 0,
        },
        volume_serial_number: 0,
        file_size_high: 0,
        file_size_low: 0,
        number_of_links: 0,
        file_index_high: 0,
        file_index_low: 0,
    };
    // SAFETY: `file` is a valid open file handle and `info` is stack-allocated.
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let file_index = ((info.file_index_high as u64) << 32) | (info.file_index_low as u64);
    Ok((
        (info.volume_serial_number as u64, file_index),
        info.number_of_links as u64,
    ))
}

#[cfg(windows)]
pub(crate) fn windows_path_identity_and_nlink_nofollow(
    path: &Path,
) -> std::io::Result<((u64, u64), u64)> {
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
    const FILE_READ_ATTRIBUTES: u32 = 0x0080;
    const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

    let f = OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)?;
    let meta = f.metadata()?;
    if meta.file_type().is_symlink() || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing symlink or reparse point path",
        ));
    }
    windows_file_identity_and_nlink(&f)
}

#[cfg(windows)]
fn lock_windows_target_handle(file: &File) -> CliResult<bool> {
    use std::os::windows::io::AsRawHandle;

    #[repr(C)]
    struct Overlapped {
        internal: usize,
        internal_high: usize,
        offset: u32,
        offset_high: u32,
        event: *mut core::ffi::c_void,
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LockFileEx(
            hFile: *mut core::ffi::c_void,
            dwFlags: u32,
            dwReserved: u32,
            nNumberOfBytesToLockLow: u32,
            nNumberOfBytesToLockHigh: u32,
            lpOverlapped: *mut Overlapped,
        ) -> i32;
    }

    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    const ERROR_LOCK_VIOLATION: i32 = 33;

    // Lock the sentinel byte at offset u64::MAX so reads of [0, expected.len()]
    // on the same handle succeed while competing writers on any alias of the
    // same underlying file fail immediately.
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: u32::MAX,
        offset_high: u32::MAX,
        event: core::ptr::null_mut(),
    };
    // SAFETY: `file` is a valid open file handle and `overlapped` lives for the call.
    let ok = unsafe {
        LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if ok != 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    if err.raw_os_error() == Some(ERROR_LOCK_VIOLATION)
        || err.kind() == std::io::ErrorKind::WouldBlock
    {
        return Ok(false);
    }
    Err(CliError::Io(err))
}

/// Fresh open + bounded compare: read at most `expected.len() + 1` bytes.
///
/// Missing path always fails (including when `expected` is empty — an empty
/// file was loaded and must still exist). Acquires a non-blocking exclusive
/// lock on the opened target handle (`flock` on Unix; `LockFileEx` on Windows
/// opened with `FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE`) and
/// holds it across `commit_replace` so cooperating writers serialize across the
/// check-and-replace window without creating sidecar files.
fn verify_and_lock_expected_target(
    path: &Path,
    expected: &[u8],
    #[cfg(unix)] expected_prior_identity: Option<(u64, u64, u32)>,
    #[cfg(windows)] expected_prior_file_id: Option<(u64, u64)>,
) -> CliResult<Option<LockedTargetGuard>> {
    let meta = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(CliError::Io(err)),
    };
    if !meta.is_file() {
        return Ok(None);
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_SHARE_ALL: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let mut file = match options.open(path) {
        Ok(f) => f,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        #[cfg(unix)]
        Err(err) if err.raw_os_error() == Some(libc::ELOOP) => return Ok(None),
        Err(err) => return Err(CliError::Io(err)),
    };
    let open_meta = file.metadata().map_err(CliError::Io)?;
    if !open_meta.is_file() || open_meta.file_type().is_symlink() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        // SAFETY: `file` is a valid open regular-file descriptor.
        let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::WouldBlock
                || err.raw_os_error() == Some(libc::EWOULDBLOCK)
            {
                return Ok(None);
            }
            return Err(CliError::Io(err));
        }
        // Re-stat path after acquiring the lock so an unlink/replace that raced
        // before flock acquisition is detected before byte comparison.
        let locked_path_meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(CliError::Io(err)),
        };
        if !locked_path_meta.is_file()
            || open_meta.dev() != meta.dev()
            || open_meta.ino() != meta.ino()
            || locked_path_meta.dev() != open_meta.dev()
            || locked_path_meta.ino() != open_meta.ino()
        {
            return Ok(None);
        }
    }
    #[cfg(windows)]
    {
        if !lock_windows_target_handle(&file)? {
            return Ok(None);
        }
        // Re-check that `path` still resolves to the same underlying file after
        // acquiring `LockFileEx` so a replace/delete race before lock
        // acquisition is caught before byte comparison.
        let locked_path_meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(CliError::Io(err)),
        };
        if !locked_path_meta.is_file() || locked_path_meta.file_type().is_symlink() {
            return Ok(None);
        }
        let Ok(same) = same_file::Handle::from_path(path).and_then(|path_handle| {
            let locked_ref = file.try_clone()?;
            let locked_handle = same_file::Handle::from_file(locked_ref)?;
            Ok(path_handle == locked_handle)
        }) else {
            return Ok(None);
        };
        if !same {
            return Ok(None);
        }
        let Ok((open_id, open_nlink)) = windows_file_identity_and_nlink(&file) else {
            return Ok(None);
        };
        let Ok((path_id, path_nlink)) = windows_path_identity_and_nlink_nofollow(path) else {
            return Ok(None);
        };
        if open_id != path_id || open_nlink != 1 || path_nlink != 1 {
            return Ok(None);
        }
        if let Some(expected_id) = expected_prior_file_id {
            if open_id != expected_id {
                return Ok(None);
            }
        }
    }
    #[cfg(unix)]
    if let Some((expected_dev, expected_ino, expected_mode)) = expected_prior_identity {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let refreshed_meta = file.metadata().map_err(CliError::Io)?;
        let path_meta = match fs::symlink_metadata(path) {
            Ok(m) => m,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(CliError::Io(err)),
        };
        if refreshed_meta.dev() != expected_dev
            || refreshed_meta.ino() != expected_ino
            || refreshed_meta.nlink() != 1
            || path_meta.dev() != expected_dev
            || path_meta.ino() != expected_ino
            || path_meta.nlink() != 1
            || (refreshed_meta.permissions().mode() & 0o777) != expected_mode
        {
            return Ok(None);
        }
    }

    let mut buf = Zeroizing::new(vec![0u8; expected.len().saturating_add(1)]);
    let mut total = 0usize;
    while total < buf.len() {
        match file.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(err) => return Err(CliError::Io(err)),
        }
    }

    if total != expected.len() || &buf[..total] != expected {
        return Ok(None);
    }
    Ok(Some(LockedTargetGuard { file }))
}

fn commit_replace(
    temp: tempfile::NamedTempFile,
    path: &Path,
    create_new: bool,
    has_expected_prior: bool,
) -> CliResult<()> {
    #[cfg(not(windows))]
    let _ = has_expected_prior;

    #[cfg(windows)]
    {
        if has_expected_prior {
            return windows_replace_file(temp, path);
        }
        if fs::symlink_metadata(path).is_ok() {
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
    match result {
        Err(CliError::Io(ref err)) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(CliError::ConcurrentModification {
                path: path.display().to_string(),
            })
        }
        other => other,
    }
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
    fn public_data_rewrite_preserves_existing_mode() {
        use std::os::unix::fs::PermissionsExt;
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recipients.txt");
        fs::write(&path, b"age1old\n").expect("seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).expect("mode");

        atomic_write_public_data(
            &path,
            b"age1new\n",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"age1old\n".to_vec()),
                create_new: false,
            },
        )
        .expect("write");

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o664);
    }

    #[test]
    fn public_data_fault_leaves_old_list_and_no_temp_residue() {
        inject_fault(Some(AtomicFault::AfterSyncBeforeReplace));
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("recipients.txt");
        fs::write(&path, b"age1old\n").expect("seed");
        let names_before: Vec<_> = fs::read_dir(dir.path())
            .expect("read before")
            .map(|entry| entry.expect("entry").file_name())
            .collect();

        atomic_write_public_data(
            &path,
            b"age1new\n",
            AtomicWriteOptions {
                expected_prior_bytes: Some(b"age1old\n".to_vec()),
                create_new: false,
            },
        )
        .expect_err("fault must surface");
        inject_fault(None);

        assert_eq!(fs::read(&path).expect("old list"), b"age1old\n");
        let names_after: Vec<_> = fs::read_dir(dir.path())
            .expect("read after")
            .map(|entry| entry.expect("entry").file_name())
            .collect();
        assert_eq!(names_after, names_before, "temp file must be cleaned up");
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

    #[cfg(unix)]
    #[test]
    fn private_ciphertext_rewrite_tightens_group_and_other_bits_and_preserves_stricter_mode() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blob.age");
        fs::write(&path, b"v1").expect("seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("set 0644");
        let meta1 = fs::metadata(&path).expect("meta1");

        atomic_write_private_ciphertext(
            &path,
            b"v2",
            Some(PrivateCiphertextPriorSnapshot {
                bytes: Zeroizing::new(b"v1".to_vec()),
                identity: (meta1.dev(), meta1.ino(), meta1.permissions().mode() & 0o777),
            }),
        )
        .expect("tighten 0644 -> 0600");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o400)).expect("set 0400");
        let meta2 = fs::metadata(&path).expect("meta2");
        atomic_write_private_ciphertext(
            &path,
            b"v3",
            Some(PrivateCiphertextPriorSnapshot {
                bytes: Zeroizing::new(b"v2".to_vec()),
                identity: (meta2.dev(), meta2.ino(), meta2.permissions().mode() & 0o777),
            }),
        )
        .expect("preserve 0400");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o400
        );

        // If the target mode or inode changes between snapshot and permission
        // selection (or if the target vanishes after a snapshot was taken),
        // atomic_write_private_ciphertext must fail closed with ConcurrentModification.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("change mode");
        let err_mode = atomic_write_private_ciphertext(
            &path,
            b"v4",
            Some(PrivateCiphertextPriorSnapshot {
                bytes: Zeroizing::new(b"v3".to_vec()),
                identity: (meta2.dev(), meta2.ino(), 0o400),
            }),
        )
        .expect_err("snapshot mode mismatch must fail closed");
        assert!(matches!(err_mode, CliError::ConcurrentModification { .. }));
        assert_eq!(fs::read(&path).unwrap(), b"v3");

        fs::remove_file(&path).expect("remove target");
        let err_missing = atomic_write_private_ciphertext(
            &path,
            b"v4",
            Some(PrivateCiphertextPriorSnapshot {
                bytes: Zeroizing::new(b"v3".to_vec()),
                identity: (meta2.dev(), meta2.ino(), 0o644),
            }),
        )
        .expect_err("vanished target after snapshot must fail closed");
        assert!(matches!(
            err_missing,
            CliError::ConcurrentModification { .. }
        ));
        assert!(!path.exists());
    }

    #[cfg(unix)]
    #[test]
    fn cas_refuses_when_competing_writer_holds_exclusive_flock() {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blob.age");
        fs::write(&path, b"v1").expect("seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode");
        let meta = fs::metadata(&path).expect("meta");

        let lock_file = fs::File::open(&path).expect("open for lock");
        // SAFETY: `lock_file` is a valid open file descriptor.
        let rc = unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        assert_eq!(rc, 0, "test must acquire exclusive flock");

        let err = atomic_write_private_ciphertext(
            &path,
            b"v2",
            Some(PrivateCiphertextPriorSnapshot {
                bytes: Zeroizing::new(b"v1".to_vec()),
                identity: (meta.dev(), meta.ino(), meta.permissions().mode() & 0o777),
            }),
        )
        .expect_err("competing exclusive flock must fail closed as ConcurrentModification");
        assert!(matches!(err, CliError::ConcurrentModification { .. }));
        assert_eq!(fs::read(&path).expect("unchanged"), b"v1");

        drop(lock_file);

        atomic_write_private_ciphertext(
            &path,
            b"v2",
            Some(PrivateCiphertextPriorSnapshot {
                bytes: Zeroizing::new(b"v1".to_vec()),
                identity: (meta.dev(), meta.ino(), meta.permissions().mode() & 0o777),
            }),
        )
        .expect("write succeeds after competing flock is released");
        assert_eq!(fs::read(&path).expect("updated"), b"v2");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn private_ciphertext_clears_inherited_acl_and_refuses_writable_dir_acl() {
        use std::process::Command;

        fn chmod_add_acl(path: &Path, entry: &str) {
            let status = Command::new("/bin/chmod")
                .arg("+a")
                .arg(entry)
                .arg(path)
                .status()
                .expect("run /bin/chmod +a");
            assert!(
                status.success(),
                "/bin/chmod +a failed on {}",
                path.display()
            );
        }

        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        chmod_add_acl(dir.path(), "user:root allow read,file_inherit");

        let path = dir.path().join("blob.age");
        atomic_write_private_ciphertext(&path, b"age-encryption.org/v1\n", None)
            .expect("create private ciphertext");
        assert!(
            !seclusor_crypto::acl::has_non_owner_file_acl(&path).expect("check ACL"),
            "inherited ACL must be cleared on private ciphertext"
        );

        let writable_dir = tempfile::tempdir().expect("writable dir");
        chmod_add_acl(writable_dir.path(), "user:root allow delete_child");
        let bad_path = writable_dir.path().join("bad.age");
        let err = atomic_write_private_ciphertext(&bad_path, b"age-encryption.org/v1\n", None)
            .expect_err("writable dir ACL must be refused");
        assert!(matches!(
            err,
            CliError::Io(ref io_err) if io_err.kind() == std::io::ErrorKind::PermissionDenied
        ));
        assert!(!bad_path.exists());
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

    #[cfg(unix)]
    #[test]
    fn private_ciphertext_cas_refuses_hardlink_created_after_snapshot() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        inject_fault(None);
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("blob.age");
        fs::write(&path, b"v1").expect("seed");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("chmod 0600");
        let meta = fs::symlink_metadata(&path).expect("meta");
        let snapshot = PrivateCiphertextPriorSnapshot {
            bytes: Zeroizing::new(b"v1".to_vec()),
            identity: (meta.dev(), meta.ino(), meta.permissions().mode() & 0o777),
        };

        let hardlink = dir.path().join("blob-extra-link.age");
        fs::hard_link(&path, &hardlink).expect("create hardlink after snapshot");

        let err = atomic_write_private_ciphertext(&path, b"v2", Some(snapshot))
            .expect_err("hardlink created after snapshot must be refused by CAS");
        assert!(matches!(err, CliError::ConcurrentModification { .. }));
        assert_eq!(fs::read(&path).expect("unchanged"), b"v1");
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

        #[test]
        fn cas_refuses_when_competing_writer_holds_windows_cas_lock() {
            use std::os::windows::fs::OpenOptionsExt;

            inject_fault(None);
            let dir = tempfile::tempdir().expect("tempdir");
            let path = dir.path().join("blob.age");
            fs::write(&path, b"v1").expect("seed");

            let mut opts = OpenOptions::new();
            opts.read(true)
                .share_mode(0x0000_0001 | 0x0000_0002 | 0x0000_0004);
            let locked_file = opts.open(&path).expect("open target");
            let (locked_id, _) =
                windows_file_identity_and_nlink(&locked_file).expect("target file identity");
            assert!(
                lock_windows_target_handle(&locked_file).expect("lock target"),
                "test must acquire exclusive byte-range lock on target"
            );
            let _guard = LockedTargetGuard { file: locked_file };

            let err = atomic_write_private_ciphertext(
                &path,
                b"v2",
                Some(PrivateCiphertextPriorSnapshot {
                    bytes: Zeroizing::new(b"v1".to_vec()),
                    file_id: locked_id,
                }),
            )
            .expect_err("competing Windows target lock must fail closed as ConcurrentModification");
            assert!(matches!(err, CliError::ConcurrentModification { .. }));
            assert_eq!(fs::read(&path).expect("unchanged"), b"v1");

            drop(_guard);

            atomic_write_private_ciphertext(
                &path,
                b"v2",
                Some(PrivateCiphertextPriorSnapshot {
                    bytes: Zeroizing::new(b"v1".to_vec()),
                    file_id: locked_id,
                }),
            )
            .expect("write succeeds after competing Windows target lock is released");
            assert_eq!(fs::read(&path).expect("updated"), b"v2");
        }
    }
}
