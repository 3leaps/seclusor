//! macOS extended ACL checks for private files and their containing directory.
//! Other platforms keep the existing POSIX-mode contract.

#[cfg(unix)]
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

#[cfg(target_os = "macos")]
use std::cell::RefCell;
#[cfg(target_os = "macos")]
use std::collections::HashSet;
#[cfg(target_os = "macos")]
use std::path::PathBuf;

#[cfg(target_os = "macos")]
thread_local! {
    static WARNED_PATHS: RefCell<Option<HashSet<PathBuf>>> = const { RefCell::new(None) };
}

/// Keep repeated preflights in one load from repeating the same ACL warning.
/// Each preflight still performs its own mode, directory, and ACL checks.
#[must_use]
#[doc(hidden)]
pub struct WarningScope {
    #[cfg(target_os = "macos")]
    owner: bool,
    // The guard must be dropped on the thread that owns the thread-local set.
    _not_send: std::marker::PhantomData<std::rc::Rc<()>>,
}

/// Begin an operation-scoped warning window. Nested windows share one set.
#[doc(hidden)]
pub fn warning_scope() -> WarningScope {
    #[cfg(target_os = "macos")]
    {
        let owner = WARNED_PATHS.with(|slot| {
            let mut paths = slot.borrow_mut();
            if paths.is_some() {
                false
            } else {
                *paths = Some(HashSet::new());
                true
            }
        });
        WarningScope {
            owner,
            _not_send: std::marker::PhantomData,
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        WarningScope {
            _not_send: std::marker::PhantomData,
        }
    }
}

impl Drop for WarningScope {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        if self.owner {
            WARNED_PATHS.with(|slot| *slot.borrow_mut() = None);
        }
    }
}

/// True when a warning should be emitted for this path in the current scope.
#[cfg(target_os = "macos")]
pub(crate) fn should_emit_warning(path: &Path) -> bool {
    WARNED_PATHS.with(|slot| {
        let mut paths = slot.borrow_mut();
        match paths.as_mut() {
            Some(paths) => paths.insert(path.to_path_buf()),
            None => true,
        }
    })
}

/// Clear inherited or existing ACL entries before private bytes are written.
/// The path must still identify the open file throughout the operation.
pub fn prepare_private_file(file: &File, path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::prepare_private_file(file, path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (file, path);
        Ok(())
    }
}

/// Refuse a directory ACL that permits a non-owner to replace private files.
pub fn reject_writable_directory_acl(path: &Path) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        macos::reject_writable_directory_acl(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Ok(())
    }
}

/// Write private plaintext directly, without leaving a plaintext temp file.
/// Mode and inherited ACLs are restricted before any new bytes are written.
/// Existing files are opened without truncation until the checks succeed.
pub fn write_private_file(path: &Path, bytes: &[u8], create_new: bool) -> io::Result<()> {
    let parent = path
        .parent()
        .filter(|part| !part.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    reject_writable_directory_acl(parent)?;

    let mut options = OpenOptions::new();
    options.write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if file.metadata()?.nlink() != 1 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private output must not have multiple hard links",
            ));
        }
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    prepare_private_file(&file, path)?;
    file.set_len(0)?;
    file.write_all(bytes)
}

/// Report whether a private file has an ACL granting access to a non-owner.
pub fn has_non_owner_file_acl(path: &Path) -> io::Result<bool> {
    #[cfg(target_os = "macos")]
    {
        macos::has_non_owner_file_acl(path)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::CStr;
    use std::fs::{self, File};
    use std::io;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::ptr;

    use exacl::{AclEntry, AclEntryKind, Perm};

    fn permission_denied(message: &'static str) -> io::Error {
        io::Error::new(io::ErrorKind::PermissionDenied, message)
    }

    fn same_open_file(file: &File, path: &Path) -> io::Result<bool> {
        let open = file.metadata()?;
        let named = fs::metadata(path)?;
        Ok(open.dev() == named.dev() && open.ino() == named.ino())
    }

    pub(super) fn prepare_private_file(file: &File, path: &Path) -> io::Result<()> {
        if !same_open_file(file, path)? {
            return Err(permission_denied(
                "private file path changed before ACL clearing",
            ));
        }
        exacl::setfacl(&[path], &[], None)?;
        if !same_open_file(file, path)? || !exacl::getfacl(path, None)?.is_empty() {
            return Err(permission_denied(
                "private file ACL could not be cleared and verified",
            ));
        }
        Ok(())
    }

    fn owner_name(uid: u32) -> io::Result<Option<String>> {
        let mut buffer = vec![0_u8; 1024];
        loop {
            let mut record = std::mem::MaybeUninit::<libc::passwd>::uninit();
            let mut result = ptr::null_mut();
            // SAFETY: getpwuid_r writes into the provided record/buffer and result
            // pointer. The record is read only when result is non-null.
            let code = unsafe {
                libc::getpwuid_r(
                    uid,
                    record.as_mut_ptr(),
                    buffer.as_mut_ptr().cast(),
                    buffer.len(),
                    &mut result,
                )
            };
            if code == libc::ERANGE && buffer.len() < 1024 * 1024 {
                buffer.resize(buffer.len() * 2, 0);
                continue;
            }
            if code != 0 {
                return Err(io::Error::from_raw_os_error(code));
            }
            if result.is_null() {
                return Ok(None);
            }
            // SAFETY: successful getpwuid_r initialized record; pw_name points
            // into the live buffer until this function returns.
            let name = unsafe { CStr::from_ptr(record.assume_init().pw_name) };
            return Ok(Some(name.to_string_lossy().into_owned()));
        }
    }

    fn is_owner(entry: &AclEntry, uid: u32, owner_name: Option<&str>) -> bool {
        entry.kind == AclEntryKind::User
            && (entry.name == uid.to_string() || owner_name == Some(entry.name.as_str()))
    }

    pub(super) fn reject_writable_directory_acl(path: &Path) -> io::Result<()> {
        let entries = exacl::getfacl(path, None)?;
        let dangerous = Perm::WRITE
            | Perm::APPEND
            | Perm::DELETE_CHILD
            | Perm::DELETE
            | Perm::WRITESECURITY
            | Perm::CHOWN;
        if !entries
            .iter()
            .any(|entry| entry.allow && entry.perms.intersects(dangerous))
        {
            return Ok(());
        }
        let uid = fs::metadata(path)?.uid();
        let owner = owner_name(uid)?;
        if entries.iter().any(|entry| {
            entry.allow
                && entry.perms.intersects(dangerous)
                && !is_owner(entry, uid, owner.as_deref())
        }) {
            return Err(permission_denied(
                "private file directory ACL grants non-owner write, delete, or ACL-edit access; inspect with ls -le and remove with chmod -N",
            ));
        }
        Ok(())
    }

    pub(super) fn has_non_owner_file_acl(path: &Path) -> io::Result<bool> {
        let entries = exacl::getfacl(path, None)?;
        if !entries.iter().any(|entry| entry.allow) {
            return Ok(false);
        }
        let uid = fs::metadata(path)?.uid();
        let owner = owner_name(uid)?;
        Ok(entries
            .iter()
            .any(|entry| entry.allow && !is_owner(entry, uid, owner.as_deref())))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use std::fs::{self, OpenOptions};
    use std::io;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use exacl::{AclEntry, Flag, Perm};

    use super::{
        has_non_owner_file_acl, prepare_private_file, reject_writable_directory_acl,
        write_private_file,
    };

    #[test]
    fn inherited_read_acl_is_cleared_before_private_write() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        exacl::setfacl(
            &[dir.path()],
            &[AclEntry::allow_user("root", Perm::READ, Flag::FILE_INHERIT)],
            None,
        )?;
        reject_writable_directory_acl(dir.path())?;
        let path = dir.path().join("identity.txt");
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        assert!(has_non_owner_file_acl(&path)?);
        prepare_private_file(&file, &path)?;
        assert!(!has_non_owner_file_acl(&path)?);
        assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn plaintext_writer_clears_inherited_acl_before_bytes() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        exacl::setfacl(
            &[dir.path()],
            &[AclEntry::allow_user("root", Perm::READ, Flag::FILE_INHERIT)],
            None,
        )?;
        let path = dir.path().join("plain.json");
        write_private_file(&path, b"secret", false)?;
        assert_eq!(fs::read(&path)?, b"secret");
        assert!(!has_non_owner_file_acl(&path)?);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn plaintext_writer_restricts_existing_file_before_overwrite() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("plain.json");
        fs::write(&path, b"old secret")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;
        exacl::setfacl(
            &[&path],
            &[AclEntry::allow_user("root", Perm::READ, None)],
            None,
        )?;
        write_private_file(&path, b"new", false)?;
        assert_eq!(fs::read(&path)?, b"new");
        assert!(!has_non_owner_file_acl(&path)?);
        assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o600);
        Ok(())
    }

    #[test]
    fn plaintext_writer_refuses_acl_writable_directory_without_output() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        exacl::setfacl(
            &[dir.path()],
            &[AclEntry::allow_user("root", Perm::WRITESECURITY, None)],
            None,
        )?;
        let path = dir.path().join("plain.json");
        let err = write_private_file(&path, b"secret", false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn explicit_read_acl_is_detected() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("identity.txt");
        fs::write(&path, b"")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        exacl::setfacl(
            &[&path],
            &[AclEntry::allow_user("root", Perm::READ, None)],
            None,
        )?;
        assert!(has_non_owner_file_acl(&path)?);
        Ok(())
    }

    #[test]
    fn warns_before_private_file_load() -> io::Result<()> {
        const CHILD_PATH: &str = "SECLUSOR_ACL_WARNING_CHILD_PATH";
        if let Some(path) = std::env::var_os(CHILD_PATH) {
            let path = std::path::Path::new(&path);
            {
                let _scope = super::warning_scope();
                crate::assert_secure_permissions(path).expect("first ACL preflight");
                {
                    let _nested_scope = super::warning_scope();
                    crate::assert_secure_permissions(path).expect("nested ACL preflight");
                }
                crate::assert_secure_permissions(path).expect("repeated ACL preflight");
            }
            crate::assert_secure_permissions(path).expect("next operation ACL preflight");
            return Ok(());
        }

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("identity.txt");
        fs::write(&path, b"")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        exacl::setfacl(
            &[&path],
            &[AclEntry::allow_user("root", Perm::READ, None)],
            None,
        )?;
        let output = std::process::Command::new(std::env::current_exe()?)
            .arg("--exact")
            .arg("acl::tests::warns_before_private_file_load")
            .arg("--nocapture")
            .env(CHILD_PATH, &path)
            .output()?;
        assert!(output.status.success(), "child preflight failed");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(stderr.matches("warning: private file").count(), 2);
        assert!(stderr.contains("ls -le"));
        assert!(stderr.contains("chmod -N"));
        Ok(())
    }

    #[test]
    fn load_preflight_refuses_writable_directory_acl() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        exacl::setfacl(
            &[dir.path()],
            &[AclEntry::allow_user("root", Perm::DELETE_CHILD, None)],
            None,
        )?;
        let path = dir.path().join("identity.txt");
        fs::write(&path, b"")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let err = crate::assert_secure_permissions(&path).unwrap_err();
        assert!(matches!(
            err,
            crate::CryptoError::Io(ref source) if source.kind() == io::ErrorKind::PermissionDenied
        ));
        Ok(())
    }

    #[test]
    fn non_owner_write_security_acl_is_rejected() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        exacl::setfacl(
            &[dir.path()],
            &[AclEntry::allow_user("root", Perm::WRITESECURITY, None)],
            None,
        )?;
        let err = reject_writable_directory_acl(dir.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }

    #[test]
    fn non_owner_chown_acl_is_rejected() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        exacl::setfacl(
            &[dir.path()],
            &[AclEntry::allow_user("root", Perm::CHOWN, None)],
            None,
        )?;
        let err = reject_writable_directory_acl(dir.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }

    #[test]
    fn non_owner_delete_child_acl_is_rejected() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        exacl::setfacl(
            &[dir.path()],
            &[AclEntry::allow_user("root", Perm::DELETE_CHILD, None)],
            None,
        )?;
        let err = reject_writable_directory_acl(dir.path()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        Ok(())
    }
}
