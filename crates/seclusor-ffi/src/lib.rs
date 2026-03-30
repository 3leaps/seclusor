//! seclusor-ffi
//!
//! C-ABI boundary for seclusor library consumers.

use std::cell::RefCell;
use std::ffi::{c_char, c_int, CStr, CString};
use std::fs;
use std::io::Read;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use seclusor_codec::{decrypt_bundle_from_file, encrypt_bundle_to_file, CodecError};
use seclusor_core::constants::MAX_SECRETS_DOC_BYTES;
use seclusor_core::crud::{get_credential, list_credential_keys};
use seclusor_core::env::{export_env, EnvExportOptions};
use seclusor_core::error::sanitize_serde_json_error_message;
use seclusor_core::validate::validate_strict;
use seclusor_core::{SeclusorError, SecretsFile};
use seclusor_crypto::{
    generate_signing_keypair, load_identity_file, parse_recipients, sign, signature_from_bytes,
    signature_to_bytes, signing_public_key, signing_public_key_from_bytes,
    signing_public_key_to_bytes, signing_secret_key_from_bytes, signing_secret_key_to_bytes,
    verify, CryptoError, Identity, SIGNATURE_LEN, SIGNING_PUBLIC_KEY_LEN, SIGNING_SECRET_KEY_LEN,
};
use seclusor_keyring::{KeyringError, Recipient};
use serde::Serialize;

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

/// C-ABI result code for FFI calls.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeclusorResult {
    Ok = 0,
    InvalidArgument = 1,
    ValidationError = 2,
    NotFound = 3,
    CryptoError = 4,
    CodecError = 5,
    IoError = 6,
    JsonError = 7,
    Panic = 50,
    UnknownError = 255,
}

/// Opaque handle for a loaded/validated secrets document.
pub struct SeclusorSecretsHandle {
    secrets: SecretsFile,
}

/// Opaque keyring handle (reserved for D6 key management APIs).
pub struct SeclusorKeyringHandle {
    identities: Vec<Identity>,
    recipients: Vec<Recipient>,
}

#[derive(Debug)]
struct FfiError {
    code: SeclusorResult,
    message: String,
}

type FfiResult<T> = Result<T, FfiError>;

#[derive(Serialize)]
struct FfiCredentialView {
    #[serde(rename = "type")]
    credential_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(rename = "ref", skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
    redacted: bool,
}

#[derive(Serialize)]
struct FfiEnvVar {
    key: String,
    value: String,
}

#[derive(Serialize)]
struct FfiKeyringStatus {
    identity_count: usize,
    recipient_count: usize,
}

fn clear_last_error() {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = None);
}

fn set_last_error(message: impl Into<String>) {
    LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(message.into()));
}

fn fail(code: SeclusorResult, message: impl Into<String>) -> FfiError {
    FfiError {
        code,
        message: message.into(),
    }
}

fn with_ffi_boundary<T>(f: impl FnOnce() -> FfiResult<T>) -> Result<T, SeclusorResult> {
    clear_last_error();
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => {
            set_last_error(err.message);
            Err(err.code)
        }
        Err(_) => {
            set_last_error("panic across FFI boundary");
            Err(SeclusorResult::Panic)
        }
    }
}

fn require_non_null<T>(ptr: *const T, label: &str) -> FfiResult<()> {
    if ptr.is_null() {
        return Err(fail(
            SeclusorResult::InvalidArgument,
            format!("{label} must not be null"),
        ));
    }
    Ok(())
}

fn cstr_required<'a>(ptr: *const c_char, label: &str) -> FfiResult<&'a str> {
    require_non_null(ptr, label)?;
    let cstr = {
        // SAFETY: pointer non-null checked above; CStr validates nul-termination.
        unsafe { CStr::from_ptr(ptr) }
    };
    cstr.to_str().map_err(|_| {
        fail(
            SeclusorResult::InvalidArgument,
            format!("{label} must be valid UTF-8"),
        )
    })
}

fn cstr_optional<'a>(ptr: *const c_char, label: &str) -> FfiResult<Option<&'a str>> {
    if ptr.is_null() {
        return Ok(None);
    }
    Ok(Some(cstr_required(ptr, label)?))
}

fn cstring_alloc(value: String) -> FfiResult<*mut c_char> {
    CString::new(value).map(CString::into_raw).map_err(|_| {
        fail(
            SeclusorResult::InvalidArgument,
            "string contains embedded NUL",
        )
    })
}

fn write_out_string(out_json: *mut *mut c_char, value: String) -> FfiResult<()> {
    require_non_null(out_json, "out_json")?;
    let raw = cstring_alloc(value)?;
    // SAFETY: out_json validated non-null and points to caller-provided storage.
    unsafe { *out_json = raw };
    Ok(())
}

fn bytes_input<'a>(ptr: *const u8, len: usize, label: &str) -> FfiResult<&'a [u8]> {
    if len == 0 {
        return Ok(&[]);
    }
    require_non_null(ptr, label)?;
    // SAFETY: ptr is non-null for non-zero len and points to readable input.
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

fn bytes_output_exact<'a>(
    ptr: *mut u8,
    len: usize,
    expected: usize,
    label: &str,
) -> FfiResult<&'a mut [u8]> {
    if len != expected {
        return Err(fail(
            SeclusorResult::InvalidArgument,
            format!("{label}_len must be {expected}"),
        ));
    }
    require_non_null(ptr, label)?;
    // SAFETY: ptr is non-null and points to writable output storage.
    Ok(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

fn json_string<T: Serialize>(value: &T) -> FfiResult<String> {
    serde_json::to_string(value).map_err(FfiError::from)
}

fn read_file_with_limit(path: &str, max: usize) -> FfiResult<Vec<u8>> {
    let actual = fs::metadata(path)?.len();
    if actual > max as u64 {
        return Err(SeclusorError::DocumentTooLarge {
            actual: actual as usize,
            max,
        }
        .into());
    }

    let mut file = fs::File::open(path)?;
    let mut limited = std::io::Read::by_ref(&mut file).take((max as u64) + 1);
    let mut bytes = Vec::new();
    limited.read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(SeclusorError::DocumentTooLarge {
            actual: bytes.len(),
            max,
        }
        .into());
    }

    Ok(bytes)
}

impl From<SeclusorError> for FfiError {
    fn from(value: SeclusorError) -> Self {
        match value {
            SeclusorError::Validation(msg) => fail(SeclusorResult::ValidationError, msg),
            SeclusorError::ProjectNotFound(msg) => fail(SeclusorResult::NotFound, msg),
            SeclusorError::CredentialNotFound { project, key } => fail(
                SeclusorResult::NotFound,
                format!("credential {key:?} not found in project {project:?}"),
            ),
            SeclusorError::AmbiguousProject(n) => fail(
                SeclusorResult::ValidationError,
                format!("ambiguous project: file has {n} projects"),
            ),
            SeclusorError::CannotAutoCreateProject => fail(
                SeclusorResult::ValidationError,
                "cannot auto-create project in non-empty secrets file",
            ),
            SeclusorError::InlineEncrypted(key) => fail(
                SeclusorResult::ValidationError,
                format!("{key} is inline-encrypted"),
            ),
            SeclusorError::RefNotExportable(key) => {
                fail(SeclusorResult::ValidationError, format!("{key} is a ref"))
            }
            SeclusorError::DocumentTooLarge { actual, max } => fail(
                SeclusorResult::ValidationError,
                format!("document exceeds maximum size {max} (actual: {actual})"),
            ),
            SeclusorError::Json(err) => fail(SeclusorResult::JsonError, err),
            SeclusorError::Io(err) => fail(SeclusorResult::IoError, err.to_string()),
        }
    }
}

impl From<CryptoError> for FfiError {
    fn from(value: CryptoError) -> Self {
        fail(SeclusorResult::CryptoError, value.to_string())
    }
}

impl From<CodecError> for FfiError {
    fn from(value: CodecError) -> Self {
        match value {
            CodecError::Core(err) => FfiError::from(err),
            CodecError::Crypto(err) => FfiError::from(err),
            CodecError::Json(err) => fail(SeclusorResult::JsonError, err),
            CodecError::Io(err) => fail(SeclusorResult::IoError, err.to_string()),
            other => fail(SeclusorResult::CodecError, other.to_string()),
        }
    }
}

impl From<KeyringError> for FfiError {
    fn from(value: KeyringError) -> Self {
        match value {
            KeyringError::Core(err) => FfiError::from(err),
            KeyringError::Crypto(err) => FfiError::from(err),
            KeyringError::Io(err) => fail(SeclusorResult::IoError, err.to_string()),
            other => fail(SeclusorResult::ValidationError, other.to_string()),
        }
    }
}

impl From<serde_json::Error> for FfiError {
    fn from(value: serde_json::Error) -> Self {
        fail(
            SeclusorResult::JsonError,
            sanitize_serde_json_error_message(&value.to_string()),
        )
    }
}

impl From<std::io::Error> for FfiError {
    fn from(value: std::io::Error) -> Self {
        fail(SeclusorResult::IoError, value.to_string())
    }
}

/// Return the last error message from the calling thread.
///
/// Caller owns the returned C string and must free with `seclusor_free_string`.
#[no_mangle]
pub extern "C" fn seclusor_last_error() -> *mut c_char {
    let cloned = LAST_ERROR.with(|slot| slot.borrow().clone());
    match cloned {
        Some(message) => CString::new(message)
            .map(CString::into_raw)
            .unwrap_or(ptr::null_mut()),
        None => ptr::null_mut(),
    }
}

/// Free a C string returned from seclusor FFI APIs.
///
/// # Safety
/// `ptr` must be either null or a pointer previously returned by this library
/// via `CString::into_raw` (for example `seclusor_last_error` or JSON-returning
/// APIs). Passing any other pointer is undefined behavior.
#[no_mangle]
pub unsafe extern "C" fn seclusor_free_string(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: ptr must originate from CString::into_raw in this library.
    drop(unsafe { CString::from_raw(ptr) });
}

/// Create a secrets handle from JSON text.
///
/// # Safety
/// `json` must be a valid, non-null, NUL-terminated C string. `out_handle`
/// must be a valid non-null pointer to storage for a handle pointer.
#[no_mangle]
pub unsafe extern "C" fn seclusor_secrets_handle_new_from_json(
    json: *const c_char,
    out_handle: *mut *mut SeclusorSecretsHandle,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(out_handle, "out_handle")?;
        // SAFETY: out_handle validated non-null.
        unsafe { *out_handle = ptr::null_mut() };
        let json = cstr_required(json, "json")?;
        let secrets: SecretsFile = serde_json::from_str(json)?;
        validate_strict(&secrets)?;
        let boxed = Box::new(SeclusorSecretsHandle { secrets });
        // SAFETY: out_handle validated non-null and points to caller-owned pointer slot.
        unsafe { *out_handle = Box::into_raw(boxed) };
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Destroy a secrets handle.
///
/// # Safety
/// `handle` must be either null or a pointer previously returned by
/// `seclusor_secrets_handle_new_from_json` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn seclusor_secrets_handle_free(handle: *mut SeclusorSecretsHandle) {
    if handle.is_null() {
        return;
    }
    // SAFETY: handle must be allocated by Box::into_raw in this library.
    drop(unsafe { Box::from_raw(handle) });
}

/// Create an empty keyring handle.
///
/// # Safety
/// `out_handle` must be a valid non-null pointer to storage for a handle
/// pointer.
#[no_mangle]
pub unsafe extern "C" fn seclusor_keyring_handle_new(
    out_handle: *mut *mut SeclusorKeyringHandle,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(out_handle, "out_handle")?;
        // SAFETY: out_handle validated non-null.
        unsafe { *out_handle = ptr::null_mut() };
        let boxed = Box::new(SeclusorKeyringHandle {
            identities: Vec::new(),
            recipients: Vec::new(),
        });
        // SAFETY: out_handle validated non-null and points to caller-owned pointer slot.
        unsafe { *out_handle = Box::into_raw(boxed) };
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Destroy a keyring handle.
///
/// # Safety
/// `handle` must be either null or a pointer previously returned by
/// `seclusor_keyring_handle_new` and not already freed.
#[no_mangle]
pub unsafe extern "C" fn seclusor_keyring_handle_free(handle: *mut SeclusorKeyringHandle) {
    if handle.is_null() {
        return;
    }
    // SAFETY: handle must be allocated by Box::into_raw in this library.
    drop(unsafe { Box::from_raw(handle) });
}

/// Add one recipient string (`age1...`) to a keyring handle.
///
/// # Safety
/// `handle` must be a valid mutable keyring handle pointer from this library.
/// `recipient` must be a valid non-null C string.
#[no_mangle]
pub unsafe extern "C" fn seclusor_keyring_handle_add_recipient(
    handle: *mut SeclusorKeyringHandle,
    recipient: *const c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(handle, "handle")?;
        let recipient = cstr_required(recipient, "recipient")?;
        let mut parsed = parse_recipients(std::iter::once(recipient))?;
        // SAFETY: handle validated non-null; mutable access is exclusive per C caller contract.
        let keyring = unsafe { &mut *handle };
        keyring.recipients.append(&mut parsed);
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Load identities from an age identity file and append to a keyring handle.
///
/// # Safety
/// `handle` must be a valid mutable keyring handle pointer from this library.
/// `identity_file_path` must be a valid non-null C string path.
#[no_mangle]
pub unsafe extern "C" fn seclusor_keyring_handle_add_identity_file(
    handle: *mut SeclusorKeyringHandle,
    identity_file_path: *const c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(handle, "handle")?;
        let identity_file_path = cstr_required(identity_file_path, "identity_file_path")?;
        let mut loaded = load_identity_file(identity_file_path)?;
        // SAFETY: handle validated non-null; mutable access is exclusive per C caller contract.
        let keyring = unsafe { &mut *handle };
        keyring.identities.append(&mut loaded);
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Return keyring handle status as JSON.
///
/// JSON shape: `{\"identity_count\":1,\"recipient_count\":2}`.
///
/// # Safety
/// `handle` must be a valid keyring handle pointer from this library. `out_json`
/// must be a valid non-null pointer to receive an allocated C string.
#[no_mangle]
pub unsafe extern "C" fn seclusor_keyring_handle_status(
    handle: *const SeclusorKeyringHandle,
    out_json: *mut *mut c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(handle, "handle")?;
        require_non_null(out_json, "out_json")?;
        // SAFETY: out_json validated non-null.
        unsafe { *out_json = ptr::null_mut() };
        // SAFETY: handle validated non-null; immutable access only.
        let keyring = unsafe { &*handle };
        let status = FfiKeyringStatus {
            identity_count: keyring.identities.len(),
            recipient_count: keyring.recipients.len(),
        };
        write_out_string(out_json, json_string(&status)?)?;
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Rekey bundle ciphertext using identities and recipients currently loaded in keyring handle.
///
/// # Safety
/// `handle` must be a valid keyring handle pointer from this library.
/// `input_ciphertext_path` and `output_ciphertext_path` must be valid non-null C strings.
#[no_mangle]
pub unsafe extern "C" fn seclusor_keyring_rekey_bundle(
    handle: *const SeclusorKeyringHandle,
    input_ciphertext_path: *const c_char,
    output_ciphertext_path: *const c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(handle, "handle")?;
        let input_ciphertext_path = cstr_required(input_ciphertext_path, "input_ciphertext_path")?;
        let output_ciphertext_path =
            cstr_required(output_ciphertext_path, "output_ciphertext_path")?;
        // SAFETY: handle validated non-null; immutable access only.
        let keyring = unsafe { &*handle };
        if keyring.identities.is_empty() {
            return Err(fail(
                SeclusorResult::ValidationError,
                "keyring has no identities loaded",
            ));
        }
        if keyring.recipients.is_empty() {
            return Err(fail(
                SeclusorResult::ValidationError,
                "keyring has no recipients loaded",
            ));
        }

        let secrets = decrypt_bundle_from_file(input_ciphertext_path, &keyring.identities)?;
        encrypt_bundle_to_file(&secrets, &keyring.recipients, output_ciphertext_path)?;
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// List credential keys for a project as JSON string.
///
/// Returns JSON array: `["API_KEY", "DB_URL"]`.
///
/// # Safety
/// `handle` must be a valid pointer from this library. `project_slug` may be
/// null or a valid NUL-terminated C string. `out_json` must be a valid non-null
/// pointer to receive an allocated C string.
#[no_mangle]
pub unsafe extern "C" fn seclusor_secrets_list(
    handle: *const SeclusorSecretsHandle,
    project_slug: *const c_char,
    out_json: *mut *mut c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(handle, "handle")?;
        require_non_null(out_json, "out_json")?;
        // SAFETY: out_json validated non-null.
        unsafe { *out_json = ptr::null_mut() };
        let project = cstr_optional(project_slug, "project_slug")?;
        let keys = {
            // SAFETY: handle validated non-null; immutable access only.
            let handle_ref = unsafe { &*handle };
            list_credential_keys(&handle_ref.secrets, project)?
        };
        write_out_string(out_json, json_string(&keys)?)?;
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Get a credential as JSON object.
///
/// Returns JSON object with redaction semantics:
/// `{"type":"secret","value":"<redacted>","redacted":true}`
///
/// # Safety
/// `handle` must be a valid pointer from this library. `project_slug` may be
/// null or a valid C string. `key` must be a valid non-null C string. `out_json`
/// must be a valid non-null pointer to receive an allocated C string.
#[no_mangle]
pub unsafe extern "C" fn seclusor_secrets_get(
    handle: *const SeclusorSecretsHandle,
    project_slug: *const c_char,
    key: *const c_char,
    reveal: c_int,
    out_json: *mut *mut c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(handle, "handle")?;
        require_non_null(out_json, "out_json")?;
        // SAFETY: out_json validated non-null.
        unsafe { *out_json = ptr::null_mut() };
        let project = cstr_optional(project_slug, "project_slug")?;
        let key = cstr_required(key, "key")?;
        let reveal = reveal != 0;

        let view = {
            // SAFETY: handle validated non-null; immutable access only.
            let handle_ref = unsafe { &*handle };
            let cred = get_credential(&handle_ref.secrets, project, key)?;
            if reveal {
                FfiCredentialView {
                    credential_type: cred.credential_type.clone(),
                    value: cred.value.clone(),
                    reference: cred.reference.clone(),
                    redacted: false,
                }
            } else {
                FfiCredentialView {
                    credential_type: cred.credential_type.clone(),
                    value: cred.value.as_ref().map(|_| "<redacted>".to_string()),
                    reference: cred.reference.as_ref().map(|_| "<redacted>".to_string()),
                    redacted: true,
                }
            }
        };

        write_out_string(out_json, json_string(&view)?)?;
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Export environment variables as JSON array.
///
/// Returns JSON array:
/// `[{"key":"APP_API_KEY","value":"..."}]`
///
/// # Safety
/// `handle` must be a valid pointer from this library. `project_slug`/`prefix`
/// may be null or valid C strings. `out_json` must be a valid non-null pointer
/// to receive an allocated C string.
#[no_mangle]
pub unsafe extern "C" fn seclusor_secrets_export_env(
    handle: *const SeclusorSecretsHandle,
    project_slug: *const c_char,
    prefix: *const c_char,
    emit_ref: c_int,
    out_json: *mut *mut c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        require_non_null(handle, "handle")?;
        require_non_null(out_json, "out_json")?;
        // SAFETY: out_json validated non-null.
        unsafe { *out_json = ptr::null_mut() };
        let project = cstr_optional(project_slug, "project_slug")?;
        let prefix = cstr_optional(prefix, "prefix")?;
        let emit_ref = emit_ref != 0;

        let env = {
            // SAFETY: handle validated non-null; immutable access only.
            let handle_ref = unsafe { &*handle };
            let opts = EnvExportOptions {
                prefix: prefix.map(ToOwned::to_owned),
                emit_ref,
                filter: Default::default(),
            };
            export_env(&handle_ref.secrets, project, &opts)?
        };
        let env_json: Vec<FfiEnvVar> = env
            .into_iter()
            .map(|entry| FfiEnvVar {
                key: entry.key,
                value: entry.value,
            })
            .collect();
        write_out_string(out_json, json_string(&env_json)?)?;
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Encrypt a secrets JSON file into bundle ciphertext file.
///
/// `recipients_json` is a JSON array of recipient strings:
/// `["age1...","age1..."]`
#[no_mangle]
pub extern "C" fn seclusor_encrypt_bundle(
    input_json_path: *const c_char,
    output_ciphertext_path: *const c_char,
    recipients_json: *const c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        let input_json_path = cstr_required(input_json_path, "input_json_path")?;
        let output_ciphertext_path =
            cstr_required(output_ciphertext_path, "output_ciphertext_path")?;
        let recipients_json = cstr_required(recipients_json, "recipients_json")?;

        let recipient_strings: Vec<String> = serde_json::from_str(recipients_json)?;
        let recipients: Vec<Recipient> =
            parse_recipients(recipient_strings.iter().map(String::as_str))?;

        let bytes = read_file_with_limit(input_json_path, MAX_SECRETS_DOC_BYTES)?;
        let secrets: SecretsFile = serde_json::from_slice(&bytes)?;
        validate_strict(&secrets)?;
        encrypt_bundle_to_file(&secrets, &recipients, output_ciphertext_path)?;
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Decrypt a bundle ciphertext file into pretty JSON file.
///
/// `identity_file_path` must point to an age identity file.
#[no_mangle]
pub extern "C" fn seclusor_decrypt_bundle(
    input_ciphertext_path: *const c_char,
    output_json_path: *const c_char,
    identity_file_path: *const c_char,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        let input_ciphertext_path = cstr_required(input_ciphertext_path, "input_ciphertext_path")?;
        let output_json_path = cstr_required(output_json_path, "output_json_path")?;
        let identity_file_path = cstr_required(identity_file_path, "identity_file_path")?;

        let identities = load_identity_file(identity_file_path)?;
        let secrets = decrypt_bundle_from_file(input_ciphertext_path, &identities)?;
        let json = serde_json::to_vec_pretty(&secrets)?;
        fs::write(output_json_path, json)?;
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Generate a new Ed25519 signing keypair.
///
/// # Safety
/// `secret_key_out` must point to a writable 32-byte buffer and
/// `public_key_out` must point to a writable 32-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn seclusor_signing_generate_keypair(
    secret_key_out: *mut u8,
    secret_key_out_len: usize,
    public_key_out: *mut u8,
    public_key_out_len: usize,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        let secret_key_out = bytes_output_exact(
            secret_key_out,
            secret_key_out_len,
            SIGNING_SECRET_KEY_LEN,
            "secret_key_out",
        )?;
        let public_key_out = bytes_output_exact(
            public_key_out,
            public_key_out_len,
            SIGNING_PUBLIC_KEY_LEN,
            "public_key_out",
        )?;
        let keypair = generate_signing_keypair()?;
        let mut secret_key_bytes = signing_secret_key_to_bytes(keypair.secret_key());
        let public_key_bytes = signing_public_key_to_bytes(keypair.public_key());
        secret_key_out.copy_from_slice(&secret_key_bytes);
        public_key_out.copy_from_slice(&public_key_bytes);
        secret_key_bytes.fill(0);
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Derive an Ed25519 public key from a canonical 32-byte secret-key seed.
///
/// # Safety
/// `secret_key` must either be null with `secret_key_len == 0` or point to a
/// readable input buffer. `public_key_out` must point to a writable 32-byte
/// buffer.
#[no_mangle]
pub unsafe extern "C" fn seclusor_signing_public_key_from_secret_key(
    secret_key: *const u8,
    secret_key_len: usize,
    public_key_out: *mut u8,
    public_key_out_len: usize,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        let secret_key = bytes_input(secret_key, secret_key_len, "secret_key")?;
        let public_key_out = bytes_output_exact(
            public_key_out,
            public_key_out_len,
            SIGNING_PUBLIC_KEY_LEN,
            "public_key_out",
        )?;
        let secret_key = signing_secret_key_from_bytes(secret_key)?;
        let public_key = signing_public_key(&secret_key);
        let public_key_bytes = signing_public_key_to_bytes(&public_key);
        public_key_out.copy_from_slice(&public_key_bytes);
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Sign a message with an Ed25519 secret key.
///
/// # Safety
/// `secret_key` must either be null with `secret_key_len == 0` or point to a
/// readable input buffer. `message` may be null only when `message_len == 0`.
/// `signature_out` must point to a writable 64-byte buffer.
#[no_mangle]
pub unsafe extern "C" fn seclusor_signing_sign(
    secret_key: *const u8,
    secret_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature_out: *mut u8,
    signature_out_len: usize,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        let secret_key = bytes_input(secret_key, secret_key_len, "secret_key")?;
        let message = bytes_input(message, message_len, "message")?;
        let signature_out = bytes_output_exact(
            signature_out,
            signature_out_len,
            SIGNATURE_LEN,
            "signature_out",
        )?;
        let secret_key = signing_secret_key_from_bytes(secret_key)?;
        let signature = sign(&secret_key, message)?;
        let signature_bytes = signature_to_bytes(&signature);
        signature_out.copy_from_slice(&signature_bytes);
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

/// Verify an Ed25519 signature.
///
/// # Safety
/// `public_key` and `signature` must either be null with zero lengths or point
/// to readable input buffers. `message` may be null only when
/// `message_len == 0`.
#[no_mangle]
pub unsafe extern "C" fn seclusor_signing_verify(
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> SeclusorResult {
    match with_ffi_boundary(|| {
        let public_key = bytes_input(public_key, public_key_len, "public_key")?;
        let message = bytes_input(message, message_len, "message")?;
        let signature = bytes_input(signature, signature_len, "signature")?;
        let public_key = signing_public_key_from_bytes(public_key)?;
        let signature = signature_from_bytes(signature)?;
        verify(&public_key, message, &signature)?;
        Ok(())
    }) {
        Ok(()) => SeclusorResult::Ok,
        Err(code) => code,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const TEST_IDENTITY: &str =
        "AGE-SECRET-KEY-1GQ9778VQXMMJVE8SK7J6VT8UJ4HDQAJUVSFCWCM02D8GEWQ72PVQ2Y5J33";

    fn cstring(value: &str) -> CString {
        CString::new(value).expect("cstring")
    }

    fn take_json(ptr: *mut c_char) -> String {
        assert!(!ptr.is_null());
        // SAFETY: pointer returned by this library and valid nul-terminated C string.
        let c = unsafe { CStr::from_ptr(ptr) };
        let s = c.to_str().expect("utf8").to_string();
        // SAFETY: pointer originated from seclusor allocation APIs.
        unsafe { seclusor_free_string(ptr) };
        s
    }

    fn last_error_text() -> String {
        take_json(seclusor_last_error())
    }

    fn write_identity_file(path: &Path, identity: &str) {
        let recipient: Recipient = identity
            .parse::<seclusor_crypto::Identity>()
            .expect("identity parse")
            .to_public();
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(path)
                .expect("create identity file");
            writeln!(file, "# public key: {recipient}").expect("write comment");
            writeln!(file, "{identity}").expect("write identity");
        }
        #[cfg(not(unix))]
        {
            fs::write(path, format!("# public key: {recipient}\n{identity}\n"))
                .expect("write identity file");
        }
    }

    #[test]
    fn secrets_handle_list_get_export_roundtrip() {
        let json = r#"{
            "schema_version":"v1.0.0",
            "env_prefix":"APP_",
            "projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"sk-123"}}}]
        }"#;
        let json = cstring(json);
        let mut handle: *mut SeclusorSecretsHandle = ptr::null_mut();

        // SAFETY: inputs are valid pointers for the duration of the call.
        assert_eq!(
            unsafe { seclusor_secrets_handle_new_from_json(json.as_ptr(), &mut handle) },
            SeclusorResult::Ok
        );
        assert!(!handle.is_null());

        let mut list_ptr: *mut c_char = ptr::null_mut();
        // SAFETY: handle and output pointer are valid.
        assert_eq!(
            unsafe { seclusor_secrets_list(handle, ptr::null(), &mut list_ptr) },
            SeclusorResult::Ok
        );
        assert_eq!(take_json(list_ptr), "[\"API_KEY\"]");

        let key = cstring("API_KEY");
        let mut get_ptr: *mut c_char = ptr::null_mut();
        // SAFETY: handle/key/output pointers are valid.
        assert_eq!(
            unsafe { seclusor_secrets_get(handle, ptr::null(), key.as_ptr(), 0, &mut get_ptr) },
            SeclusorResult::Ok
        );
        let got: serde_json::Value =
            serde_json::from_str(&take_json(get_ptr)).expect("parse get json");
        assert_eq!(got["redacted"], true);
        assert_eq!(got["value"], "<redacted>");

        let mut export_ptr: *mut c_char = ptr::null_mut();
        // SAFETY: handle/output pointers are valid.
        assert_eq!(
            unsafe {
                seclusor_secrets_export_env(handle, ptr::null(), ptr::null(), 0, &mut export_ptr)
            },
            SeclusorResult::Ok
        );
        let env: serde_json::Value =
            serde_json::from_str(&take_json(export_ptr)).expect("parse export json");
        assert_eq!(env.as_array().expect("array").len(), 1);

        // SAFETY: handle was allocated by this library and not freed yet.
        unsafe { seclusor_secrets_handle_free(handle) };
    }

    #[test]
    fn last_error_set_for_invalid_argument() {
        let mut out: *mut SeclusorSecretsHandle = ptr::null_mut();
        // SAFETY: out pointer is valid; null json is intentional to test validation.
        let result = unsafe { seclusor_secrets_handle_new_from_json(ptr::null(), &mut out) };
        assert_eq!(result, SeclusorResult::InvalidArgument);
        let err_text = last_error_text();
        assert!(err_text.contains("json must not be null"));
    }

    #[test]
    fn last_error_redacts_plaintext_strings_in_json_errors() {
        let json = cstring(r#"{"schema_version":"v1.0.0","projects":"cfat_secret_token"}"#);
        let mut handle: *mut SeclusorSecretsHandle = ptr::null_mut();

        let result = unsafe { seclusor_secrets_handle_new_from_json(json.as_ptr(), &mut handle) };
        assert_eq!(result, SeclusorResult::JsonError);
        assert!(handle.is_null());

        let err_text = last_error_text();
        assert!(!err_text.contains("cfat_secret_token"));
        assert!(err_text.contains("string \"<redacted>\""));
    }

    #[test]
    fn signing_ffi_roundtrip_and_zero_length_message() {
        let mut secret_key = [0_u8; SIGNING_SECRET_KEY_LEN];
        let mut public_key = [0_u8; SIGNING_PUBLIC_KEY_LEN];
        assert_eq!(
            unsafe {
                seclusor_signing_generate_keypair(
                    secret_key.as_mut_ptr(),
                    secret_key.len(),
                    public_key.as_mut_ptr(),
                    public_key.len(),
                )
            },
            SeclusorResult::Ok
        );

        let mut derived_public_key = [0_u8; SIGNING_PUBLIC_KEY_LEN];
        assert_eq!(
            unsafe {
                seclusor_signing_public_key_from_secret_key(
                    secret_key.as_ptr(),
                    secret_key.len(),
                    derived_public_key.as_mut_ptr(),
                    derived_public_key.len(),
                )
            },
            SeclusorResult::Ok
        );
        assert_eq!(derived_public_key, public_key);

        let mut signature = [0_u8; SIGNATURE_LEN];
        assert_eq!(
            unsafe {
                seclusor_signing_sign(
                    secret_key.as_ptr(),
                    secret_key.len(),
                    ptr::null(),
                    0,
                    signature.as_mut_ptr(),
                    signature.len(),
                )
            },
            SeclusorResult::Ok
        );
        assert_eq!(
            unsafe {
                seclusor_signing_verify(
                    public_key.as_ptr(),
                    public_key.len(),
                    ptr::null(),
                    0,
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            SeclusorResult::Ok
        );
    }

    #[test]
    fn signing_ffi_verify_accepts_null_zero_length_message() {
        let secret_key: [u8; SIGNING_SECRET_KEY_LEN] = std::array::from_fn(|index| index as u8);
        let mut public_key = [0_u8; SIGNING_PUBLIC_KEY_LEN];
        assert_eq!(
            unsafe {
                seclusor_signing_public_key_from_secret_key(
                    secret_key.as_ptr(),
                    secret_key.len(),
                    public_key.as_mut_ptr(),
                    public_key.len(),
                )
            },
            SeclusorResult::Ok
        );

        let mut signature = [0_u8; SIGNATURE_LEN];
        assert_eq!(
            unsafe {
                seclusor_signing_sign(
                    secret_key.as_ptr(),
                    secret_key.len(),
                    ptr::null(),
                    0,
                    signature.as_mut_ptr(),
                    signature.len(),
                )
            },
            SeclusorResult::Ok
        );
        assert_eq!(
            unsafe {
                seclusor_signing_verify(
                    public_key.as_ptr(),
                    public_key.len(),
                    ptr::null(),
                    0,
                    signature.as_ptr(),
                    signature.len(),
                )
            },
            SeclusorResult::Ok
        );
    }

    #[test]
    fn signing_ffi_distinguishes_invalid_argument_and_crypto_failures() {
        let mut secret_key = [0_u8; SIGNING_SECRET_KEY_LEN];
        let mut public_key = [0_u8; SIGNING_PUBLIC_KEY_LEN];
        assert_eq!(
            unsafe {
                seclusor_signing_generate_keypair(
                    secret_key.as_mut_ptr(),
                    secret_key.len(),
                    public_key.as_mut_ptr(),
                    public_key.len(),
                )
            },
            SeclusorResult::Ok
        );

        let mut short_public_key = [0_u8; SIGNING_PUBLIC_KEY_LEN - 1];
        let result = unsafe {
            seclusor_signing_public_key_from_secret_key(
                secret_key.as_ptr(),
                secret_key.len(),
                short_public_key.as_mut_ptr(),
                short_public_key.len(),
            )
        };
        assert_eq!(result, SeclusorResult::InvalidArgument);
        assert_eq!(last_error_text(), "public_key_out_len must be 32");

        let mut signature = [0_u8; SIGNATURE_LEN];
        let result = unsafe {
            seclusor_signing_sign(
                ptr::null(),
                1,
                ptr::null(),
                0,
                signature.as_mut_ptr(),
                signature.len(),
            )
        };
        assert_eq!(result, SeclusorResult::InvalidArgument);
        assert_eq!(last_error_text(), "secret_key must not be null");

        let result = unsafe {
            seclusor_signing_sign(
                secret_key[..SIGNING_SECRET_KEY_LEN - 1].as_ptr(),
                SIGNING_SECRET_KEY_LEN - 1,
                b"msg".as_ptr(),
                3,
                signature.as_mut_ptr(),
                signature.len(),
            )
        };
        assert_eq!(result, SeclusorResult::CryptoError);
        assert_eq!(last_error_text(), "invalid Ed25519 secret-key bytes");

        assert_eq!(
            unsafe {
                seclusor_signing_sign(
                    secret_key.as_ptr(),
                    secret_key.len(),
                    b"msg".as_ptr(),
                    3,
                    signature.as_mut_ptr(),
                    signature.len(),
                )
            },
            SeclusorResult::Ok
        );

        let result = unsafe {
            seclusor_signing_verify(
                public_key.as_ptr(),
                public_key.len(),
                b"other".as_ptr(),
                5,
                signature.as_ptr(),
                signature.len(),
            )
        };
        assert_eq!(result, SeclusorResult::CryptoError);
        assert_eq!(last_error_text(), "signature verification failed");

        let invalid_signature = [0_u8; SIGNATURE_LEN - 1];
        let result = unsafe {
            seclusor_signing_verify(
                public_key.as_ptr(),
                public_key.len(),
                b"msg".as_ptr(),
                3,
                invalid_signature.as_ptr(),
                invalid_signature.len(),
            )
        };
        assert_eq!(result, SeclusorResult::CryptoError);
        assert_eq!(last_error_text(), "invalid Ed25519 signature bytes");
    }

    #[test]
    fn bundle_encrypt_decrypt_ffi_functions_work() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("secrets.json");
        let bundle = dir.path().join("secrets.age");
        let output = dir.path().join("secrets.out.json");
        let identity_file = dir.path().join("identity.txt");

        let identity = TEST_IDENTITY
            .parse::<seclusor_crypto::Identity>()
            .expect("identity parse");
        write_identity_file(&identity_file, TEST_IDENTITY);
        let recipient = identity.to_public().to_string();

        fs::write(
            &input,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"sk-123"}}}]}"#,
        )
        .expect("write input");

        let input_c = cstring(input.to_str().expect("utf8 path"));
        let bundle_c = cstring(bundle.to_str().expect("utf8 path"));
        let output_c = cstring(output.to_str().expect("utf8 path"));
        let identity_c = cstring(identity_file.to_str().expect("utf8 path"));
        let recipients_json = cstring(&format!("[\"{recipient}\"]"));

        assert_eq!(
            seclusor_encrypt_bundle(
                input_c.as_ptr(),
                bundle_c.as_ptr(),
                recipients_json.as_ptr()
            ),
            SeclusorResult::Ok
        );
        assert_eq!(
            seclusor_decrypt_bundle(bundle_c.as_ptr(), output_c.as_ptr(), identity_c.as_ptr()),
            SeclusorResult::Ok
        );

        let output_json = fs::read_to_string(output).expect("read output");
        assert!(output_json.contains("\"API_KEY\""));
    }

    #[test]
    fn bundle_encrypt_rejects_oversized_input_file() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("oversized.json");
        let output = dir.path().join("secrets.age");

        let file = fs::File::create(&input).expect("create oversized input");
        file.set_len((MAX_SECRETS_DOC_BYTES as u64) + 1)
            .expect("set oversized length");
        drop(file);

        let identity = TEST_IDENTITY
            .parse::<seclusor_crypto::Identity>()
            .expect("identity parse");
        let recipient = identity.to_public().to_string();

        let input_c = cstring(input.to_str().expect("utf8 path"));
        let output_c = cstring(output.to_str().expect("utf8 path"));
        let recipients_json = cstring(&format!("[\"{recipient}\"]"));

        let result = seclusor_encrypt_bundle(
            input_c.as_ptr(),
            output_c.as_ptr(),
            recipients_json.as_ptr(),
        );
        assert_eq!(result, SeclusorResult::ValidationError);
        let err = seclusor_last_error();
        let err_text = take_json(err);
        assert!(err_text.contains("document exceeds maximum size"));
    }

    #[test]
    fn keyring_handle_status_add_and_rekey_bundle() {
        let dir = tempfile::tempdir().expect("temp dir");
        let input = dir.path().join("secrets.json");
        let original_bundle = dir.path().join("secrets.age");
        let rekeyed_bundle = dir.path().join("secrets.rekeyed.age");
        let old_identity_file = dir.path().join("old-identity.txt");
        let new_identity_file = dir.path().join("new-identity.txt");
        let output = dir.path().join("secrets.out.json");

        let old_identity = TEST_IDENTITY
            .parse::<seclusor_crypto::Identity>()
            .expect("old identity parse");
        let old_recipient = old_identity.to_public().to_string();
        write_identity_file(&old_identity_file, TEST_IDENTITY);

        let new_identity = seclusor_crypto::Identity::generate();
        let new_identity_text = seclusor_crypto::identity_to_string(&new_identity);
        write_identity_file(&new_identity_file, &new_identity_text);
        let new_recipient = new_identity.to_public().to_string();

        fs::write(
            &input,
            r#"{"schema_version":"v1.0.0","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"sk-123"}}}]}"#,
        )
        .expect("write input");

        let input_c = cstring(input.to_str().expect("utf8 path"));
        let bundle_c = cstring(original_bundle.to_str().expect("utf8 path"));
        let recipients_json = cstring(&format!("[\"{old_recipient}\"]"));
        assert_eq!(
            seclusor_encrypt_bundle(
                input_c.as_ptr(),
                bundle_c.as_ptr(),
                recipients_json.as_ptr()
            ),
            SeclusorResult::Ok
        );

        let mut keyring: *mut SeclusorKeyringHandle = ptr::null_mut();
        // SAFETY: output pointer valid.
        assert_eq!(
            unsafe { seclusor_keyring_handle_new(&mut keyring) },
            SeclusorResult::Ok
        );
        assert!(!keyring.is_null());

        let mut status_ptr: *mut c_char = ptr::null_mut();
        // SAFETY: handle/output pointers valid.
        assert_eq!(
            unsafe { seclusor_keyring_handle_status(keyring, &mut status_ptr) },
            SeclusorResult::Ok
        );
        let status: serde_json::Value =
            serde_json::from_str(&take_json(status_ptr)).expect("status json");
        assert_eq!(status["identity_count"], 0);
        assert_eq!(status["recipient_count"], 0);

        let old_identity_c = cstring(old_identity_file.to_str().expect("utf8 path"));
        // SAFETY: pointers valid.
        assert_eq!(
            unsafe { seclusor_keyring_handle_add_identity_file(keyring, old_identity_c.as_ptr()) },
            SeclusorResult::Ok
        );
        let new_recipient_c = cstring(&new_recipient);
        // SAFETY: pointers valid.
        assert_eq!(
            unsafe { seclusor_keyring_handle_add_recipient(keyring, new_recipient_c.as_ptr()) },
            SeclusorResult::Ok
        );

        let input_bundle_c = cstring(original_bundle.to_str().expect("utf8 path"));
        let output_bundle_c = cstring(rekeyed_bundle.to_str().expect("utf8 path"));
        // SAFETY: pointers valid.
        assert_eq!(
            unsafe {
                seclusor_keyring_rekey_bundle(
                    keyring,
                    input_bundle_c.as_ptr(),
                    output_bundle_c.as_ptr(),
                )
            },
            SeclusorResult::Ok
        );

        let output_c = cstring(output.to_str().expect("utf8 path"));
        let new_identity_c = cstring(new_identity_file.to_str().expect("utf8 path"));
        assert_eq!(
            seclusor_decrypt_bundle(
                output_bundle_c.as_ptr(),
                output_c.as_ptr(),
                new_identity_c.as_ptr()
            ),
            SeclusorResult::Ok
        );
        let output_json = fs::read_to_string(output).expect("read output");
        assert!(output_json.contains("\"API_KEY\""));

        // SAFETY: handle was allocated by this library and not freed yet.
        unsafe { seclusor_keyring_handle_free(keyring) };
    }
}
