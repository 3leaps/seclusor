#ifndef SECLUSOR_H
#define SECLUSOR_H

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

/**
 * C-ABI result code for FFI calls.
 */
typedef enum SeclusorResult {
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
} SeclusorResult;

/**
 * Opaque keyring handle (reserved for D6 key management APIs).
 */
typedef struct SeclusorKeyringHandle SeclusorKeyringHandle;

/**
 * Opaque handle for a loaded/validated secrets document.
 */
typedef struct SeclusorSecretsHandle SeclusorSecretsHandle;

/**
 * Return the last error message from the calling thread.
 *
 * Caller owns the returned C string and must free with `seclusor_free_string`.
 */
char *seclusor_last_error(void);

/**
 * Free a C string returned from seclusor FFI APIs.
 *
 * # Safety
 * `ptr` must be either null or a pointer previously returned by this library
 * via `CString::into_raw` (for example `seclusor_last_error` or JSON-returning
 * APIs). Passing any other pointer is undefined behavior.
 */
void seclusor_free_string(char *ptr);

/**
 * Create a secrets handle from JSON text.
 *
 * # Safety
 * `json` must be a valid, non-null, NUL-terminated C string. `out_handle`
 * must be a valid non-null pointer to storage for a handle pointer.
 */
enum SeclusorResult seclusor_secrets_handle_new_from_json(const char *json,
                                                          struct SeclusorSecretsHandle **out_handle);

/**
 * Destroy a secrets handle.
 *
 * # Safety
 * `handle` must be either null or a pointer previously returned by
 * `seclusor_secrets_handle_new_from_json` and not already freed.
 */
void seclusor_secrets_handle_free(struct SeclusorSecretsHandle *handle);

/**
 * Create an empty keyring handle.
 *
 * # Safety
 * `out_handle` must be a valid non-null pointer to storage for a handle
 * pointer.
 */
enum SeclusorResult seclusor_keyring_handle_new(struct SeclusorKeyringHandle **out_handle);

/**
 * Destroy a keyring handle.
 *
 * # Safety
 * `handle` must be either null or a pointer previously returned by
 * `seclusor_keyring_handle_new` and not already freed.
 */
void seclusor_keyring_handle_free(struct SeclusorKeyringHandle *handle);

/**
 * Add one recipient string (`age1...`) to a keyring handle.
 *
 * # Safety
 * `handle` must be a valid mutable keyring handle pointer from this library.
 * `recipient` must be a valid non-null C string.
 */
enum SeclusorResult seclusor_keyring_handle_add_recipient(struct SeclusorKeyringHandle *handle,
                                                          const char *recipient);

/**
 * Load identities from an age identity file and append to a keyring handle.
 *
 * # Safety
 * `handle` must be a valid mutable keyring handle pointer from this library.
 * `identity_file_path` must be a valid non-null C string path.
 */
enum SeclusorResult seclusor_keyring_handle_add_identity_file(struct SeclusorKeyringHandle *handle,
                                                              const char *identity_file_path);

/**
 * Return keyring handle status as JSON.
 *
 * JSON shape: `{\"identity_count\":1,\"recipient_count\":2}`.
 *
 * # Safety
 * `handle` must be a valid keyring handle pointer from this library. `out_json`
 * must be a valid non-null pointer to receive an allocated C string.
 */
enum SeclusorResult seclusor_keyring_handle_status(const struct SeclusorKeyringHandle *handle,
                                                   char **out_json);

/**
 * Rekey bundle ciphertext using identities and recipients currently loaded in keyring handle.
 *
 * # Safety
 * `handle` must be a valid keyring handle pointer from this library.
 * `input_ciphertext_path` and `output_ciphertext_path` must be valid non-null C strings.
 */
enum SeclusorResult seclusor_keyring_rekey_bundle(const struct SeclusorKeyringHandle *handle,
                                                  const char *input_ciphertext_path,
                                                  const char *output_ciphertext_path);

/**
 * List credential keys for a project as JSON string.
 *
 * Returns JSON array: `["API_KEY", "DB_URL"]`.
 *
 * # Safety
 * `handle` must be a valid pointer from this library. `project_slug` may be
 * null or a valid NUL-terminated C string. `out_json` must be a valid non-null
 * pointer to receive an allocated C string.
 */
enum SeclusorResult seclusor_secrets_list(const struct SeclusorSecretsHandle *handle,
                                          const char *project_slug,
                                          char **out_json);

/**
 * Get a credential as JSON object.
 *
 * Returns JSON object with redaction semantics:
 * `{"type":"secret","value":"<redacted>","redacted":true}`
 *
 * # Safety
 * `handle` must be a valid pointer from this library. `project_slug` may be
 * null or a valid C string. `key` must be a valid non-null C string. `out_json`
 * must be a valid non-null pointer to receive an allocated C string.
 */
enum SeclusorResult seclusor_secrets_get(const struct SeclusorSecretsHandle *handle,
                                         const char *project_slug,
                                         const char *key,
                                         int reveal,
                                         char **out_json);

/**
 * Export environment variables as JSON array.
 *
 * Returns JSON array:
 * `[{"key":"APP_API_KEY","value":"..."}]`
 *
 * # Safety
 * `handle` must be a valid pointer from this library. `project_slug`/`prefix`
 * may be null or valid C strings. `out_json` must be a valid non-null pointer
 * to receive an allocated C string.
 */
enum SeclusorResult seclusor_secrets_export_env(const struct SeclusorSecretsHandle *handle,
                                                const char *project_slug,
                                                const char *prefix,
                                                int emit_ref,
                                                char **out_json);

/**
 * Encrypt a secrets JSON file into bundle ciphertext file.
 *
 * `recipients_json` is a JSON array of recipient strings:
 * `["age1...","age1..."]`
 */
enum SeclusorResult seclusor_encrypt_bundle(const char *input_json_path,
                                            const char *output_ciphertext_path,
                                            const char *recipients_json);

/**
 * Decrypt a bundle ciphertext file into pretty JSON file.
 *
 * `identity_file_path` must point to an age identity file.
 */
enum SeclusorResult seclusor_decrypt_bundle(const char *input_ciphertext_path,
                                            const char *output_json_path,
                                            const char *identity_file_path);

/**
 * Generate a new Ed25519 signing keypair.
 *
 * # Safety
 * `secret_key_out` must point to a writable 32-byte buffer and
 * `public_key_out` must point to a writable 32-byte buffer.
 */
enum SeclusorResult seclusor_signing_generate_keypair(uint8_t *secret_key_out,
                                                      uintptr_t secret_key_out_len,
                                                      uint8_t *public_key_out,
                                                      uintptr_t public_key_out_len);

/**
 * Derive an Ed25519 public key from a canonical 32-byte secret-key seed.
 *
 * # Safety
 * `secret_key` must either be null with `secret_key_len == 0` or point to a
 * readable input buffer. `public_key_out` must point to a writable 32-byte
 * buffer.
 */
enum SeclusorResult seclusor_signing_public_key_from_secret_key(const uint8_t *secret_key,
                                                                uintptr_t secret_key_len,
                                                                uint8_t *public_key_out,
                                                                uintptr_t public_key_out_len);

/**
 * Sign a message with an Ed25519 secret key.
 *
 * # Safety
 * `secret_key` must either be null with `secret_key_len == 0` or point to a
 * readable input buffer. `message` may be null only when `message_len == 0`.
 * `signature_out` must point to a writable 64-byte buffer.
 */
enum SeclusorResult seclusor_signing_sign(const uint8_t *secret_key,
                                          uintptr_t secret_key_len,
                                          const uint8_t *message,
                                          uintptr_t message_len,
                                          uint8_t *signature_out,
                                          uintptr_t signature_out_len);

/**
 * Verify an Ed25519 signature.
 *
 * # Safety
 * `public_key` and `signature` must either be null with zero lengths or point
 * to readable input buffers. `message` may be null only when
 * `message_len == 0`.
 */
enum SeclusorResult seclusor_signing_verify(const uint8_t *public_key,
                                            uintptr_t public_key_len,
                                            const uint8_t *message,
                                            uintptr_t message_len,
                                            const uint8_t *signature,
                                            uintptr_t signature_len);

#endif  /* SECLUSOR_H */
