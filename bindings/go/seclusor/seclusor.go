package seclusor

/*
#include "seclusor.h"
#include <stdlib.h>
*/
import "C"

import (
	"encoding/json"
	"errors"
	"unsafe"
)

type ResultCode int

const (
	ResultOK         ResultCode = 0
	ResultInvalidArg ResultCode = 1
	ResultValidation ResultCode = 2
	ResultNotFound   ResultCode = 3
	ResultCrypto     ResultCode = 4
	ResultCodec      ResultCode = 5
	ResultIO         ResultCode = 6
	ResultJSON       ResultCode = 7
	ResultPanic      ResultCode = 50
	ResultUnknown    ResultCode = 255
)

const (
	SigningSecretKeyLen = 32
	SigningPublicKeyLen = 32
	SignatureLen        = 64
)

// WipeBytes best-effort zeroes a byte slice in place.
//
// Use this for secret-key material after encrypting it at rest or once
// signing is complete. It does not guarantee elimination of all copies that
// may exist due to Go runtime behavior, but it reduces retention of the
// current slice contents.
func WipeBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

type Error struct {
	Code    ResultCode
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}

type SecretsHandle struct {
	ptr *C.SeclusorSecretsHandle
}

type KeyringHandle struct {
	ptr *C.SeclusorKeyringHandle
}

type CredentialView struct {
	Type     string  `json:"type"`
	Value    *string `json:"value,omitempty"`
	Ref      *string `json:"ref,omitempty"`
	Redacted bool    `json:"redacted"`
}

type EnvVar struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type KeyringStatus struct {
	IdentityCount  int `json:"identity_count"`
	RecipientCount int `json:"recipient_count"`
}

func lastErrorMessage() string {
	ptr := C.seclusor_last_error()
	if ptr == nil {
		return "seclusor ffi call failed"
	}
	defer C.seclusor_free_string(ptr)
	return C.GoString(ptr)
}

func toError(code C.enum_SeclusorResult) error {
	if code == C.Ok {
		return nil
	}
	return &Error{
		Code:    ResultCode(code),
		Message: lastErrorMessage(),
	}
}

func LoadSecretsJSON(jsonText string) (*SecretsHandle, error) {
	if jsonText == "" {
		return nil, errors.New("jsonText must not be empty")
	}

	cJSON := C.CString(jsonText)
	defer C.free(unsafe.Pointer(cJSON))

	var handle *C.SeclusorSecretsHandle
	if err := toError(C.seclusor_secrets_handle_new_from_json(cJSON, &handle)); err != nil {
		return nil, err
	}
	return &SecretsHandle{ptr: handle}, nil
}

func (h *SecretsHandle) Close() {
	if h == nil || h.ptr == nil {
		return
	}
	C.seclusor_secrets_handle_free(h.ptr)
	h.ptr = nil
}

func (h *SecretsHandle) ensureOpen() error {
	if h == nil || h.ptr == nil {
		return errors.New("secrets handle is nil or closed")
	}
	return nil
}

func cstringOrNil(value string) func() *C.char {
	return func() *C.char {
		if value == "" {
			return nil
		}
		ptr := C.CString(value)
		return ptr
	}
}

func freeCString(ptr *C.char) {
	if ptr != nil {
		C.free(unsafe.Pointer(ptr))
	}
}

func bytesPtr(value []byte) *C.uint8_t {
	if len(value) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&value[0]))
}

func fromJSONString[T any](raw *C.char, into *T) error {
	if raw == nil {
		return errors.New("ffi returned null JSON pointer")
	}
	defer C.seclusor_free_string(raw)
	return json.Unmarshal([]byte(C.GoString(raw)), into)
}

func (h *SecretsHandle) List(projectSlug string) ([]string, error) {
	if err := h.ensureOpen(); err != nil {
		return nil, err
	}

	project := cstringOrNil(projectSlug)()
	defer freeCString(project)

	var out *C.char
	if err := toError(C.seclusor_secrets_list(h.ptr, project, &out)); err != nil {
		return nil, err
	}

	var keys []string
	if err := fromJSONString(out, &keys); err != nil {
		return nil, err
	}
	return keys, nil
}

func (h *SecretsHandle) Get(projectSlug, key string, reveal bool) (*CredentialView, error) {
	if err := h.ensureOpen(); err != nil {
		return nil, err
	}
	if key == "" {
		return nil, errors.New("key must not be empty")
	}

	project := cstringOrNil(projectSlug)()
	defer freeCString(project)
	cKey := C.CString(key)
	defer C.free(unsafe.Pointer(cKey))

	revealInt := C.int(0)
	if reveal {
		revealInt = 1
	}

	var out *C.char
	if err := toError(C.seclusor_secrets_get(h.ptr, project, cKey, revealInt, &out)); err != nil {
		return nil, err
	}

	var cred CredentialView
	if err := fromJSONString(out, &cred); err != nil {
		return nil, err
	}
	return &cred, nil
}

func (h *SecretsHandle) ExportEnv(projectSlug, prefix string, emitRef bool) ([]EnvVar, error) {
	if err := h.ensureOpen(); err != nil {
		return nil, err
	}

	project := cstringOrNil(projectSlug)()
	defer freeCString(project)
	cPrefix := cstringOrNil(prefix)()
	defer freeCString(cPrefix)

	emitRefInt := C.int(0)
	if emitRef {
		emitRefInt = 1
	}

	var out *C.char
	if err := toError(C.seclusor_secrets_export_env(h.ptr, project, cPrefix, emitRefInt, &out)); err != nil {
		return nil, err
	}

	var vars []EnvVar
	if err := fromJSONString(out, &vars); err != nil {
		return nil, err
	}
	return vars, nil
}

func EncryptBundle(inputJSONPath, outputCipherPath string, recipients []string) error {
	if len(recipients) == 0 {
		return errors.New("recipients must not be empty")
	}

	payload, err := json.Marshal(recipients)
	if err != nil {
		return err
	}

	cInput := C.CString(inputJSONPath)
	defer C.free(unsafe.Pointer(cInput))
	cOutput := C.CString(outputCipherPath)
	defer C.free(unsafe.Pointer(cOutput))
	cRecipients := C.CString(string(payload))
	defer C.free(unsafe.Pointer(cRecipients))

	return toError(C.seclusor_encrypt_bundle(cInput, cOutput, cRecipients))
}

func DecryptBundle(inputCipherPath, outputJSONPath, identityFilePath string) error {
	cInput := C.CString(inputCipherPath)
	defer C.free(unsafe.Pointer(cInput))
	cOutput := C.CString(outputJSONPath)
	defer C.free(unsafe.Pointer(cOutput))
	cIdentity := C.CString(identityFilePath)
	defer C.free(unsafe.Pointer(cIdentity))

	return toError(C.seclusor_decrypt_bundle(cInput, cOutput, cIdentity))
}

func GenerateSigningKeypair() ([]byte, []byte, error) {
	secretKey := make([]byte, SigningSecretKeyLen)
	publicKey := make([]byte, SigningPublicKeyLen)
	if err := toError(C.seclusor_signing_generate_keypair(
		bytesPtr(secretKey),
		C.size_t(len(secretKey)),
		bytesPtr(publicKey),
		C.size_t(len(publicKey)),
	)); err != nil {
		return nil, nil, err
	}
	return secretKey, publicKey, nil
}

func SigningPublicKeyFromSecretKey(secretKey []byte) ([]byte, error) {
	publicKey := make([]byte, SigningPublicKeyLen)
	if err := toError(C.seclusor_signing_public_key_from_secret_key(
		bytesPtr(secretKey),
		C.size_t(len(secretKey)),
		bytesPtr(publicKey),
		C.size_t(len(publicKey)),
	)); err != nil {
		return nil, err
	}
	return publicKey, nil
}

func Sign(secretKey, message []byte) ([]byte, error) {
	signature := make([]byte, SignatureLen)
	if err := toError(C.seclusor_signing_sign(
		bytesPtr(secretKey),
		C.size_t(len(secretKey)),
		bytesPtr(message),
		C.size_t(len(message)),
		bytesPtr(signature),
		C.size_t(len(signature)),
	)); err != nil {
		return nil, err
	}
	return signature, nil
}

func Verify(publicKey, message, signature []byte) error {
	return toError(C.seclusor_signing_verify(
		bytesPtr(publicKey),
		C.size_t(len(publicKey)),
		bytesPtr(message),
		C.size_t(len(message)),
		bytesPtr(signature),
		C.size_t(len(signature)),
	))
}

func NewKeyringHandle() (*KeyringHandle, error) {
	var handle *C.SeclusorKeyringHandle
	if err := toError(C.seclusor_keyring_handle_new(&handle)); err != nil {
		return nil, err
	}
	return &KeyringHandle{ptr: handle}, nil
}

func (h *KeyringHandle) Close() {
	if h == nil || h.ptr == nil {
		return
	}
	C.seclusor_keyring_handle_free(h.ptr)
	h.ptr = nil
}

func (h *KeyringHandle) ensureOpen() error {
	if h == nil || h.ptr == nil {
		return errors.New("keyring handle is nil or closed")
	}
	return nil
}

func (h *KeyringHandle) AddRecipient(recipient string) error {
	if err := h.ensureOpen(); err != nil {
		return err
	}
	if recipient == "" {
		return errors.New("recipient must not be empty")
	}
	cRecipient := C.CString(recipient)
	defer C.free(unsafe.Pointer(cRecipient))
	return toError(C.seclusor_keyring_handle_add_recipient(h.ptr, cRecipient))
}

func (h *KeyringHandle) AddIdentityFile(identityFilePath string) error {
	if err := h.ensureOpen(); err != nil {
		return err
	}
	if identityFilePath == "" {
		return errors.New("identityFilePath must not be empty")
	}
	cPath := C.CString(identityFilePath)
	defer C.free(unsafe.Pointer(cPath))
	return toError(C.seclusor_keyring_handle_add_identity_file(h.ptr, cPath))
}

func (h *KeyringHandle) Status() (*KeyringStatus, error) {
	if err := h.ensureOpen(); err != nil {
		return nil, err
	}
	var out *C.char
	if err := toError(C.seclusor_keyring_handle_status(h.ptr, &out)); err != nil {
		return nil, err
	}
	var status KeyringStatus
	if err := fromJSONString(out, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (h *KeyringHandle) RekeyBundle(inputCipherPath, outputCipherPath string) error {
	if err := h.ensureOpen(); err != nil {
		return err
	}
	cInput := C.CString(inputCipherPath)
	defer C.free(unsafe.Pointer(cInput))
	cOutput := C.CString(outputCipherPath)
	defer C.free(unsafe.Pointer(cOutput))
	return toError(C.seclusor_keyring_rekey_bundle(h.ptr, cInput, cOutput))
}
