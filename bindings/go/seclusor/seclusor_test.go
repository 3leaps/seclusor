//go:build cgo

package seclusor

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testDataPath(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("testdata", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("testdata %s: %v", name, err)
	}
	return p
}

// copyIdentityFixture materializes a tracked identity fixture under t.TempDir()
// with mode 0600. Git stores ordinary files as 0644 on checkout, which
// AddIdentityFile correctly rejects on Unix.
func copyIdentityFixture(t *testing.T, name string) string {
	t.Helper()
	src := testDataPath(t, name)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatalf("read identity fixture %s: %v", name, err)
	}
	dst := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(dst, data, 0o600); err != nil {
		t.Fatalf("write identity fixture %s: %v", name, err)
	}
	return dst
}

func TestSecretsHandleListGetExport(t *testing.T) {
	jsonText := `{"schema_version":"v1.0.0","env_prefix":"APP_","projects":[{"project_slug":"demo","credentials":{"API_KEY":{"type":"secret","value":"sk-123"}}}]}`

	h, err := LoadSecretsJSON(jsonText)
	if err != nil {
		t.Fatalf("LoadSecretsJSON: %v", err)
	}
	defer h.Close()

	keys, err := h.List("demo")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "API_KEY" {
		t.Fatalf("unexpected keys: %#v", keys)
	}

	cred, err := h.Get("demo", "API_KEY", false)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !cred.Redacted || cred.Value == nil || *cred.Value != "<redacted>" {
		t.Fatalf("unexpected credential view: %#v", cred)
	}

	vars, err := h.ExportEnv("demo", "APP_", false)
	if err != nil {
		t.Fatalf("ExportEnv: %v", err)
	}
	if len(vars) != 1 || vars[0].Key != "APP_API_KEY" {
		t.Fatalf("unexpected env vars: %#v", vars)
	}
}

func TestKeyringHandleStatusAndValidation(t *testing.T) {
	h, err := NewKeyringHandle()
	if err != nil {
		t.Fatalf("NewKeyringHandle: %v", err)
	}
	defer h.Close()

	status, err := h.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if status.IdentityCount != 0 || status.RecipientCount != 0 {
		t.Fatalf("unexpected initial status: %#v", status)
	}

	if err := h.AddRecipient("not-a-recipient"); err == nil {
		t.Fatalf("expected add recipient to fail for invalid input")
	}
}

func TestSigningGenerateDeriveSignVerify(t *testing.T) {
	secretKey, publicKey, err := GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair: %v", err)
	}
	if len(secretKey) != SigningSecretKeyLen {
		t.Fatalf("unexpected secret key length: %d", len(secretKey))
	}
	if len(publicKey) != SigningPublicKeyLen {
		t.Fatalf("unexpected public key length: %d", len(publicKey))
	}

	derivedPublicKey, err := SigningPublicKeyFromSecretKey(secretKey)
	if err != nil {
		t.Fatalf("SigningPublicKeyFromSecretKey: %v", err)
	}
	if !bytes.Equal(derivedPublicKey, publicKey) {
		t.Fatalf("derived public key mismatch")
	}

	message := []byte("ffi signing message")
	signature, err := Sign(secretKey, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(signature) != SignatureLen {
		t.Fatalf("unexpected signature length: %d", len(signature))
	}

	if err := Verify(publicKey, message, signature); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestSigningEmptyMessageAndErrorCategories(t *testing.T) {
	secretKey, publicKey, err := GenerateSigningKeypair()
	if err != nil {
		t.Fatalf("GenerateSigningKeypair: %v", err)
	}

	signature, err := Sign(secretKey, nil)
	if err != nil {
		t.Fatalf("Sign nil message: %v", err)
	}
	if err := Verify(publicKey, nil, signature); err != nil {
		t.Fatalf("Verify nil message: %v", err)
	}

	_, err = Sign(secretKey[:SigningSecretKeyLen-1], []byte("msg"))
	if err == nil {
		t.Fatalf("expected wrong-length secret key to fail")
	}
	ffiErr, ok := err.(*Error)
	if !ok || ffiErr.Code != ResultCrypto {
		t.Fatalf("expected ResultCrypto for wrong secret key length, got %#v", err)
	}

	err = Verify(publicKey[:SigningPublicKeyLen-1], []byte("msg"), signature)
	if err == nil {
		t.Fatalf("expected wrong-length public key to fail")
	}
	ffiErr, ok = err.(*Error)
	if !ok || ffiErr.Code != ResultCrypto {
		t.Fatalf("expected ResultCrypto for wrong public key length, got %#v", err)
	}

	err = Verify(publicKey, []byte("msg"), signature[:SignatureLen-1])
	if err == nil {
		t.Fatalf("expected wrong-length signature to fail")
	}
	ffiErr, ok = err.(*Error)
	if !ok || ffiErr.Code != ResultCrypto {
		t.Fatalf("expected ResultCrypto for wrong signature length, got %#v", err)
	}

	badSignature := bytes.Repeat([]byte{0xff}, SignatureLen)
	err = Verify(publicKey, nil, badSignature)
	if err == nil {
		t.Fatalf("expected semantically invalid signature to fail")
	}
	ffiErr, ok = err.(*Error)
	if !ok || ffiErr.Code != ResultCrypto {
		t.Fatalf("expected ResultCrypto for bad signature verify failure, got %#v", err)
	}
}

func TestSigningDeterministicVector(t *testing.T) {
	secretKey := []byte{
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	}
	message := []byte("d12 deterministic signing vector")

	publicKey, err := SigningPublicKeyFromSecretKey(secretKey)
	if err != nil {
		t.Fatalf("SigningPublicKeyFromSecretKey: %v", err)
	}
	signature, err := Sign(secretKey, message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	wantPublicKey, err := hex.DecodeString("03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8")
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	wantSignature, err := hex.DecodeString("e158fc7f04a9f0797b0e8e83bff679fa01bf7c60d8ab91d5efd7b90ce3227a025b6e10cb23e83d36fb50cb2f0e97a2a6da684861d60b136ccf82e1a79331b802")
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	if !bytes.Equal(publicKey, wantPublicKey) {
		t.Fatalf("unexpected public key: %x", publicKey)
	}
	if !bytes.Equal(signature, wantSignature) {
		t.Fatalf("unexpected signature: %x", signature)
	}
}

func TestWipeBytesZeroesSlice(t *testing.T) {
	value := []byte{1, 2, 3, 4}
	WipeBytes(value)
	if !bytes.Equal(value, []byte{0, 0, 0, 0}) {
		t.Fatalf("expected wiped slice, got %#v", value)
	}
}

func openTestKeyring(t *testing.T) *KeyringHandle {
	t.Helper()
	kr, err := NewKeyringHandle()
	if err != nil {
		t.Fatalf("NewKeyringHandle: %v", err)
	}
	if err := kr.AddIdentityFile(copyIdentityFixture(t, "test-identity.txt")); err != nil {
		t.Fatalf("AddIdentityFile: %v", err)
	}
	return kr
}

func assertRevealedAPIKey(t *testing.T, h *SecretsHandle) {
	t.Helper()
	keys, err := h.List("demo")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 1 || keys[0] != "API_KEY" {
		t.Fatalf("unexpected keys: %#v", keys)
	}
	cred, err := h.Get("demo", "API_KEY", true)
	if err != nil {
		t.Fatalf("Get reveal: %v", err)
	}
	if cred.Value == nil || *cred.Value != "sk-123" || cred.Redacted {
		t.Fatalf("unexpected revealed credential: %#v", cred)
	}
	vars, err := h.ExportEnv("demo", "APP_", false)
	if err != nil {
		t.Fatalf("ExportEnv: %v", err)
	}
	if len(vars) != 1 || vars[0].Key != "APP_API_KEY" || vars[0].Value != "sk-123" {
		t.Fatalf("unexpected export: %#v", vars)
	}
}

func TestLoadSecretsBundleRoundtrip(t *testing.T) {
	data, err := os.ReadFile(testDataPath(t, "secrets.age"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	if !bytes.Contains(data, []byte("age-encryption.org")) {
		t.Fatalf("bundle fixture missing age header")
	}
	// Pointer+length must tolerate embedded NULs (C strings cannot).
	if !bytes.Contains(data, []byte{0}) {
		t.Fatalf("bundle fixture must contain at least one NUL byte for pointer+length coverage")
	}
	kr := openTestKeyring(t)
	defer kr.Close()

	h, err := LoadSecretsBundle(data, kr)
	if err != nil {
		t.Fatalf("LoadSecretsBundle: %v", err)
	}
	defer h.Close()
	assertRevealedAPIKey(t, h)
}

func TestLoadSecretsInlineRoundtrip(t *testing.T) {
	data, err := os.ReadFile(testDataPath(t, "inline-encrypted.json"))
	if err != nil {
		t.Fatalf("read inline: %v", err)
	}
	kr := openTestKeyring(t)
	defer kr.Close()

	h, err := LoadSecretsInline(data, kr)
	if err != nil {
		t.Fatalf("LoadSecretsInline: %v", err)
	}
	defer h.Close()
	assertRevealedAPIKey(t, h)
}

func TestLoadSecretsEncryptedFailures(t *testing.T) {
	bundle, err := os.ReadFile(testDataPath(t, "secrets.age"))
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	inline, err := os.ReadFile(testDataPath(t, "inline-encrypted.json"))
	if err != nil {
		t.Fatalf("read inline: %v", err)
	}
	plain, err := os.ReadFile(testDataPath(t, "plaintext.json"))
	if err != nil {
		t.Fatalf("read plaintext: %v", err)
	}

	emptyKR, err := NewKeyringHandle()
	if err != nil {
		t.Fatalf("empty keyring: %v", err)
	}
	defer emptyKR.Close()

	if _, err := LoadSecretsBundle(bundle, emptyKR); err == nil {
		t.Fatalf("expected empty keyring bundle load to fail")
	}
	if _, err := LoadSecretsInline(inline, emptyKR); err == nil {
		t.Fatalf("expected empty keyring inline load to fail")
	}
	if _, err := LoadSecretsBundle(nil, emptyKR); err == nil {
		t.Fatalf("expected empty data to fail")
	}
	if _, err := LoadSecretsBundle(bundle, nil); err == nil {
		t.Fatalf("expected nil keyring to fail")
	}

	kr := openTestKeyring(t)
	defer kr.Close()

	// Named constructor rejects the other codec / plaintext.
	if _, err := LoadSecretsBundle(inline, kr); err == nil {
		t.Fatalf("bundle loader must reject inline JSON")
	}
	if _, err := LoadSecretsInline(bundle, kr); err == nil {
		t.Fatalf("inline loader must reject bundle")
	}
	if _, err := LoadSecretsInline(plain, kr); err == nil {
		t.Fatalf("inline loader must reject plaintext JSON")
	}

	// Closed keyring.
	kr2 := openTestKeyring(t)
	kr2.Close()
	if _, err := LoadSecretsBundle(bundle, kr2); err == nil {
		t.Fatalf("closed keyring must fail")
	}

	// Wrong identity: fails closed without leaking secrets or ciphertext body.
	wrongKR, err := NewKeyringHandle()
	if err != nil {
		t.Fatalf("NewKeyringHandle wrong: %v", err)
	}
	defer wrongKR.Close()
	if err := wrongKR.AddIdentityFile(copyIdentityFixture(t, "wrong-identity.txt")); err != nil {
		t.Fatalf("AddIdentityFile wrong: %v", err)
	}
	_, err = LoadSecretsBundle(bundle, wrongKR)
	if err == nil {
		t.Fatalf("expected wrong identity to fail")
	}
	msg := err.Error()
	for _, leak := range []string{"sk-123", "AGE-SECRET-KEY-", "age-encryption.org"} {
		if strings.Contains(msg, leak) {
			t.Fatalf("wrong-identity error leaked sensitive material %q: %q", leak, msg)
		}
	}

	// Wrong-codec error must not include the secret value either.
	_, err = LoadSecretsBundle(inline, kr)
	if err == nil {
		t.Fatalf("expected wrong-codec error")
	}
	if strings.Contains(err.Error(), "sk-123") {
		t.Fatalf("error leaked secret: %q", err.Error())
	}
}
