//go:build cgo

package seclusor

import (
	"bytes"
	"testing"
)

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

func TestWipeBytesZeroesSlice(t *testing.T) {
	value := []byte{1, 2, 3, 4}
	WipeBytes(value)
	if !bytes.Equal(value, []byte{0, 0, 0, 0}) {
		t.Fatalf("expected wiped slice, got %#v", value)
	}
}
