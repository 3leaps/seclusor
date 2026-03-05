//go:build cgo

package seclusor

import (
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
