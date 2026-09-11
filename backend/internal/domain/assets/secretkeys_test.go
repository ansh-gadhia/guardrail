package assets

import (
	"errors"
	"strings"
	"testing"
)

// A credential-bearing header on the device row is stored in the clear, beside
// a vault that goes to considerable lengths to avoid exactly that.
func TestValidateCustomHeadersRefusesCredentialHeaders(t *testing.T) {
	for _, name := range []string{
		"Authorization", "authorization", "AUTHORIZATION",
		"Proxy-Authorization", "Cookie", "X-API-Key", "x-api-key",
		"X-Auth-Token", "ApiKey", "X-Vault-Token",
		// Caught by the substring hints rather than the exact list.
		"X-Device-Password", "my_secret_header", "X-Session-Token",
	} {
		err := ValidateCustomHeaders(map[string]string{name: "anything"})
		if err == nil {
			t.Errorf("%q was accepted as a plaintext device header", name)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: error does not wrap ErrInvalid: %v", name, err)
		}
		// The message has to say where the value belongs, or the operator just
		// tries a different field.
		if !strings.Contains(err.Error(), "injection") {
			t.Errorf("%q: message does not point at the vault: %v", name, err)
		}
	}
}

// Ordinary headers are the reason the field exists.
func TestValidateCustomHeadersAllowsOrdinaryHeaders(t *testing.T) {
	ok := map[string]string{
		"User-Agent":       "GuardRail",
		"Accept-Language":  "en",
		"X-Forwarded-Host": "console.internal",
		"X-Tenant":         "acme",
		"Referer":          "https://console.internal/",
	}
	if err := ValidateCustomHeaders(ok); err != nil {
		t.Fatalf("a legitimate header set was refused: %v", err)
	}
	if err := ValidateCustomHeaders(nil); err != nil {
		t.Errorf("nil headers refused: %v", err)
	}
}

// Only the NAME is inspected. A validator that pattern-matched values would be
// reading the thing it is trying to keep out of its hands.
func TestValidateCustomHeadersIgnoresValues(t *testing.T) {
	if err := ValidateCustomHeaders(map[string]string{
		"X-Tenant": "Bearer eyJhbGciOiJIUzI1NiJ9.looks-like-a-token",
	}); err != nil {
		t.Fatalf("a header was refused for the shape of its VALUE: %v", err)
	}
}

func TestValidateFreeformKeys(t *testing.T) {
	if err := ValidateFreeformKeys("metadata", map[string]any{"db_password": "x"}); err == nil {
		t.Error("a password-named key was accepted")
	}
	if err := ValidateFreeformKeys("metadata", map[string]any{"apiSecret": "x"}); err == nil {
		t.Error("a secret-named key was accepted")
	}
	if err := ValidateFreeformKeys("metadata", map[string]any{
		"owner": "ops", "rack": "B12", "notes": "replaced 2026-01",
	}); err != nil {
		t.Errorf("ordinary metadata refused: %v", err)
	}
}

// A Slack or Teams incoming-webhook URL IS a bearer credential — the path is
// the secret — and refusing those would remove the feature. So the validator
// catches only what is unambiguously wrong and has somewhere better to be.
func TestValidateChannelConfig(t *testing.T) {
	refuse := []map[string]any{
		{"url": "https://user:hunter2@hooks.example.com/notify"},
		{"url": "https://hooks.example.com/notify?token=abc123"},
		{"url": "https://hooks.example.com/notify?api_key=abc123"},
		{"password": "hunter2"},
	}
	for _, cfg := range refuse {
		if err := ValidateChannelConfig(cfg); err == nil {
			t.Errorf("accepted a config that stores a credential in the clear: %v", cfg)
		}
	}

	allow := []map[string]any{
		{"url": "https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXX"},
		{"url": "https://hooks.example.com/notify?channel=ops&format=json"},
		{"address": "soc@corp.example"},
		{},
		nil,
	}
	for _, cfg := range allow {
		if err := ValidateChannelConfig(cfg); err != nil {
			t.Errorf("refused a legitimate channel config %v: %v", cfg, err)
		}
	}
}
