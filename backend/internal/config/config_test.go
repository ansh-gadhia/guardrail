package config

import (
	"strings"
	"testing"
)

// setRequired sets the minimum env for a valid Load, then applies overrides.
func setRequired(t *testing.T, overrides map[string]string) {
	t.Helper()
	base := map[string]string{
		"GUARDRAIL_POSTGRES_DSN":    "postgres://u:p@localhost:5432/guardrail",
		"GUARDRAIL_JWT_SIGNING_KEY": strings.Repeat("a", 32),
		"GUARDRAIL_MASTER_KEY":      strings.Repeat("b", 32),
	}
	for k, v := range base {
		t.Setenv(k, v)
	}
	for k, v := range overrides {
		t.Setenv(k, v)
	}
}

func TestLoad_Defaults(t *testing.T) {
	setRequired(t, nil)
	c, err := Load()
	if err != nil {
		t.Fatalf("expected valid config, got error: %v", err)
	}
	if c.HTTP.Addr != ":8080" {
		t.Errorf("default HTTP addr = %q, want :8080", c.HTTP.Addr)
	}
	if c.Auth.AccessTokenTTL.Minutes() != 15 {
		t.Errorf("default access TTL = %v, want 15m", c.Auth.AccessTokenTTL)
	}
}

func TestLoad_MissingSecretsFailsClosed(t *testing.T) {
	t.Setenv("GUARDRAIL_POSTGRES_DSN", "postgres://x")
	// JWT + master key intentionally unset.
	if _, err := Load(); err == nil {
		t.Fatal("expected error when required secrets are missing")
	}
}

func TestLoad_ShortSecretRejected(t *testing.T) {
	setRequired(t, map[string]string{"GUARDRAIL_MASTER_KEY": "tooshort"})
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "MASTER_KEY") {
		t.Fatalf("expected master key length error, got: %v", err)
	}
}

func TestLoad_WildcardCORSRejectedInProduction(t *testing.T) {
	setRequired(t, map[string]string{
		"GUARDRAIL_ENV":                "production",
		"GUARDRAIL_CORS_ALLOW_ORIGINS": "*",
	})
	if _, err := Load(); err == nil {
		t.Fatal("expected wildcard CORS to be rejected in production")
	}
}

// A negative memory knob converts to an enormous unsigned requirement
// downstream and would refuse every recorded session. Boot must reject it
// rather than silently disabling recording across the estate.
func TestNegativeIsolationMemoryRejected(t *testing.T) {
	for _, key := range []string{
		"GUARDRAIL_ISOLATION_SESSION_MEMORY_MB",
		"GUARDRAIL_ISOLATION_HOST_RESERVE_MB",
	} {
		t.Run(key, func(t *testing.T) {
			setRequired(t, nil)
			t.Setenv(key, "-1")
			if _, err := Load(); err == nil {
				t.Fatalf("%s=-1 must fail validation", key)
			}
		})
	}
}

func TestIsolationMemoryDefaults(t *testing.T) {
	setRequired(t, nil)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Browser.SessionMemoryMB <= 0 || c.Browser.HostReserveMB <= 0 {
		t.Errorf("defaults must be positive: session=%d reserve=%d",
			c.Browser.SessionMemoryMB, c.Browser.HostReserveMB)
	}
}
