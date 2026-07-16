//go:build integration

package test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/config"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	domvault "github.com/guardrail/guardrail/internal/domain/vault"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
	"github.com/guardrail/guardrail/internal/platform/database"
)

func newPG(t *testing.T) (*postgres.DB, func()) {
	t.Helper()
	dsn := envOrSkip(t, "GUARDRAIL_TEST_DSN")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	db, err := database.New(ctx, config.PostgresConfig{DSN: dsn, MaxConns: 4, MinConns: 1, MaxConnLifetime: time.Hour})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	return postgres.New(db.Pool), db.Close
}

func envOrSkip(t *testing.T, key string) string {
	t.Helper()
	v := os.Getenv(key)
	if v == "" {
		t.Skipf("%s not set; skipping", key)
	}
	return v
}

func TestIntegration_VaultEnvelopeAndDeviceBinding(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	scope := domassets.Scope{OrganizationID: defaultOrgID}
	vScope := domvault.Scope{OrganizationID: defaultOrgID}

	// Real envelope encryptor.
	kp, err := security.NewEnvKeyProvider(strings.Repeat("m", 40))
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	enc := security.NewEnvelopeEncryptor(kp)

	devices := postgres.NewDeviceRepo(pg)
	creds := postgres.NewCredentialRepo(pg)

	// Register a device.
	dev := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "fw-" + uuid.NewString()[:6],
		Host: "10.0.0." + uuid.NewString()[:2], Port: 443, Scheme: "https", VerifyTLS: true,
		Vendor: "Fortinet", DeviceType: "firewall", Status: "active",
		CustomHeaders: map[string]string{"X-Test": "1"}, Tags: []string{"prod", "edge"},
	}
	if err := devices.Create(ctx, scope, dev); err != nil {
		t.Fatalf("create device: %v", err)
	}

	// Store a sealed credential — plaintext must never hit the DB.
	const password = "SuperSecretDevicePw!"
	sealed, err := enc.Seal([]byte(password))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	cred := &domvault.Credential{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "fw-admin",
		Type: domvault.TypePassword, Username: "admin", Injection: domvault.InjectForm, Sealed: sealed,
	}
	if err := creds.Create(ctx, vScope, cred); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	if err := creds.BindToDevice(ctx, vScope, dev.ID, cred.ID, true); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// Resolve for the device (as the gateway would) and decrypt.
	resolved, err := creds.ResolveForDevice(ctx, vScope, dev.ID)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	plaintext, err := enc.Open(resolved.Sealed)
	if err != nil {
		t.Fatalf("open resolved: %v", err)
	}
	if string(plaintext) != password {
		t.Fatalf("decrypted secret mismatch: %q", plaintext)
	}
	if resolved.Username != "admin" {
		t.Fatalf("username = %q", resolved.Username)
	}

	// The read path (GetByID) returns metadata; the stored ciphertext is not the
	// plaintext.
	got, err := creds.GetByID(ctx, vScope, cred.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if strings.Contains(string(got.Sealed.Ciphertext), password) {
		t.Fatal("ciphertext contains plaintext — envelope encryption failed")
	}
}
