//go:build integration

package test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	appvault "github.com/guardrail/guardrail/internal/app/vault"
	"github.com/guardrail/guardrail/internal/config"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
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
	// A nil owner binds the device's SHARED credential — the only kind that
	// existed before per-user accounts, and what this device (in the default
	// 'shared' mode) resolves for everybody entitled to it.
	if err := creds.BindToDevice(ctx, vScope, dev.ID, cred.ID, nil); err != nil {
		t.Fatalf("bind: %v", err)
	}

	// Resolve for the device (as the gateway would) and decrypt.
	resolved, err := creds.ResolveForDevice(ctx, vScope, dev.ID, uuid.New())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	plaintext, err := enc.Open(resolved.Credential.Sealed)
	if err != nil {
		t.Fatalf("open resolved: %v", err)
	}
	if string(plaintext) != password {
		t.Fatalf("decrypted secret mismatch: %q", plaintext)
	}
	if resolved.Credential.Username != "admin" {
		t.Fatalf("username = %q", resolved.Credential.Username)
	}
	if resolved.PerUser || resolved.Inherited {
		t.Fatal("a shared credential is neither per-user nor inherited")
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

// Rotating a per-user account must not change how its secret is injected.
//
// The console's Rotate dialog sends a username and a secret. It used to send no
// injection method, and the write path resolved an absent one to the scheme's
// default — so an account bound with an SSH private key came back as
// ssh-password with the PEM still in the vault, and the rotation reported
// success. The first anybody heard of it was the next failed connect.
func TestIntegration_RotatingAnAccountKeepsItsInjectionMethod(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	kp, err := security.NewEnvKeyProvider(strings.Repeat("m", 40))
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	svc := appvault.NewService(postgres.NewCredentialRepo(pg), security.NewEnvelopeEncryptor(kp), nil)

	scope := domassets.Scope{OrganizationID: defaultOrgID}
	dev := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "sw-" + uuid.NewString()[:6],
		Host: "sw-" + uuid.NewString() + ".test", Port: 22, Scheme: "ssh", DeviceType: "switch", Status: "active",
		CredentialMode: domassets.CredentialPerUser,
	}
	if err := postgres.NewDeviceRepo(pg).Create(ctx, scope, dev); err != nil {
		t.Fatalf("create device: %v", err)
	}
	actor := domiam.Claims{OrganizationID: defaultOrgID, UserID: uuid.New()}
	// A real row: device_credentials.user_id is a foreign key, so a made-up id
	// fails the bind rather than the assertion.
	owner := &domiam.User{
		ID: uuid.New(), OrganizationID: defaultOrgID,
		Email:    domiam.NewEmail("rot-" + uuid.NewString()[:8] + "@example.com"),
		Username: "rot", PasswordHash: "x", AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := postgres.NewUserRepo(pg).Create(ctx, domiam.TenantScope{OrganizationID: defaultOrgID}, owner); err != nil {
		t.Fatalf("create user: %v", err)
	}
	userID := owner.ID

	bind := func(injection domvault.InjectionMethod, secret string) {
		t.Helper()
		if err := svc.SetForUser(ctx, actor, &dev.ID, nil, userID, appvault.CredentialInput{
			Name: "alice-admin", Username: "alice-admin",
			Injection: injection, Scheme: dev.Scheme, Secret: secret,
		}); err != nil {
			t.Fatalf("bind (%s): %v", injection, err)
		}
	}
	injectionNow := func() domvault.InjectionMethod {
		t.Helper()
		own, _, lerr := svc.DeviceBindings(ctx, actor, dev.ID)
		if lerr != nil {
			t.Fatalf("list bindings: %v", lerr)
		}
		for i := range own {
			if own[i].UserID != nil && *own[i].UserID == userID {
				return own[i].Injection
			}
		}
		t.Fatal("the binding disappeared")
		return ""
	}

	bind(domvault.InjectSSHKey, "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----")
	if got := injectionNow(); got != domvault.InjectSSHKey {
		t.Fatalf("after binding: injection = %q, want %q", got, domvault.InjectSSHKey)
	}

	// Exactly what the Rotate dialog sends: a username, a new secret, no method.
	if err := svc.SetForUser(ctx, actor, &dev.ID, nil, userID, appvault.CredentialInput{
		Name: "alice-admin", Username: "alice-admin", Scheme: dev.Scheme,
		Secret: "-----BEGIN OPENSSH PRIVATE KEY-----\ny\n-----END OPENSSH PRIVATE KEY-----",
	}); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := injectionNow(); got != domvault.InjectSSHKey {
		t.Fatalf("rotation changed the injection method to %q; the key is now offered as a password", got)
	}

	// Naming a method still changes it — this keeps an omission from being read
	// as a decision, it does not make the field unwritable.
	bind(domvault.InjectSSHPassword, "hunter2")
	if got := injectionNow(); got != domvault.InjectSSHPassword {
		t.Fatalf("an explicit method did not apply: injection = %q", got)
	}
}
