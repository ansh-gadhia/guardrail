//go:build integration

// Fixtures for the C1 tests — binding integrity and credential AAD.
//
// Both suites were written against a populated deployment: they asked the
// database what it happened to contain and worked on that. Against a CLEAN
// database — which is what CI runs — they found nothing and called t.Skip, so
// the fix for the most serious finding in the audit had a green build and no
// coverage whatsoever. Five tests skipped and the run still reported ok.
//
// These helpers give each of those tests rows of its own, so a skip now means a
// missing environment variable rather than an empty table. Everything created
// here is tracked for teardown by the residue purge.
package test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	domvault "github.com/guardrail/guardrail/internal/domain/vault"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// seededBinding is one live device with a shared, UNSIGNED binding to a
// credential — the pre-0035 row shape the upgrade has to keep working — plus a
// second credential to repoint that binding at.
type seededBinding struct {
	device    uuid.UUID
	cred      uuid.UUID
	otherCred uuid.UUID
	org       uuid.UUID
}

// seedBinding creates that shape, sealed under the DEPLOYMENT's master key.
//
// Not the fixture key the other suites use: TestCredentialAADResolveStillWorks
// AfterConversion resolves every live binding and then opens the secret with the
// deployment's own encryptor, so a row sealed under anything else would fail the
// test for a reason that has nothing to do with what it is checking.
func seedBinding(t *testing.T, pg *postgres.DB) seededBinding {
	t.Helper()
	ctx := context.Background()
	enc, repo := deploymentSealer(t, pg)

	d := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID,
		Name: "c1-" + uuid.NewString()[:8],
		// Uniquely indexed on (org, host, port), and a short suffix collides once
		// the suite has created enough of them.
		Host: "c1-" + uuid.NewString() + ".test", Port: 22, Scheme: "ssh",
		Status: "active", DeviceType: "switch",
		CredentialMode: domassets.CredentialShared, MinApprovals: 1,
	}
	if err := postgres.NewDeviceRepo(pg).Create(ctx, domassets.Scope{OrganizationID: defaultOrgID}, d); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	trackDevice(t, d.ID)

	cred := seedCredential(t, pg, enc, repo, "c1-bound")
	other := seedCredential(t, pg, enc, repo, "c1-other")

	// repo carries no binding signer, so this lands with binding_mac NULL —
	// exactly what a database written before migration 0035 looks like.
	if err := repo.BindToDevice(ctx, domvault.Scope{OrganizationID: defaultOrgID}, d.ID, cred, nil); err != nil {
		t.Fatalf("seed binding: %v", err)
	}
	return seededBinding{device: d.ID, cred: cred, otherCred: other, org: defaultOrgID}
}

// seedLegacyCredential stores a credential sealed the pre-0036 way: no tag over
// any associated data, so aad_version is 0 and ReSealLegacyCredentials has
// something real to convert.
func seedLegacyCredential(t *testing.T, pg *postgres.DB) uuid.UUID {
	t.Helper()
	enc, repo := deploymentSealer(t, pg)
	sealed, err := enc.Seal([]byte("legacy-secret"), nil) // nil AAD == pre-0036
	if err != nil {
		t.Fatalf("seal legacy: %v", err)
	}
	if sealed.AADVersion != domvault.AADNone {
		t.Fatalf("fixture is not legacy: aad_version=%d", sealed.AADVersion)
	}
	return storeCredential(t, repo, sealed, "c1-legacy")
}

// deploymentSealer builds an encryptor on the deployment's master key and
// registers that KEK, because credentials.kek_id is a foreign key into
// encryption_keys and the id is derived from the key itself — so a key the
// registry has never seen fails every insert on the constraint.
func deploymentSealer(t *testing.T, pg *postgres.DB) (*security.EnvelopeEncryptor, *postgres.CredentialRepo) {
	t.Helper()
	kp, err := security.NewEnvKeyProvider(masterKey(t))
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	kekID, _, err := kp.Active()
	if err != nil {
		t.Fatalf("active kek: %v", err)
	}
	trackKEK(t, kekID)
	repo := postgres.NewCredentialRepo(pg)
	if err := repo.RegisterKEK(context.Background(), kekID, "env"); err != nil {
		t.Fatalf("register kek: %v", err)
	}
	return security.NewEnvelopeEncryptor(kp), repo
}

// seedCredential stores one sealed in the CURRENT shape — bound to its own
// identity, as everything written after 0036 is.
func seedCredential(t *testing.T, pg *postgres.DB, enc *security.EnvelopeEncryptor,
	repo *postgres.CredentialRepo, name string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	sealed, err := enc.Seal([]byte("seed-secret"), domvault.CredentialAAD(defaultOrgID, id))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	return storeCredentialWithID(t, repo, id, sealed, name)
}

func storeCredential(t *testing.T, repo *postgres.CredentialRepo,
	sealed domvault.SealedSecret, name string) uuid.UUID {
	t.Helper()
	return storeCredentialWithID(t, repo, uuid.New(), sealed, name)
}

func storeCredentialWithID(t *testing.T, repo *postgres.CredentialRepo, id uuid.UUID,
	sealed domvault.SealedSecret, name string) uuid.UUID {
	t.Helper()
	c := &domvault.Credential{
		ID: id, OrganizationID: defaultOrgID,
		Name: name + "-" + uuid.NewString()[:8], Type: domvault.TypePassword,
		Username: name, Injection: domvault.InjectSSHPassword, Sealed: sealed,
	}
	if err := repo.Create(context.Background(), domvault.Scope{OrganizationID: defaultOrgID}, c); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	return trackCredential(t, c.ID)
}
