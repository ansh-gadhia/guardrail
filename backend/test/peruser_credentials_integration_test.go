//go:build integration

// Per-user credential resolution, exercised against a live migrated database so
// the recursive group walk and the credential_mode branch are run as SQL rather
// than as an assumption.
//
//	GUARDRAIL_TEST_DSN=postgres://guardrail_app:apppass@127.0.0.1:5433/guardrail?sslmode=disable \
//	  go test -tags=integration ./test/...
package test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	domvault "github.com/guardrail/guardrail/internal/domain/vault"
	"github.com/guardrail/guardrail/internal/infra/postgres"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// credFixture builds the collaborators every test here needs.
type credFixture struct {
	devices *postgres.DeviceRepo
	creds   *postgres.CredentialRepo
	groups  *postgres.AssetGroupRepo
	users   *postgres.UserRepo
	aScope  domassets.Scope
	vScope  domvault.Scope
	enc     domvault.Encryptor
}

func newCredFixture(t *testing.T, pg *postgres.DB) *credFixture {
	t.Helper()
	kp, err := security.NewEnvKeyProvider(strings.Repeat("m", 40))
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	return &credFixture{
		devices: postgres.NewDeviceRepo(pg),
		creds:   postgres.NewCredentialRepo(pg),
		groups:  postgres.NewAssetGroupRepo(pg),
		users:   postgres.NewUserRepo(pg),
		aScope:  domassets.Scope{OrganizationID: defaultOrgID},
		vScope:  domvault.Scope{OrganizationID: defaultOrgID},
		enc:     security.NewEnvelopeEncryptor(kp),
	}
}

func (f *credFixture) device(t *testing.T, ctx context.Context, mode string) *domassets.Device {
	t.Helper()
	d := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "sw-" + uuid.NewString()[:8],
		// Fully unique host: devices are uniquely indexed on (org, host, port), and
		// a short random suffix collides once the suite has created enough of them.
		Host: "dev-" + uuid.NewString() + ".test", Port: 22, Scheme: "ssh", Status: "active",
		DeviceType: "switch", CredentialMode: mode, MinApprovals: 1,
	}
	if err := f.devices.Create(ctx, f.aScope, d); err != nil {
		t.Fatalf("create device: %v", err)
	}
	return d
}

// credential seals a secret and returns the stored credential id.
func (f *credFixture) credential(t *testing.T, ctx context.Context, username, secret string) uuid.UUID {
	t.Helper()
	sealed, err := f.enc.Seal([]byte(secret))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	c := &domvault.Credential{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: username,
		Type: domvault.TypePassword, Username: username,
		Injection: domvault.InjectSSHPassword, Sealed: sealed,
	}
	if err := f.creds.Create(ctx, f.vScope, c); err != nil {
		t.Fatalf("create credential: %v", err)
	}
	return c.ID
}

// A shared device behaves exactly as it did before per-user accounts existed:
// everyone entitled resolves the one credential bound with no owner.
func TestIntegration_SharedModeResolvesForAnyone(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newCredFixture(t, pg)

	d := f.device(t, ctx, domassets.CredentialShared)
	cid := f.credential(t, ctx, "admin", "sharedpass")
	if err := f.creds.BindToDevice(ctx, f.vScope, d.ID, cid, nil); err != nil {
		t.Fatalf("bind shared: %v", err)
	}

	// Two unrelated people, neither of whom has an account of their own.
	for _, who := range []uuid.UUID{uuid.New(), uuid.New()} {
		res, err := f.creds.ResolveForDevice(ctx, f.vScope, d.ID, who)
		if err != nil {
			t.Fatalf("resolve for %v: %v", who, err)
		}
		if res.Credential.Username != "admin" {
			t.Fatalf("expected the shared credential, got %q", res.Credential.Username)
		}
		if res.PerUser || res.Inherited {
			t.Fatal("a shared credential is neither per-user nor inherited")
		}
		ok, err := f.creds.HasCredentialForDevice(ctx, f.vScope, d.ID, who)
		if err != nil || !ok {
			t.Fatalf("pre-flight disagreed with resolution: ok=%v err=%v", ok, err)
		}
	}
}

// The bug this whole feature turns on: a per-user device must NOT fall back to
// the shared credential. Falling back would log somebody into the device as the
// shared admin account when they were supposed to appear in its own logs under
// their own name — destroying the attribution the mode exists to create.
func TestIntegration_PerUserNeverFallsBackToShared(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newCredFixture(t, pg)

	d := f.device(t, ctx, domassets.CredentialPerUser)
	shared := f.credential(t, ctx, "root", "sharedpass")
	if err := f.creds.BindToDevice(ctx, f.vScope, d.ID, shared, nil); err != nil {
		t.Fatalf("bind shared: %v", err)
	}

	stranger := uuid.New()
	if _, err := f.creds.ResolveForDevice(ctx, f.vScope, d.ID, stranger); !errors.Is(err, domvault.ErrNotFound) {
		t.Fatalf("per-user resolution must refuse rather than use the shared credential, got %v", err)
	}
	// And the pre-flight must agree, or a session gets created for a connect
	// that cannot be completed.
	ok, err := f.creds.HasCredentialForDevice(ctx, f.vScope, d.ID, stranger)
	if err != nil {
		t.Fatalf("pre-flight: %v", err)
	}
	if ok {
		t.Fatal("pre-flight said yes where resolution says no: the session would be created, " +
			"the audit event emitted, and the failure would land mid-connect")
	}
}

// A person's own account on the device wins, and is reported as per-user.
func TestIntegration_PerUserResolvesOwnAccount(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newCredFixture(t, pg)

	d := f.device(t, ctx, domassets.CredentialPerUser)
	alice := makeUser(t, ctx, f, "alice")
	bob := makeUser(t, ctx, f, "bob")

	aCred := f.credential(t, ctx, "alice-admin", "alicepass")
	bCred := f.credential(t, ctx, "bob-admin", "bobpass")
	if err := f.creds.BindToDevice(ctx, f.vScope, d.ID, aCred, &alice); err != nil {
		t.Fatalf("bind alice: %v", err)
	}
	if err := f.creds.BindToDevice(ctx, f.vScope, d.ID, bCred, &bob); err != nil {
		t.Fatalf("bind bob: %v", err)
	}

	for who, want := range map[uuid.UUID]string{alice: "alice-admin", bob: "bob-admin"} {
		res, err := f.creds.ResolveForDevice(ctx, f.vScope, d.ID, who)
		if err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if res.Credential.Username != want {
			t.Fatalf("expected %q, got %q — people are being injected with each other's accounts",
				want, res.Credential.Username)
		}
		if !res.PerUser {
			t.Fatal("resolution should report per-user provenance")
		}
		if res.Inherited {
			t.Fatal("a binding on the device itself is not inherited")
		}
	}
}

// A group binding covers every device in the subtree, and the NEAREST ancestor
// wins. Without this, per-user accounts stop being usable at about ten devices.
func TestIntegration_GroupBindingInheritsAndNearestWins(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newCredFixture(t, pg)

	// Datacentre -> Core, with the device in Core.
	parent := &domassets.AssetGroup{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "dc-" + uuid.NewString()[:6], Type: "folder",
	}
	if err := f.groups.Create(ctx, f.aScope, parent); err != nil {
		t.Fatalf("create parent group: %v", err)
	}
	child := &domassets.AssetGroup{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "core-" + uuid.NewString()[:6],
		Type: "folder", ParentID: &parent.ID,
	}
	if err := f.groups.Create(ctx, f.aScope, child); err != nil {
		t.Fatalf("create child group: %v", err)
	}

	d := f.device(t, ctx, domassets.CredentialPerUser)
	if err := f.groups.SetDeviceGroups(ctx, f.aScope, d.ID, []uuid.UUID{child.ID}); err != nil {
		t.Fatalf("add device to group: %v", err)
	}

	alice := makeUser(t, ctx, f, "alice")
	far := f.credential(t, ctx, "alice-dc", "farpass")
	if err := f.creds.BindToGroup(ctx, f.vScope, parent.ID, far, alice); err != nil {
		t.Fatalf("bind to parent: %v", err)
	}

	// Only the distant ancestor binds: the device still inherits it.
	res, err := f.creds.ResolveForDevice(ctx, f.vScope, d.ID, alice)
	if err != nil {
		t.Fatalf("resolve inherited: %v", err)
	}
	if res.Credential.Username != "alice-dc" {
		t.Fatalf("expected the inherited account, got %q", res.Credential.Username)
	}
	if !res.Inherited || !res.PerUser {
		t.Fatalf("inherited=%v per_user=%v — provenance is what the approval gate's "+
			"owner-bypass limit depends on", res.Inherited, res.PerUser)
	}

	// Now bind nearer. The closer group must win.
	near := f.credential(t, ctx, "alice-core", "nearpass")
	if err := f.creds.BindToGroup(ctx, f.vScope, child.ID, near, alice); err != nil {
		t.Fatalf("bind to child: %v", err)
	}
	res, err = f.creds.ResolveForDevice(ctx, f.vScope, d.ID, alice)
	if err != nil {
		t.Fatalf("resolve nearest: %v", err)
	}
	if res.Credential.Username != "alice-core" {
		t.Fatalf("nearest ancestor must win, got %q", res.Credential.Username)
	}

	// And a binding on the device itself beats both.
	own := f.credential(t, ctx, "alice-switch", "ownpass")
	if err := f.creds.BindToDevice(ctx, f.vScope, d.ID, own, &alice); err != nil {
		t.Fatalf("bind device: %v", err)
	}
	res, err = f.creds.ResolveForDevice(ctx, f.vScope, d.ID, alice)
	if err != nil {
		t.Fatalf("resolve own: %v", err)
	}
	if res.Credential.Username != "alice-switch" {
		t.Fatalf("a device binding must beat an inherited one, got %q", res.Credential.Username)
	}
	if res.Inherited {
		t.Fatal("a device binding is not inherited")
	}
}

// The batch projection used by the device list must agree with per-device
// resolution, or the console shows a green tick on a device that will refuse.
func TestIntegration_DeviceListProjectionMatchesResolution(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newCredFixture(t, pg)

	shared := f.device(t, ctx, domassets.CredentialShared)
	sc := f.credential(t, ctx, "admin", "p")
	if err := f.creds.BindToDevice(ctx, f.vScope, shared.ID, sc, nil); err != nil {
		t.Fatalf("bind: %v", err)
	}

	mine := f.device(t, ctx, domassets.CredentialPerUser)
	alice := makeUser(t, ctx, f, "alice")
	ac := f.credential(t, ctx, "alice-admin", "p")
	if err := f.creds.BindToDevice(ctx, f.vScope, mine.ID, ac, &alice); err != nil {
		t.Fatalf("bind: %v", err)
	}

	theirs := f.device(t, ctx, domassets.CredentialPerUser)
	bob := makeUser(t, ctx, f, "bob")
	bc := f.credential(t, ctx, "bob-admin", "p")
	if err := f.creds.BindToDevice(ctx, f.vScope, theirs.ID, bc, &bob); err != nil {
		t.Fatalf("bind: %v", err)
	}

	ids := []uuid.UUID{shared.ID, mine.ID, theirs.ID}

	// The estate view: every one of these is provisioned — somebody can connect
	// to it. Answering this per viewer would paint Bob's device as unconfigured
	// for Alice, and an administrator browsing forty working per-user devices
	// would see forty warnings.
	provisioned, err := f.creds.DeviceIDsProvisioned(ctx, f.vScope, ids)
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	for _, id := range ids {
		if !provisioned[id] {
			t.Fatalf("device %v has a bound account but reads as unprovisioned", id)
		}
	}

	// The personal view: Alice connects to two of the three.
	want := map[uuid.UUID]bool{shared.ID: true, mine.ID: true, theirs.ID: false}
	for id, expect := range want {
		ok, herr := f.creds.HasCredentialForDevice(ctx, f.vScope, id, alice)
		if herr != nil {
			t.Fatalf("has-credential: %v", herr)
		}
		if ok != expect {
			t.Fatalf("device %v: pre-flight says %v for Alice, expected %v", id, ok, expect)
		}
	}

	// An unprovisioned per-user device reads as such for everybody.
	empty := f.device(t, ctx, domassets.CredentialPerUser)
	got, err := f.creds.DeviceIDsProvisioned(ctx, f.vScope, []uuid.UUID{empty.ID})
	if err != nil {
		t.Fatalf("projection: %v", err)
	}
	if got[empty.ID] {
		t.Fatal("a per-user device with no accounts bound must read as unprovisioned")
	}
}

// Retiring somebody's accounts must find both their device and their group
// bindings. Missing the group ones would leave a departed employee's password
// working on every device in a subtree.
func TestIntegration_UserBindingsCoverDeviceAndGroup(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newCredFixture(t, pg)

	alice := makeUser(t, ctx, f, "alice")
	d := f.device(t, ctx, domassets.CredentialPerUser)
	dc := f.credential(t, ctx, "alice-dev", "p")
	if err := f.creds.BindToDevice(ctx, f.vScope, d.ID, dc, &alice); err != nil {
		t.Fatalf("bind device: %v", err)
	}
	g := &domassets.AssetGroup{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "grp-" + uuid.NewString()[:6], Type: "folder",
	}
	if err := f.groups.Create(ctx, f.aScope, g); err != nil {
		t.Fatalf("create group: %v", err)
	}
	gc := f.credential(t, ctx, "alice-grp", "p")
	if err := f.creds.BindToGroup(ctx, f.vScope, g.ID, gc, alice); err != nil {
		t.Fatalf("bind group: %v", err)
	}

	ids, err := f.creds.CredentialIDsForUser(ctx, f.vScope, alice)
	if err != nil {
		t.Fatalf("credentials for user: %v", err)
	}
	found := map[uuid.UUID]bool{}
	for _, id := range ids {
		found[id] = true
	}
	if !found[dc] || !found[gc] {
		t.Fatalf("offboarding must find both bindings; got %d of 2", len(ids))
	}

	list, err := f.creds.ListUserBindings(ctx, f.vScope, alice)
	if err != nil {
		t.Fatalf("list user bindings: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected a device and a group binding, got %d", len(list))
	}
}

// A device may hold exactly one shared credential and one per person. Without
// the partial unique indexes, resolution would depend on insertion order.
func TestIntegration_BindingUniqueness(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newCredFixture(t, pg)

	d := f.device(t, ctx, domassets.CredentialShared)
	first := f.credential(t, ctx, "admin-1", "p")
	second := f.credential(t, ctx, "admin-2", "p")
	if err := f.creds.BindToDevice(ctx, f.vScope, d.ID, first, nil); err != nil {
		t.Fatalf("bind first: %v", err)
	}
	if err := f.creds.BindToDevice(ctx, f.vScope, d.ID, second, nil); err == nil {
		t.Fatal("a device must not hold two shared credentials: resolution would " +
			"depend on which row the planner returned first")
	}
}

// makeUser creates a real user; per-user bindings are foreign-keyed to users,
// so a synthetic UUID fails the constraint rather than binding to nobody.
func makeUser(t *testing.T, ctx context.Context, f *credFixture, prefix string) uuid.UUID {
	t.Helper()
	u := &domiam.User{
		ID: uuid.New(), OrganizationID: defaultOrgID,
		Email:        domiam.NewEmail(prefix + "-" + uuid.NewString()[:8] + "@example.com"),
		Username:     prefix,
		PasswordHash: "x", AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := f.users.Create(ctx, domiam.TenantScope{OrganizationID: defaultOrgID}, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u.ID
}
