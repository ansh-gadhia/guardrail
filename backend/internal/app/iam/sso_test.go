package iam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/security"
)

// ssoClaimOf reads the sso marker straight out of an access token's payload.
//
// The payload rather than a full Verify: this harness runs on a fixed clock in
// the past, so a real verification would fail on expiry and tell us nothing
// about the claim we are actually asking after.
func ssoClaimOf(t *testing.T, token string) bool {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	var payload struct {
		SSO bool `json:"sso"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	return payload.SSO
}

// ---- fakes for the SSO collaborators ----

// stubVerifier returns a canned assertion, so these tests exercise what the
// application layer DOES with a verified token rather than re-testing the
// verification chain (which sso_verify_test.go covers against real signatures).
type stubVerifier struct {
	assertion *iam.SSOAssertion
	err       error
}

func (s *stubVerifier) Configured() bool { return true }
func (s *stubVerifier) VerifySSOToken(context.Context, string) (*iam.SSOAssertion, error) {
	if s.err != nil {
		return nil, s.err
	}
	cp := *s.assertion
	return &cp, nil
}

// memReplay is an in-memory nonce store. failWith makes it unreachable, which is
// how the fail-closed rule gets tested rather than assumed.
type memReplay struct {
	mu       sync.Mutex
	seen     map[string]bool
	failWith error
}

func newMemReplay() *memReplay { return &memReplay{seen: map[string]bool{}} }

func (m *memReplay) Consume(_ context.Context, nonce string, _ time.Duration) (bool, error) {
	if m.failWith != nil {
		return false, m.failWith
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.seen[nonce] {
		return false, nil
	}
	m.seen[nonce] = true
	return true, nil
}

// ---- harness ----

// ssoOrg is the provisioning organization; GUARDRAIL_FEDERATION_ORG_ID in
// production. It is configuration, never anything the token can choose.
var ssoOrg = uuid.MustParse("00000000-0000-0000-0000-0000000000aa")

// seededRoles mirrors db/seed.sql closely enough for the role resolver: the
// names and the approval ranks are what it reads.
func seededRoles() []iam.Role {
	return []iam.Role{
		{ID: iam.SuperAdminRoleID, Name: RoleSuperAdmin, IsSystem: true, ApprovalLevel: 100},
		{ID: uuid.MustParse("10000000-0000-0000-0000-000000000002"), Name: RoleOrgAdmin, IsSystem: true, ApprovalLevel: 50},
		{ID: uuid.MustParse("10000000-0000-0000-0000-000000000003"), Name: RoleAuditor, IsSystem: true, ApprovalLevel: 0},
		{ID: uuid.MustParse("10000000-0000-0000-0000-000000000004"), Name: RoleOperator, IsSystem: true, ApprovalLevel: 10},
		{ID: uuid.MustParse("10000000-0000-0000-0000-000000000005"), Name: RoleReadOnly, IsSystem: true, ApprovalLevel: 0},
	}
}

type ssoHarness struct {
	svc      *Service
	users    *fakeUserRepo
	sessions *fakeSessionRepo
	orgs     *fakeOrgRepo
	replay   *memReplay
	verifier *stubVerifier
	audit    *captureAudit
	now      time.Time
}

func newSSOHarness(t *testing.T, tune func(*Deps)) *ssoHarness {
	t.Helper()
	users := newFakeUserRepo()
	sessions := newFakeSessionRepo(users)
	rec := &captureAudit{}
	replay := newMemReplay()
	verifier := &stubVerifier{}
	roleMap, err := NewSSORoleMap("", "")
	if err != nil {
		t.Fatalf("role map: %v", err)
	}
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	ssoCfg := DefaultSSOConfig()
	ssoCfg.OrgRef = "default"

	orgs := newFakeOrgRepo()
	orgs.bySlug["default"] = &iam.Organization{ID: ssoOrg, Name: "GuardRail Default", Slug: "default", Status: "active"}

	d := Deps{
		Users: users, Orgs: orgs, Roles: fakeRoleRepo{roles: seededRoles()}, Sessions: sessions,
		Hasher: security.NewArgon2Hasher(security.Argon2Params{
			Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32,
		}),
		Tokens:  security.NewJWTIssuer("0123456789abcdef0123456789abcdef", "guardrail", 15*time.Minute),
		Refresh: security.NewRefreshGenerator(), Audit: rec, Throttle: nopThrottle{},
		Clock:  fixedClock{t: now},
		Config: Config{MaxLoginFailures: 5, LockoutDuration: 15 * time.Minute, RefreshTTL: 720 * time.Hour},

		FederationOrgID: ssoOrg,
		SSOVerifier:     verifier,
		Replay:          replay,
		SSORoles:        roleMap,
		SSO:             ssoCfg,
	}
	if tune != nil {
		tune(&d)
	}
	return &ssoHarness{svc: NewService(d), users: users, sessions: sessions, orgs: orgs,
		replay: replay, verifier: verifier, audit: rec, now: now}
}

func assertion() *iam.SSOAssertion {
	return &iam.SSOAssertion{
		Subject: "siem-user-1", Email: "analyst@corp.example", Username: "jdoe",
		Role: "L2", Access: "read-write", Nonce: "nonce-1",
		ExpiresAt: time.Date(2026, 1, 1, 12, 0, 30, 0, time.UTC), Leeway: time.Minute,
	}
}

func (h *ssoHarness) login(t *testing.T, a *iam.SSOAssertion) (*TokenPair, error) {
	t.Helper()
	h.verifier.assertion = a
	return h.svc.LoginWithSIEM(context.Background(), "opaque-token",
		ReqMeta{IP: "10.0.0.9", UserAgent: "test"})
}

func (h *ssoHarness) findUser(t *testing.T, email string) *iam.User {
	t.Helper()
	u, err := h.users.GetByEmailInOrg(context.Background(), ssoOrg, iam.NewEmail(email))
	if err != nil {
		t.Fatalf("user %s not found: %v", email, err)
	}
	return u
}

// ---- provisioning ----

func TestSSOLogin_ProvisionsOnFirstSignIn(t *testing.T) {
	h := newSSOHarness(t, nil)

	pair, err := h.login(t, assertion())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if pair.AccessToken == "" {
		t.Fatal("expected an access token")
	}

	u := h.findUser(t, "analyst@corp.example")
	if u.AuthProvider != iam.ProviderSIEM {
		t.Errorf("auth provider: %q", u.AuthProvider)
	}
	if u.SSO.Subject != "siem-user-1" || !u.SSO.Managed {
		t.Errorf("SIEM identity not recorded: %+v", u.SSO)
	}
	if u.SSO.SourceRole != "L2:rw" {
		t.Errorf("provenance: %q, want L2:rw", u.SSO.SourceRole)
	}
	// No password hash at all — the account cannot be reached through the
	// password path, so there is deliberately nothing there to attack.
	if u.PasswordHash != "" {
		t.Error("a SIEM-provisioned account must carry no password hash")
	}
	if u.IsSuperAdmin {
		t.Error("provisioning must never set the super-admin column")
	}

	granted, ok := h.users.rolesOf(u.ID)
	if !ok || len(granted) != 1 {
		t.Fatalf("expected exactly one role granted, got %v", granted)
	}
	if granted[0] != seededRoles()[3].ID { // Operator
		t.Errorf("L2:rw should map to Operator, got %v", granted[0])
	}
}

// A person the SIEM names with no email cannot be created: there is nothing to
// put in the column that IS the login identifier.
func TestSSOLogin_RefusesToProvisionWithoutEmail(t *testing.T) {
	h := newSSOHarness(t, nil)
	a := assertion()
	a.Email = ""

	if _, err := h.login(t, a); !errors.Is(err, iam.ErrSSOToken) {
		t.Fatalf("want ErrSSOToken, got %v", err)
	}
}

func TestSSOLogin_JITOffRefusesUnknownPerson(t *testing.T) {
	h := newSSOHarness(t, func(d *Deps) { d.SSO.JITProvision = false })

	if _, err := h.login(t, assertion()); !errors.Is(err, iam.ErrSSOToken) {
		t.Fatalf("want ErrSSOToken, got %v", err)
	}
	if _, err := h.users.GetByEmailInOrg(context.Background(), ssoOrg,
		iam.NewEmail("analyst@corp.example")); !errors.Is(err, iam.ErrNotFound) {
		t.Fatal("no account should have been created")
	}
}

// ---- replay ----

func TestSSOLogin_SecondUseOfATokenIsRefused(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	_, err := h.login(t, assertion())
	if !errors.Is(err, iam.ErrSSOToken) {
		t.Fatalf("a replayed token must be refused, got %v", err)
	}
}

// The nonce is spent BEFORE anything is created, so a replay that slips through
// verification still cannot provision an account or move a role.
func TestSSOLogin_ReplayIsRefusedBeforeAnyWrite(t *testing.T) {
	h := newSSOHarness(t, nil)
	h.replay.mu.Lock()
	h.replay.seen["nonce-1"] = true
	h.replay.mu.Unlock()

	if _, err := h.login(t, assertion()); !errors.Is(err, iam.ErrSSOToken) {
		t.Fatalf("want ErrSSOToken, got %v", err)
	}
	if _, err := h.users.GetByEmailInOrg(context.Background(), ssoOrg,
		iam.NewEmail("analyst@corp.example")); !errors.Is(err, iam.ErrNotFound) {
		t.Fatal("a replayed token must not have provisioned an account")
	}
}

// An unreachable replay store fails CLOSED. Nothing else in the product stops a
// replayed exchange token, and on this product the session it opens can connect
// to a device.
func TestSSOLogin_ReplayStoreOutageFailsClosed(t *testing.T) {
	h := newSSOHarness(t, nil)
	h.replay.failWith = errors.New("redis: connection refused")

	_, err := h.login(t, assertion())
	if !errors.Is(err, iam.ErrSSOUnavailable) {
		t.Fatalf("want ErrSSOUnavailable, got %v", err)
	}
}

// ---- privilege ----

// The hard bar. Super Admin turns row-level security off, so it reads and writes
// every tenant on the deployment; a claim in a token must never select it, and
// no configuration lifts this.
func TestSSOLogin_NeverGrantsSuperAdmin(t *testing.T) {
	for _, override := range []string{
		`{"Administrator": "Super Admin"}`,
		`{"Administrator": {"rw": "Super Admin", "ro": "Super Admin"}}`,
	} {
		t.Run(override, func(t *testing.T) {
			h := newSSOHarness(t, func(d *Deps) {
				m, err := NewSSORoleMap(override, "")
				if err != nil {
					t.Fatalf("role map: %v", err)
				}
				d.SSORoles = m
			})
			a := assertion()
			a.Role, a.Access = "Administrator", "read-write"

			if _, err := h.login(t, a); err != nil {
				t.Fatalf("login: %v", err)
			}
			u := h.findUser(t, "analyst@corp.example")
			granted, _ := h.users.rolesOf(u.ID)
			for _, id := range granted {
				if id == iam.SuperAdminRoleID {
					t.Fatal("SSO granted the Super Admin role")
				}
			}
			if u.IsSuperAdmin {
				t.Fatal("SSO set the super-admin column")
			}
		})
	}
}

// The configurable ceiling clamps anything above it. Once the token can pick a
// role, a forged token can pick a role.
func TestSSOLogin_CeilingClampsMappedRole(t *testing.T) {
	h := newSSOHarness(t, func(d *Deps) { d.SSO.MaxRole = RoleOperator })
	a := assertion()
	a.Role, a.Access = "Administrator", "read-write" // maps to Organization Admin (50)

	if _, err := h.login(t, a); err != nil {
		t.Fatalf("login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")
	granted, _ := h.users.rolesOf(u.ID)
	if len(granted) != 1 || granted[0] != seededRoles()[3].ID {
		t.Fatalf("expected the clamp to Operator, got %v", granted)
	}
}

// An unrecognised role must never guess upward, and must not leave the person
// with no roles at all — which on this product is a console where every page is
// empty and every action refused.
func TestSSOLogin_UnknownRoleFallsToTheFloor(t *testing.T) {
	h := newSSOHarness(t, nil)
	a := assertion()
	a.Role, a.Access = "Grand Poobah", "read-write"

	if _, err := h.login(t, a); err != nil {
		t.Fatalf("login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")
	granted, _ := h.users.rolesOf(u.ID)
	if len(granted) != 1 || granted[0] != seededRoles()[4].ID { // Read-only
		t.Fatalf("expected the Read-only floor, got %v", granted)
	}
}

// An unstated access mode is read-only. Between over- and under-granting on a
// claim nobody made, only one of the two is safe.
func TestSSOLogin_AbsentAccessModeIsReadOnly(t *testing.T) {
	h := newSSOHarness(t, nil)
	a := assertion()
	a.Role, a.Access = "L3", ""

	if _, err := h.login(t, a); err != nil {
		t.Fatalf("login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")
	granted, _ := h.users.rolesOf(u.ID)
	if len(granted) != 1 || granted[0] != seededRoles()[2].ID { // Auditor
		t.Fatalf("L3 with no access mode should be Auditor, got %v", granted)
	}
}

// ---- identity reconciliation ----

// An account that predates SIEM sign-in is found by email and adopts the subject
// on the spot — no migration window, no script.
func TestSSOLogin_BackfillsSubjectOntoExistingAccount(t *testing.T) {
	h := newSSOHarness(t, nil)
	existing := &iam.User{
		ID: iam.NewID(), OrganizationID: ssoOrg, Email: iam.NewEmail("analyst@corp.example"),
		AuthProvider: iam.ProviderLocal, Status: "active", PasswordHash: "x",
	}
	h.users.add(existing)

	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")
	if u.ID != existing.ID {
		t.Fatal("a second account was provisioned instead of adopting the existing one")
	}
	if u.SSO.Subject != "siem-user-1" {
		t.Errorf("subject not backfilled: %q", u.SSO.Subject)
	}
	// The account was NOT taken over: an existing account's roles stay a local
	// decision until somebody says otherwise.
	if u.SSO.Managed {
		t.Error("adopting a subject must not hand an existing account to the SIEM to overwrite")
	}
}

// Once keyed by subject, a change of address follows the person instead of
// orphaning them. This is the whole reason the join key is not the email.
func TestSSOLogin_RenameFollowsTheSubject(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("first login: %v", err)
	}
	first := h.findUser(t, "analyst@corp.example")

	renamed := assertion()
	renamed.Email = "j.doe@corp.example"
	renamed.Nonce = "nonce-2"
	if _, err := h.login(t, renamed); err != nil {
		t.Fatalf("second login: %v", err)
	}

	after := h.findUser(t, "j.doe@corp.example")
	if after.ID != first.ID {
		t.Fatal("a rename orphaned the account and provisioned a second one")
	}
}

// A rename onto an address somebody else already holds is logged and skipped.
// Failing an entire sign-in over a display attribute is the wrong trade.
func TestSSOLogin_RenameCollisionDoesNotFailTheLogin(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("first login: %v", err)
	}
	h.users.add(&iam.User{
		ID: iam.NewID(), OrganizationID: ssoOrg, Email: iam.NewEmail("taken@corp.example"),
		AuthProvider: iam.ProviderLocal, Status: "active",
	})

	clash := assertion()
	clash.Email = "taken@corp.example"
	clash.Nonce = "nonce-3"
	if _, err := h.login(t, clash); err != nil {
		t.Fatalf("a colliding rename must not fail the sign-in: %v", err)
	}
	// The original address is untouched, and still resolves to the same person.
	if u := h.findUser(t, "analyst@corp.example"); u.SSO.Subject != "siem-user-1" {
		t.Error("the original account should be unchanged")
	}
}

// ---- sync and the ownership boundary ----

func TestSSOLogin_SyncTracksTheSIEM(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("first login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")

	promoted := assertion()
	promoted.Role, promoted.Access = "Administrator", "read-write"
	promoted.Nonce = "nonce-2"
	if _, err := h.login(t, promoted); err != nil {
		t.Fatalf("second login: %v", err)
	}

	granted, _ := h.users.rolesOf(u.ID)
	if len(granted) != 1 || granted[0] != seededRoles()[1].ID { // Organization Admin
		t.Fatalf("promotion did not sync, got %v", granted)
	}
}

// A role edited by hand in GuardRail detaches the account, and the next sign-in
// leaves it alone. Without this, an administrator's decision would last exactly
// until its subject next signed in — worse than refusing the edit, because it
// looks like it worked.
func TestSSOLogin_ManualRoleEditDetachesFromSync(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("first login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")

	admin := iam.Claims{UserID: iam.NewID(), OrganizationID: ssoOrg, IsSuperAdmin: true}
	readOnly := seededRoles()[4].ID
	if err := h.svc.AssignRoles(context.Background(), admin, u.ID, []iam.ID{readOnly}, ReqMeta{}); err != nil {
		t.Fatalf("assign roles: %v", err)
	}

	promoted := assertion()
	promoted.Role, promoted.Access = "Administrator", "read-write"
	promoted.Nonce = "nonce-2"
	if _, err := h.login(t, promoted); err != nil {
		t.Fatalf("second login: %v", err)
	}

	granted, _ := h.users.rolesOf(u.ID)
	if len(granted) != 1 || granted[0] != readOnly {
		t.Fatalf("the SIEM overwrote a local decision: %v", granted)
	}
}

// A SIEM that stops sending the role claim must not silently demote everybody on
// their next sign-in.
func TestSSOLogin_MissingRoleClaimDoesNotDemote(t *testing.T) {
	h := newSSOHarness(t, nil)
	a := assertion()
	a.Role, a.Access = "Administrator", "read-write"
	if _, err := h.login(t, a); err != nil {
		t.Fatalf("first login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")
	orgAdmin := seededRoles()[1].ID

	silent := assertion()
	silent.Role, silent.Access = "", ""
	silent.Nonce = "nonce-2"
	if _, err := h.login(t, silent); err != nil {
		t.Fatalf("second login: %v", err)
	}

	granted, _ := h.users.rolesOf(u.ID)
	if len(granted) != 1 || granted[0] != orgAdmin {
		t.Fatalf("a missing role claim demoted the account: %v", granted)
	}
}

// ---- account state and second factor ----

func TestSSOLogin_RefusesDisabledAccount(t *testing.T) {
	h := newSSOHarness(t, nil)
	h.users.add(&iam.User{
		ID: iam.NewID(), OrganizationID: ssoOrg, Email: iam.NewEmail("analyst@corp.example"),
		AuthProvider: iam.ProviderSIEM, Status: "disabled",
		SSO: iam.SSOIdentity{Subject: "siem-user-1", Managed: true},
	})

	if _, err := h.login(t, assertion()); !errors.Is(err, iam.ErrAccountInactive) {
		t.Fatalf("want ErrAccountInactive, got %v", err)
	}
}

// The session carries the SSO marker, and it survives a refresh. Without the
// second half an off-network analyst is signed out fifteen minutes in.
func TestSSOLogin_MarkerSurvivesRefresh(t *testing.T) {
	h := newSSOHarness(t, nil)
	pair, err := h.login(t, assertion())
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if !ssoClaimOf(t, pair.AccessToken) {
		t.Fatal("the access token from an exchange must carry the SSO marker")
	}

	rotated, err := h.svc.Refresh(context.Background(), pair.RefreshToken, ReqMeta{IP: "10.0.0.9"})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !ssoClaimOf(t, rotated.AccessToken) {
		t.Fatal("the marker was lost on refresh")
	}
}

// A password sign-in must never come back marked SSO — otherwise the marker
// would be a way to opt yourself out of the network policy.
func TestPasswordLogin_IsNotMarkedSSO(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "local@corp.example", "supersecret-123")
	pair, err := h.svc.Login(context.Background(), LoginInput{
		Email: "local@corp.example", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}

	if ssoClaimOf(t, pair.AccessToken) {
		t.Fatal("a password login was marked as SIEM-vouched")
	}
}

// ---- not configured ----

func TestSSOLogin_DisabledWithoutKeyMaterial(t *testing.T) {
	h := newSSOHarness(t, func(d *Deps) { d.SSOVerifier = nil })
	if h.svc.SIEMSSOEnabled() {
		t.Fatal("SSO must not report itself enabled with no verifier")
	}
	if _, err := h.login(t, assertion()); !errors.Is(err, iam.ErrSSONotConfigured) {
		t.Fatalf("want ErrSSONotConfigured, got %v", err)
	}
}

// ---- which organization ----

// The common case: a single-tenant install, nothing configured. There is exactly
// one right answer, and making somebody paste a uuid they have no choice about
// is a setup step that exists only to be got wrong.
func TestSSOLogin_SingleTenantNeedsNoOrgSetting(t *testing.T) {
	h := newSSOHarness(t, func(d *Deps) { d.SSO.OrgRef = "" })

	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("login: %v", err)
	}
	if u := h.findUser(t, "analyst@corp.example"); u.OrganizationID != ssoOrg {
		t.Fatalf("landed in %s, want %s", u.OrganizationID, ssoOrg)
	}
}

// A slug is accepted, because that is the name an operator actually knows.
func TestSSOLogin_OrgBySlug(t *testing.T) {
	h := newSSOHarness(t, func(d *Deps) { d.SSO.OrgRef = "default" })

	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("login: %v", err)
	}
	if u := h.findUser(t, "analyst@corp.example"); u.OrganizationID != ssoOrg {
		t.Fatalf("landed in %s, want %s", u.OrganizationID, ssoOrg)
	}
}

func TestSSOLogin_OrgByUUID(t *testing.T) {
	h := newSSOHarness(t, func(d *Deps) { d.SSO.OrgRef = ssoOrg.String() })

	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("login: %v", err)
	}
}

// With several tenants there is no obvious answer, so it refuses and names them
// rather than picking one. Filing an analyst into the wrong tenant does not
// announce itself — they sign in, see an estate that is not theirs, and
// everything after that is an audit problem.
func TestSSOLogin_MultiTenantRefusesToGuess(t *testing.T) {
	h := newSSOHarness(t, func(d *Deps) { d.SSO.OrgRef = "" })
	h.orgs.bySlug["acme"] = &iam.Organization{ID: iam.NewID(), Name: "Acme", Slug: "acme", Status: "active"}

	_, err := h.login(t, assertion())
	if !errors.Is(err, iam.ErrSSONotConfigured) {
		t.Fatalf("want ErrSSONotConfigured, got %v", err)
	}
	for _, want := range []string{"acme", "default", "GUARDRAIL_SIEM_SSO_ORG"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the message should name %q so the operator can act on it: %v", want, err)
		}
	}
}

func TestSSOLogin_UnknownOrgSlugIsNamed(t *testing.T) {
	h := newSSOHarness(t, func(d *Deps) { d.SSO.OrgRef = "not-a-real-tenant" })

	_, err := h.login(t, assertion())
	if !errors.Is(err, iam.ErrSSONotConfigured) {
		t.Fatalf("want ErrSSONotConfigured, got %v", err)
	}
	if !strings.Contains(err.Error(), "not-a-real-tenant") {
		t.Errorf("the message should quote the slug that was not found: %v", err)
	}
}

// ---- handing an account back to the SIEM ----

// The detach in AssignRoles is otherwise a one-way door: an administrator who
// edits somebody's roles for a week-long project has permanently stopped that
// account tracking the SIEM, and the only way back would be an UPDATE against
// the production database.
func TestSSOResync_ReattachesAfterALocalEdit(t *testing.T) {
	h := newSSOHarness(t, nil)
	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("first login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")
	admin := iam.Claims{UserID: iam.NewID(), OrganizationID: ssoOrg, IsSuperAdmin: true}
	readOnly := seededRoles()[4].ID

	// A local edit detaches, and the SIEM stops overwriting it.
	if err := h.svc.AssignRoles(context.Background(), admin, u.ID, []iam.ID{readOnly}, ReqMeta{}); err != nil {
		t.Fatalf("assign: %v", err)
	}
	promoted := assertion()
	promoted.Role, promoted.Access, promoted.Nonce = "Administrator", "read-write", "n2"
	if _, err := h.login(t, promoted); err != nil {
		t.Fatalf("login: %v", err)
	}
	if granted, _ := h.users.rolesOf(u.ID); len(granted) != 1 || granted[0] != readOnly {
		t.Fatalf("the SIEM overwrote a local decision: %v", granted)
	}

	// Handed back, explicitly.
	if err := h.svc.ResumeSSOSync(context.Background(), admin, u.ID, ReqMeta{}); err != nil {
		t.Fatalf("resync: %v", err)
	}
	promoted.Nonce = "n3"
	if _, err := h.login(t, promoted); err != nil {
		t.Fatalf("login: %v", err)
	}
	granted, _ := h.users.rolesOf(u.ID)
	if len(granted) != 1 || granted[0] != seededRoles()[1].ID { // Organization Admin
		t.Fatalf("the account did not resume tracking the SIEM: %v", granted)
	}
}

// Raising the flag on an account that has never signed in through the SIEM would
// arm a rule that can never fire, and leave the operator waiting for a change
// that is not coming.
func TestSSOResync_RefusesAnAccountWithNoSIEMIdentity(t *testing.T) {
	h := newSSOHarness(t, nil)
	local := &iam.User{
		ID: iam.NewID(), OrganizationID: ssoOrg, Email: iam.NewEmail("local@corp.example"),
		AuthProvider: iam.ProviderLocal, Status: "active", PasswordHash: "x",
	}
	h.users.add(local)
	admin := iam.Claims{UserID: iam.NewID(), OrganizationID: ssoOrg, IsSuperAdmin: true}

	err := h.svc.ResumeSSOSync(context.Background(), admin, local.ID, ReqMeta{})
	if !errors.Is(err, iam.ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}
}

// The installation account is refused, like every other change to it: handing
// the one account that can restore the platform to an external system to
// overwrite is exactly what that guard is for.
func TestSSOResync_RefusesTheInstallationAccount(t *testing.T) {
	h := newSSOHarness(t, nil)
	boot := &iam.User{
		ID: iam.NewID(), OrganizationID: ssoOrg, Email: iam.NewEmail("root@corp.example"),
		AuthProvider: iam.ProviderLocal, Status: "active", IsSuperAdmin: true,
		SSO: iam.SSOIdentity{Subject: "siem-root"},
	}
	h.users.add(boot)
	admin := iam.Claims{UserID: iam.NewID(), OrganizationID: ssoOrg, IsSuperAdmin: true}

	err := h.svc.ResumeSSOSync(context.Background(), admin, boot.ID, ReqMeta{})
	if !errors.Is(err, iam.ErrProtectedAccount) {
		t.Fatalf("want ErrProtectedAccount, got %v", err)
	}
}

// ---- what the console is told to put in front of somebody ----

// A newly provisioned SIEM account has no password, so must_change_password is
// false and the whole first-run flow — including the two-factor offer at the end
// of it — used to be skipped. The console decides from these two fields, so they
// have to be right on the very first response.
func TestSSOLogin_PrincipalDrivesTheFirstRunOffer(t *testing.T) {
	h := newSSOHarness(t, nil)

	pair, err := h.login(t, assertion())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	p := pair.Principal
	if p.AuthProvider != string(iam.ProviderSIEM) {
		t.Errorf("auth_provider = %q, want %q", p.AuthProvider, iam.ProviderSIEM)
	}
	if p.MFAEnabled {
		t.Error("a brand-new account cannot already hold a confirmed second factor")
	}
	if p.MustChangePassword {
		t.Error("a SIEM account has no password, so it can never be pending a change")
	}
	if !p.FirstLogin {
		t.Fatal("the account was just created, so this is its first sign-in")
	}
	// The condition the console gates on, asserted here so a change to any field
	// behind it is caught by a test that says what it was for.
	if !(p.FirstLogin && !p.MFAEnabled) {
		t.Fatal("the two-factor offer would not be shown to a new SIEM user")
	}

	// And it is offered ONCE. A second sign-in goes straight in.
	again := assertion()
	again.Nonce = "n2"
	next, err := h.login(t, again)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if next.Principal.FirstLogin {
		t.Fatal("the second sign-in still reports itself as the first")
	}
}

// Local and federated accounts are gated by the SAME rule. This pins that: a
// brand-new local account reports first_login exactly as a SIEM one does, so the
// console does not need to know which kind it is looking at.
func TestFirstLogin_IsTheSameSignalForALocalAccount(t *testing.T) {
	h := newHarness(t)
	h.addUser(t, "fresh@acme.com", "supersecret-123")

	first, err := h.svc.Login(context.Background(), LoginInput{
		Email: "fresh@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !first.Principal.FirstLogin {
		t.Fatal("a local account's first sign-in must report first_login")
	}
	if first.Principal.AuthProvider != string(iam.ProviderLocal) {
		t.Errorf("auth_provider = %q", first.Principal.AuthProvider)
	}

	second, err := h.svc.Login(context.Background(), LoginInput{
		Email: "fresh@acme.com", Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if second.Principal.FirstLogin {
		t.Fatal("the second sign-in still reports itself as the first")
	}
}

// Rotating a token is not a sign-in. Without this, the offer would return every
// fifteen minutes for as long as somebody stayed logged in.
func TestFirstLogin_RefreshIsNotASignIn(t *testing.T) {
	h := newSSOHarness(t, nil)
	pair, err := h.login(t, assertion())
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if !pair.Principal.FirstLogin {
		t.Fatal("expected the first sign-in to say so")
	}
	rotated, err := h.svc.Refresh(context.Background(), pair.RefreshToken, ReqMeta{IP: "10.0.0.9"})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if rotated.Principal.FirstLogin {
		t.Fatal("a token refresh reported itself as a first sign-in")
	}
}

// Once a factor is confirmed the offer stops, and the exchange returns a
// challenge instead of a session.
func TestSSOLogin_ConfirmedFactorEndsTheOfferAndGatesTheLogin(t *testing.T) {
	mfa := newFakeMFARepo()
	h := newSSOHarness(t, func(d *Deps) {
		d.MFA = mfa
		d.TOTP = fakeTOTP{good: "123456", good2: "234567"}
		d.Cipher = identityCipher{}
		d.MFAChal = security.NewMFAChallenger("0123456789abcdef0123456789abcdef", 5*time.Minute)
	})

	if _, err := h.login(t, assertion()); err != nil {
		t.Fatalf("first login: %v", err)
	}
	u := h.findUser(t, "analyst@corp.example")

	confirmed := h.now
	mfa.method = &iam.MFAMethod{UserID: u.ID, Type: iam.MFATypeTOTP,
		Secret: []byte("s"), ConfirmedAt: &confirmed}

	second := assertion()
	second.Nonce = "n2"
	pair, err := h.login(t, second)
	if err != nil {
		t.Fatalf("second login: %v", err)
	}
	if !pair.MFARequired || pair.MFAToken == "" {
		t.Fatal("an account with a confirmed factor must be challenged, not signed straight in")
	}

	// And the marker survives the challenge, so the session minted on the far
	// side is still a SIEM-vouched one.
	_, sso, err := security.NewMFAChallenger("0123456789abcdef0123456789abcdef", 5*time.Minute).
		Verify(pair.MFAToken, h.now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify challenge: %v", err)
	}
	if !sso {
		t.Fatal("the challenge lost the SSO marker, so the session after it would not be SIEM-vouched")
	}
}
