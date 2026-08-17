//go:build integration

// Approval-gate persistence, exercised against a live migrated database.
//
// The interesting behaviour here is transactional — rank checked inside the same
// transaction as the vote, single-use redemption enforced by a predicate rather
// than by application code — so it is tested where it actually runs.
package test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	domaccess "github.com/guardrail/guardrail/internal/domain/access"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
)

type approvalFixture struct {
	requests *postgres.RequestRepo
	grants   *postgres.GrantRepo
	sessions *postgres.AccessSessionRepo
	roles    *postgres.RoleRepo
	devices  *postgres.DeviceRepo
	users    *postgres.UserRepo
	scope    domaccess.Scope
	aScope   domassets.Scope
	tScope   domiam.TenantScope
}

func newApprovalFixture(t *testing.T, pg *postgres.DB) *approvalFixture {
	t.Helper()
	return &approvalFixture{
		requests: postgres.NewRequestRepo(pg),
		grants:   postgres.NewGrantRepo(pg),
		sessions: postgres.NewAccessSessionRepo(pg),
		roles:    postgres.NewRoleRepo(pg),
		devices:  postgres.NewDeviceRepo(pg),
		users:    postgres.NewUserRepo(pg),
		scope:    domaccess.Scope{OrganizationID: defaultOrgID},
		aScope:   domassets.Scope{OrganizationID: defaultOrgID},
		tScope:   domiam.TenantScope{OrganizationID: defaultOrgID},
	}
}

func (f *approvalFixture) user(t *testing.T, ctx context.Context, name string) uuid.UUID {
	t.Helper()
	u := &domiam.User{
		ID: uuid.New(), OrganizationID: defaultOrgID,
		Email:        domiam.NewEmail(name + "-" + uuid.NewString()[:8] + "@example.com"),
		Username:     name,
		PasswordHash: "x", AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := f.users.Create(ctx, f.tScope, u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u.ID
}

func (f *approvalFixture) device(t *testing.T, ctx context.Context, minApprovals int) *domassets.Device {
	t.Helper()
	d := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "fw-" + uuid.NewString()[:8],
		Host: "fw-" + uuid.NewString() + ".test", Port: 443,
		Scheme: "https", Status: "active", DeviceType: "firewall",
		RequiresApproval: true, MinApprovals: minApprovals,
	}
	if err := f.devices.Create(ctx, f.aScope, d); err != nil {
		t.Fatalf("create device: %v", err)
	}
	return d
}

func (f *approvalFixture) request(t *testing.T, ctx context.Context, user, device uuid.UUID,
	level, minApprovals int) *domaccess.Request {
	t.Helper()
	r := &domaccess.Request{
		ID: uuid.New(), OrganizationID: defaultOrgID, UserID: user, DeviceID: device,
		Status: domaccess.RequestPending, Reason: "changing a firewall rule",
		RequestedMinutes: 30, MinApprovals: minApprovals, RequesterLevel: level,
		ExpiresAt: time.Now().Add(domaccess.DefaultRequestTTL),
	}
	if err := f.requests.Create(ctx, f.scope, r); err != nil {
		t.Fatalf("create request: %v", err)
	}
	return r
}

// session creates a real brokered session row.
func (f *approvalFixture) session(t *testing.T, ctx context.Context, user, device uuid.UUID) uuid.UUID {
	t.Helper()
	now := time.Now()
	until := now.Add(time.Hour)
	sess := &domaccess.Session{
		ID: uuid.New(), OrganizationID: defaultOrgID, UserID: user, DeviceID: device,
		Protocol: domaccess.ProtocolHTTPS, Status: domaccess.StatusActive,
		GrantedFrom: &now, GrantedUntil: &until, StartedAt: &now,
	}
	if err := f.sessions.Create(ctx, f.scope, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	return sess.ID
}

// The device policy really is persisted, and min_approvals never reads back as
// zero — which would gate a device and then require nothing to open it.
func TestIntegration_DeviceApprovalPolicyRoundTrips(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	d := f.device(t, ctx, 2)
	got, err := f.devices.GetByID(ctx, f.aScope, d.ID)
	if err != nil {
		t.Fatalf("get device: %v", err)
	}
	if !got.RequiresApproval {
		t.Fatal("requires_approval did not persist")
	}
	if got.EffectiveMinApprovals() != 2 {
		t.Fatalf("min_approvals = %d, want 2", got.EffectiveMinApprovals())
	}
	if got.CredentialMode != domassets.CredentialShared {
		t.Fatalf("credential_mode should default to shared, got %q", got.CredentialMode)
	}
}

// An approver must outrank the requester STRICTLY. That single rule is also what
// makes self-approval and peer-approval impossible, so it is checked here rather
// than trusted to a separate guard somebody could later remove.
func TestIntegration_RankIsEnforcedInsideTheTransaction(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	requester := f.user(t, ctx, "operator")
	peer := f.user(t, ctx, "peer")
	boss := f.user(t, ctx, "boss")
	d := f.device(t, ctx, 1)
	req := f.request(t, ctx, requester, d.ID, 10, 1)

	// Self: level 10 against a level-10 request.
	if _, err := f.requests.AddDecision(ctx, f.scope, req.ID, requester,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, 10, false); !errors.Is(err, domaccess.ErrCannotDecide) {
		t.Fatalf("self-approval must be refused, got %v", err)
	}
	// A peer at the same rank.
	if _, err := f.requests.AddDecision(ctx, f.scope, req.ID, peer,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, 10, false); !errors.Is(err, domaccess.ErrCannotDecide) {
		t.Fatalf("an equal rank must not approve, got %v", err)
	}
	// Somebody above.
	got, err := f.requests.AddDecision(ctx, f.scope, req.ID, boss,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, 50, false)
	if err != nil {
		t.Fatalf("a higher rank must be able to approve: %v", err)
	}
	if got.Status != domaccess.RequestApproved {
		t.Fatalf("status = %q, want approved", got.Status)
	}
}

// The two-person rule counts DISTINCT people. A second vote from the same
// approver is refused rather than counted, at the database.
func TestIntegration_TwoPersonRuleCountsDistinctPeople(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	requester := f.user(t, ctx, "operator")
	first := f.user(t, ctx, "boss1")
	second := f.user(t, ctx, "boss2")
	d := f.device(t, ctx, 2)
	req := f.request(t, ctx, requester, d.ID, 10, 2)

	got, err := f.requests.AddDecision(ctx, f.scope, req.ID, first,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, 50, false)
	if err != nil {
		t.Fatalf("first approval: %v", err)
	}
	if got.Status != domaccess.RequestPending {
		t.Fatalf("one of two approvals must leave it pending, got %q", got.Status)
	}

	if _, err := f.requests.AddDecision(ctx, f.scope, req.ID, first,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, 50, false); !errors.Is(err, domaccess.ErrAlreadyDecided) {
		t.Fatalf("the same person must not vote twice, got %v", err)
	}

	got, err = f.requests.AddDecision(ctx, f.scope, req.ID, second,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, 50, false)
	if err != nil {
		t.Fatalf("second approval: %v", err)
	}
	if got.Status != domaccess.RequestApproved {
		t.Fatalf("two of two approvals must approve it, got %q", got.Status)
	}
	if got.Approvals() != 2 {
		t.Fatalf("approvals = %d, want 2", got.Approvals())
	}
}

// One denial settles it, even under a two-person rule. Raising the bar for
// GRANTING access must never raise the bar for refusing it.
func TestIntegration_OneDenialSettlesIt(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	requester := f.user(t, ctx, "operator")
	boss := f.user(t, ctx, "boss")
	d := f.device(t, ctx, 2)
	req := f.request(t, ctx, requester, d.ID, 10, 2)

	got, err := f.requests.AddDecision(ctx, f.scope, req.ID, boss,
		domaccess.Decision{Decision: domaccess.DecisionDeny, Note: "not during the freeze"}, 50, false)
	if err != nil {
		t.Fatalf("deny: %v", err)
	}
	if got.Status != domaccess.RequestDenied {
		t.Fatalf("one denial must settle a two-approval request, got %q", got.Status)
	}
}

// "Allow once" means once. Redemption is guarded by a predicate on the row, so
// two tabs racing the same approval produce one session, not two.
func TestIntegration_RedemptionIsSingleUse(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	requester := f.user(t, ctx, "operator")
	boss := f.user(t, ctx, "boss")
	d := f.device(t, ctx, 1)
	req := f.request(t, ctx, requester, d.ID, 10, 1)
	if _, err := f.requests.AddDecision(ctx, f.scope, req.ID, boss,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, 50, false); err != nil {
		t.Fatalf("approve: %v", err)
	}

	// Real sessions: access_requests.session_id is a foreign key, because the
	// join from a recording back to the approval that authorized it has to be
	// trustworthy.
	now := time.Now()
	first := f.session(t, ctx, requester, d.ID)
	second := f.session(t, ctx, requester, d.ID)
	if err := f.requests.Redeem(ctx, f.scope, req.ID, first, now); err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	if err := f.requests.Redeem(ctx, f.scope, req.ID, second, now); !errors.Is(err, domaccess.ErrRequestNotApproved) {
		t.Fatalf("an approval must be redeemable once, got %v", err)
	}
}

// A pending request escalates one rank before it dies, so a request whose first
// approver was on leave finds somebody else rather than silently expiring.
func TestIntegration_UnansweredRequestsEscalateThenExpire(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	requester := f.user(t, ctx, "operator")
	d := f.device(t, ctx, 1)
	req := f.request(t, ctx, requester, d.ID, 10, 1)

	// Well past its deadline.
	future := time.Now().Add(2 * domaccess.DefaultRequestTTL)
	if _, err := f.requests.Escalate(ctx, future); err != nil {
		t.Fatalf("escalate: %v", err)
	}
	got, err := f.requests.GetByID(ctx, f.scope, req.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domaccess.RequestPending {
		t.Fatalf("escalation must not close the request, got %q", got.Status)
	}
	if got.EscalatedLevel == nil || *got.EscalatedLevel != 11 {
		t.Fatalf("escalated_level = %v, want 11 (one above the requester)", got.EscalatedLevel)
	}

	// Second deadline passes with still no answer.
	if _, err := f.requests.ExpireOverdue(ctx, future.Add(2*domaccess.DefaultRequestTTL)); err != nil {
		t.Fatalf("expire: %v", err)
	}
	got, err = f.requests.GetByID(ctx, f.scope, req.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domaccess.RequestExpired {
		t.Fatalf("status = %q, want expired", got.Status)
	}
}

// An approved-but-unredeemed request expires too. An approval that stays
// redeemable indefinitely is a standing grant nobody chose to write down.
func TestIntegration_ApprovedButUnredeemedExpires(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	requester := f.user(t, ctx, "operator")
	boss := f.user(t, ctx, "boss")
	d := f.device(t, ctx, 1)
	req := f.request(t, ctx, requester, d.ID, 10, 1)
	if _, err := f.requests.AddDecision(ctx, f.scope, req.ID, boss,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, 50, false); err != nil {
		t.Fatalf("approve: %v", err)
	}

	if _, err := f.requests.ExpireOverdue(ctx, time.Now().Add(2*domaccess.DefaultRequestTTL)); err != nil {
		t.Fatalf("expire: %v", err)
	}
	got, err := f.requests.GetByID(ctx, f.scope, req.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Status != domaccess.RequestExpired {
		t.Fatalf("an unredeemed approval must expire, got %q", got.Status)
	}
	if got.Redeemable(time.Now()) {
		t.Fatal("an expired request must not be redeemable")
	}
}

// A standing grant authorizes future connects until it is revoked, and revoking
// it takes effect immediately.
func TestIntegration_StandingGrantLifecycle(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	who := f.user(t, ctx, "operator")
	boss := f.user(t, ctx, "boss")
	d := f.device(t, ctx, 1)

	g := &domaccess.Grant{
		ID: uuid.New(), OrganizationID: defaultOrgID, UserID: who, DeviceID: d.ID, GrantedBy: &boss,
	}
	if err := f.grants.Create(ctx, f.scope, g); err != nil {
		t.Fatalf("create grant: %v", err)
	}

	now := time.Now()
	live, err := f.grants.Live(ctx, f.scope, who, d.ID, now)
	if err != nil {
		t.Fatalf("live lookup: %v", err)
	}
	if !live.Live(now) {
		t.Fatal("a fresh grant with no expiry must be live")
	}

	// Re-granting supersedes rather than colliding with uq_grant_live.
	g2 := &domaccess.Grant{
		ID: uuid.New(), OrganizationID: defaultOrgID, UserID: who, DeviceID: d.ID, GrantedBy: &boss,
	}
	if err := f.grants.Create(ctx, f.scope, g2); err != nil {
		t.Fatalf("re-grant must supersede, not collide: %v", err)
	}

	if _, err := f.grants.Revoke(ctx, f.scope, g2.ID, boss, time.Now()); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := f.grants.Live(ctx, f.scope, who, d.ID, time.Now()); !errors.Is(err, domaccess.ErrNotFound) {
		t.Fatalf("a revoked grant must stop authorizing immediately, got %v", err)
	}
	// Revoking twice is a conflict, not a silent success: the caller terminates
	// sessions off the back of this and must not be told it worked twice.
	if _, err := f.grants.Revoke(ctx, f.scope, g2.ID, boss, time.Now()); !errors.Is(err, domaccess.ErrNotFound) {
		t.Fatalf("double revoke should report not-found, got %v", err)
	}
}

// The rank queries the gate depends on: a person's effective level is the MAX
// across their roles, and the approver count only counts people who both hold
// approval:decide and outrank the level asked about.
func TestIntegration_RankQueries(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	// Operator (10) plus Read-only (0) must resolve to 10, not 0: being given an
	// extra low-ranked role must not demote somebody.
	u := f.user(t, ctx, "operator")
	operatorRole := domiam.ID(uuid.MustParse("10000000-0000-0000-0000-000000000004"))
	readOnlyRole := domiam.ID(uuid.MustParse("10000000-0000-0000-0000-000000000005"))
	if err := f.users.SetRoles(ctx, f.tScope, u, []domiam.ID{operatorRole, readOnlyRole}); err != nil {
		t.Fatalf("assign roles: %v", err)
	}
	level, err := f.roles.MaxApprovalLevel(ctx, f.tScope, u)
	if err != nil {
		t.Fatalf("max level: %v", err)
	}
	if level != 10 {
		t.Fatalf("effective level = %d, want 10 — MAX across roles, so a low role cannot demote", level)
	}

	// An ordinary rank has somebody above it, which is what the unapprovable-
	// configuration check reads.
	n, err := f.roles.ApproverCountAbove(ctx, f.tScope, 10)
	if err != nil {
		t.Fatalf("approver count: %v", err)
	}
	if n == 0 {
		t.Fatal("an Operator-level request should have at least one possible approver")
	}

	// Super admins are counted at every level on purpose: AddDecision lets them
	// decide regardless of rank, so a check that excluded them would report a
	// deadlock that does not exist and block a device from being gated.
	high, err := f.roles.ApproverCountAbove(ctx, f.tScope, domiam.SuperAdminLevel)
	if err != nil {
		t.Fatalf("approver count: %v", err)
	}
	if high == 0 {
		t.Fatal("a super admin can decide any request, so they must count as an approver at every level")
	}
}
