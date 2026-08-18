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
	"github.com/jackc/pgx/v5"

	appiam "github.com/guardrail/guardrail/internal/app/iam"
	domaccess "github.com/guardrail/guardrail/internal/domain/access"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
)

type approvalFixture struct {
	db       *postgres.DB
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
		db:       pg,
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

// markEmergency flags a request as break-glass and backdates it. Written
// directly because no application path produces a request that was taken days
// ago, and the quota query is entirely about how long ago things happened.
func (f *approvalFixture) markEmergency(t *testing.T, ctx context.Context, id uuid.UUID, at time.Time) {
	t.Helper()
	err := f.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE access_requests
			SET is_emergency = true, status = 'approved', created_at = $2 WHERE id = $1`, id, at)
		return e
	})
	if err != nil {
		t.Fatalf("mark emergency: %v", err)
	}
}

// attachSession records that a request was actually redeemed into a session,
// which is what separates access somebody took from access they only asked for.
func (f *approvalFixture) attachSession(t *testing.T, ctx context.Context, id, sessionID uuid.UUID) {
	t.Helper()
	err := f.db.WithSystemScope(ctx, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `UPDATE access_requests SET session_id = $2 WHERE id = $1`, id, sessionID)
		return e
	})
	if err != nil {
		t.Fatalf("attach session: %v", err)
	}
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

	// The unapprovable-configuration check: with nobody above an Operator, a
	// request at that rank could only ever expire — which is exactly what the
	// device form refuses to let somebody configure.
	//
	// The approver is created here rather than assumed. Depending on whatever
	// users happen to exist made this pass on a database that had been seeded
	// with an admin and fail on a fresh one.
	boss := f.user(t, ctx, "boss")
	orgAdminRole := domiam.ID(uuid.MustParse("10000000-0000-0000-0000-000000000002"))
	if err := f.users.SetRoles(ctx, f.tScope, boss, []domiam.ID{orgAdminRole}); err != nil {
		t.Fatalf("assign org admin: %v", err)
	}
	n, err := f.roles.ApproverCountAbove(ctx, f.tScope, 10)
	if err != nil {
		t.Fatalf("approver count: %v", err)
	}
	if n == 0 {
		t.Fatal("an Organization Admin outranks an Operator and holds approval:decide, " +
			"so an Operator-level request must have a possible approver")
	}

	// Nobody outranks the super-admin level by rank alone, so an org with no
	// super admin reports a gap there — which is the honest answer.
	high, err := f.roles.ApproverCountAbove(ctx, f.tScope, domiam.SuperAdminLevel)
	if err != nil {
		t.Fatalf("approver count: %v", err)
	}
	before := high

	// Super admins are counted at every level on purpose: AddDecision lets them
	// decide regardless of rank, so excluding them would report a deadlock that
	// does not exist and block a device from being gated. Prove it by adding one.
	su := f.user(t, ctx, "root")
	superRole := domiam.SuperAdminRoleID
	if err := f.users.SetRoles(ctx, f.tScope, su, []domiam.ID{superRole}); err != nil {
		t.Fatalf("assign super admin role: %v", err)
	}
	after, err := f.roles.ApproverCountAbove(ctx, f.tScope, domiam.SuperAdminLevel)
	if err != nil {
		t.Fatalf("approver count: %v", err)
	}
	if after != before+1 {
		t.Fatalf("a super admin must count as an approver at every level: %d -> %d", before, after)
	}
	// Deliberately granted by ROLE, not by the is_super_admin column. That is the
	// only route the console offers, and reading only the column here told an
	// organization whose super admin was created that way that nobody could
	// approve anything — blocking them from gating a device over a deadlock that
	// did not exist.
	_ = superRole
}

// A person at the pending-request cap must still be able to take emergency
// access.
//
// Regression: the rate limit ran before the emergency branch mattered, so the
// operator most likely to be at the cap — the one who has been hammering the
// ordinary request button — was the one locked out of the 3am door.
func TestIntegration_RateLimitDoesNotBlockEmergency(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	who := f.user(t, ctx, "operator")
	d := f.device(t, ctx, 1)

	// Fill the cap with ordinary pending requests.
	for i := 0; i < domaccess.MaxPendingPerUser; i++ {
		f.request(t, ctx, who, f.device(t, ctx, 1).ID, 10, 1)
	}
	n, err := f.requests.CountPending(ctx, f.scope, who)
	if err != nil {
		t.Fatalf("count pending: %v", err)
	}
	if n < domaccess.MaxPendingPerUser {
		t.Fatalf("expected the cap to be reached, got %d pending", n)
	}

	// An emergency is created already approved, and must be storable regardless.
	minutes := 30
	em := &domaccess.Request{
		ID: uuid.New(), OrganizationID: defaultOrgID, UserID: who, DeviceID: d.ID,
		Status: domaccess.RequestApproved, Reason: "firewall down at 3am",
		RequestedMinutes: minutes, GrantedMinutes: &minutes, MinApprovals: 1,
		RequesterLevel: 10, IsEmergency: true,
		ExpiresAt: time.Now().Add(domaccess.DefaultRequestTTL),
	}
	if err := f.requests.Create(ctx, f.scope, em); err != nil {
		t.Fatalf("emergency request at the cap: %v", err)
	}
	if !em.Redeemable(time.Now()) {
		t.Fatal("an emergency request must be immediately redeemable")
	}

	// And it must show up in the review queue rather than vanishing.
	list, err := f.requests.List(ctx, f.scope, domaccess.RequestFilter{UnreviewedEmergency: true, Limit: 50})
	if err != nil {
		t.Fatalf("review queue: %v", err)
	}
	found := false
	for i := range list {
		if list[i].ID == em.ID {
			found = true
		}
	}
	if !found {
		t.Fatal("emergency access must land in the review queue for after-the-fact sign-off")
	}
}

// Listing must be narrowable to one person, which is what the console's "My
// requests" tab asks for. Without it a privileged user asking for their own
// requests was shown the whole tenant's.
func TestIntegration_RequestsFilterByUser(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	mine := f.user(t, ctx, "mine")
	theirs := f.user(t, ctx, "theirs")
	d := f.device(t, ctx, 1)
	want := f.request(t, ctx, mine, d.ID, 10, 1)
	f.request(t, ctx, theirs, d.ID, 10, 1)

	list, err := f.requests.List(ctx, f.scope, domaccess.RequestFilter{UserID: &mine, Limit: 50})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) == 0 {
		t.Fatal("filtering by user returned nothing")
	}
	for i := range list {
		if list[i].UserID != mine {
			t.Fatalf("request %v belongs to somebody else — the filter leaked the tenant's requests", list[i].ID)
		}
	}
	if list[0].ID != want.ID {
		t.Fatalf("expected %v, got %v", want.ID, list[0].ID)
	}
}

// A NON-super-admin must be able to approve somebody who ranks below them.
//
// Every earlier test approved as a super admin, who bypasses rank entirely, so
// they all passed while the rank hierarchy was inert: user roles were hydrated
// without approval_level, so every ordinary principal carried rank 0 and the
// strict comparison 0 > 0 meant nobody but a super admin could decide anything.
// This asserts the claims a real sign-in produces, not levels handed in by the
// test.
func TestIntegration_NonSuperAdminApproverCarriesRealRank(t *testing.T) {
	svc, closeIAM := newService(t)
	defer closeIAM()
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)
	actor := superAdmin()

	orgAdminRole := domiam.ID(uuid.MustParse("10000000-0000-0000-0000-000000000002"))
	operatorRole := domiam.ID(uuid.MustParse("10000000-0000-0000-0000-000000000004"))

	boss, err := svc.CreateUser(ctx, actor, appiam.CreateUserInput{
		Email: "boss-" + uuid.NewString()[:8] + "@example.com", Username: "boss",
		Password: "IntegrationPass123!", RoleIDs: []domiam.ID{orgAdminRole},
	})
	if err != nil {
		t.Fatalf("create approver: %v", err)
	}
	op, err := svc.CreateUser(ctx, actor, appiam.CreateUserInput{
		Email: "op-" + uuid.NewString()[:8] + "@example.com", Username: "op",
		Password: "IntegrationPass123!", RoleIDs: []domiam.ID{operatorRole},
	})
	if err != nil {
		t.Fatalf("create requester: %v", err)
	}

	// The ranks a sign-in would actually put on the token.
	if boss.ApprovalLevel != 50 {
		t.Fatalf("Organization Admin principal carries rank %d, want 50 — user roles are "+
			"being hydrated without approval_level", boss.ApprovalLevel)
	}
	if op.ApprovalLevel != 10 {
		t.Fatalf("Operator principal carries rank %d, want 10", op.ApprovalLevel)
	}

	// And the gate honours them: the Organization Admin decides the Operator's
	// request without being a super admin.
	d := f.device(t, ctx, 1)
	req := f.request(t, ctx, op.UserID, d.ID, op.ApprovalLevel, 1)
	got, err := f.requests.AddDecision(ctx, f.scope, req.ID, boss.UserID,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, boss.ApprovalLevel, false)
	if err != nil {
		t.Fatalf("an Organization Admin must be able to approve an Operator: %v", err)
	}
	if got.Status != domaccess.RequestApproved {
		t.Fatalf("status = %q, want approved", got.Status)
	}

	// A peer still cannot.
	peer, err := svc.CreateUser(ctx, actor, appiam.CreateUserInput{
		Email: "peer-" + uuid.NewString()[:8] + "@example.com", Username: "peer",
		Password: "IntegrationPass123!", RoleIDs: []domiam.ID{operatorRole},
	})
	if err != nil {
		t.Fatalf("create peer: %v", err)
	}
	req2 := f.request(t, ctx, op.UserID, d.ID, op.ApprovalLevel, 1)
	if _, err := f.requests.AddDecision(ctx, f.scope, req2.ID, peer.UserID,
		domaccess.Decision{Decision: domaccess.DecisionApprove}, peer.ApprovalLevel, false); !errors.Is(err, domaccess.ErrCannotDecide) {
		t.Fatalf("an equal rank must not approve, got %v", err)
	}
}

// The emergency quota counts break-glass accesses somebody actually TOOK, inside
// the window, and reports the oldest so the refusal can say when it frees up.
//
// Tested against the database because every clause is load-bearing and none of
// them is visible from the application layer: the session_id predicate is what
// stops a misconfigured device burning a week's quota on connects that gave
// nobody access, and MIN(created_at) is what makes the refusal a sentence rather
// than a wall.
func TestIntegration_EmergencyQuotaCountsOnlyAccessesTaken(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()
	f := newApprovalFixture(t, pg)

	user := f.user(t, ctx, "breaker")
	device := f.device(t, ctx, 1)
	now := time.Now()

	// Taken 2 days ago: counts.
	taken := f.request(t, ctx, user, device.ID, 10, 1)
	f.markEmergency(t, ctx, taken.ID, now.Add(-48*time.Hour))
	f.attachSession(t, ctx, taken.ID, f.session(t, ctx, user, device.ID))

	// Raised but never became a session — the device had no credential bound.
	// Cost nobody any access, so it must not spend quota.
	failed := f.request(t, ctx, user, device.ID, 10, 1)
	f.markEmergency(t, ctx, failed.ID, now.Add(-24*time.Hour))

	// Taken, but older than the window: aged out.
	old := f.request(t, ctx, user, device.ID, 10, 1)
	f.markEmergency(t, ctx, old.ID, now.Add(-30*24*time.Hour))
	f.attachSession(t, ctx, old.ID, f.session(t, ctx, user, device.ID))

	// An ordinary approved request that was used is not an emergency at all.
	ordinary := f.request(t, ctx, user, device.ID, 10, 1)
	f.attachSession(t, ctx, ordinary.ID, f.session(t, ctx, user, device.ID))

	since := now.Add(-7 * 24 * time.Hour)
	n, oldest, err := f.requests.CountEmergenciesSince(ctx, f.scope, user, since)
	if err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Errorf("count = %d, want 1 — only the taken, in-window emergency counts", n)
	}
	if oldest.IsZero() {
		t.Fatal("no oldest timestamp; the refusal cannot say when the quota frees up")
	}
	if drift := oldest.Sub(now.Add(-48 * time.Hour)); drift > time.Second || drift < -time.Second {
		t.Errorf("oldest = %v, want the 48h-old emergency", oldest)
	}

	// Somebody who has taken none is unaffected.
	clean := f.user(t, ctx, "careful")
	if n, _, err := f.requests.CountEmergenciesSince(ctx, f.scope, clean, since); err != nil || n != 0 {
		t.Errorf("count for a user with no emergencies = %d (err %v), want 0", n, err)
	}
}
