//go:build integration

package test

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"time"

	"github.com/guardrail/guardrail/internal/app/analytics"
	appassets "github.com/guardrail/guardrail/internal/app/assets"
	domaccess "github.com/guardrail/guardrail/internal/domain/access"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	"github.com/guardrail/guardrail/internal/domain/audit"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
)

// The audit_events CHECK constraint is the gatekeeper for the outcome
// vocabulary, and the recorder swallows its own errors — Record's result is
// discarded at every call site, deliberately, so a failed audit write cannot
// take down the operation it describes. That combination means a value the
// database rejects does not fail loudly: the event simply never appears.
//
// So the migration has to be proven from the outside. Against the pre-0029
// schema this test fails at the insert with a constraint violation, which is
// precisely the failure the shipped code would have hidden.
func TestIntegration_AuditAcceptsAPendingOutcome(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	org := defaultOrgID
	actor := uuid.New()
	marker := "test.pending." + uuid.NewString()[:8]
	if err := postgres.NewAuditRepo(pg).Record(ctx, audit.Event{
		ID: uuid.New(), OrganizationID: &org, ActorID: &actor, ActorEmail: "audit-probe@guardrail.local",
		Action: marker, Category: audit.CategorySession, Result: audit.ResultPending,
	}); err != nil {
		t.Fatalf("the database refused a pending audit event: %v", err)
	}

	rows, err := postgres.NewAnalyticsRepo(pg).ListAudit(ctx,
		analytics.Scope{OrganizationID: defaultOrgID}, analytics.AuditFilter{Action: marker, Limit: 10})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("read back %d events, want 1", len(rows))
	}
	if rows[0].Result != string(audit.ResultPending) {
		t.Errorf("stored result = %q, want %q", rows[0].Result, audit.ResultPending)
	}
}

// A refused attempt to switch recording off used to be written as
// "device.recording_denied — success". Two things were wrong with that at once:
// filtering the Audit Log for denials never surfaced it, and the row a reviewer
// did happen to see claimed the change had gone through when it had been
// blocked. Recording is evidence, so an attempt to remove it is exactly the row
// that has to be accurate.
func TestIntegration_RefusingToDisableRecordingIsAuditedAsDenied(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	// A real owner row: devices.created_by is a foreign key, so a made-up UUID is
	// rejected before the test can get anywhere near the recording policy.
	suffix := uuid.NewString()[:8]
	ownerUser := &domiam.User{
		ID: domiam.ID(uuid.New()), OrganizationID: domiam.ID(defaultOrgID),
		Email:    domiam.NewEmail("rec-owner-" + suffix + "@test.local"),
		Username: "rec-owner-" + suffix, AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := postgres.NewUserRepo(pg).Create(ctx,
		domiam.TenantScope{OrganizationID: domiam.ID(defaultOrgID)}, ownerUser); err != nil {
		t.Fatalf("seed owner: %v", err)
	}
	owner := uuid.UUID(ownerUser.ID)
	dev := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "rec-" + suffix,
		Host: "rec-" + suffix + ".test", Port: 22, Scheme: "ssh",
		Status: "active", RecordSessions: true, CreatedBy: &owner,
	}
	if err := postgres.NewDeviceRepo(pg).Create(ctx,
		domassets.Scope{OrganizationID: defaultOrgID}, dev); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	svc := appassets.NewService(postgres.NewDeviceRepo(pg), postgres.NewAssetGroupRepo(pg), postgres.NewAuditRepo(pg))
	// Somebody who is neither the owner nor a super admin. They may edit the
	// device; they may not touch its recording policy.
	//
	// They have to be a REAL user with real reach, not an invented UUID. Device
	// reads are filtered to what the reader reaches, so a principal with no
	// standing at all is refused earlier and with a different answer — not found
	// rather than forbidden — and the denial this test exists to prove would
	// never be reached. A team granting manage over every device is the shortest
	// honest way to say "this person can see and edit the device".
	tScope := domiam.TenantScope{OrganizationID: domiam.ID(defaultOrgID)}
	strangerUser := &domiam.User{
		ID: domiam.ID(uuid.New()), OrganizationID: domiam.ID(defaultOrgID),
		Email:    domiam.NewEmail("rec-stranger-" + suffix + "@test.local"),
		Username: "rec-stranger-" + suffix, AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := postgres.NewUserRepo(pg).Create(ctx, tScope, strangerUser); err != nil {
		t.Fatalf("seed stranger: %v", err)
	}
	teams := postgres.NewTeamRepo(pg)
	team := &domiam.Team{Name: "rec-strangers-" + suffix, AllDevicesLevel: domiam.AccessManage}
	if err := teams.Create(ctx, tScope, team); err != nil {
		t.Fatalf("seed team: %v", err)
	}
	if err := teams.SetMembers(ctx, tScope, team.ID, []domiam.ID{strangerUser.ID}); err != nil {
		t.Fatalf("seed team member: %v", err)
	}
	stranger := domiam.Claims{
		UserID: uuid.UUID(strangerUser.ID), OrganizationID: defaultOrgID,
		Email: string(strangerUser.Email),
	}
	off := false
	if _, err := svc.UpdateDevice(ctx, stranger, dev.ID, appassets.DeviceInput{
		Name: dev.Name, Host: dev.Host, Port: dev.Port, Scheme: dev.Scheme,
		RecordSessions: &off,
	}); !errors.Is(err, domassets.ErrForbidden) {
		t.Fatalf("switching recording off as a stranger = %v, want ErrForbidden", err)
	}

	rows, err := postgres.NewAnalyticsRepo(pg).ListAudit(ctx,
		analytics.Scope{OrganizationID: defaultOrgID},
		analytics.AuditFilter{Action: "device.recording_denied", TargetID: dev.ID.String(), Limit: 10})
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("read back %d device.recording_denied events, want 1", len(rows))
	}
	if rows[0].Result == string(audit.ResultSuccess) {
		t.Error(`a refused attempt to disable recording is logged as "success"`)
	}
	if rows[0].Result != string(audit.ResultDenied) {
		t.Errorf("stored result = %q, want %q", rows[0].Result, audit.ResultDenied)
	}
}

// The paged session listing scans its own column list by hand, in parallel with
// scanSession, and the two are coupled only by a comment asking whoever edits
// one to edit the other. Adding last_activity_at to the shared SQL and not to
// this scanner turned GET /sessions into a 500 with no log line — the console
// showed "Couldn't load session recordings" and nothing said why.
//
// So: list sessions for real. Any future column added to one side and not the
// other fails here instead of in front of an operator.
func TestIntegration_SessionListingScansEveryColumnItSelects(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	sessions := postgres.NewAccessSessionRepo(pg)
	sc := domaccess.Scope{OrganizationID: defaultOrgID}

	// A session whose window lapsed long before the record was closed — the shape
	// that reports broker downtime as access if the duration is end minus start.
	suffix := uuid.NewString()[:8]
	owner := &domiam.User{
		ID: domiam.ID(uuid.New()), OrganizationID: domiam.ID(defaultOrgID),
		Email:    domiam.NewEmail("span-" + suffix + "@test.local"),
		Username: "span-" + suffix, AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := postgres.NewUserRepo(pg).Create(ctx,
		domiam.TenantScope{OrganizationID: domiam.ID(defaultOrgID)}, owner); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	dev := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "span-" + suffix,
		Host: "span-" + suffix + ".test", Port: 443, Scheme: "https", Status: "active",
	}
	if err := postgres.NewDeviceRepo(pg).Create(ctx,
		domassets.Scope{OrganizationID: defaultOrgID}, dev); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	start := time.Now().Add(-48 * time.Hour)
	until := start.Add(time.Hour)
	activity := start.Add(4 * time.Second)
	sess := &domaccess.Session{
		ID: uuid.New(), OrganizationID: defaultOrgID, UserID: uuid.UUID(owner.ID), DeviceID: dev.ID,
		Protocol: domaccess.ProtocolHTTPS, Status: domaccess.StatusActive,
		GrantedFrom: &start, GrantedUntil: &until, StartedAt: &start, LastActivityAt: &activity,
		DeviceName: dev.Name,
	}
	if err := sessions.Create(ctx, sc, sess); err != nil {
		t.Fatalf("create session: %v", err)
	}
	// Create does not persist activity — nothing has happened yet. TouchActivity
	// is the real path, and it is what the idle reaper measures from.
	if err := sessions.TouchActivity(ctx, sess.ID, activity); err != nil {
		t.Fatalf("touch activity: %v", err)
	}

	views, _, err := sessions.ListView(ctx, sc, domaccess.SessionFilter{DeviceID: &dev.ID, Limit: 10})
	if err != nil {
		t.Fatalf("listing sessions failed — a selected column is not being scanned: %v", err)
	}
	if len(views) != 1 {
		t.Fatalf("listed %d sessions, want 1", len(views))
	}
	if views[0].LastActivityAt == nil {
		t.Error("last_activity_at came back nil; the listing selects it but drops it on the floor")
	}

	// The reaper closes it at the moment authorization lapsed, not at the moment
	// it noticed — which here is two days late.
	if _, err := sessions.ExpireOverdue(ctx, time.Now()); err != nil {
		t.Fatalf("ExpireOverdue: %v", err)
	}
	got, err := sessions.GetByID(ctx, sc, sess.ID)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.EndedAt == nil {
		t.Fatal("an overdue session was not expired")
	}
	if drift := got.EndedAt.Sub(until); drift > time.Second || drift < -time.Second {
		t.Errorf("ended_at is %v from granted_until; a late reaper recorded %v of access that was never authorized",
			drift, drift)
	}
}

// The hash chain is the thing that makes this an audit LOG rather than a table
// of rows somebody could edit. It shipped in the first release and nothing ever
// walked it, so two defects sat in it undetected:
//
//   - it FORKED, because each event linked to the latest-DATED predecessor
//     rather than the last-inserted one, and
//   - its hashes could not be recomputed at all, because they were taken over Go
//     values that Postgres rounds (nanoseconds to microseconds) and re-orders
//     (jsonb sorts object keys its own way) on the way in.
//
// Both are the kind of fault that only a verifier finds, which is why nothing
// found them. These tests are that verifier's own proof.
func TestIntegration_AuditChainVerifies(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	repo := postgres.NewAuditRepo(pg)
	org := newChainOrg(t, pg) // a chain of this test's own, unaffected by other rows
	actor := uuid.New()

	for i := 0; i < 12; i++ {
		if err := repo.Record(ctx, audit.Event{
			ID: uuid.New(), OrganizationID: &org, ActorID: &actor,
			ActorEmail: "chain-probe@guardrail.local",
			Action:     "test.chain", Category: audit.CategorySession,
			Result: audit.ResultSuccess, IP: "10.200.10.69",
			// Deliberately awkward: keys that jsonb and Go sort differently, and a
			// character Go escapes and Postgres does not.
			Detail: map[string]any{"zz": i, "a": "x<y&z", "middle": []any{1, "two"}},
		}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	rep, err := repo.VerifyChain(ctx, &org, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("a chain nobody touched does not verify: %s (at %v)", rep.Reason, rep.BrokenAt)
	}
	if rep.Checked != 12 {
		t.Fatalf("checked %d events, want 12", rep.Checked)
	}
	if rep.Unverifiable != 0 {
		t.Errorf("%d events reported unverifiable; every one of these was written by the current scheme", rep.Unverifiable)
	}
}

// Events written OUT OF TIMESTAMP ORDER used to fork the chain: both linked to
// the same predecessor, and a forked chain proves nothing, because a spliced-in
// row is indistinguishable from a branch. Callers really do write out of order —
// anything carrying its own clock does.
func TestIntegration_AuditChainSurvivesOutOfOrderTimestamps(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	repo := postgres.NewAuditRepo(pg)
	org := newChainOrg(t, pg)
	base := time.Date(2026, 8, 18, 14, 0, 0, 0, time.UTC)

	for _, offset := range []time.Duration{0, -2 * time.Hour, time.Hour, -30 * time.Minute, 15 * time.Minute} {
		if err := repo.Record(ctx, audit.Event{
			ID: uuid.New(), OrganizationID: &org, Timestamp: base.Add(offset),
			ActorEmail: "clock-skew@guardrail.local",
			Action:     "test.out_of_order", Category: audit.CategoryAuth, Result: audit.ResultSuccess,
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	rep, err := repo.VerifyChain(ctx, &org, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !rep.OK {
		t.Fatalf("out-of-order timestamps broke the chain: %s", rep.Reason)
	}
	if rep.Checked != 5 {
		t.Fatalf("checked %d events, want 5", rep.Checked)
	}
}

// And the point of all of it: an altered row is caught, and named.
func TestIntegration_AuditChainCatchesAnAlteredRow(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	repo := postgres.NewAuditRepo(pg)
	org := newChainOrg(t, pg)
	var victim uuid.UUID
	for i := 0; i < 5; i++ {
		id := uuid.New()
		if i == 2 {
			victim = id
		}
		if err := repo.Record(ctx, audit.Event{
			ID: id, OrganizationID: &org, ActorEmail: "chain-probe@guardrail.local",
			Action: "test.tamper", Category: audit.CategorySession, Result: audit.ResultDenied,
		}); err != nil {
			t.Fatalf("record: %v", err)
		}
	}

	// The application role holds no UPDATE grant on audit_events, which is the
	// point — so this edit is made as the owner, standing in for somebody with
	// database access. That is precisely the attacker a hash chain exists for.
	tamperWithAuditRow(t, ctx, victim)

	rep, err := repo.VerifyChain(ctx, &org, 0)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if rep.OK {
		t.Fatal("an event was rewritten in the database and the chain still verified")
	}
	if rep.BrokenAt == nil || *rep.BrokenAt != victim {
		t.Fatalf("broken at %v, want the row that was edited (%s)", rep.BrokenAt, victim)
	}
	if rep.Checked != 2 {
		t.Errorf("checked %d events before the break, want the 2 that precede it", rep.Checked)
	}
}

// tamperWithAuditRow edits an audit event directly, standing in for somebody
// with database access.
//
// It needs a connection that OWNS the table. The application's own role is
// granted no UPDATE or DELETE on audit_events — that is the product guarantee,
// and it is why the rest of the suite, which runs as that role, cannot perform
// this edit. So the owner DSN is a separate variable, and without it the test
// says why it did not run rather than reporting a pass it did not earn.
func tamperWithAuditRow(t *testing.T, ctx context.Context, id uuid.UUID) {
	t.Helper()
	dsn := os.Getenv("GUARDRAIL_TEST_OWNER_DSN")
	if dsn == "" {
		dsn = os.Getenv("GUARDRAIL_TEST_DSN")
	}
	if dsn == "" {
		t.Skip("set GUARDRAIL_TEST_DSN (and GUARDRAIL_TEST_OWNER_DSN) to run integration tests")
	}
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect as the table owner: %v", err)
	}
	defer conn.Close(ctx)
	if _, err := conn.Exec(ctx, `UPDATE audit_events SET result='success' WHERE id=$1`, id); err != nil {
		t.Skipf("this connection cannot rewrite audit_events (%v). "+
			"That is the correct grant for the application role; point "+
			"GUARDRAIL_TEST_OWNER_DSN at the role that owns the table to exercise this.", err)
	}
}

// newChainOrg creates an organization so the test writes into a chain of its own.
// audit_events carries a foreign key to organizations, and — more to the point —
// a chain shared with every other test's rows would prove nothing about ordering.
func newChainOrg(t *testing.T, pg *postgres.DB) uuid.UUID {
	t.Helper()
	slug := "chain-" + uuid.NewString()[:8]
	o := &domiam.Organization{ID: uuid.New(), Name: slug, Slug: slug, Status: "active"}
	if err := postgres.NewOrgRepo(pg).Create(context.Background(),
		domiam.TenantScope{IsSuperAdmin: true}, o); err != nil {
		t.Fatalf("create organization: %v", err)
	}
	return o.ID
}
