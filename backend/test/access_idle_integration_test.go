//go:build integration

package test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	domaccess "github.com/guardrail/guardrail/internal/domain/access"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
)

// The idle sweep is pure SQL, so the service-level fakes prove nothing about it:
// an earlier version of this query typechecked in Go, passed every unit test, and
// then failed on every tick in production with "operator does not exist:
// timestamp with time zone < interval", because an uncast $1 let Postgres resolve
// the subtraction as interval-minus-interval. Only real Postgres catches that
// class of bug, which is what these tests are for.

// fixtures owns the rows a test creates and removes them afterwards. These tests
// run against a real database that may also be someone's running install, and
// ExpireIdle is system-scoped — leaving fixture devices behind would put fake
// hardware in a live inventory. Deletion goes through a direct pool because the
// repositories only soft-delete, which would still leave the rows in place.
type fixtures struct {
	t        *testing.T
	pool     *pgxpool.Pool
	sessions []uuid.UUID
	devices  []uuid.UUID
	users    []uuid.UUID
}

func newFixtures(t *testing.T) *fixtures {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), envOrSkip(t, "GUARDRAIL_TEST_DSN"))
	if err != nil {
		t.Fatalf("fixture pool: %v", err)
	}
	f := &fixtures{t: t, pool: pool}
	t.Cleanup(f.cleanup)
	return f
}

// cleanup deletes in FK order: sessions reference devices and users with
// ON DELETE RESTRICT, so the children have to go first.
func (f *fixtures) cleanup() {
	defer f.pool.Close()
	ctx := context.Background()
	for _, q := range []struct {
		sql string
		ids []uuid.UUID
	}{
		{`DELETE FROM access_sessions WHERE id = ANY($1)`, f.sessions},
		{`DELETE FROM devices WHERE id = ANY($1)`, f.devices},
		{`DELETE FROM users WHERE id = ANY($1)`, f.users},
	} {
		if len(q.ids) == 0 {
			continue
		}
		if _, err := f.pool.Exec(ctx, q.sql, q.ids); err != nil {
			// Not fatal: the test's own result matters more than the tidying, but
			// a silent failure here is how the inventory fills up with fakes.
			f.t.Errorf("cleanup %q: %v", q.sql, err)
		}
	}
}

// newIdleDevice registers a device with the given idle timeout and returns its ID.
// The host is randomised because uq_device_endpoint is unique on
// (organization_id, host, port, scheme) and these tests share a database.
func (f *fixtures) newIdleDevice(devices *postgres.DeviceRepo, timeout int) uuid.UUID {
	f.t.Helper()
	id := uuid.NewString()[:8]
	dev := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: "idle-" + id,
		Host: "idle-" + id + ".test", Port: 443, Scheme: "https", VerifyTLS: false,
		DeviceType: "router", Status: "active", IdleTimeoutMinutes: timeout,
	}
	if err := devices.Create(context.Background(), domassets.Scope{OrganizationID: defaultOrgID}, dev); err != nil {
		f.t.Fatalf("create device (timeout=%d): %v", timeout, err)
	}
	f.devices = append(f.devices, dev.ID)
	return dev.ID
}

// newIdleUser creates the operator the sessions belong to. access_sessions.user_id
// is a real foreign key, so a synthetic UUID will not do.
func (f *fixtures) newIdleUser(users *postgres.UserRepo) uuid.UUID {
	f.t.Helper()
	id := uuid.NewString()[:8]
	u := &domiam.User{
		ID: domiam.ID(uuid.New()), OrganizationID: domiam.ID(defaultOrgID),
		Email:    domiam.NewEmail("idle-" + id + "@test.local"),
		Username: "idle-" + id, AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := users.Create(context.Background(), domiam.TenantScope{OrganizationID: domiam.ID(defaultOrgID)}, u); err != nil {
		f.t.Fatalf("create user: %v", err)
	}
	f.users = append(f.users, uuid.UUID(u.ID))
	return uuid.UUID(u.ID)
}

// newSession opens an active session against a device. A nil startedAt models a
// session that was created but never started, which must still age out.
func (f *fixtures) newSession(sessions *postgres.AccessSessionRepo, userID, deviceID uuid.UUID, startedAt *time.Time) uuid.UUID {
	f.t.Helper()
	s := &domaccess.Session{
		ID: uuid.New(), OrganizationID: defaultOrgID, UserID: userID, DeviceID: deviceID,
		Protocol: domaccess.ProtocolHTTPS, Status: domaccess.StatusActive,
		GatewayNode: "test-node", StartedAt: startedAt,
	}
	sc := domaccess.Scope{OrganizationID: defaultOrgID}
	if err := sessions.Create(context.Background(), sc, s); err != nil {
		f.t.Fatalf("create session: %v", err)
	}
	f.sessions = append(f.sessions, s.ID)
	return s.ID
}

// statusOf re-reads a session's status and end reason from the database, so the
// assertion sees what the sweep actually wrote rather than a stale in-memory copy.
func statusOf(t *testing.T, sessions *postgres.AccessSessionRepo, id uuid.UUID) (string, string) {
	t.Helper()
	s, err := sessions.GetByID(context.Background(), domaccess.Scope{OrganizationID: defaultOrgID}, id)
	if err != nil {
		t.Fatalf("read session %s: %v", id, err)
	}
	return string(s.Status), s.EndReason
}

// contains reports whether the sweep returned the given session. ExpireIdle is
// system-scoped and sweeps every org, so a shared test database will hand back
// other rows too; assertions must key on identity, never on the total count.
func contains(got []domaccess.ExpiredSession, id uuid.UUID) bool {
	for _, e := range got {
		if e.ID == id {
			return true
		}
	}
	return false
}

func TestIntegration_ExpireIdleEndsStaleSessions(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	fx := newFixtures(t)
	devices := postgres.NewDeviceRepo(pg)
	sessions := postgres.NewAccessSessionRepo(pg)
	user := fx.newIdleUser(postgres.NewUserRepo(pg))

	now := time.Now()
	longAgo := now.Add(-2 * time.Hour)
	recently := now.Add(-1 * time.Minute)

	dev30 := fx.newIdleDevice(devices, 30)
	dev0 := fx.newIdleDevice(devices, 0)

	// Idle for two hours against a 30-minute timeout: must be reaped.
	stale := fx.newSession(sessions, user, dev30, &longAgo)
	// Active a minute ago against the same timeout: must survive.
	fresh := fx.newSession(sessions, user, dev30, &recently)
	// Equally stale, but its device has the timeout switched off: must survive.
	exempt := fx.newSession(sessions, user, dev0, &longAgo)
	// Never started at all. created_at is now, so it is not yet stale — this
	// pins the COALESCE fallback, which is the only reason such a row ages out.
	unstarted := fx.newSession(sessions, user, dev30, nil)

	got, err := sessions.ExpireIdle(ctx, now)
	if err != nil {
		t.Fatalf("ExpireIdle: %v", err)
	}

	if !contains(got, stale) {
		t.Errorf("stale session %s was not reported by the sweep", stale)
	}
	if status, reason := statusOf(t, sessions, stale); status != "expired" || reason != "idle_timeout" {
		t.Errorf("stale session: got status=%q reason=%q, want expired/idle_timeout", status, reason)
	}

	for name, id := range map[string]uuid.UUID{"fresh": fresh, "exempt": exempt, "unstarted": unstarted} {
		if contains(got, id) {
			t.Errorf("%s session %s was reaped but should not have been", name, id)
		}
		if status, _ := statusOf(t, sessions, id); status != "active" {
			t.Errorf("%s session: got status=%q, want active", name, status)
		}
	}

	// The sweep must report enough to tear the session down on its gateway; an ID
	// with no protocol would leave the browser process orphaned.
	for _, e := range got {
		if e.ID == stale {
			if e.OrgID != defaultOrgID || e.Protocol != domaccess.ProtocolHTTPS {
				t.Errorf("sweep returned org=%s proto=%q, want %s/https", e.OrgID, e.Protocol, defaultOrgID)
			}
		}
	}
}

// An unstarted session must age out from created_at, or opening a session and
// walking away would keep it live until its grant window expired.
func TestIntegration_ExpireIdleUsesCreatedAtFallback(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	fx := newFixtures(t)
	devices := postgres.NewDeviceRepo(pg)
	sessions := postgres.NewAccessSessionRepo(pg)
	user := fx.newIdleUser(postgres.NewUserRepo(pg))

	dev := fx.newIdleDevice(devices, 30)
	id := fx.newSession(sessions, user, dev, nil)

	// Sweep from an hour in the future: with created_at ~now and no activity or
	// start stamp, only the COALESCE fallback can make this row stale.
	got, err := sessions.ExpireIdle(ctx, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("ExpireIdle: %v", err)
	}
	if !contains(got, id) {
		t.Fatalf("unstarted session %s did not age out from created_at", id)
	}
	if status, reason := statusOf(t, sessions, id); status != "expired" || reason != "idle_timeout" {
		t.Errorf("got status=%q reason=%q, want expired/idle_timeout", status, reason)
	}
}

// TouchActivity is what stands between a working session and the reaper, so it
// has to actually move the clock the sweep reads.
func TestIntegration_TouchActivityKeepsSessionAlive(t *testing.T) {
	pg, closeDB := newPG(t)
	defer closeDB()
	ctx := context.Background()

	fx := newFixtures(t)
	devices := postgres.NewDeviceRepo(pg)
	sessions := postgres.NewAccessSessionRepo(pg)
	user := fx.newIdleUser(postgres.NewUserRepo(pg))

	now := time.Now()
	longAgo := now.Add(-2 * time.Hour)

	dev := fx.newIdleDevice(devices, 30)
	id := fx.newSession(sessions, user, dev, &longAgo)

	// Without this the session is two hours idle and would be reaped.
	if err := sessions.TouchActivity(ctx, id, now); err != nil {
		t.Fatalf("TouchActivity: %v", err)
	}

	got, err := sessions.ExpireIdle(ctx, now)
	if err != nil {
		t.Fatalf("ExpireIdle: %v", err)
	}
	if contains(got, id) {
		t.Fatalf("touched session %s was reaped anyway", id)
	}
	if status, _ := statusOf(t, sessions, id); status != "active" {
		t.Errorf("got status=%q, want active", status)
	}

	// A touch must not resurrect a session the reaper already closed, or a request
	// racing termination would flip a dead session back to live.
	if err := sessions.UpdateStatus(ctx, domaccess.Scope{OrganizationID: defaultOrgID},
		id, domaccess.StatusEnded, "terminated", now); err != nil {
		t.Fatalf("UpdateStatus: %v", err)
	}
	if err := sessions.TouchActivity(ctx, id, now.Add(time.Minute)); err != nil {
		t.Fatalf("TouchActivity after end: %v", err)
	}
	if status, _ := statusOf(t, sessions, id); status != "ended" {
		t.Errorf("touch resurrected an ended session: got status=%q, want ended", status)
	}
}
