//go:build integration

package test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	domaccess "github.com/guardrail/guardrail/internal/domain/access"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/infra/postgres"
)

// Teams decide which devices a person reaches. The rule itself lives in SQL
// (app_device_reach, migration 0034) because two callers need it — the connect
// check and the inventory listing — and a rule written twice drifts. These tests
// exercise it through the repositories that ship, not through a re-implementation
// of the query in Go, which would only prove the copy agrees with itself.

type teamFixture struct {
	pg      *postgres.DB
	teams   *postgres.TeamRepo
	devices *postgres.DeviceRepo
	groups  *postgres.AssetGroupRepo
	auth    *postgres.AuthorizerRepo
	users   *postgres.UserRepo
	tScope  domiam.TenantScope
	aScope  domassets.Scope
	suffix  string

	// Everything this fixture created, torn down in t.Cleanup. These tests run
	// against a REAL database that is often a working deployment, and rows they
	// leave behind show up in somebody's device inventory — so cleaning up is
	// part of the test, not an optional courtesy.
	madeDevices []uuid.UUID
	madeUsers   []uuid.UUID
	madeGroups  []uuid.UUID
	madeTeams   []uuid.UUID
}

func newTeamFixture(t *testing.T, pg *postgres.DB) *teamFixture {
	t.Helper()
	f := &teamFixture{
		pg: pg, teams: postgres.NewTeamRepo(pg), devices: postgres.NewDeviceRepo(pg),
		groups: postgres.NewAssetGroupRepo(pg), auth: postgres.NewAuthorizerRepo(pg),
		users:  postgres.NewUserRepo(pg),
		tScope: domiam.TenantScope{OrganizationID: domiam.ID(defaultOrgID)},
		// Writes and read-backs of things the test just created are not
		// authorization questions.
		aScope: domassets.Scope{OrganizationID: defaultOrgID, PostAuthorized: true},
		suffix: uuid.NewString()[:8],
	}
	t.Cleanup(func() { f.cleanup(t) })
	return f
}

// cleanup removes every row the fixture created, in dependency order.
//
// access_sessions references devices and users with ON DELETE RESTRICT, so those
// go first or the device delete fails. Everything else cascades from the four
// parents. Failures are reported rather than fatal: a teardown that calls
// t.Fatal masks the real failure of the test it is tearing down.
func (f *teamFixture) cleanup(t *testing.T) {
	t.Helper()
	if len(f.madeDevices)+len(f.madeUsers)+len(f.madeGroups)+len(f.madeTeams) == 0 {
		return
	}
	ctx := context.Background()
	err := f.pg.WithSystemScope(ctx, func(tx pgx.Tx) error {
		for _, q := range []struct {
			sql string
			ids []uuid.UUID
		}{
			{`DELETE FROM access_request_decisions WHERE request_id IN (
			    SELECT id FROM access_requests WHERE device_id = ANY($1) OR user_id = ANY($1))`, nil},
			{`DELETE FROM device_access_grants WHERE device_id = ANY($1) OR user_id = ANY($1)`, nil},
			{`DELETE FROM access_requests WHERE device_id = ANY($1) OR user_id = ANY($1)`, nil},
			{`DELETE FROM access_sessions WHERE device_id = ANY($1) OR user_id = ANY($1)`, nil},
		} {
			both := append(append([]uuid.UUID{}, f.madeDevices...), f.madeUsers...)
			if _, err := tx.Exec(ctx, q.sql, both); err != nil {
				return err
			}
		}
		for _, q := range []struct {
			sql string
			ids []uuid.UUID
		}{
			{`DELETE FROM devices WHERE id = ANY($1)`, f.madeDevices},
			{`DELETE FROM teams WHERE id = ANY($1)`, f.madeTeams},
			{`DELETE FROM asset_groups WHERE id = ANY($1)`, f.madeGroups},
			{`DELETE FROM users WHERE id = ANY($1)`, f.madeUsers},
		} {
			if len(q.ids) == 0 {
				continue
			}
			if _, err := tx.Exec(ctx, q.sql, q.ids); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Errorf("fixture cleanup left rows behind: %v", err)
	}
}

func (f *teamFixture) user(t *testing.T, ctx context.Context, name string) domiam.ID {
	t.Helper()
	u := &domiam.User{
		ID: domiam.ID(uuid.New()), OrganizationID: domiam.ID(defaultOrgID),
		Email:    domiam.NewEmail(name + "-" + f.suffix + "@team.test"),
		Username: name + "-" + f.suffix, AuthProvider: domiam.ProviderLocal, Status: "active",
	}
	if err := f.users.Create(ctx, f.tScope, u); err != nil {
		t.Fatalf("create user %s: %v", name, err)
	}
	f.madeUsers = append(f.madeUsers, uuid.UUID(u.ID))
	return u.ID
}

func (f *teamFixture) device(t *testing.T, ctx context.Context, name, dtype string) uuid.UUID {
	t.Helper()
	d := &domassets.Device{
		ID: uuid.New(), OrganizationID: defaultOrgID, Name: name + "-" + f.suffix,
		Host: name + "-" + f.suffix + ".team.test", Port: 443, Scheme: "https",
		DeviceType: dtype, Status: "active",
	}
	if err := f.devices.Create(ctx, f.aScope, d); err != nil {
		t.Fatalf("create device %s: %v", name, err)
	}
	f.madeDevices = append(f.madeDevices, d.ID)
	return d.ID
}

func (f *teamFixture) group(t *testing.T, ctx context.Context, name string, parent *uuid.UUID) uuid.UUID {
	t.Helper()
	g := &domassets.AssetGroup{
		ID: uuid.New(), OrganizationID: defaultOrgID, ParentID: parent,
		Name: name + "-" + f.suffix, Type: "folder",
	}
	if err := f.groups.Create(ctx, f.aScope, g); err != nil {
		t.Fatalf("create group %s: %v", name, err)
	}
	f.madeGroups = append(f.madeGroups, g.ID)
	return g.ID
}

func (f *teamFixture) team(t *testing.T, ctx context.Context, name string, blanket domiam.AccessLevel, members []domiam.ID) domiam.ID {
	t.Helper()
	tm := &domiam.Team{Name: name + "-" + f.suffix, AllDevicesLevel: blanket}
	if err := f.teams.Create(ctx, f.tScope, tm); err != nil {
		t.Fatalf("create team %s: %v", name, err)
	}
	f.madeTeams = append(f.madeTeams, uuid.UUID(tm.ID))
	if len(members) > 0 {
		if err := f.teams.SetMembers(ctx, f.tScope, tm.ID, members); err != nil {
			t.Fatalf("set members of %s: %v", name, err)
		}
	}
	return tm.ID
}

// reach lists what a user sees, keyed by device id, with the level.
func (f *teamFixture) reach(t *testing.T, ctx context.Context, user domiam.ID) map[uuid.UUID]string {
	t.Helper()
	devs, err := f.devices.List(ctx, domassets.Scope{
		OrganizationID: defaultOrgID, UserID: uuid.UUID(user),
	}, domassets.Filter{Limit: 500})
	if err != nil {
		t.Fatalf("list devices: %v", err)
	}
	out := map[uuid.UUID]string{}
	for _, d := range devs {
		out[d.ID] = d.AccessLevel
	}
	return out
}

// An IT team reaches IT kit and a security team reaches security kit, and
// neither can enumerate the other's. Hiding is the point: before teams, a scoped
// role could list every device in the organization — names, addresses, ports,
// liveness — and was refused only at the Connect button.
func TestIntegration_TeamsScopeWhatEachTeamSees(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	itUser := f.user(t, ctx, "it")
	csUser := f.user(t, ctx, "cs")

	itGroup := f.group(t, ctx, "IT", nil)
	csGroup := f.group(t, ctx, "Security", nil)
	itDev := f.device(t, ctx, "switch", "switch")
	csDev := f.device(t, ctx, "siem", "appliance")
	if err := f.groups.AddMember(ctx, f.aScope, itGroup, itDev); err != nil {
		t.Fatalf("add it device: %v", err)
	}
	if err := f.groups.AddMember(ctx, f.aScope, csGroup, csDev); err != nil {
		t.Fatalf("add cs device: %v", err)
	}

	itTeam := f.team(t, ctx, "IT", domiam.AccessNone, []domiam.ID{itUser})
	csTeam := f.team(t, ctx, "CS", domiam.AccessNone, []domiam.ID{csUser})
	if err := f.teams.SetGrants(ctx, f.tScope, itTeam, domiam.TeamGrants{
		Groups: []domiam.GroupGrant{{AssetGroupID: itGroup, Level: domiam.AccessConnect}},
	}); err != nil {
		t.Fatalf("grant it: %v", err)
	}
	if err := f.teams.SetGrants(ctx, f.tScope, csTeam, domiam.TeamGrants{
		Groups: []domiam.GroupGrant{{AssetGroupID: csGroup, Level: domiam.AccessManage}},
	}); err != nil {
		t.Fatalf("grant cs: %v", err)
	}

	itReach := f.reach(t, ctx, itUser)
	if itReach[itDev] != "connect" {
		t.Errorf("IT reaches its own switch at %q, want connect", itReach[itDev])
	}
	if _, seen := itReach[csDev]; seen {
		t.Error("IT can see the security team's appliance; it must not be listed at all")
	}

	csReach := f.reach(t, ctx, csUser)
	if csReach[csDev] != "manage" {
		t.Errorf("CS reaches its own appliance at %q, want manage", csReach[csDev])
	}
	if _, seen := csReach[itDev]; seen {
		t.Error("CS can see the IT switch; it must not be listed at all")
	}
}

// A grant on a parent group covers the devices in its children. Without
// inheritance a group tree cannot be reorganised: moving a group under another
// would silently revoke it, and nothing would report that it had.
func TestIntegration_TeamGrantInheritsDownTheGroupTree(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	user := f.user(t, ctx, "nested")
	parent := f.group(t, ctx, "IT", nil)
	child := f.group(t, ctx, "IT-Network", &parent)
	grandchild := f.group(t, ctx, "IT-Network-Edge", &child)

	deep := f.device(t, ctx, "edge", "router")
	if err := f.groups.AddMember(ctx, f.aScope, grandchild, deep); err != nil {
		t.Fatalf("add device: %v", err)
	}

	team := f.team(t, ctx, "IT", domiam.AccessNone, []domiam.ID{user})
	// The grant names the ROOT only.
	if err := f.teams.SetGrants(ctx, f.tScope, team, domiam.TeamGrants{
		Groups: []domiam.GroupGrant{{AssetGroupID: parent, Level: domiam.AccessConnect}},
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if got := f.reach(t, ctx, user)[deep]; got != "connect" {
		t.Errorf("a device two levels below the granted group reads %q, want connect", got)
	}
}

// 'view' is the level that exists to say "you may see this and not touch it".
// If it let somebody connect it would mean nothing at all.
func TestIntegration_ViewGrantIsVisibleButNotConnectable(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	user := f.user(t, ctx, "viewer")
	group := f.group(t, ctx, "Watched", nil)
	dev := f.device(t, ctx, "fw", "firewall")
	if err := f.groups.AddMember(ctx, f.aScope, group, dev); err != nil {
		t.Fatalf("add device: %v", err)
	}
	team := f.team(t, ctx, "Watchers", domiam.AccessNone, []domiam.ID{user})
	if err := f.teams.SetGrants(ctx, f.tScope, team, domiam.TeamGrants{
		Groups: []domiam.GroupGrant{{AssetGroupID: group, Level: domiam.AccessView}},
	}); err != nil {
		t.Fatalf("grant: %v", err)
	}

	if got := f.reach(t, ctx, user)[dev]; got != "view" {
		t.Fatalf("listing shows %q, want view", got)
	}
	ok, err := f.auth.CanAccessDevice(ctx,
		domaccess.Scope{OrganizationID: defaultOrgID}, uuid.UUID(user), dev)
	if err != nil {
		t.Fatalf("CanAccessDevice: %v", err)
	}
	if ok {
		t.Error("a view grant must not permit a session to be brokered")
	}
}

// Two teams overlapping on one device resolve to the HIGHER level. Union and not
// intersection: adding somebody to a second team must never take away what the
// first gave them, or "add them to the DR team as well" becomes a change that
// quietly removes access somewhere else.
func TestIntegration_OverlappingTeamsTakeTheHigherLevel(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	user := f.user(t, ctx, "both")
	group := f.group(t, ctx, "Shared", nil)
	dev := f.device(t, ctx, "shared", "switch")
	if err := f.groups.AddMember(ctx, f.aScope, group, dev); err != nil {
		t.Fatalf("add device: %v", err)
	}

	low := f.team(t, ctx, "Watchers", domiam.AccessNone, []domiam.ID{user})
	high := f.team(t, ctx, "Owners", domiam.AccessNone, []domiam.ID{user})
	if err := f.teams.SetGrants(ctx, f.tScope, low, domiam.TeamGrants{
		Groups: []domiam.GroupGrant{{AssetGroupID: group, Level: domiam.AccessView}},
	}); err != nil {
		t.Fatalf("grant low: %v", err)
	}
	if err := f.teams.SetGrants(ctx, f.tScope, high, domiam.TeamGrants{
		Groups: []domiam.GroupGrant{{AssetGroupID: group, Level: domiam.AccessManage}},
	}); err != nil {
		t.Fatalf("grant high: %v", err)
	}

	if got := f.reach(t, ctx, user)[dev]; got != "manage" {
		t.Errorf("overlapping view+manage resolved to %q, want manage", got)
	}
}

// The blanket grant is what an admin or platform team needs: enumerating such a
// team against every group instead produces a grant that stops covering anything
// created afterwards, and gives no sign that it has.
func TestIntegration_BlanketGrantCoversDevicesCreatedLater(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	user := f.user(t, ctx, "platform")
	f.team(t, ctx, "Platform", domiam.AccessManage, []domiam.ID{user})

	// Registered AFTER the team was granted, and in no group at all.
	late := f.device(t, ctx, "late", "server")
	if got := f.reach(t, ctx, user)[late]; got != "manage" {
		t.Errorf("a device created after the blanket grant reads %q, want manage", got)
	}
}

// A team with no grants confers nothing. This is the state a team is in while it
// is being set up, and it must not be mistaken for "everything".
func TestIntegration_TeamWithoutGrantsReachesNothing(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	user := f.user(t, ctx, "empty")
	f.team(t, ctx, "Empty", domiam.AccessNone, []domiam.ID{user})
	f.device(t, ctx, "unreachable", "switch")

	if got := f.reach(t, ctx, user); len(got) != 0 {
		t.Errorf("a member of a team with no grants reaches %d devices, want 0", len(got))
	}
}

// The join tables carry no organization of their own, and a foreign key check
// bypasses RLS — so an id belonging to another tenant would satisfy the FK. The
// repository sources ids through the RLS-protected parent and checks the row
// count, which is what turns that into an error instead of a grant.
func TestIntegration_GrantsCannotNameAnotherTenantsIDs(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	team := f.team(t, ctx, "Tenant", domiam.AccessNone, nil)

	t.Run("an unknown asset group is refused", func(t *testing.T) {
		err := f.teams.SetGrants(ctx, f.tScope, team, domiam.TeamGrants{
			Groups: []domiam.GroupGrant{{AssetGroupID: domiam.ID(uuid.New()), Level: domiam.AccessManage}},
		})
		if !errors.Is(err, domiam.ErrNotFound) {
			t.Fatalf("granting an invisible group = %v, want ErrNotFound", err)
		}
	})
	t.Run("an unknown user is refused", func(t *testing.T) {
		err := f.teams.SetMembers(ctx, f.tScope, team, []domiam.ID{domiam.ID(uuid.New())})
		if !errors.Is(err, domiam.ErrNotFound) {
			t.Fatalf("adding an invisible user = %v, want ErrNotFound", err)
		}
	})
	t.Run("an unknown team is refused", func(t *testing.T) {
		err := f.teams.SetGrants(ctx, f.tScope, domiam.ID(uuid.New()), domiam.TeamGrants{})
		if !errors.Is(err, domiam.ErrNotFound) {
			t.Fatalf("granting on an invisible team = %v, want ErrNotFound", err)
		}
	})
}

// Deleting a team takes its grants with it. That is the point of deleting one,
// and it is the direction that narrows reach rather than widening it.
func TestIntegration_DeletingATeamRevokesItsReach(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	user := f.user(t, ctx, "temp")
	dev := f.device(t, ctx, "temp", "switch")
	team := f.team(t, ctx, "Temporary", domiam.AccessManage, []domiam.ID{user})

	if got := f.reach(t, ctx, user)[dev]; got != "manage" {
		t.Fatalf("before delete the device reads %q, want manage", got)
	}
	if err := f.teams.Delete(ctx, f.tScope, team); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, seen := f.reach(t, ctx, user)[dev]; seen {
		t.Error("the device is still reachable after its only granting team was deleted")
	}
}

// GetByID and List both carry the member count, and GetByID assembles its result
// across two queries — it returned a nil team for a while because the second one
// was written to overwrite the first rather than fill it in, which nothing else
// here would have caught.
func TestIntegration_TeamReadBackCarriesMembership(t *testing.T) {
	pg, closeDB := newPG(t)
	// t.Cleanup, not defer: cleanup functions run LIFO and AFTER every defer,
	// so a deferred close would shut the pool before the fixture could use it
	// to delete its rows. Registered here and the fixture's teardown after,
	// the fixture runs first and the pool closes last.
	t.Cleanup(closeDB)
	ctx := context.Background()
	f := newTeamFixture(t, pg)

	a := f.user(t, ctx, "member-a")
	b := f.user(t, ctx, "member-b")
	id := f.team(t, ctx, "Readback", domiam.AccessConnect, []domiam.ID{a, b})

	got, err := f.teams.GetByID(ctx, f.tScope, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got == nil {
		t.Fatal("GetByID returned no team and no error")
	}
	if got.MemberCount != 2 {
		t.Errorf("GetByID member count = %d, want 2", got.MemberCount)
	}
	if got.AllDevicesLevel != domiam.AccessConnect {
		t.Errorf("blanket level read back as %q, want connect", got.AllDevicesLevel)
	}

	list, err := f.teams.List(ctx, f.tScope)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var found *domiam.Team
	for i := range list {
		if list[i].ID == id {
			found = &list[i]
		}
	}
	if found == nil {
		t.Fatal("the team is missing from List")
	}
	if found.MemberCount != 2 {
		t.Errorf("List member count = %d, want 2", found.MemberCount)
	}

	// A team with no blanket grant reads back as "none", not as an empty string —
	// callers compare against AccessNone.
	plain := f.team(t, ctx, "Plain", domiam.AccessNone, nil)
	p, err := f.teams.GetByID(ctx, f.tScope, plain)
	if err != nil {
		t.Fatalf("GetByID plain: %v", err)
	}
	if p.AllDevicesLevel != domiam.AccessNone {
		t.Errorf("a team with no blanket grant reads back as %q, want none", p.AllDevicesLevel)
	}

	if _, err := f.teams.GetByID(ctx, f.tScope, domiam.ID(uuid.New())); !errors.Is(err, domiam.ErrNotFound) {
		t.Errorf("GetByID on an unknown team = %v, want ErrNotFound", err)
	}
}
