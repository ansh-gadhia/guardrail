package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// superAdminRole is the seeded role as it is actually stored: a name, and NO
// permission rows. That emptiness is the point — super admin means "everything",
// which is expressed by holding the role, not by a grant list that would have to
// be updated every time a permission is added.
func superAdminRole() iam.Role {
	return iam.Role{ID: iam.SuperAdminRoleID, Name: "Super Admin"}
}

// The bug the operator reported: they created a user, gave it the role named
// "Super Admin" in the console, and it signed in to an empty dashboard with no
// access to anything.
//
// The cause was that authorization read only users.is_super_admin — a column the
// console never sets — while the role it does set carries zero permissions. So
// the account held a role called Super Admin and was, in fact, powerless.
func TestSuperAdminRoleConfersSuperAdmin(t *testing.T) {
	u := &iam.User{
		ID: iam.NewID(), OrganizationID: iam.NewID(),
		Email:        iam.NewEmail("ansh@example.com"),
		IsSuperAdmin: false, // the console cannot set this
		Roles:        []iam.Role{superAdminRole()},
	}

	if !u.HasSuperAdmin() {
		t.Fatal("a user holding the Super Admin role is not a super admin; the console's role assignment does nothing")
	}
	claims := claimsFromUser(u)
	if !claims.IsSuperAdmin {
		t.Error("claims do not carry super admin, so every permission check fails")
	}
	// The decisive assertion: the role grants no permissions of its own, so if
	// authorization did not understand the role, Has() would be false for
	// everything and the dashboard would render empty — exactly what was reported.
	if len(u.Permissions()) != 0 {
		t.Fatalf("fixture drift: the Super Admin role should carry no permission rows, got %v", u.Permissions())
	}
	for _, p := range []string{"device:read", "user:write", "log:read", "some:future:permission"} {
		if !claims.Has(p) {
			t.Errorf("super admin denied %q", p)
		}
	}
}

// The bootstrap flag still works on its own: the first admin is created from the
// environment before any role exists to assign.
func TestSuperAdminColumnStillConfersSuperAdmin(t *testing.T) {
	u := &iam.User{ID: iam.NewID(), IsSuperAdmin: true}
	if !u.HasSuperAdmin() {
		t.Error("the bootstrap is_super_admin flag no longer confers super admin")
	}
}

// An ordinary user must not become a super admin by holding ordinary roles.
func TestNonSuperAdminRolesDoNotConfer(t *testing.T) {
	u := &iam.User{
		ID: iam.NewID(),
		Roles: []iam.Role{
			{ID: iam.NewID(), Name: "Organization Admin", Permissions: []string{"user:write", "device:read"}},
			{ID: iam.NewID(), Name: "Auditor", Permissions: []string{"log:read"}},
		},
	}
	if u.HasSuperAdmin() {
		t.Fatal("a user with only ordinary roles was treated as a super admin")
	}
	claims := claimsFromUser(u)
	if claims.Has("credential:write") {
		t.Error("a permission the user's roles do not grant was allowed")
	}
	if !claims.Has("user:write") {
		t.Error("a permission the user's roles DO grant was denied")
	}
}

// Granting the Super Admin role is itself a privileged act.
//
// Super admin turns off row-level security (TenantScope.IsSuperAdmin), so if any
// principal with user:write could grant it, an Organization Admin — scoped to one
// tenant by design — could escalate to reading every other tenant's data. Now
// that the role actually confers the privilege, this door has to be shut.
func TestNonSuperAdminCannotGrantSuperAdminRole(t *testing.T) {
	h := newHarness(t)
	orgID := h.addOrg("acme")

	// An Organization Admin: real power inside its tenant, no super admin.
	actor := iam.Claims{
		UserID: iam.NewID(), OrganizationID: orgID, Email: "orgadmin@acme.com",
		IsSuperAdmin: false, Permissions: []string{"user:write"},
	}
	target := iam.NewID()

	err := h.svc.AssignRoles(context.Background(), actor, target, []iam.ID{iam.SuperAdminRoleID}, ReqMeta{})
	if !errors.Is(err, iam.ErrPermissionDenied) {
		t.Fatalf("AssignRoles(Super Admin) by a non-super-admin = %v, want ErrPermissionDenied", err)
	}
	// The refusal has to happen before the write, not be reported after it.
	if roles, called := h.users.rolesOf(target); called {
		t.Errorf("the role was written anyway: %v", roles)
	}
}

// The same door on the other path: CreateUser must not mint a super admin either.
func TestNonSuperAdminCannotCreateUserWithSuperAdminRole(t *testing.T) {
	h := newHarness(t)
	orgID := h.addOrg("acme")
	actor := iam.Claims{
		UserID: iam.NewID(), OrganizationID: orgID, Email: "orgadmin@acme.com",
		IsSuperAdmin: false, Permissions: []string{"user:write"},
	}

	_, err := h.svc.CreateUser(context.Background(), actor, CreateUserInput{
		Email: "escalate@acme.com", Username: "escalate", Password: "a-long-enough-password-1",
		RoleIDs: []iam.ID{iam.SuperAdminRoleID},
	})
	if !errors.Is(err, iam.ErrPermissionDenied) {
		t.Fatalf("CreateUser with the Super Admin role by a non-super-admin = %v, want ErrPermissionDenied", err)
	}
	// Refused before the row was written: CreateUser has no transaction spanning
	// Create and SetRoles, so a late refusal would strand an orphaned user.
	if _, err := h.users.GetByEmailInOrg(context.Background(), orgID, iam.NewEmail("escalate@acme.com")); !errors.Is(err, iam.ErrNotFound) {
		t.Error("the user was created even though the role grant was refused")
	}
}

// A super admin can still grant the role — otherwise the privilege could never be
// delegated and the bootstrap account would be the only one, forever.
func TestSuperAdminCanGrantSuperAdminRole(t *testing.T) {
	h := newHarness(t)
	orgID := h.addOrg("acme")
	actor := iam.Claims{
		UserID: iam.NewID(), OrganizationID: orgID, Email: "root@acme.com",
		IsSuperAdmin: true,
	}
	// A real user: AssignRoles looks the target up so it can refuse changes to
	// the installation account, so a phantom id is now a 404 rather than a
	// role grant that would have failed later on a foreign key.
	target := h.addUserInOrg(t, orgID, "target@acme.com", "TargetPass123!").ID

	if err := h.svc.AssignRoles(context.Background(), actor, target, []iam.ID{iam.SuperAdminRoleID}, ReqMeta{}); err != nil {
		t.Fatalf("a super admin was refused: %v", err)
	}
	roles, called := h.users.rolesOf(target)
	if !called || len(roles) != 1 || roles[0] != iam.SuperAdminRoleID {
		t.Errorf("role not granted: called=%v roles=%v", called, roles)
	}
}

// Ordinary roles must stay grantable by an ordinary admin: the guard is aimed at
// one role, not at role management generally.
func TestNonSuperAdminCanGrantOrdinaryRoles(t *testing.T) {
	h := newHarness(t)
	orgID := h.addOrg("acme")
	actor := iam.Claims{
		UserID: iam.NewID(), OrganizationID: orgID, Email: "orgadmin@acme.com",
		IsSuperAdmin: false, Permissions: []string{"user:write"},
	}
	target := h.addUserInOrg(t, orgID, "ordinary@acme.com", "TargetPass123!").ID
	ordinary := []iam.ID{iam.NewID(), iam.NewID()}

	if err := h.svc.AssignRoles(context.Background(), actor, target, ordinary, ReqMeta{}); err != nil {
		t.Fatalf("an org admin was refused ordinary roles: %v", err)
	}
	if roles, called := h.users.rolesOf(target); !called || len(roles) != 2 {
		t.Errorf("ordinary roles not granted: called=%v roles=%v", called, roles)
	}
}

// The roles of the account GuardRail was installed with are refused to
// everybody, including a super admin. It is the recovery path: nothing inside
// the product can recreate it, so a rule a privileged person could switch off
// would be a speed bump rather than a protection.
//
// Deletion is the deliberate exception — see the sibling test below.
func TestBootstrapAdminRolesAreProtectedFromEveryone(t *testing.T) {
	h := newHarness(t)
	orgID := h.addOrg("acme")
	root := iam.Claims{
		UserID: iam.NewID(), OrganizationID: orgID, Email: "root@acme.com", IsSuperAdmin: true,
	}

	boot := h.addUserInOrg(t, orgID, "installed@acme.com", "BootPass123456!")
	// The is_super_admin COLUMN is what seed-admin sets; that is the marker.
	boot.IsSuperAdmin = true
	if err := h.users.Create(context.Background(), iam.TenantScope{OrganizationID: orgID}, boot); err != nil {
		t.Fatalf("store bootstrap admin: %v", err)
	}

	if err := h.svc.AssignRoles(context.Background(), root, boot.ID, []iam.ID{iam.NewID()}, ReqMeta{}); !errors.Is(err, iam.ErrProtectedAccount) {
		t.Fatalf("a super admin must not be able to change its roles, got %v", err)
	}
	// Its own holder cannot demote it either — self-service lockout is still
	// lockout.
	self := iam.Claims{UserID: boot.ID, OrganizationID: orgID, Email: boot.Email.String(), IsSuperAdmin: true}
	if err := h.svc.AssignRoles(context.Background(), self, boot.ID, nil, ReqMeta{}); !errors.Is(err, iam.ErrProtectedAccount) {
		t.Fatalf("the account must not be able to demote itself, got %v", err)
	}

	// A super admin promoted through the console holds the ROLE, not the column,
	// and stays manageable — otherwise the protection would quietly freeze every
	// admin an organization ever creates.
	promoted := h.addUserInOrg(t, orgID, "promoted@acme.com", "PromoPass123456!")
	if err := h.svc.AssignRoles(context.Background(), root, promoted.ID, []iam.ID{iam.SuperAdminRoleID}, ReqMeta{}); err != nil {
		t.Fatalf("promoting through the console should work: %v", err)
	}
	if err := h.svc.AssignRoles(context.Background(), root, promoted.ID, nil, ReqMeta{}); err != nil {
		t.Fatalf("a console-promoted super admin must remain demotable: %v", err)
	}
}

// Deletion is the one change to the installation account that is allowed.
//
// It is allowed because it is the only one that can be undone from outside: the
// email uniqueness index is partial on deleted_at, so removing the account frees
// the address and `guardrail seed-admin` recreates it. Demoting it or resetting
// its password leaves an account that exists and cannot let anybody back in,
// which is why those two stay refused — including here, so that relaxing the
// delete rule cannot quietly relax them as well.
func TestBootstrapAdminCanBeRemovedButNotDemotedOrReset(t *testing.T) {
	h := newHarness(t)
	orgID := h.addOrg("acme")
	root := iam.Claims{
		UserID: iam.NewID(), OrganizationID: orgID, Email: "root@acme.com", IsSuperAdmin: true,
	}

	boot := h.addUserInOrg(t, orgID, "installed@acme.com", "BootPass123456!")
	boot.IsSuperAdmin = true
	if err := h.users.Create(context.Background(), iam.TenantScope{OrganizationID: orgID}, boot); err != nil {
		t.Fatalf("store bootstrap admin: %v", err)
	}

	if _, err := h.svc.ResetPassword(context.Background(), root, boot.ID, "", ReqMeta{}); !errors.Is(err, iam.ErrProtectedAccount) {
		t.Fatalf("resetting its password must stay refused, got %v", err)
	}
	if err := h.svc.DeleteUser(context.Background(), root, boot.ID, ReqMeta{}); err != nil {
		t.Fatalf("removing the installation account must be allowed, got %v", err)
	}
}
