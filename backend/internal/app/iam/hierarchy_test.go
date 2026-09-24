package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// withRole gives a harness user one of the seeded roles.
func withRole(u *iam.User, name string) *iam.User {
	for _, r := range seededRoles() {
		if r.Name == name {
			u.Roles = []iam.Role{r}
			return u
		}
	}
	panic("no seeded role " + name)
}

func claimsOf(u *iam.User) iam.Claims {
	return iam.Claims{UserID: u.ID, OrganizationID: u.OrganizationID, Email: u.Email.String(),
		IsSuperAdmin: u.HasSuperAdmin(), ApprovalLevel: u.ApprovalLevel(), Permissions: []string{"user:write", "user:read"}}
}

// The incident: an Organization Admin changed a Super Admin's role, and the
// log recorded it as an ordinary success. Nobody manages somebody ranked at or
// above them — not their role, password, account, teams or sign-ins.
func TestHierarchy_NobodyManagesTheirEqualOrSuperior(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	org := iam.NewID()
	orgAdmin := withRole(h.addUserInOrg(t, org, "orgadmin@acme.com", "Pass-word-1234"), RoleOrgAdmin)
	super := withRole(h.addUserInOrg(t, org, "super@acme.com", "Pass-word-1234"), RoleSuperAdmin)
	peer := withRole(h.addUserInOrg(t, org, "peer@acme.com", "Pass-word-1234"), RoleOrgAdmin)
	operator := withRole(h.addUserInOrg(t, org, "op@acme.com", "Pass-word-1234"), RoleOperator)
	actor := claimsOf(orgAdmin)

	for _, target := range []*iam.User{super, peer} {
		for what, try := range map[string]func() error{
			"change their role": func() error {
				return h.svc.AssignRoles(ctx, actor, target.ID, []iam.ID{roleID(RoleReadOnly)}, ReqMeta{})
			},
			"remove their account": func() error { return h.svc.DeleteUser(ctx, actor, target.ID, ReqMeta{}) },
		} {
			if err := try(); !errors.Is(err, iam.ErrPermissionDenied) {
				t.Errorf("an Organization Admin could %s of %s: %v", what, target.Email, err)
			}
		}
	}
	// Password resets reach an equal — Organization Admins help each other
	// back in — but never anybody ranked above.
	if _, err := h.svc.ResetPassword(ctx, actor, peer.ID, "", ReqMeta{}); err != nil {
		t.Errorf("an Organization Admin could not reset a fellow Organization Admin's password: %v", err)
	}
	if _, err := h.svc.ResetPassword(ctx, actor, super.ID, "", ReqMeta{}); !errors.Is(err, iam.ErrPermissionDenied) {
		t.Errorf("an Organization Admin could reset a Super Admin's password: %v", err)
	}
	if n := len(h.audit.find("user.protected_denied", "outranked")); n != 5 {
		t.Errorf("recorded %d refusals, want 5 — every refused attempt is on the record", n)
	}
	defer func() {
		// Two promotions and one creation past the ceiling, each on the record.
		if n := len(h.audit.find("user.protected_denied", "role_above")); n != 3 {
			t.Errorf("recorded %d refused grants, want 3", n)
		}
	}()

	// Down the ranks is what the role is for...
	if err := h.svc.AssignRoles(ctx, actor, operator.ID, []iam.ID{roleID(RoleAuditor)}, ReqMeta{}); err != nil {
		t.Fatalf("an Organization Admin could not change an Operator's role: %v", err)
	}
	// ...but not up to their own rank or past it.
	for _, role := range []string{RoleOrgAdmin, RoleSuperAdmin} {
		if err := h.svc.AssignRoles(ctx, actor, operator.ID, []iam.ID{roleID(role)}, ReqMeta{}); !errors.Is(err, iam.ErrPermissionDenied) {
			t.Errorf("an Organization Admin could make an Operator %s: %v", role, err)
		}
	}
	if _, err := h.svc.CreateUser(ctx, actor, CreateUserInput{Email: "new@acme.com", Password: "Kx7-mQ2vRn9t",
		RoleIDs: []iam.ID{roleID(RoleOrgAdmin)}}); !errors.Is(err, iam.ErrPermissionDenied) {
		t.Errorf("an Organization Admin could create another Organization Admin: %v", err)
	}

	// A super admin manages anybody (the installation account aside, which has
	// its own rule), including another super admin.
	if err := h.svc.AssignRoles(ctx, claimsOf(super), peer.ID, []iam.ID{roleID(RoleOperator)}, ReqMeta{}); err != nil {
		t.Errorf("a Super Admin could not change an Organization Admin's role: %v", err)
	}
}

// The change is recorded by name, before and after. "role_count: 1" said a
// role had changed and nothing about what it was or became.
func TestHierarchy_RoleChangeRecordsFromAndTo(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	org := iam.NewID()
	admin := withRole(h.addUserInOrg(t, org, "super@acme.com", "Pass-word-1234"), RoleSuperAdmin)
	op := withRole(h.addUserInOrg(t, org, "op@acme.com", "Pass-word-1234"), RoleOperator)

	if err := h.svc.AssignRoles(ctx, claimsOf(admin), op.ID, []iam.ID{roleID(RoleOrgAdmin)}, ReqMeta{}); err != nil {
		t.Fatal(err)
	}
	ev := h.audit.find("user.assign_roles", "")
	if len(ev) != 1 {
		t.Fatalf("%d events", len(ev))
	}
	from, _ := ev[0].Detail["from"].([]string)
	to, _ := ev[0].Detail["to"].([]string)
	if len(from) != 1 || from[0] != RoleOperator || len(to) != 1 || to[0] != RoleOrgAdmin {
		t.Fatalf("recorded from %v to %v, want [%s] to [%s]", from, to, RoleOperator, RoleOrgAdmin)
	}
}
