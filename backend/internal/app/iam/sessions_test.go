package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// signIn logs a user in and returns the raw refresh token of the new session.
func signIn(t *testing.T, h *harness, email string) string {
	t.Helper()
	pair, err := h.svc.Login(context.Background(), LoginInput{Email: email, Password: "supersecret-123"})
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}
	return pair.RefreshToken
}

func familyOf(views []SessionView, userID iam.ID) iam.ID {
	for _, v := range views {
		if v.UserID == userID {
			return v.ID
		}
	}
	return iam.ID{}
}

func TestSessions_ListScopesAndCurrentFlag(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	u1 := h.addUser(t, "a@acme.com", "supersecret-123")
	u2 := h.addUser(t, "b@acme.com", "supersecret-123")
	u3 := h.addUser(t, "c@other.com", "supersecret-123")
	u2.OrganizationID = u1.OrganizationID // u1 + u2 share a tenant; u3 is elsewhere

	current := signIn(t, h, "a@acme.com") // u1 device #1 (the "current" one)
	signIn(t, h, "a@acme.com")            // u1 device #2
	signIn(t, h, "b@acme.com")            // u2
	signIn(t, h, "c@other.com")           // u3

	// Self view: a user with no admin permission sees only their own sessions,
	// and exactly the one matching their refresh cookie is flagged Current.
	self := iam.Claims{UserID: u1.ID, OrganizationID: u1.OrganizationID, Email: "a@acme.com"}
	own, err := h.svc.ListSessions(ctx, self, current, false)
	if err != nil {
		t.Fatalf("list self: %v", err)
	}
	if len(own) != 2 {
		t.Fatalf("self view: want 2 sessions, got %d", len(own))
	}
	currentCount := 0
	for _, s := range own {
		if s.UserID != u1.ID || !s.Self {
			t.Fatalf("self view leaked or mis-flagged: %+v", s)
		}
		if s.Current {
			currentCount++
		}
	}
	if currentCount != 1 {
		t.Fatalf("want exactly one Current session, got %d", currentCount)
	}

	// Super admin sees everything (all four families).
	super := iam.Claims{UserID: u1.ID, OrganizationID: u1.OrganizationID, Email: "a@acme.com", IsSuperAdmin: true}
	all, _ := h.svc.ListSessions(ctx, super, "", false)
	if len(all) != 4 {
		t.Fatalf("super admin: want 4 sessions, got %d", len(all))
	}

	// selfOnly forces the own-sessions view even for an admin.
	superSelf, _ := h.svc.ListSessions(ctx, super, "", true)
	if len(superSelf) != 2 {
		t.Fatalf("super admin selfOnly: want 2, got %d", len(superSelf))
	}

	// A non-super admin with user:read is scoped to their tenant: u1 + u2, not u3.
	orgAdmin := iam.Claims{UserID: u1.ID, OrganizationID: u1.OrganizationID, Email: "a@acme.com", Permissions: []string{"user:read"}}
	scoped, _ := h.svc.ListSessions(ctx, orgAdmin, "", false)
	if len(scoped) != 3 {
		t.Fatalf("org admin: want 3, got %d", len(scoped))
	}
	for _, s := range scoped {
		if s.UserID == u3.ID {
			t.Fatal("org scope leaked a session from another tenant")
		}
	}
}

func TestSessions_RevokeAuthorization(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	u1 := h.addUser(t, "a@acme.com", "supersecret-123")
	u2 := h.addUser(t, "b@acme.com", "supersecret-123")
	u2.OrganizationID = u1.OrganizationID

	current := signIn(t, h, "a@acme.com")
	signIn(t, h, "b@acme.com")

	self := iam.Claims{UserID: u1.ID, OrganizationID: u1.OrganizationID, Email: "a@acme.com"}
	super := iam.Claims{UserID: u1.ID, OrganizationID: u1.OrganizationID, Email: "a@acme.com", IsSuperAdmin: true}
	u2Claims := iam.Claims{UserID: u2.ID, OrganizationID: u2.OrganizationID, Email: "b@acme.com"}
	readOnly := iam.Claims{UserID: u2.ID, OrganizationID: u2.OrganizationID, Email: "b@acme.com", Permissions: []string{"user:read"}}

	all, _ := h.svc.ListSessions(ctx, super, "", false)
	u1Family := familyOf(all, u1.ID)
	u2Family := familyOf(all, u2.ID)

	// Another user with no permission cannot revoke u1's session.
	if err := h.svc.RevokeSession(ctx, u2Claims, u1Family, ReqMeta{}); !errors.Is(err, iam.ErrPermissionDenied) {
		t.Fatalf("no-perm cross-user revoke: want ErrPermissionDenied, got %v", err)
	}
	// user:read is not enough to revoke someone else's session (needs user:write).
	if err := h.svc.RevokeSession(ctx, readOnly, u1Family, ReqMeta{}); !errors.Is(err, iam.ErrPermissionDenied) {
		t.Fatalf("read-only cross-user revoke: want ErrPermissionDenied, got %v", err)
	}
	// Unknown family is a not-found.
	if err := h.svc.RevokeSession(ctx, super, iam.NewID(), ReqMeta{}); !errors.Is(err, iam.ErrNotFound) {
		t.Fatalf("revoke unknown family: want ErrNotFound, got %v", err)
	}

	// A user may always revoke their own session.
	if err := h.svc.RevokeSession(ctx, self, u1Family, ReqMeta{}); err != nil {
		t.Fatalf("self revoke: %v", err)
	}
	if left, _ := h.svc.ListSessions(ctx, self, current, false); len(left) != 0 {
		t.Fatalf("after self revoke: want 0 own sessions, got %d", len(left))
	}

	// A super admin may revoke anyone's session.
	if err := h.svc.RevokeSession(ctx, super, u2Family, ReqMeta{}); err != nil {
		t.Fatalf("admin revoke: %v", err)
	}
	if all2, _ := h.svc.ListSessions(ctx, super, "", false); len(all2) != 0 {
		t.Fatalf("after all revokes: want 0 sessions, got %d", len(all2))
	}
}
