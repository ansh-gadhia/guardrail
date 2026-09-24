package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// A person holds one role. Two at once made their permissions the union of two
// jobs and their approval rank the higher of the two — one extra tick away.
func TestRoles_APersonHasOne(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	actor := iam.Claims{UserID: iam.NewID(), OrganizationID: iam.NewID(), Email: "admin@acme.com", IsSuperAdmin: true}
	two := []iam.ID{iam.NewID(), iam.NewID()}

	_, err := h.svc.CreateUser(ctx, actor, CreateUserInput{Email: "new@acme.com", Password: "Kx7-mQ2vRn9t", RoleIDs: two})
	if !errors.Is(err, iam.ErrInvalidInput) {
		t.Fatalf("created a user with two roles: %v", err)
	}
	if found, _ := h.users.GetByEmailGlobal(ctx, "new@acme.com"); len(found) > 0 {
		t.Fatal("the refused user was written anyway")
	}

	u := h.addUser(t, "ops@acme.com", "supersecret-123")
	if err := h.svc.AssignRoles(ctx, actor, u.ID, two, ReqMeta{}); !errors.Is(err, iam.ErrInvalidInput) {
		t.Fatalf("gave a user two roles: %v", err)
	}
}
