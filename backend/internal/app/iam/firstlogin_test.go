package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// An admin-set password is known to two people. These tests pin the lifecycle
// that fixes that: the account is flagged at creation, the flag reaches the
// console via the principal, and choosing a new password clears it.

func TestCreateUser_FlagsPasswordForChange(t *testing.T) {
	h := newHarness(t)
	actor := iam.Claims{UserID: iam.NewID(), OrganizationID: iam.NewID(), Email: "admin@acme.com"}

	p, err := h.svc.CreateUser(context.Background(), actor, CreateUserInput{
		Email: "new@acme.com", Username: "new", Password: "Kx7-mQ2vRn9t",
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if !p.MustChangePassword {
		t.Error("a user created with an admin-set password is not flagged to change it")
	}
}

func TestCreateUser_RejectsWeakPassword(t *testing.T) {
	h := newHarness(t)
	actor := iam.Claims{UserID: iam.NewID(), OrganizationID: iam.NewID(), Email: "admin@acme.com"}

	for _, pw := range []string{"short", "Password123!", "alllowercaseletters"} {
		_, err := h.svc.CreateUser(context.Background(), actor, CreateUserInput{
			Email: "x@acme.com", Password: pw,
		})
		if !errors.Is(err, iam.ErrPasswordPolicy) {
			t.Errorf("CreateUser with %q: want ErrPasswordPolicy, got %v", pw, err)
		}
	}
}

func TestChangePassword_ClearsTheForcedChangeFlag(t *testing.T) {
	h := newHarness(t)
	u := h.addUser(t, "temp@acme.com", "Kx7-mQ2vRn9t")
	u.MustChangePassword = true
	h.users.add(u)
	claims := iam.Claims{UserID: u.ID, OrganizationID: u.OrganizationID, Email: u.Email.String()}

	if _, err := h.svc.ChangePassword(context.Background(), claims, "Kx7-mQ2vRn9t", "Zt4-wLp8Bq3h", ReqMeta{}); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}

	// The flag must be down, or the console would trap the user in a loop.
	pair, err := h.svc.Login(context.Background(), LoginInput{Email: "temp@acme.com", Password: "Zt4-wLp8Bq3h"})
	if err != nil {
		t.Fatalf("login with the new password: %v", err)
	}
	if pair.Principal.MustChangePassword {
		t.Error("the forced-change flag survived the password change")
	}
}

func TestLogin_SurfacesTheForcedChangeFlag(t *testing.T) {
	h := newHarness(t)
	u := h.addUser(t, "temp@acme.com", "Kx7-mQ2vRn9t")
	u.MustChangePassword = true
	h.users.add(u)

	pair, err := h.svc.Login(context.Background(), LoginInput{Email: "temp@acme.com", Password: "Kx7-mQ2vRn9t"})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// Sign-in must still succeed — the console needs a token to *call* the
	// change-password endpoint. The flag is what gates the UI, not the token.
	if pair.AccessToken == "" {
		t.Fatal("no access token issued; the user could not call change-password")
	}
	if !pair.Principal.MustChangePassword {
		t.Error("login did not tell the console the password must be changed")
	}
}
