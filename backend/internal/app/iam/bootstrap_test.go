package iam

import (
	"context"
	"errors"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

func (h *harness) addOrg(slug string) iam.ID {
	id := iam.NewID()
	h.orgs.bySlug[slug] = &iam.Organization{ID: id, Slug: slug, Name: slug}
	return id
}

func TestEnsureBootstrapAdmin_CreatesThenIdempotent(t *testing.T) {
	h := newHarness(t)
	h.addOrg("default")
	in := BootstrapAdminInput{Email: "root@acme.com", Password: "bootstrap-pw-123", Username: "root", OrgSlug: "default"}

	created, err := h.svc.EnsureBootstrapAdmin(context.Background(), in)
	if err != nil || !created {
		t.Fatalf("first run: created=%v err=%v", created, err)
	}
	// The bootstrapped credential must actually authenticate.
	if _, err := h.svc.Login(context.Background(), LoginInput{Email: "root@acme.com", Password: "bootstrap-pw-123"}); err != nil {
		t.Fatalf("login after bootstrap: %v", err)
	}
	// Second run is a no-op (idempotent) — no duplicate, no error.
	created2, err := h.svc.EnsureBootstrapAdmin(context.Background(), in)
	if err != nil {
		t.Fatalf("second run err: %v", err)
	}
	if created2 {
		t.Fatal("expected idempotent no-op on second run")
	}
}

func TestEnsureBootstrapAdmin_WeakPasswordFailsClosed(t *testing.T) {
	h := newHarness(t)
	h.addOrg("default")
	_, err := h.svc.EnsureBootstrapAdmin(context.Background(),
		BootstrapAdminInput{Email: "root@acme.com", Password: "short", OrgSlug: "default"})
	if !errors.Is(err, iam.ErrPasswordPolicy) {
		t.Fatalf("weak password: want ErrPasswordPolicy, got %v", err)
	}
}

func TestEnsureBootstrapAdmin_TightenedPolicyDoesNotBreakExistingInstall(t *testing.T) {
	// An existing deployment whose admin password predates a policy change must
	// still boot: the account already exists, so the env password is never used.
	h := newHarness(t)
	orgID := h.addOrg("default")
	h.addUserInOrg(t, orgID, "root@acme.com", "whatever-it-was")

	created, err := h.svc.EnsureBootstrapAdmin(context.Background(),
		BootstrapAdminInput{Email: "root@acme.com", Password: "Password123!", OrgSlug: "default"})
	if err != nil {
		t.Fatalf("existing admin + now-weak env password: want a quiet no-op, got %v", err)
	}
	if created {
		t.Fatal("expected no-op when the admin already exists")
	}
}

func TestEnsureBootstrapAdmin_NotConfiguredIsNoOp(t *testing.T) {
	h := newHarness(t)
	created, err := h.svc.EnsureBootstrapAdmin(context.Background(), BootstrapAdminInput{})
	if err != nil || created {
		t.Fatalf("unconfigured bootstrap: want no-op, got created=%v err=%v", created, err)
	}
}

func TestChangePassword_FullFlow(t *testing.T) {
	h := newHarness(t)
	u := h.addUser(t, "user@acme.com", "Kx7-mQ2vRn9t")
	claims := iam.Claims{UserID: u.ID, OrganizationID: u.OrganizationID, Email: u.Email.String()}
	ctx := context.Background()

	if _, err := h.svc.ChangePassword(ctx, claims, "wrong-current", "Zt4-wLp8Bq3h", ReqMeta{}); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("wrong current: want ErrInvalidCredentials, got %v", err)
	}
	if _, err := h.svc.ChangePassword(ctx, claims, "Kx7-mQ2vRn9t", "short", ReqMeta{}); !errors.Is(err, iam.ErrPasswordPolicy) {
		t.Fatalf("short new: want ErrPasswordPolicy, got %v", err)
	}
	if _, err := h.svc.ChangePassword(ctx, claims, "Kx7-mQ2vRn9t", "Kx7-mQ2vRn9t", ReqMeta{}); !errors.Is(err, iam.ErrPasswordReuse) {
		t.Fatalf("reuse: want ErrPasswordReuse, got %v", err)
	}

	pair, err := h.svc.ChangePassword(ctx, claims, "Kx7-mQ2vRn9t", "Zt4-wLp8Bq3h", ReqMeta{})
	if err != nil {
		t.Fatalf("change: %v", err)
	}
	if pair.AccessToken == "" || pair.RefreshToken == "" {
		t.Fatal("expected re-issued tokens so the caller stays signed in")
	}
	if _, err := h.svc.Login(ctx, LoginInput{Email: "user@acme.com", Password: "Kx7-mQ2vRn9t"}); !errors.Is(err, iam.ErrInvalidCredentials) {
		t.Fatalf("old password should no longer work, got %v", err)
	}
	if _, err := h.svc.Login(ctx, LoginInput{Email: "user@acme.com", Password: "Zt4-wLp8Bq3h"}); err != nil {
		t.Fatalf("new password should work: %v", err)
	}
}
