package iam

import (
	"testing"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// Audit rows are read under row-level security: an event with no organization is
// visible to a super admin and to nobody else. A failed sign-in against an
// address that does not exist used to be written exactly that way, so the one
// pattern a tenant's own administrator most needs to see — somebody working
// through a list of guessed addresses — was the one pattern hidden from them.

func TestLogin_UnknownEmail_IsAttributedToTheSoleOrganization(t *testing.T) {
	h := newHarness(t)
	orgID := iam.NewID()
	h.orgs.bySlug["acme"] = &iam.Organization{ID: orgID, Slug: "acme", Name: "Acme"}

	if _, err := h.svc.Login(t.Context(), LoginInput{Email: "nobody@acme.com", Password: "whatever"}); err == nil {
		t.Fatal("login with an unknown email must fail")
	}

	events := h.audit.find("auth.login", "unknown_user")
	if len(events) != 1 {
		t.Fatalf("recorded %d unknown_user events, want 1", len(events))
	}
	got := events[0]
	if got.OrganizationID == nil {
		t.Fatal("failed login recorded with no organization: invisible to the Organization Admin who owns this login page")
	}
	if *got.OrganizationID != orgID {
		t.Fatalf("organization = %s, want %s", got.OrganizationID, orgID)
	}
	if got.Result != audit.ResultFailure {
		t.Fatalf("result = %q, want failure", got.Result)
	}
}

func TestLogin_UnknownEmail_NamedOrganizationWins(t *testing.T) {
	h := newHarness(t)
	acme := iam.NewID()
	beta := iam.NewID()
	h.orgs.bySlug["acme"] = &iam.Organization{ID: acme, Slug: "acme", Name: "Acme"}
	h.orgs.bySlug["beta"] = &iam.Organization{ID: beta, Slug: "beta", Name: "Beta"}

	// Two tenants, so there is no sole organization to fall back on — but the
	// attempt named one, and a named organization is not a guess.
	if _, err := h.svc.Login(t.Context(), LoginInput{
		Email: "ghost@beta.com", Password: "whatever", Organization: "beta",
	}); err == nil {
		t.Fatal("login with an unknown email must fail")
	}

	events := h.audit.find("auth.login", "unknown_user")
	if len(events) != 1 {
		t.Fatalf("recorded %d unknown_user events, want 1", len(events))
	}
	if events[0].OrganizationID == nil || *events[0].OrganizationID != beta {
		t.Fatalf("organization = %v, want %s", events[0].OrganizationID, beta)
	}
}

func TestLogin_UnknownEmail_MultipleTenantsStaysUnattributed(t *testing.T) {
	h := newHarness(t)
	h.orgs.bySlug["acme"] = &iam.Organization{ID: iam.NewID(), Slug: "acme", Name: "Acme"}
	h.orgs.bySlug["beta"] = &iam.Organization{ID: iam.NewID(), Slug: "beta", Name: "Beta"}

	if _, err := h.svc.Login(t.Context(), LoginInput{Email: "ghost@nowhere.com", Password: "x"}); err == nil {
		t.Fatal("login with an unknown email must fail")
	}

	events := h.audit.find("auth.login", "unknown_user")
	if len(events) != 1 {
		t.Fatalf("recorded %d unknown_user events, want 1", len(events))
	}
	// Guessing here would file one tenant's attack traffic in another tenant's
	// ledger, and that ledger is hash-chained: it cannot be corrected afterwards.
	if events[0].OrganizationID != nil {
		t.Fatalf("organization = %s, want none: with several tenants there is nothing to attribute this to",
			events[0].OrganizationID)
	}
}

func TestLogin_BadPassword_KeepsTheAccountsOwnOrganization(t *testing.T) {
	h := newHarness(t)
	orgID := iam.NewID()
	u := h.addUserInOrg(t, orgID, "bob@acme.com", "correct-horse-battery")

	if _, err := h.svc.Login(t.Context(), LoginInput{Email: "bob@acme.com", Password: "wrong"}); err == nil {
		t.Fatal("login with a wrong password must fail")
	}

	events := h.audit.find("auth.login", "bad_password")
	if len(events) != 1 {
		t.Fatalf("recorded %d bad_password events, want 1", len(events))
	}
	if events[0].OrganizationID == nil || *events[0].OrganizationID != orgID {
		t.Fatalf("organization = %v, want %s", events[0].OrganizationID, orgID)
	}
	if events[0].TargetID != u.ID.String() {
		t.Fatalf("target = %q, want the account %s", events[0].TargetID, u.ID)
	}
}

func TestLogin_AmbiguousEmail_IsRecordedForEveryCandidate(t *testing.T) {
	h := newHarness(t)
	acme := iam.NewID()
	beta := iam.NewID()
	h.addUserInOrg(t, acme, "shared@example.com", "pw-one-aaaaaaaa")
	h.addUserInOrg(t, beta, "shared@example.com", "pw-two-aaaaaaaa")

	// An address in two tenants with no organization named. This attempt used to
	// be recorded nowhere at all: it is not a bad password, so it never reached
	// the failure path, and the request returned early.
	if _, err := h.svc.Login(t.Context(), LoginInput{Email: "shared@example.com", Password: "pw-one-aaaaaaaa"}); err == nil {
		t.Fatal("an ambiguous email must not sign anybody in")
	}

	events := h.audit.find("auth.login", "email_ambiguous")
	if len(events) != 2 {
		t.Fatalf("recorded %d events, want one per candidate organization (2)", len(events))
	}
	seen := map[iam.ID]bool{}
	for _, e := range events {
		if e.OrganizationID == nil {
			t.Fatal("ambiguous attempt recorded with no organization")
		}
		seen[*e.OrganizationID] = true
	}
	if !seen[acme] || !seen[beta] {
		t.Fatalf("organizations told = %v, want both %s and %s", seen, acme, beta)
	}
}
