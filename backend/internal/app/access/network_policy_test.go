package access

import (
	"context"
	"strings"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

func adminClaims() iam.Claims {
	c := actorClaims()
	c.Permissions = []string{PermOrgWrite}
	return c
}

// The whole reason saving a policy is a service method and not a straight write.
// An allowlist that does not contain the administrator writing it locks that
// administrator out the instant it is stored, and the only way back in is a
// database session on the host.
func TestSetNetworkPolicy_RefusesAPolicyThatWouldLockTheAuthorOut(t *testing.T) {
	h := newHarness(opts{})
	actor := adminClaims()
	_, err := h.svc.SetNetworkPolicy(context.Background(), actor, access.NetworkPolicy{
		AllowEnabled: true,
		Allow:        []access.NetworkRule{{CIDR: "10.200.10.0/24", Note: "office"}},
	}, ReqMeta{IP: "203.0.113.9"})
	if err == nil {
		t.Fatal("saving an allowlist that excludes the author must be refused")
	}
	if !strings.Contains(err.Error(), "203.0.113.9") {
		t.Errorf("the refusal must name the address that would be shut out, got: %v", err)
	}
	// And nothing was stored.
	set, _ := h.settings.GetSettings(context.Background(), scopeOf(actor), actor.OrganizationID)
	if set.Network.AllowEnabled {
		t.Error("the policy was stored despite being refused")
	}
}

func TestSetNetworkPolicy_RefusesBlockingYourOwnAddress(t *testing.T) {
	h := newHarness(opts{})
	_, err := h.svc.SetNetworkPolicy(context.Background(), adminClaims(), access.NetworkPolicy{
		BlockEnabled: true,
		Block:        []access.NetworkRule{{CIDR: "203.0.113.0/24"}},
	}, ReqMeta{IP: "203.0.113.9"})
	if err == nil {
		t.Fatal("blocking the range you are connected from must be refused")
	}
	if !strings.Contains(err.Error(), "blocklist") {
		t.Errorf("the refusal should say which list did it, got: %v", err)
	}
}

func TestSetNetworkPolicy_RefusesAnEmptyAllowlistThatIsSwitchedOn(t *testing.T) {
	h := newHarness(opts{})
	_, err := h.svc.SetNetworkPolicy(context.Background(), adminClaims(), access.NetworkPolicy{
		AllowEnabled: true,
	}, ReqMeta{IP: "203.0.113.9"})
	if err == nil {
		t.Fatal("an empty allowlist refuses every address, including the author's")
	}
}

func TestSetNetworkPolicy_StoresAndAuditsAPolicyThatKeepsTheAuthorIn(t *testing.T) {
	h := newHarness(opts{})
	actor := adminClaims()
	set, err := h.svc.SetNetworkPolicy(context.Background(), actor, access.NetworkPolicy{
		AllowEnabled: true,
		Allow: []access.NetworkRule{
			{CIDR: "10.200.10.0/24", Note: "office"},
			{CIDR: "203.0.113.9", Note: "my VPN exit"},
		},
		BlockEnabled: true,
		Block:        []access.NetworkRule{{CIDR: "198.51.100.0/24"}},
	}, ReqMeta{IP: "203.0.113.9"})
	if err != nil {
		t.Fatalf("set network policy: %v", err)
	}
	if !set.Network.AllowEnabled || len(set.Network.Allow) != 2 {
		t.Fatalf("policy not stored: %+v", set.Network)
	}
	e := h.audit.find("settings.network_policy")
	if e == nil {
		t.Fatal("changing who may reach the console must be audited")
	}
	if e.Detail["allowlist_enabled"] != true || e.Detail["blocklist_enabled"] != true {
		t.Errorf("audit detail = %v", e.Detail)
	}
}

func TestCheckNetworkSource_EnforcesTheStoredPolicy(t *testing.T) {
	h := newHarness(opts{})
	ctx := context.Background()
	actor := adminClaims()
	if _, err := h.svc.SetNetworkPolicy(ctx, actor, access.NetworkPolicy{
		AllowEnabled: true,
		Allow:        []access.NetworkRule{{CIDR: "203.0.113.0/24"}},
	}, ReqMeta{IP: "203.0.113.9"}); err != nil {
		t.Fatalf("set network policy: %v", err)
	}

	if ok, _ := h.svc.CheckNetworkSource(ctx, actor.OrganizationID, false, "203.0.113.20"); !ok {
		t.Error("an allowlisted address must be let through")
	}
	ok, reason := h.svc.CheckNetworkSource(ctx, actor.OrganizationID, false, "10.0.0.1")
	if ok {
		t.Error("an address off the allowlist must be refused")
	}
	if reason != "not_allowlisted" {
		t.Errorf("reason = %q", reason)
	}
	// A platform operator locked out by a customer's typo has no way back that
	// does not involve psql on the host.
	if ok, _ := h.svc.CheckNetworkSource(ctx, actor.OrganizationID, true, "10.0.0.1"); !ok {
		t.Error("a super admin must not be locked out by a tenant's policy")
	}
}

func TestSetBranding_StoresAndAuditsWithoutPuttingTheArtworkInTheLedger(t *testing.T) {
	h := newHarness(opts{})
	logo := "data:image/png;base64," + strings.Repeat("A", 512)
	set, err := h.svc.SetBranding(context.Background(), adminClaims(), access.Branding{
		ClientName: "  Acme Bank  ", ClientLogo: logo, Enabled: true,
	}, ReqMeta{IP: "203.0.113.9"})
	if err != nil {
		t.Fatalf("set branding: %v", err)
	}
	if set.Branding.ClientName != "Acme Bank" {
		t.Errorf("client name = %q, want it trimmed", set.Branding.ClientName)
	}
	e := h.audit.find("settings.branding")
	if e == nil {
		t.Fatal("changing the console's identity must be audited")
	}
	// The ledger is hash-chained and kept forever; a data URI does not belong in
	// it. What changed is recorded, what it looks like lives in the settings row.
	for k, v := range e.Detail {
		if s, ok := v.(string); ok && strings.Contains(s, "data:image/") {
			t.Fatalf("audit detail %q carries the artwork itself", k)
		}
	}
	if e.Detail["has_logo"] != true {
		t.Errorf("audit should record that a logo is set: %v", e.Detail)
	}
}
