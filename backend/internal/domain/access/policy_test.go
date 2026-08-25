package access

import (
	"net/netip"
	"testing"
)

func addr(t *testing.T, s string) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return a
}

func TestVerdict_NoPolicyAllowsEverything(t *testing.T) {
	var p NetworkPolicy
	if ok, _ := p.Verdict(addr(t, "203.0.113.9")); !ok {
		t.Fatal("a deployment with no policy must not refuse anybody")
	}
}

func TestVerdict_AllowlistRefusesWhatIsNotOnIt(t *testing.T) {
	p := NetworkPolicy{AllowEnabled: true, Allow: []NetworkRule{{CIDR: "10.200.10.0/24"}}}
	if ok, _ := p.Verdict(addr(t, "10.200.10.69")); !ok {
		t.Error("an address inside the range must be allowed")
	}
	ok, reason := p.Verdict(addr(t, "10.200.11.5"))
	if ok {
		t.Error("an address outside the range must be refused")
	}
	if reason != "not_allowlisted" {
		t.Errorf("reason = %q, want not_allowlisted", reason)
	}
}

func TestVerdict_DisabledListsAreInert(t *testing.T) {
	// The switch is the control, not the contents. An administrator drafting a
	// list must be able to save it without it taking effect.
	p := NetworkPolicy{
		Allow: []NetworkRule{{CIDR: "10.0.0.0/8"}},
		Block: []NetworkRule{{CIDR: "203.0.113.9"}},
	}
	if ok, _ := p.Verdict(addr(t, "203.0.113.9")); !ok {
		t.Fatal("a blocklist that is switched off must refuse nobody")
	}
}

func TestVerdict_BlocklistWinsOverAllowlist(t *testing.T) {
	// An address on both lists is being argued about. Refusing is the answer that
	// fails safe.
	p := NetworkPolicy{
		AllowEnabled: true, Allow: []NetworkRule{{CIDR: "10.0.0.0/8"}},
		BlockEnabled: true, Block: []NetworkRule{{CIDR: "10.1.2.3"}},
	}
	ok, reason := p.Verdict(addr(t, "10.1.2.3"))
	if ok {
		t.Error("an address on the blocklist must be refused even when it is also allowed")
	}
	if reason != "blocklisted" {
		t.Errorf("reason = %q, want blocklisted", reason)
	}
}

func TestVerdict_UnparseableSourceIsRefusedOnlyWhenAPolicyIsInForce(t *testing.T) {
	var none NetworkPolicy
	if ok, _ := none.Verdict(netip.Addr{}); !ok {
		t.Error("with no policy, an unknown source must not be refused")
	}
	p := NetworkPolicy{AllowEnabled: true, Allow: []NetworkRule{{CIDR: "10.0.0.0/8"}}}
	ok, reason := p.Verdict(netip.Addr{})
	if ok {
		t.Error("\"we could not tell where this came from\" must not be a way past an allowlist")
	}
	if reason != "unresolvable_source_address" {
		t.Errorf("reason = %q", reason)
	}
}

// A v4 address reaches a dual-stack listener as ::ffff:10.0.0.1. Matching that
// literally against a 10.0.0.0/8 rule fails, and the administrator sees an
// allowlist that refuses the addresses written on it.
func TestVerdict_IPv4MappedAddressesMatchIPv4Rules(t *testing.T) {
	p := NetworkPolicy{AllowEnabled: true, Allow: []NetworkRule{{CIDR: "10.200.10.0/24"}}}
	if ok, _ := p.Verdict(addr(t, "::ffff:10.200.10.69")); !ok {
		t.Fatal("an IPv4-mapped address must match the IPv4 rule it is")
	}
}

func TestNormalizeRules_MasksAndDeduplicates(t *testing.T) {
	got, err := NormalizeRules([]NetworkRule{
		{CIDR: " 10.1.2.3/8 ", Note: "office"},
		{CIDR: "10.0.0.0/8"},
		{CIDR: "203.0.113.9"},
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rules, want 2 after masking and dedup: %v", len(got), got)
	}
	// Stored as the range it actually means, not as a line that reads like a
	// single host and silently permits sixteen million addresses.
	if got[0].CIDR != "10.0.0.0/8" || got[0].Note != "office" {
		t.Errorf("first rule = %+v, want 10.0.0.0/8 with its note kept", got[0])
	}
	if got[1].CIDR != "203.0.113.9" {
		t.Errorf("second rule = %+v", got[1])
	}
}

func TestNormalizeRules_RejectsTheWholeListOnABadEntry(t *testing.T) {
	// Dropping the bad line silently would leave an allowlist missing exactly the
	// entry somebody meant to add, which is how a lockout happens.
	if _, err := NormalizeRules([]NetworkRule{{CIDR: "10.0.0.0/8"}, {CIDR: "not-an-address"}}); err == nil {
		t.Fatal("a malformed entry must refuse the save, not vanish from the list")
	}
}

func TestBranding_ConfiguredNeedsSomethingToShowAndTheSwitchOn(t *testing.T) {
	if (Branding{Enabled: true}).Configured() {
		t.Error("empty branding is not configured")
	}
	if (Branding{ClientName: "Acme", Enabled: false}).Configured() {
		t.Error("branding that is switched off must fall back to the vendor seal")
	}
	if !(Branding{ClientName: "Acme", Enabled: true}).Configured() {
		t.Error("a client name alone is enough to brand the console")
	}
	if !(Branding{ClientLogo: "data:image/png;base64,AAAA", Enabled: true}).Configured() {
		t.Error("a logo alone is enough to brand the console")
	}
}

func TestBranding_ValidateRejectsNonImagesAndOversizeArtwork(t *testing.T) {
	if err := (Branding{ClientLogo: "https://example.com/logo.png"}).Validate(); err == nil {
		t.Error("a remote URL must be refused: the console must not fetch a third-party asset on every page")
	}
	big := "data:image/png;base64," + string(make([]byte, MaxClientLogo))
	if err := (Branding{ClientLogo: big}).Validate(); err == nil {
		t.Error("oversize artwork must be refused")
	}
}
