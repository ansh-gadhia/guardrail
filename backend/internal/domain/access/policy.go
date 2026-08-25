package access

import (
	"fmt"
	"net/netip"
	"strings"
)

// ---- Branding --------------------------------------------------------------

// Branding is how an organization's console presents itself.
//
// A deployment handed to a client is that client's console. Until this existed
// the rail under the product wordmark carried the vendor's seal and nothing
// else, so putting a customer's own identity on it meant editing the source.
type Branding struct {
	// ClientName is shown as a wordmark when there is no logo, and as the logo's
	// accessible name when there is one.
	ClientName string
	// ClientLogo is a data: URI holding the artwork, or empty. Inline rather than
	// a stored object: it is one small image that every signed-in page needs, so
	// it travels with the settings the shell already reads.
	ClientLogo string
	// Enabled turns client branding on without discarding it. An administrator
	// who wants the vendor seal back for a week should not have to delete the
	// artwork to get it.
	Enabled bool
}

// Configured reports whether there is anything to show.
func (b Branding) Configured() bool {
	return b.Enabled && (strings.TrimSpace(b.ClientName) != "" || b.ClientLogo != "")
}

// MaxClientName and MaxClientLogo bound what may be stored. The logo limit is on
// the encoded data URI, which is roughly a third larger than the file behind it.
const (
	MaxClientName = 120
	MaxClientLogo = 400_000
)

// Validate reports why branding cannot be stored, or nil.
func (b Branding) Validate() error {
	if len([]rune(b.ClientName)) > MaxClientName {
		return fmt.Errorf("%w: the client name may be at most %d characters", ErrInvalid, MaxClientName)
	}
	if b.ClientLogo == "" {
		return nil
	}
	if !strings.HasPrefix(b.ClientLogo, "data:image/") {
		return fmt.Errorf("%w: the logo must be an image", ErrInvalid)
	}
	if len(b.ClientLogo) > MaxClientLogo {
		return fmt.Errorf("%w: the logo is too large — use an image under about 280 KB", ErrInvalid)
	}
	return nil
}

// ---- Network policy --------------------------------------------------------

// NetworkRule is one entry in an address list: a single address or a CIDR block,
// with a note saying what it is. The note is the difference between a list an
// administrator can maintain and a column of numbers nobody dares touch.
type NetworkRule struct {
	CIDR string `json:"cidr"`
	Note string `json:"note,omitempty"`
}

// NetworkPolicy is which source addresses may reach an organization's console.
//
// The two lists are independent, each with its own switch, because they answer
// different questions: an allowlist says "only from here", a blocklist says
// "never from there". One combined switch would mean that barring a single
// address first requires enumerating every address that is permitted.
type NetworkPolicy struct {
	AllowEnabled bool
	Allow        []NetworkRule
	BlockEnabled bool
	Block        []NetworkRule
}

// MaxNetworkRules bounds each list.
const MaxNetworkRules = 256

// Verdict decides whether an address may proceed, and says why when it may not.
//
// The blocklist is consulted first and wins. An address that appears on both
// lists is being argued about, and refusing is the answer that fails safe.
func (p NetworkPolicy) Verdict(ip netip.Addr) (bool, string) {
	if !ip.IsValid() {
		// An address we could not parse cannot be matched against a list. With a
		// policy in force that is a refusal, not a pass: "we could not tell where
		// this came from" must not be the way past an allowlist.
		if p.AllowEnabled || p.BlockEnabled {
			return false, "unresolvable_source_address"
		}
		return true, ""
	}
	if p.BlockEnabled && matchesAny(p.Block, ip) {
		return false, "blocklisted"
	}
	if p.AllowEnabled && !matchesAny(p.Allow, ip) {
		return false, "not_allowlisted"
	}
	return true, ""
}

// Active reports whether either list is in force.
func (p NetworkPolicy) Active() bool { return p.AllowEnabled || p.BlockEnabled }

func matchesAny(rules []NetworkRule, ip netip.Addr) bool {
	for _, r := range rules {
		if matches(r.CIDR, ip) {
			return true
		}
	}
	return false
}

func matches(entry string, ip netip.Addr) bool {
	entry = strings.TrimSpace(entry)
	if entry == "" {
		return false
	}
	if strings.Contains(entry, "/") {
		pfx, err := netip.ParsePrefix(entry)
		if err != nil {
			return false
		}
		// Unmap so a v4 address arriving as ::ffff:10.0.0.1 — which is how it
		// reaches a dual-stack listener — still matches a 10.0.0.0/8 rule.
		return pfx.Contains(ip.Unmap())
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return false
	}
	return addr.Unmap() == ip.Unmap()
}

// NormalizeRules validates and canonicalises a list of rules, rejecting the
// whole list rather than silently dropping an entry: an allowlist that quietly
// lost the line naming head office is worse than one that refused to save.
func NormalizeRules(rules []NetworkRule) ([]NetworkRule, error) {
	if len(rules) > MaxNetworkRules {
		return nil, fmt.Errorf("%w: at most %d entries per list", ErrInvalid, MaxNetworkRules)
	}
	out := make([]NetworkRule, 0, len(rules))
	seen := map[string]bool{}
	for _, r := range rules {
		entry := strings.TrimSpace(r.CIDR)
		if entry == "" {
			continue
		}
		canon, err := canonicalEntry(entry)
		if err != nil {
			return nil, err
		}
		if seen[canon] {
			continue
		}
		seen[canon] = true
		note := strings.TrimSpace(r.Note)
		if len([]rune(note)) > 120 {
			note = string([]rune(note)[:120])
		}
		out = append(out, NetworkRule{CIDR: canon, Note: note})
	}
	return out, nil
}

func canonicalEntry(entry string) (string, error) {
	if strings.Contains(entry, "/") {
		pfx, err := netip.ParsePrefix(entry)
		if err != nil {
			return "", fmt.Errorf("%w: %q is not a valid address range — use a form like 10.0.0.0/8", ErrInvalid, entry)
		}
		// Masked, so 10.1.2.3/8 is stored as the 10.0.0.0/8 it actually means
		// rather than as a line that reads like a single host.
		return pfx.Masked().String(), nil
	}
	addr, err := netip.ParseAddr(entry)
	if err != nil {
		return "", fmt.Errorf("%w: %q is not a valid address", ErrInvalid, entry)
	}
	return addr.Unmap().String(), nil
}
