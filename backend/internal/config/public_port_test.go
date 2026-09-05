package config

import "testing"

// The tunnel URL is the one address this server writes out in full, so the port
// rule it uses is worth pinning down: 443 must stay implicit (a URL carrying
// ":443" is ugly and, worse, differs textually from the origin the browser
// computes), and every other port must be present or the link is unreachable.
func TestPublicPortSuffix(t *testing.T) {
	cases := []struct {
		port int
		want string
	}{
		{443, ""},
		{0, ""}, // unset: behave as the default rather than emitting ":0"
		{4444, ":4444"},
		{8443, ":8443"},
		{80, ":80"},
	}
	for _, c := range cases {
		got := HTTPConfig{PublicHTTPSPort: c.port}.PublicPortSuffix()
		if got != c.want {
			t.Errorf("PublicPortSuffix() with port %d = %q, want %q", c.port, got, c.want)
		}
	}
}

func TestTunnelAuthority(t *testing.T) {
	cases := []struct {
		domain string
		port   int
		want   string
	}{
		{"tunnel.guardrail.lan", 443, "tunnel.guardrail.lan"},
		{"tunnel.guardrail.lan", 4444, "tunnel.guardrail.lan:4444"},
		// Tunnel disabled: the answer is empty, never a bare ":4444" that would
		// compose into "<sid>.:4444" and be dispatched to nowhere.
		{"", 4444, ""},
		{"", 443, ""},
	}
	for _, c := range cases {
		got := HTTPConfig{TunnelDomain: c.domain, PublicHTTPSPort: c.port}.TunnelAuthority()
		if got != c.want {
			t.Errorf("TunnelAuthority(%q, %d) = %q, want %q", c.domain, c.port, got, c.want)
		}
	}
}
