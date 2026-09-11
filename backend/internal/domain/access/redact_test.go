package access

import "testing"

// The secret used throughout. If any assertion below ever finds it in output,
// the redaction has a hole and a target credential reaches session_events.
const leaked = "hunter2"

func TestRedactQuery(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"single pair", "password=" + leaked, "password=<redacted>"},
		{"keys and order survive", "b=1&a=2&c=3", "b=<redacted>&a=<redacted>&c=<redacted>"},
		{"duplicates survive", "k=1&k=2", "k=<redacted>&k=<redacted>"},
		{"bare key untouched", "verbose", "verbose"},
		{"bare key among pairs", "verbose&pw=" + leaked, "verbose&pw=<redacted>"},
		{"empty value still redacted", "pw=", "pw=<redacted>"},
		{"value containing = is fully removed", "t=a=b=" + leaked, "t=<redacted>"},
		{"encoded value", "pw=%73%65%63%72%65%74", "pw=<redacted>"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := RedactQuery(c.in); got != c.want {
				t.Fatalf("RedactQuery(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

func TestRedactURL(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		wantHas   []string
		wantLacks []string
	}{
		{
			name:      "the real-world shape from the audit",
			in:        "http://192.168.1.1/login.html?Username=admin&Password=" + leaked + "&sessionKey=abc",
			wantHas:   []string{"192.168.1.1", "/login.html", "Username=", "Password=", "sessionKey="},
			wantLacks: []string{leaked, "admin", "abc"},
		},
		{
			name:      "no query is returned unchanged",
			in:        "https://device/config",
			wantHas:   []string{"https://device/config"},
			wantLacks: []string{"<redacted>"},
		},
		{
			name:      "fragment survives",
			in:        "https://d/p?pw=" + leaked + "#section",
			wantHas:   []string{"#section", "pw="},
			wantLacks: []string{leaked},
		},
		{
			name: "unparseable input with a query is still redacted",
			// A control character makes url.Parse fail; the fallback must not
			// pass the tail through.
			in:        "ht\x7ftp://x/y?pw=" + leaked,
			wantHas:   []string{"pw="},
			wantLacks: []string{leaked},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := RedactURL(c.in)
			for _, want := range c.wantHas {
				if !contains(got, want) {
					t.Errorf("RedactURL(%q) = %q, want it to contain %q", c.in, got, want)
				}
			}
			for _, bad := range c.wantLacks {
				if contains(got, bad) {
					t.Errorf("RedactURL(%q) = %q, LEAKED %q", c.in, got, bad)
				}
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
