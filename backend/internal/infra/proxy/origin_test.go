package proxy

import (
	"net/http"
	"net/url"
	"testing"
)

const originPrefix = "/proxy/abc123/"

func originTarget(t *testing.T) *url.URL {
	t.Helper()
	u, err := url.Parse("https://10.0.0.1:2443")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// The browser computes Referer/Origin against GuardRail, because that is the
// address it is talking to. Forwarding those verbatim tells the device the
// broker's URLs and session id, and breaks appliances that CSRF-check them
// against their own origin — which is exactly where a login POST is checked.
func TestRebaseRequestOriginRewritesToDevice(t *testing.T) {
	req := httpReq("https://guardrail.local:8080/proxy/abc123/api/v2/auth")
	req.Header.Set("Referer", "https://guardrail.local:8080/proxy/abc123/ng/login?next=%2Fdash")
	req.Header.Set("Origin", "https://guardrail.local:8080")

	rebaseRequestOrigin(req, originTarget(t), originPrefix)

	if got, want := req.Header.Get("Origin"), "https://10.0.0.1:2443"; got != want {
		t.Errorf("Origin = %q, want %q", got, want)
	}
	if got, want := req.Header.Get("Referer"), "https://10.0.0.1:2443/ng/login?next=%2Fdash"; got != want {
		t.Errorf("Referer = %q, want %q", got, want)
	}
}

// A bare session prefix is the device's root.
func TestRebaseRequestOriginPrefixRootBecomesDeviceRoot(t *testing.T) {
	req := httpReq("https://guardrail.local:8080/proxy/abc123/static/main.js")
	req.Header.Set("Referer", "https://guardrail.local:8080/proxy/abc123/")

	rebaseRequestOrigin(req, originTarget(t), originPrefix)

	if got, want := req.Header.Get("Referer"), "https://10.0.0.1:2443/"; got != want {
		t.Errorf("Referer = %q, want %q", got, want)
	}
}

// A referrer from outside this session cannot be expressed in the device's terms.
// It must be dropped, not passed through — passing it through would hand the
// device a GuardRail console URL, which is the leak this function exists to stop.
func TestRebaseRequestOriginDropsForeignReferer(t *testing.T) {
	for _, ref := range []string{
		"https://guardrail.local:8080/devices",        // the console itself
		"https://guardrail.local:8080/proxy/other99/", // a different session
		"https://evil.example.com/x",
		"://not a url",
	} {
		req := httpReq("https://guardrail.local:8080/proxy/abc123/x")
		req.Header.Set("Referer", ref)

		rebaseRequestOrigin(req, originTarget(t), originPrefix)

		if got := req.Header.Get("Referer"); got != "" {
			t.Errorf("Referer %q was forwarded as %q; it must be dropped", ref, got)
		}
	}
}

// No Origin in, no Origin out: inventing one would assert a provenance the
// browser never claimed.
func TestRebaseRequestOriginDoesNotInventOrigin(t *testing.T) {
	req := httpReq("https://guardrail.local:8080/proxy/abc123/x")
	rebaseRequestOrigin(req, originTarget(t), originPrefix)
	if got := req.Header.Get("Origin"); got != "" {
		t.Errorf("Origin = %q, want it absent", got)
	}
}

func httpReq(rawurl string) *http.Request {
	u, _ := url.Parse(rawurl)
	return &http.Request{URL: u, Header: http.Header{}}
}
