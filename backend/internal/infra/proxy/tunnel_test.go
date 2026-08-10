package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

const testTunnelDomain = "tunnel.guardrail.lan"

// establishTunnelled builds a gateway with the tunnel enabled and starts one
// session against target, returning the gateway, the session id and its token.
func establishTunnelled(t *testing.T, target string) (*HTTPGateway, uuid.UUID, string) {
	t.Helper()
	g := NewHTTPGateway(
		fakeDeviceLookup{ep: access.Endpoint{
			Protocol: access.ProtocolHTTP, BaseURL: target, Host: "127.0.0.1", VerifyTLS: true,
		}},
		nil, nil, "test-node", testTunnelDomain,
	)
	sess := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New()}
	live, err := g.Establish(context.Background(), sess,
		fakeResolver{cred: access.Credential{Injection: "basic", Username: "admin", Secret: "s3cret-pw"}})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	want := sess.ID.String() + "." + testTunnelDomain
	if live.TunnelHost != want {
		t.Fatalf("TunnelHost = %q, want %q", live.TunnelHost, want)
	}
	return g, sess.ID, live.ProxyToken
}

// The whole point of this transport: the path the browser asked for reaches the
// device unchanged, query included. Under /proxy/<sid>/ this needs prefix
// stripping and a path/query repack; here there is nothing to get wrong.
func TestServeTunnel_PassesPathAndQueryVerbatim(t *testing.T) {
	var gotPath, gotQuery string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotQuery = r.URL.Path, r.URL.RawQuery
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	g, sid, token := establishTunnelled(t, target.URL)

	req := httptest.NewRequest(http.MethodGet, "/ng/dashboard/page?tab=2&q=a%2Fb", nil)
	req.Host = sid.String() + "." + testTunnelDomain
	rec := httptest.NewRecorder()
	if !g.ServeTunnel(rec, req, sid, token) {
		t.Fatal("ServeTunnel returned false for a live session")
	}
	if gotPath != "/ng/dashboard/page" {
		t.Errorf("device saw path %q, want /ng/dashboard/page", gotPath)
	}
	if gotQuery != "tab=2&q=a%2Fb" {
		t.Errorf("device saw query %q, want tab=2&q=a%%2Fb", gotQuery)
	}
}

func TestServeTunnel_InjectsCredentialServerSide(t *testing.T) {
	var gotAuth string
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	g, sid, token := establishTunnelled(t, target.URL)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = sid.String() + "." + testTunnelDomain
	rec := httptest.NewRecorder()
	if !g.ServeTunnel(rec, req, sid, token) {
		t.Fatal("ServeTunnel returned false")
	}
	if gotAuth == "" || !strings.HasPrefix(gotAuth, "Basic ") {
		t.Fatalf("device did not receive injected Basic auth, got %q", gotAuth)
	}
	// The operator's browser must never be told the credential.
	if got := rec.Header().Get("Authorization"); got != "" {
		t.Errorf("credential echoed to the browser: %q", got)
	}
}

func TestServeTunnel_RejectsWrongTokenAndUnknownSession(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	g, sid, token := establishTunnelled(t, target.URL)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if g.ServeTunnel(httptest.NewRecorder(), req, sid, token+"x") {
		t.Error("a wrong token was accepted")
	}
	if g.ServeTunnel(httptest.NewRecorder(), req, uuid.New(), token) {
		t.Error("an unknown session id was accepted")
	}
	// Ending the session must close the tunnel too, not just the path transport.
	if err := g.End(context.Background(), sid); err != nil {
		t.Fatalf("End: %v", err)
	}
	if g.ServeTunnel(httptest.NewRecorder(), req, sid, token) {
		t.Error("an ended session still served over the tunnel")
	}
	if _, ok := g.TunnelCookieToken(sid); ok {
		t.Error("TunnelCookieToken still reports an ended session")
	}
}

// With no tunnel domain configured, nothing about the existing path transport
// changes and there is no tunnel to serve. This is the fallback guarantee.
func TestServeTunnel_DisabledWhenNoDomain(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	g := NewHTTPGateway(
		fakeDeviceLookup{ep: access.Endpoint{
			Protocol: access.ProtocolHTTP, BaseURL: target.URL, Host: "127.0.0.1", VerifyTLS: true,
		}},
		nil, nil, "n", "",
	)
	sess := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New()}
	live, err := g.Establish(context.Background(), sess, fakeResolver{cred: access.Credential{Injection: "none"}})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if live.TunnelHost != "" {
		t.Errorf("TunnelHost = %q, want empty when the tunnel is disabled", live.TunnelHost)
	}
	if live.ProxyPath != "/proxy/"+sess.ID.String()+"/" {
		t.Errorf("ProxyPath = %q, path transport must be unchanged", live.ProxyPath)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if g.ServeTunnel(httptest.NewRecorder(), req, sess.ID, live.ProxyToken) {
		t.Error("ServeTunnel served a session with no tunnel configured")
	}
}

func TestRebaseTunnelOrigin(t *testing.T) {
	target, _ := url.Parse("https://device.corp:8443")
	tunnelHost := "11111111-1111-1111-1111-111111111111.tunnel.guardrail.lan"

	t.Run("origin and referer become the device's own", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/login", nil)
		req.Header.Set("Origin", "https://"+tunnelHost)
		req.Header.Set("Referer", "https://"+tunnelHost+"/ng/login?next=%2Fdash")
		rebaseTunnelOrigin(req, target, tunnelHost)
		if got := req.Header.Get("Origin"); got != "https://device.corp:8443" {
			t.Errorf("Origin = %q", got)
		}
		// Path and query survive; only the origin is swapped.
		if got := req.Header.Get("Referer"); got != "https://device.corp:8443/ng/login?next=%2Fdash" {
			t.Errorf("Referer = %q", got)
		}
	})

	t.Run("a foreign referer is dropped, not translated", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Referer", "https://guardrail.lan/sessions")
		rebaseTunnelOrigin(req, target, tunnelHost)
		if got := req.Header.Get("Referer"); got != "" {
			t.Errorf("Referer = %q, want dropped", got)
		}
	})

	t.Run("absent headers are not invented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rebaseTunnelOrigin(req, target, tunnelHost)
		if req.Header.Get("Origin") != "" || req.Header.Get("Referer") != "" {
			t.Error("headers were added to a request that had none")
		}
	})
}

func TestModifyTunnelResponse(t *testing.T) {
	target, _ := url.Parse("https://device.corp")
	tunnelHost := "22222222-2222-2222-2222-222222222222.tunnel.guardrail.lan"
	mod := modifyTunnelResponse(target, tunnelHost)

	resp := &http.Response{Header: http.Header{}}
	resp.Header.Add("Set-Cookie", "SESSIONID=abc; Domain=device.corp; Path=/; HttpOnly; Secure")
	resp.Header.Add("Set-Cookie", "csrf=xyz; Path=/")
	resp.Header.Set("Location", "https://device.corp/ng/dashboard")
	resp.Header.Set("Strict-Transport-Security", "max-age=31536000")

	if err := mod(resp); err != nil {
		t.Fatalf("modifyTunnelResponse: %v", err)
	}

	cookies := resp.Header["Set-Cookie"]
	// Domain= must go, or the browser rejects a cookie scoped to a host it is not
	// talking to and the operator is silently signed out.
	if strings.Contains(strings.ToLower(cookies[0]), "domain=") {
		t.Errorf("Domain survived: %q", cookies[0])
	}
	// Everything else about the cookie is the device's business.
	for _, want := range []string{"SESSIONID=abc", "HttpOnly", "Secure", "Path=/"} {
		if !strings.Contains(cookies[0], want) {
			t.Errorf("cookie lost %q: %q", want, cookies[0])
		}
	}
	if cookies[1] != "csrf=xyz; Path=/" {
		t.Errorf("a cookie with no Domain was altered: %q", cookies[1])
	}
	if got := resp.Header.Get("Location"); got != "https://"+tunnelHost+"/ng/dashboard" {
		t.Errorf("Location = %q, want it re-pointed at the tunnel host", got)
	}
	if resp.Header.Get("Strict-Transport-Security") != "" {
		t.Error("device HSTS was allowed through onto the tunnel domain")
	}
}

func TestModifyTunnelResponse_LeavesForeignRedirectsAlone(t *testing.T) {
	target, _ := url.Parse("https://device.corp")
	mod := modifyTunnelResponse(target, "33333333-3333-3333-3333-333333333333.tunnel.guardrail.lan")
	resp := &http.Response{Header: http.Header{}}
	// An SSO bounce to a third party is not ours to rewrite.
	resp.Header.Set("Location", "https://idp.example.com/authorize?x=1")
	if err := mod(resp); err != nil {
		t.Fatalf("modifyTunnelResponse: %v", err)
	}
	if got := resp.Header.Get("Location"); got != "https://idp.example.com/authorize?x=1" {
		t.Errorf("Location = %q, want untouched", got)
	}
}
