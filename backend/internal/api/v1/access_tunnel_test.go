package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// fakeTunnel stands in for the HTTP proxy gateway. It records what it was asked
// to serve so a test can assert the dispatch, not the proxying.
type fakeTunnel struct {
	token   string
	live    bool
	servedT string // the token ServeTunnel was called with
	servedP string // the path it saw
}

func (f *fakeTunnel) ServeTunnel(w http.ResponseWriter, r *http.Request, _ uuid.UUID, token string) bool {
	f.servedT, f.servedP = token, r.URL.Path
	if !f.live || token != f.token {
		return false
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("device-body"))
	return true
}

func (f *fakeTunnel) TunnelCookieToken(uuid.UUID) (string, bool) {
	if !f.live {
		return "", false
	}
	return f.token, true
}

func newTunnelHandler(f *fakeTunnel) *AccessHandler {
	return NewAccessHandler(nil, nil, true, TunnelConfig{
		Domain:   "tunnel.guardrail.lan",
		Gateway:  f,
		GrantKey: []byte("test-grant-key-at-least-32-bytes-long!!"),
	})
}

// engineWith mirrors router.New's ordering: tunnel dispatch registered before any
// route, then a console route and a NoRoute that stands in for the served SPA.
func engineWith(h *AccessHandler) *gin.Engine {
	gin.SetMode(gin.TestMode)
	e := gin.New()
	h.RegisterTunnel(e)
	e.GET("/api/v1/ping", func(c *gin.Context) { c.String(http.StatusOK, "pong") })
	e.NoRoute(func(c *gin.Context) { c.String(http.StatusOK, "console-spa") })
	return e
}

func TestTunnel_GrantSetsHostOnlyCookieAndRedirects(t *testing.T) {
	sid := uuid.New()
	f := &fakeTunnel{token: "session-token", live: true}
	h := newTunnelHandler(f)
	e := engineWith(h)

	req := httptest.NewRequest(http.MethodGet, "/__grant__?t="+h.mintGrant(sid, time.Now().Add(30*time.Second)), nil)
	req.Host = sid.String() + ".tunnel.guardrail.lan"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/" {
		t.Errorf("Location = %q, want /", loc)
	}
	// The grant travels in the query string, so the device must not be handed a
	// referrer that would carry it.
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q, want no-referrer", got)
	}
	sc := rec.Header().Get("Set-Cookie")
	if !strings.Contains(sc, "guardrail_tunnel_"+sid.String()+"=session-token") {
		t.Fatalf("cookie not set: %q", sc)
	}
	// No Domain attribute => host-only => the cookie cannot reach another
	// session's subdomain. This is the isolation between concurrent sessions.
	if strings.Contains(strings.ToLower(sc), "domain=") {
		t.Errorf("cookie is not host-only: %q", sc)
	}
	for _, want := range []string{"HttpOnly", "Secure"} {
		if !strings.Contains(sc, want) {
			t.Errorf("cookie missing %s: %q", want, sc)
		}
	}
}

func TestTunnel_GrantRejectsTamperedExpiredAndCrossSession(t *testing.T) {
	sid, other := uuid.New(), uuid.New()
	h := newTunnelHandler(&fakeTunnel{token: "tok", live: true})

	valid := h.mintGrant(sid, time.Now().Add(30*time.Second))
	cases := map[string]string{
		"tampered mac": valid[:len(valid)-2] + "AA",
		"empty":        "",
		"not a grant":  "garbage",
		"expired":      h.mintGrant(sid, time.Now().Add(-time.Second)),
		"another sid":  h.mintGrant(other, time.Now().Add(30*time.Second)),
		"missing dot":  strings.ReplaceAll(valid, ".", ""),
		"swapped halves": func() string {
			a, b, _ := strings.Cut(valid, ".")
			return b + "." + a
		}(),
	}
	for name, tok := range cases {
		if h.verifyGrant(sid, tok) {
			t.Errorf("%s: grant accepted, want rejected", name)
		}
	}
	if !h.verifyGrant(sid, valid) {
		t.Error("a valid grant was rejected")
	}
}

func TestTunnel_RequiresCookieThenServes(t *testing.T) {
	sid := uuid.New()
	f := &fakeTunnel{token: "session-token", live: true}
	e := engineWith(newTunnelHandler(f))

	// No cookie: refused, and the gateway is never consulted.
	req := httptest.NewRequest(http.MethodGet, "/ng/dashboard", nil)
	req.Host = sid.String() + ".tunnel.guardrail.lan"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if f.servedT != "" {
		t.Error("gateway was consulted without a cookie")
	}

	// With the cookie: proxied, path intact.
	req = httptest.NewRequest(http.MethodGet, "/ng/dashboard?tab=1", nil)
	req.Host = sid.String() + ".tunnel.guardrail.lan"
	req.AddCookie(&http.Cookie{Name: "guardrail_tunnel_" + sid.String(), Value: "session-token"})
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != "device-body" {
		t.Fatalf("status = %d body = %q", rec.Code, rec.Body.String())
	}
	if f.servedP != "/ng/dashboard" {
		t.Errorf("gateway saw path %q", f.servedP)
	}
}

// A dead session must report itself as gone rather than falling through to the
// console — the failure this whole transport exists to prevent.
func TestTunnel_EndedSessionIsGoneNotConsole(t *testing.T) {
	sid := uuid.New()
	e := engineWith(newTunnelHandler(&fakeTunnel{token: "tok", live: false}))

	req := httptest.NewRequest(http.MethodGet, "/ng/dashboard", nil)
	req.Host = sid.String() + ".tunnel.guardrail.lan"
	req.AddCookie(&http.Cookie{Name: "guardrail_tunnel_" + sid.String(), Value: "tok"})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusGone {
		t.Fatalf("status = %d, want 410", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "console-spa") {
		t.Error("a tunnel request fell through to the console SPA")
	}
}

// Every path on a tunnel host belongs to the device, including ones that collide
// with the console's own routes. If /api/v1/ping were answered by GuardRail here,
// any device whose UI has an /api path would break.
func TestTunnel_ConsolePathsOnTunnelHostGoToTheDevice(t *testing.T) {
	sid := uuid.New()
	f := &fakeTunnel{token: "tok", live: true}
	e := engineWith(newTunnelHandler(f))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
	req.Host = sid.String() + ".tunnel.guardrail.lan"
	req.AddCookie(&http.Cookie{Name: "guardrail_tunnel_" + sid.String(), Value: "tok"})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)

	if rec.Body.String() == "pong" {
		t.Fatal("the console answered a device path on a tunnel host")
	}
	if f.servedP != "/api/v1/ping" {
		t.Errorf("gateway saw %q, want the device path", f.servedP)
	}
}

// The console must be completely unaffected: same host, same routes, no dispatch.
func TestTunnel_ConsoleHostIsUntouched(t *testing.T) {
	f := &fakeTunnel{token: "tok", live: true}
	e := engineWith(newTunnelHandler(f))

	for _, host := range []string{
		"guardrail.lan",
		"192.168.1.10:8443",
		// Shaped like a tunnel host but under a different domain: not ours.
		uuid.New().String() + ".tunnel.example.com",
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Body.String() != "pong" {
			t.Errorf("host %q: body = %q, want the console to answer", host, rec.Body.String())
		}
	}
	if f.servedT != "" {
		t.Error("console traffic reached the tunnel gateway")
	}
}

func TestTunnel_HostWithPortAndNonUUIDLabel(t *testing.T) {
	sid := uuid.New()
	f := &fakeTunnel{token: "tok", live: true}
	e := engineWith(newTunnelHandler(f))

	// A port on the Host header must not defeat the suffix match.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = sid.String() + ".tunnel.guardrail.lan:8443"
	req.AddCookie(&http.Cookie{Name: "guardrail_tunnel_" + sid.String(), Value: "tok"})
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("host with port: status = %d, want 200", rec.Code)
	}

	// A label that is not a session id is a bad request, not a console page.
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "not-a-uuid.tunnel.guardrail.lan"
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad label: status = %d, want 400", rec.Code)
	}
}

// With no domain configured nothing is registered at all, so every request —
// including one shaped like a tunnel request — is served exactly as before.
func TestTunnel_DisabledLeavesTheConsoleAlone(t *testing.T) {
	h := NewAccessHandler(nil, nil, true, TunnelConfig{})
	if h.TunnelEnabled() {
		t.Fatal("TunnelEnabled with a zero TunnelConfig")
	}
	e := engineWith(h)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/ping", nil)
	req.Host = uuid.New().String() + ".tunnel.guardrail.lan"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Body.String() != "pong" {
		t.Errorf("body = %q, want the console to answer normally", rec.Body.String())
	}
}
