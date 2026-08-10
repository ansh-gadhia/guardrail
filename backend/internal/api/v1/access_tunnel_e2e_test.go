package v1

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	domaccess "github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/infra/proxy"
)

// End to end over the real gateway: a fake appliance, the real HTTPGateway, the
// real handler and middleware, driven exactly as a browser would drive them.
// The unit tests above use a fake gateway to pin the dispatch; this one exists to
// catch the wiring between the two halves, which is where a mistake would
// otherwise only show up on a real device.

// closeNotifyRecorder is a recorder that also satisfies http.CloseNotifier.
//
// Gin's ResponseWriter type-asserts that interface when httputil.ReverseProxy
// asks whether the client hung up, and a bare httptest.ResponseRecorder makes it
// panic. Every real net/http response writer implements it, so this bridges the
// test harness only — it is not standing in for something missing in production.
type closeNotifyRecorder struct{ *httptest.ResponseRecorder }

func (closeNotifyRecorder) CloseNotify() <-chan bool { return make(chan bool) }

func newRecorder() closeNotifyRecorder {
	return closeNotifyRecorder{httptest.NewRecorder()}
}

type e2eLookup struct{ ep domaccess.Endpoint }

func (l e2eLookup) Endpoint(context.Context, domaccess.Scope, uuid.UUID) (domaccess.Endpoint, error) {
	return l.ep, nil
}

type e2eResolver struct{ cred domaccess.Credential }

func (r e2eResolver) Resolve(context.Context, *domaccess.Session) (domaccess.Credential, error) {
	return r.cred, nil
}
func (r e2eResolver) HasCredential(context.Context, domaccess.Scope, uuid.UUID) (bool, error) {
	return true, nil
}

func TestTunnel_EndToEndOverRealGateway(t *testing.T) {
	const domain = "tunnel.guardrail.lan"

	// A minimal appliance: requires Basic auth, sets a Domain-scoped cookie, and
	// serves a root-absolute SPA path — the shape that breaks under a prefix.
	var sawAuth, sawPath, sawOrigin, sawReferer string
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth, sawPath = r.Header.Get("Authorization"), r.URL.Path
		sawOrigin, sawReferer = r.Header.Get("Origin"), r.Header.Get("Referer")
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Set-Cookie", "APPSESSION=zzz; Domain=appliance.corp; Path=/; HttpOnly")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		_, _ = w.Write([]byte("APPLIANCE-DASHBOARD"))
	}))
	defer device.Close()

	du, _ := url.Parse(device.URL)
	gw := proxy.NewHTTPGateway(
		e2eLookup{ep: domaccess.Endpoint{
			Protocol: domaccess.ProtocolHTTP, BaseURL: device.URL, Host: du.Hostname(), VerifyTLS: true,
		}},
		nil, nil, "test-node", domain,
	)

	sess := &domaccess.Session{
		ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(),
	}
	live, err := gw.Establish(context.Background(), sess,
		e2eResolver{cred: domaccess.Credential{Injection: "basic", Username: "admin", Secret: "pw"}})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	h := NewAccessHandler(nil, nil, true, TunnelConfig{
		Domain: domain, Gateway: gw, GrantKey: []byte("an-e2e-grant-key-of-sufficient-length"),
	})
	gin.SetMode(gin.TestMode)
	e := gin.New()
	h.RegisterTunnel(e)
	e.NoRoute(func(c *gin.Context) { c.String(http.StatusOK, "console-spa") })

	host := live.TunnelHost
	if host != sess.ID.String()+"."+domain {
		t.Fatalf("TunnelHost = %q", host)
	}

	// 1. Redeem the grant, exactly as the opened tab does.
	grant := h.tunnelURLFor(sess.ID)
	gu, err := url.Parse(grant)
	if err != nil {
		t.Fatalf("grant url: %v", err)
	}
	if gu.Host != host || gu.Path != "/__grant__" {
		t.Fatalf("grant url = %q, want https://%s/__grant__?t=…", grant, host)
	}
	req := httptest.NewRequest(http.MethodGet, "/__grant__?"+gu.RawQuery, nil)
	req.Host = host
	rec := newRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("grant: status = %d, want 302", rec.Code)
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("grant set %d cookies, want 1", len(cookies))
	}
	jar := cookies[0]
	if jar.Domain != "" {
		t.Errorf("cookie Domain = %q, want host-only", jar.Domain)
	}

	// 2. Follow the redirect to a device SPA deep link — the exact navigation that
	//    escapes a path prefix and lands on the console. Here it must reach the
	//    device, because the device owns this origin.
	req = httptest.NewRequest(http.MethodGet, "/ng/dashboard?tab=2", nil)
	req.Host = host
	req.Header.Set("Origin", "https://"+host)
	req.Header.Set("Referer", "https://"+host+"/ng/login")
	req.AddCookie(jar)
	rec = newRecorder()
	e.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("device request: status = %d, body = %q", rec.Code, rec.Body.String())
	}
	if body := rec.Body.String(); !strings.Contains(body, "APPLIANCE-DASHBOARD") {
		t.Fatalf("body = %q, want the device page", body)
	}
	if sawPath != "/ng/dashboard" {
		t.Errorf("device saw path %q, want /ng/dashboard verbatim", sawPath)
	}
	if !strings.HasPrefix(sawAuth, "Basic ") {
		t.Errorf("credential was not injected: %q", sawAuth)
	}
	// The device is told the request came from itself, not from the tunnel host.
	if sawOrigin != device.URL {
		t.Errorf("device saw Origin %q, want %q", sawOrigin, device.URL)
	}
	if !strings.HasPrefix(sawReferer, device.URL) {
		t.Errorf("device saw Referer %q, want it rebased onto %q", sawReferer, device.URL)
	}
	// Response side: the device's cookie is re-scoped and its HSTS is dropped.
	for _, sc := range rec.Result().Header["Set-Cookie"] {
		if strings.Contains(strings.ToLower(sc), "domain=") {
			t.Errorf("device cookie kept its Domain: %q", sc)
		}
	}
	if rec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("device HSTS reached the browser on the tunnel domain")
	}

	// 3. Ending the session closes the tunnel; it must not fall back to the console.
	if err := gw.End(context.Background(), sess.ID); err != nil {
		t.Fatalf("End: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/ng/dashboard", nil)
	req.Host = host
	req.AddCookie(jar)
	rec = newRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusGone {
		t.Fatalf("after End: status = %d, want 410", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "console-spa") {
		t.Error("an ended session fell through to the console")
	}
}

// Two live sessions must not be able to use each other's cookie, which is what
// the host-only cookie guarantees. Asserted at the gateway, since a browser would
// never send the wrong one in the first place.
func TestTunnel_ConcurrentSessionsAreIsolated(t *testing.T) {
	const domain = "tunnel.guardrail.lan"
	device := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer device.Close()

	du, _ := url.Parse(device.URL)
	gw := proxy.NewHTTPGateway(
		e2eLookup{ep: domaccess.Endpoint{
			Protocol: domaccess.ProtocolHTTP, BaseURL: device.URL, Host: du.Hostname(), VerifyTLS: true,
		}},
		nil, nil, "n", domain,
	)
	res := e2eResolver{cred: domaccess.Credential{Injection: "none"}}

	a := &domaccess.Session{ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New()}
	b := &domaccess.Session{ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New()}
	liveA, err := gw.Establish(context.Background(), a, res)
	if err != nil {
		t.Fatalf("Establish A: %v", err)
	}
	liveB, err := gw.Establish(context.Background(), b, res)
	if err != nil {
		t.Fatalf("Establish B: %v", err)
	}

	if liveA.ProxyToken == liveB.ProxyToken {
		t.Fatal("two sessions share a token")
	}
	if liveA.TunnelHost == liveB.TunnelHost {
		t.Fatal("two sessions share a hostname")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if gw.ServeTunnel(newRecorder(), req, a.ID, liveB.ProxyToken) {
		t.Error("session A accepted session B's token")
	}
	if !gw.ServeTunnel(newRecorder(), req, a.ID, liveA.ProxyToken) {
		t.Error("session A rejected its own token")
	}
}
