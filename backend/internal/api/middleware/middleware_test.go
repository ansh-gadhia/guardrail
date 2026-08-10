package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func testEngine() *gin.Engine {
	gin.SetMode(gin.TestMode)
	return gin.New()
}

func TestRequestID_GeneratesWhenAbsent(t *testing.T) {
	r := testEngine()
	r.Use(RequestID())
	r.GET("/", func(c *gin.Context) { c.String(http.StatusOK, RequestIDFrom(c)) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	if got := w.Header().Get(RequestIDHeader); got == "" {
		t.Fatal("expected a generated request id header")
	}
	if w.Body.Len() == 0 {
		t.Fatal("expected request id available in context")
	}
}

func TestRequestID_EchoesValidInbound(t *testing.T) {
	const id = "11111111-1111-1111-1111-111111111111"
	r := testEngine()
	r.Use(RequestID())
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(RequestIDHeader, id)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get(RequestIDHeader); got != id {
		t.Fatalf("request id = %q, want echoed %q", got, id)
	}
}

func TestSecurityHeaders(t *testing.T) {
	r := testEngine()
	r.Use(SecurityHeaders(""))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))

	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := w.Header().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
	if w.Header().Get("Content-Security-Policy") == "" {
		t.Error("expected a Content-Security-Policy header")
	}
}

func TestRecovery_CatchesPanic(t *testing.T) {
	r := testEngine()
	r.Use(Recovery(zap.NewNop()))
	r.GET("/boom", func(c *gin.Context) { panic("kaboom") })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500 after recovered panic", w.Code)
	}
}

func TestAccessLog_DoesNotBreakChain(t *testing.T) {
	r := testEngine()
	r.Use(AccessLog(zap.NewNop()))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusTeapot) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if w.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418 (middleware must not alter response)", w.Code)
	}
}

// A device UI hard-navigates to root-absolute URLs via window.location, which no
// client-side shim can intercept. The router catches that escape server-side and
// bounces it back into /proxy/<sid>/ — but it identifies the session from the
// Referer, so under "no-referrer" the browser sent none and the containment never
// fired: the device UI was handed the GuardRail console instead. The referrer has
// to survive on this route class.
func TestSecurityHeadersKeepsReferrerOnProxyRoutes(t *testing.T) {
	r := testEngine()
	r.Use(SecurityHeaders(""))
	r.GET("/proxy/:sid/*path", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/proxy/abc-123/ng/page", nil))

	if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy on a proxy route = %q, want same-origin; "+
			"without it the browser sends no Referer and the escape containment cannot find the session", got)
	}
}

// Everywhere else keeps the stricter policy: only the proxy needs the referrer,
// and only for same-origin requests.
func TestSecurityHeadersKeepsNoReferrerOffProxyRoutes(t *testing.T) {
	r := testEngine()
	r.Use(SecurityHeaders(""))
	r.GET("/api/v1/devices", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/devices", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, p := range []string{"/api/v1/devices", "/devices"} {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, p, nil))
		if got := w.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("Referrer-Policy on %s = %q, want no-referrer", p, got)
		}
	}
}

// On a tunnel host the path is the DEVICE's path, so this route class cannot be
// recognised by path the way /proxy/ can. Before the host check existed, a device
// page at /ng/dashboard fell through to the console branch and was served
// GuardRail's CSP and X-Frame-Options — which blocks the device's own scripts and
// styles and breaks the UI the tunnel exists to make work.
func TestSecurityHeadersLeavesDeviceHeadersAloneOnTunnelHost(t *testing.T) {
	r := testEngine()
	r.Use(SecurityHeaders("tunnel.guardrail.lan"))
	r.GET("/ng/dashboard", func(c *gin.Context) { c.Status(http.StatusOK) })

	for _, host := range []string{
		"11111111-1111-1111-1111-111111111111.tunnel.guardrail.lan",
		"11111111-1111-1111-1111-111111111111.tunnel.guardrail.lan:8443",
	} {
		req := httptest.NewRequest(http.MethodGet, "/ng/dashboard", nil)
		req.Host = host
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		if got := w.Header().Get("Content-Security-Policy"); got != "" {
			t.Errorf("host %s: CSP = %q, want none — the device ships its own", host, got)
		}
		if got := w.Header().Get("X-Frame-Options"); got != "" {
			t.Errorf("host %s: X-Frame-Options = %q, want none", host, got)
		}
		// Appliances CSRF-check the Referer against themselves; same-origin keeps
		// it within the session's own origin without ever reaching the console.
		if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
			t.Errorf("host %s: Referrer-Policy = %q, want same-origin", host, got)
		}
	}
}

// The same path on the console host keeps the console's policy. The host is the
// only thing that distinguishes them.
func TestSecurityHeadersKeepsConsolePolicyOffTunnelHost(t *testing.T) {
	r := testEngine()
	r.Use(SecurityHeaders("tunnel.guardrail.lan"))
	r.GET("/ng/dashboard", func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/ng/dashboard", nil)
	req.Host = "guardrail.lan"
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if got := w.Header().Get("Content-Security-Policy"); got == "" {
		t.Error("console host lost its CSP")
	}
	if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want DENY", got)
	}
}
