// Package proxy implements the HTTP/HTTPS access Gateway: a credential-injecting
// reverse proxy. When a user connects, the broker establishes a session here;
// the gateway resolves the device credential just-in-time, holds it in memory
// only, and injects it into every proxied request so it is applied server-side
// and NEVER exposed to the user's browser. A per-session random token binds the
// browser to the session. The richer Chromium/form-fill gateway plugs in later
// behind the same access.Gateway interface without changing the broker.
package proxy

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// sessionCtx holds the live proxy state for one session (in-memory only).
type sessionCtx struct {
	target    *url.URL
	proxy     *httputil.ReverseProxy
	token     string // browser-binding token
	headers   map[string]string
	expiresAt time.Time
}

// HTTPGateway implements access.Gateway for http/https targets.
type HTTPGateway struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*sessionCtx
	devices  access.DeviceLookup
	events   access.EventRecorder
	activity access.ActivitySink
	node     string
}

// NewHTTPGateway constructs the gateway. activity may be nil, in which case
// sessions are never marked as used and idle expiry does not apply to them.
func NewHTTPGateway(devices access.DeviceLookup, events access.EventRecorder, activity access.ActivitySink, node string) *HTTPGateway {
	return &HTTPGateway{
		sessions: map[uuid.UUID]*sessionCtx{}, devices: devices,
		events: events, activity: activity, node: node,
	}
}

// Protocol reports the modality this gateway serves.
func (g *HTTPGateway) Protocol() access.Protocol { return access.ProtocolHTTPS }

// Establish resolves the device endpoint and credential, builds a
// credential-injecting reverse proxy, and returns the client handle.
func (g *HTTPGateway) Establish(ctx context.Context, s *access.Session, r access.CredentialResolver) (access.LiveSession, error) {
	ep, err := g.devices.Endpoint(ctx, access.Scope{OrganizationID: s.OrganizationID}, s.DeviceID)
	if err != nil {
		return access.LiveSession{}, err
	}
	if err := GuardSSRF(ep.Host); err != nil {
		return access.LiveSession{}, err
	}
	target, err := url.Parse(ep.BaseURL)
	if err != nil {
		return access.LiveSession{}, fmt.Errorf("proxy: bad device url: %w", err)
	}

	// Just-in-time, one-shot credential resolution. Held only in this closure.
	// Fail closed (defence in depth — the broker also pre-checks): a device with
	// no bound credential is refused unless it explicitly allows break-glass
	// unmanaged access, in which case its own login page is proxied with no
	// server-side injection.
	cred, err := r.Resolve(ctx, s)
	if err != nil {
		if !errors.Is(err, access.ErrNoCredential) {
			return access.LiveSession{}, err
		}
		if !ep.AllowUnmanaged {
			return access.LiveSession{}, access.ErrNoCredential
		}
		cred = access.Credential{Injection: "none"}
	}

	// Refuse a credential this gateway cannot apply, rather than proxying without
	// it. Form fill needs a browser to type into the page; this gateway only
	// rewrites HTTP, so it would have to send the secret to the operator — which
	// is the one thing it must never do. Silently skipping the injection instead
	// left the operator at the device's own login page holding nothing, with the
	// console still reporting the credential as bound.
	if cred.Injection == "form" {
		return access.LiveSession{}, access.ErrInjectionUnsupported
	}

	prefix := "/proxy/" + s.ID.String() + "/"
	rp := &httputil.ReverseProxy{
		Director: g.director(target, ep.CustomHeaders, cred, prefix),
		Transport: &http.Transport{
			// verify_tls is honored per device; management UIs often use
			// self-signed certs, so this is configurable per target.
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: !ep.VerifyTLS}, //nolint:gosec // per-device policy
			ForceAttemptHTTP2: true,
		},
		// Rebase device responses (HTML <base>+shim, redirects, cookies) under the
		// session prefix so a UI written for the origin root works when re-served
		// at /proxy/<sid>/, and stamp the attribution watermark into HTML.
		ModifyResponse: modifyResponse(prefix, s.WatermarkOr()),
		// Never leak upstream errors (which could echo device internals) to the
		// user; log-and-generic is applied by the caller's middleware.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream unavailable"))
		},
	}

	token := randomToken()
	until := time.Now().Add(time.Hour)
	if s.GrantedUntil != nil {
		until = *s.GrantedUntil
	}
	g.mu.Lock()
	g.sessions[s.ID] = &sessionCtx{target: target, proxy: rp, token: token, headers: ep.CustomHeaders, expiresAt: until}
	g.mu.Unlock()

	return access.LiveSession{
		SessionID: s.ID, GatewayNode: g.node,
		ProxyPath: "/proxy/" + s.ID.String() + "/", ProxyToken: token,
	}, nil
}

// director rewrites the outbound request to the target and injects credentials
// server-side. The user's browser never sees the credential.
func (g *HTTPGateway) director(target *url.URL, headers map[string]string, cred access.Credential, prefix string) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		if target.Path != "" && target.Path != "/" {
			req.URL.Path = singleJoin(target.Path, req.URL.Path)
		}
		rebaseRequestOrigin(req, target, prefix)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		switch cred.Injection {
		case "basic":
			req.SetBasicAuth(cred.Username, cred.Secret)
		case "header":
			// Secret carries the full header value, e.g. "Bearer <token>".
			req.Header.Set("Authorization", cred.Secret)
		}
		// Strip hop-by-hop / forwarded identity that could confuse the device.
		req.Header.Del("X-Forwarded-For")
		// Ask upstream not to compress so ModifyResponse can rewrite HTML bodies
		// reliably (no gzip/br decode step needed).
		req.Header.Del("Accept-Encoding")
	}
}

// rebaseRequestOrigin rewrites Referer/Origin from GuardRail's origin to the
// device's own, as the device UI would have sent them if served directly.
//
// The browser computes these against the address it is actually talking to, so
// they name GuardRail and carry the session prefix. Forwarding that verbatim does
// two bad things: it tells the device the broker's URLs and session id, and it
// breaks any appliance that CSRF-checks Referer/Origin against its own origin —
// the login POST is exactly where such a check lives.
//
// A referrer that is not under this session's prefix is dropped rather than
// translated. It cannot be expressed in the device's terms, and guessing would
// mean inventing a provenance for a request.
func rebaseRequestOrigin(req *http.Request, target *url.URL, prefix string) {
	origin := target.Scheme + "://" + target.Host
	if req.Header.Get("Origin") != "" {
		req.Header.Set("Origin", origin)
	}
	ref := req.Header.Get("Referer")
	if ref == "" {
		return
	}
	u, err := url.Parse(ref)
	if err != nil || !strings.HasPrefix(u.Path, prefix) {
		req.Header.Del("Referer")
		return
	}
	// "/proxy/<sid>/ng/page" -> "/ng/page"; the prefix's trailing slash is kept so
	// a bare prefix rebases to the device root.
	rebased := origin + "/" + strings.TrimPrefix(u.Path, prefix)
	if u.RawQuery != "" {
		rebased += "?" + u.RawQuery
	}
	req.Header.Set("Referer", rebased)
}

// End tears down a session's proxy state and wipes the in-memory credential.
func (g *HTTPGateway) End(_ context.Context, sessionID uuid.UUID) error {
	g.mu.Lock()
	delete(g.sessions, sessionID)
	g.mu.Unlock()
	return nil
}

// Serve proxies one request for a session. It validates the browser-binding
// token, records a url_change event, and streams the response. It returns false
// if the session is unknown/expired so the caller can respond appropriately.
func (g *HTTPGateway) Serve(w http.ResponseWriter, req *http.Request, sessionID uuid.UUID, token, upstreamPath string) bool {
	g.mu.RLock()
	sc, ok := g.sessions[sessionID]
	g.mu.RUnlock()
	if !ok || time.Now().After(sc.expiresAt) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(sc.token)) != 1 {
		return false
	}

	// The operator is still here. Touched after the token check so an unauthorized
	// caller cannot keep somebody else's session alive.
	if g.activity != nil {
		g.activity.Touch(sessionID)
	}

	// Record the visited path + method for the playback timeline (best-effort).
	if g.events != nil {
		_ = g.events.RecordEvent(req.Context(), sessionID, "url_change",
			map[string]any{"path": upstreamPath, "method": req.Method})
	}

	// Rewrite to the upstream-relative path and proxy.
	proxied := req.Clone(req.Context())
	if upstreamPath == "" {
		upstreamPath = "/"
	}
	if !strings.HasPrefix(upstreamPath, "/") {
		upstreamPath = "/" + upstreamPath
	}
	// upstreamPath arrives as "path?query" — the caller has no other way to pass
	// both through the SessionServer's single path argument. Path and query have
	// to be separated again here, because URL.Path is the DECODED path: a '?' left
	// in it is not a delimiter, it is a literal character, and Go re-encodes it as
	// %3F on the way out. The device then gets a request for a path that does not
	// exist ("/logout%3Fredir=%2F"), and an appliance SPA answers unknown paths
	// with its shell — so every URL carrying a query silently returned the app
	// shell instead of the page asked for. On a FortiGate that is an infinite
	// redirect loop: the shell asks whether it is logged in, is told no, navigates
	// to /logout?redir=..., and is handed the shell again.
	path, query, _ := strings.Cut(upstreamPath, "?")
	proxied.URL.Path = path
	proxied.URL.RawQuery = query
	proxied.RequestURI = ""
	sc.proxy.ServeHTTP(w, proxied)
	return true
}

// Console adapts the reverse proxy to the delivery layer's SessionServer: it
// proxies the device response directly.
func (g *HTTPGateway) Console(w http.ResponseWriter, req *http.Request, sessionID uuid.UUID, token, upstreamPath string) bool {
	return g.Serve(w, req, sessionID, token, upstreamPath)
}

// Stream is unsupported by the reverse proxy (it serves the device's own HTML,
// not a pixel stream), so it reports no session.
func (g *HTTPGateway) Stream(_ http.ResponseWriter, _ *http.Request, _ uuid.UUID, _ string) bool {
	return false
}

func singleJoin(a, b string) string {
	return strings.TrimSuffix(a, "/") + "/" + strings.TrimPrefix(b, "/")
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
