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
	target *url.URL
	// proxy serves the session under the path prefix /proxy/<sid>/, rewriting the
	// device's HTML so a root-written UI survives the prefix (see rewrite.go).
	proxy *httputil.ReverseProxy
	// tunnelProxy serves the same session at the root of its own hostname,
	// <sid>.<tunnel-domain>, with no rewriting at all (see tunnel.go). It is nil
	// when no tunnel domain is configured.
	tunnelProxy *httputil.ReverseProxy
	token       string // browser-binding token
	headers     map[string]string
	expiresAt   time.Time
}

// HTTPGateway implements access.Gateway for http/https targets.
type HTTPGateway struct {
	mu       sync.RWMutex
	sessions map[uuid.UUID]*sessionCtx
	devices  access.DeviceLookup
	events   access.EventRecorder
	activity access.ActivitySink
	node     string
	// tunnelAuthority is what a per-session hostname must end with for a browser
	// to reach it: the tunnel domain, plus the public port when that is not 443.
	// The port belongs here because everything this field feeds is an absolute
	// URL or an Origin/Referer comparison, and both are wrong without it —
	// silently, on any deployment not published on 443.
	tunnelAuthority string
}

// NewHTTPGateway constructs the gateway. activity may be nil, in which case
// sessions are never marked as used and idle expiry does not apply to them.
// tunnelAuthority may be empty, which disables whole-host tunnel delivery.
func NewHTTPGateway(devices access.DeviceLookup, events access.EventRecorder, activity access.ActivitySink, node, tunnelAuthority string) *HTTPGateway {
	return &HTTPGateway{
		sessions: map[uuid.UUID]*sessionCtx{}, devices: devices,
		events: events, activity: activity, node: node,
		tunnelAuthority: tunnelAuthority,
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
			// #nosec G402 -- per-device policy, not a blanket opt-out: verification is
			// on unless the operator unticked it for this device, which management UIs
			// with self-signed certs require. The device is reached over the management
			// network and its credential is injected server-side either way.
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: !ep.VerifyTLS}, //nolint:gosec // per-device policy
			ForceAttemptHTTP2: true,
		},
		// Rebase device responses (HTML <base>+shim, redirects, cookies) under the
		// session prefix so a UI written for the origin root works when re-served at
		// /proxy/<sid>/. No watermark is injected on this path — see modifyResponse.
		//nolint:bodyclose // ModifyResponse inspects the upstream response and hands
		// it on; closing the body here would truncate the reply to the operator.
		ModifyResponse: modifyResponse(prefix),
		// Never leak upstream errors (which could echo device internals) to the
		// user; log-and-generic is applied by the caller's middleware.
		ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
			w.WriteHeader(http.StatusBadGateway)
			_, _ = w.Write([]byte("upstream unavailable"))
		},
	}

	// Whole-host delivery, when a tunnel domain is configured. This is a second
	// view onto the SAME session — same credential closure, same target, and
	// deliberately the same *http.Transport value, so the device's verify_tls
	// policy is shared rather than duplicated (two transports would mean two
	// connection pools and two chances to get the TLS policy wrong).
	var tunnelHost string
	var tp *httputil.ReverseProxy
	if g.tunnelAuthority != "" {
		tunnelHost = s.ID.String() + "." + g.tunnelAuthority
		tp = &httputil.ReverseProxy{
			Director:  g.tunnelDirector(target, ep.CustomHeaders, cred, tunnelHost),
			Transport: rp.Transport,
			//nolint:bodyclose // as above: the body is forwarded, not consumed.
			ModifyResponse: modifyTunnelResponse(target, tunnelHost),
			ErrorHandler:   rp.ErrorHandler,
		}
	}

	token := randomToken()
	until := time.Now().Add(time.Hour)
	if s.GrantedUntil != nil {
		until = *s.GrantedUntil
	}
	g.mu.Lock()
	g.sessions[s.ID] = &sessionCtx{
		target: target, proxy: rp, tunnelProxy: tp,
		token: token, headers: ep.CustomHeaders, expiresAt: until,
	}
	g.mu.Unlock()

	return access.LiveSession{
		SessionID: s.ID, GatewayNode: g.node,
		ProxyPath: "/proxy/" + s.ID.String() + "/", ProxyToken: token,
		TunnelHost: tunnelHost,
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
		_ = g.events.RecordEvent(req.Context(), sessionID, "url_change", timelineData(req.Method, upstreamPath))
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

// ServeTunnel proxies one whole-host request for a session. Unlike Serve it does
// not rewrite the path: the browser is talking to <sid>.<tunnel-domain>, whose
// root IS the device root, so the request line is already upstream-relative and
// passes through untouched (query included — there is no path/query repacking to
// get wrong here, which is the entire reason this transport exists).
//
// It returns false for an unknown, expired, tunnel-disabled or mis-authenticated
// session so the caller can answer 410 without this having written anything.
func (g *HTTPGateway) ServeTunnel(w http.ResponseWriter, req *http.Request, sessionID uuid.UUID, token string) bool {
	g.mu.RLock()
	sc, ok := g.sessions[sessionID]
	g.mu.RUnlock()
	if !ok || sc.tunnelProxy == nil || time.Now().After(sc.expiresAt) {
		return false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(sc.token)) != 1 {
		return false
	}

	// Touched after the token check, so an unauthorized caller cannot keep
	// somebody else's session alive.
	if g.activity != nil {
		g.activity.Touch(sessionID)
	}
	if g.events != nil {
		_ = g.events.RecordEvent(req.Context(), sessionID, "url_change", timelineData(req.Method, req.URL.RequestURI()))
	}
	sc.tunnelProxy.ServeHTTP(w, req)
	return true
}

// TunnelCookieToken returns the session's browser-binding token so the delivery
// layer can plant it as the tunnel cookie once a grant is redeemed. It reports
// false when the session is unknown or has no tunnel. The token is a session
// handle, never a device credential, and is never logged.
func (g *HTTPGateway) TunnelCookieToken(sessionID uuid.UUID) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	sc, ok := g.sessions[sessionID]
	if !ok || sc.tunnelProxy == nil {
		return "", false
	}
	return sc.token, true
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

/*
Telling a session's actions apart from its page loads.

	Every request through the proxy is recorded, because dropping one would be
	dropping evidence. But a single page view is one action and forty asset
	fetches, and a timeline that lists all forty is one nobody reads — the four
	rows that matter are somewhere in the middle of four hundred. So nothing is
	dropped; the asset fetches are labelled, and the reviewer's timeline hides
	them until asked.

	Extension, not Content-Type, because this runs before the response exists.
*/
func timelineData(method, path string) map[string]any {
	d := map[string]any{"path": path, "method": method}
	if isAssetPath(path) {
		d["asset"] = true
	}
	return d
}

// assetExt are the suffixes a browser fetches for itself. A device that serves
// its config export as .json is the reason .json is absent: that one IS an
// action.
var assetExt = []string{
	".css", ".js", ".mjs", ".map",
	".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico", ".bmp",
	".woff", ".woff2", ".ttf", ".otf", ".eot",
	".mp3", ".mp4", ".webm", ".ogg", ".wav",
}

// isAssetPath reports whether a path looks like page furniture rather than
// something the operator did.
func isAssetPath(p string) bool {
	if q := strings.IndexByte(p, '?'); q >= 0 {
		p = p[:q]
	}
	p = strings.ToLower(p)
	for _, ext := range assetExt {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}
