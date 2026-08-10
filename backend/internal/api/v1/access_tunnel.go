package v1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	domaccess "github.com/guardrail/guardrail/internal/domain/access"
)

// Whole-host tunnel delivery: the browser-facing half.
//
// A tunnelled session is reached at https://<sid>.<tunnel-domain>/ — a distinct
// origin from the console, which is the entire point (see infra/proxy/tunnel.go).
// A distinct origin also means the console's own session cookie is NOT sent
// there, so the tunnel host needs its own credential. That is what the grant
// handshake below establishes:
//
//	console                  tunnel host
//	   |  connect -> tunnel_url = https://<sid>.<domain>/__grant__?t=<OTT>
//	   |------------------------->|  GET /__grant__?t=<OTT>
//	                              |  verify HMAC + expiry
//	                              |  Set-Cookie guardrail_tunnel_<sid> (host-only)
//	                              |  302 -> "/" with Referrer-Policy: no-referrer
//	                              |<-- every later request carries the cookie
//
// The one-time token is short-lived and travels in the query string, so the
// redirect deliberately sends no referrer: the device must never observe it.

// tunnelGrantTTL bounds how long a minted grant may be redeemed for. It only has
// to survive the browser opening a tab, so it is short by design.
const tunnelGrantTTL = 30 * time.Second

// tunnelCookieMaxAge bounds the tunnel cookie's lifetime. The session's own
// expiry is authoritative and enforced server-side on every request; this is
// only so an abandoned tab does not keep a stale cookie forever.
const tunnelCookieMaxAge = 3600

func tunnelCookieName(sid string) string { return "guardrail_tunnel_" + sid }

// TunnelEnabled reports whether whole-host delivery is configured.
func (h *AccessHandler) TunnelEnabled() bool { return h.tunnel != nil && h.tunnelDomain != "" }

// RegisterTunnel installs the host-dispatch middleware on the root engine.
//
// It MUST be registered before any route or NoRoute handler. Gin copies the
// middleware chain into each route at registration time, so middleware added
// after the routes exist would never run for them — and a tunnel request would
// fall through to the console's static-file NoRoute, serving the GuardRail SPA
// where the device UI was expected. That failure is silent and looks exactly
// like the bug this whole transport was built to fix.
func (h *AccessHandler) RegisterTunnel(e *gin.Engine) {
	if !h.TunnelEnabled() {
		return
	}
	e.Use(h.tunnelMiddleware())
}

// tunnelMiddleware routes a request by Host: anything under the tunnel domain is
// a device request and is handled here; everything else is the console and
// continues down the normal chain untouched.
func (h *AccessHandler) tunnelMiddleware() gin.HandlerFunc {
	suffix := "." + h.tunnelDomain
	return func(c *gin.Context) {
		host := c.Request.Host
		// Host may carry a port (and, for IPv6, brackets). Only the name matters.
		if i := strings.LastIndexByte(host, ':'); i >= 0 && !strings.HasSuffix(host, "]") {
			host = host[:i]
		}
		host = strings.ToLower(strings.TrimSuffix(host, "."))
		if !strings.HasSuffix(host, suffix) {
			c.Next()
			return
		}
		h.handleTunnel(c, strings.TrimSuffix(host, suffix))
		c.Abort()
	}
}

// handleTunnel serves one request on a tunnel host. label is the leftmost part of
// the hostname, which must be the session id.
func (h *AccessHandler) handleTunnel(c *gin.Context, label string) {
	sid, err := uuid.Parse(label)
	if err != nil {
		problem(c, http.StatusBadRequest, "Bad Request", "invalid session id")
		return
	}
	if c.Request.URL.Path == "/__grant__" {
		h.tunnelGrant(c, sid)
		return
	}
	token, err := c.Cookie(tunnelCookieName(sid.String()))
	if err != nil || token == "" {
		problem(c, http.StatusUnauthorized, "Unauthorized", "no tunnel session")
		return
	}
	if !h.tunnel.ServeTunnel(c.Writer, c.Request, sid, token) {
		problem(c, http.StatusGone, "Session Closed", "the access session is no longer active")
	}
}

// tunnelGrant redeems a one-time grant for the session cookie, then redirects to
// the device root.
//
// The redirect is what keeps the token out of the device's reach: the browser
// lands on "/" with no query string, so the device never sees a URL carrying the
// grant, and Referrer-Policy: no-referrer stops it leaking through the referer of
// the subresource loads that follow.
func (h *AccessHandler) tunnelGrant(c *gin.Context, sid uuid.UUID) {
	if !h.verifyGrant(sid, c.Query("t")) {
		problem(c, http.StatusUnauthorized, "Unauthorized", "invalid or expired grant")
		return
	}
	token, ok := h.tunnel.TunnelCookieToken(sid)
	if !ok {
		problem(c, http.StatusGone, "Session Closed", "the access session is no longer active")
		return
	}
	c.SetSameSite(http.SameSiteLaxMode)
	// Domain "" => a host-only cookie, scoped to exactly <sid>.<tunnel-domain>.
	// This is load-bearing isolation, not a detail: with a Domain attribute the
	// cookie would be sent to every other session's subdomain too, and two
	// concurrent sessions would share a credential.
	c.SetCookie(tunnelCookieName(sid.String()), token, tunnelCookieMaxAge, "/", "", h.secure, true)
	c.Header("Referrer-Policy", "no-referrer")
	c.Redirect(http.StatusFound, "/")
}

// tunnelURL is the authenticated console endpoint that mints a fresh grant for a
// session the caller may already have open: GET /sessions/:id/tunnel.
//
// It exists because a grant is single-purpose and expires in seconds, so the one
// minted at connect time cannot be reused to reopen a closed tab. It also means
// the console can open the tunnel from a real user click (a button), rather than
// from an async callback where the browser's popup blocker would eat the
// window.open.
func (h *AccessHandler) tunnelURL(c *gin.Context) {
	if !h.TunnelEnabled() {
		problem(c, http.StatusNotFound, "Not Found", "whole-host tunnel delivery is not enabled")
		return
	}
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid session id")
		return
	}
	// Org-scoped read first: this is what stops one tenant minting a grant for
	// another tenant's session id.
	sess, err := h.svc.Get(c.Request.Context(), actor, id)
	if err != nil {
		failAccess(c, err)
		return
	}
	if sess.Status != domaccess.StatusActive {
		problem(c, http.StatusGone, "Session Closed", "the access session is no longer active")
		return
	}
	// Only a session the HTTP gateway is actually holding has a tunnel; a desktop
	// or terminal session reports false here.
	if _, ok := h.tunnel.TunnelCookieToken(id); !ok {
		problem(c, http.StatusNotFound, "Not Found", "this session is not delivered over a tunnel")
		return
	}
	c.JSON(http.StatusOK, gin.H{"tunnel_url": h.tunnelURLFor(id)})
}

// tunnelURLFor builds the one-time grant URL for a session.
func (h *AccessHandler) tunnelURLFor(sid uuid.UUID) string {
	grant := h.mintGrant(sid, time.Now().Add(tunnelGrantTTL))
	return "https://" + sid.String() + "." + h.tunnelDomain + "/__grant__?t=" + url.QueryEscape(grant)
}

// mintGrant issues a stateless one-time grant: the session id and an expiry,
// authenticated with an HMAC the server alone can produce.
//
// Stateless is deliberate. The alternative (a redis key claimed on redemption)
// buys strict single-use, but the token is delivered over TLS to the operator's
// own browser, expires in seconds, and grants only the session that operator just
// opened — so the store would add a failure mode and a dependency for very little.
func (h *AccessHandler) mintGrant(sid uuid.UUID, exp time.Time) string {
	msg := sid.String() + "|" + strconv.FormatInt(exp.Unix(), 10)
	mac := hmac.New(sha256.New, h.grantKey)
	mac.Write([]byte(msg))
	return base64.RawURLEncoding.EncodeToString([]byte(msg)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyGrant checks a grant's signature, its binding to this session, and its
// expiry — in that order, so an unauthenticated value is never parsed for meaning.
func (h *AccessHandler) verifyGrant(sid uuid.UUID, tok string) bool {
	if len(h.grantKey) == 0 || tok == "" {
		return false
	}
	b64msg, b64mac, ok := strings.Cut(tok, ".")
	if !ok {
		return false
	}
	msg, err1 := base64.RawURLEncoding.DecodeString(b64msg)
	want, err2 := base64.RawURLEncoding.DecodeString(b64mac)
	if err1 != nil || err2 != nil {
		return false
	}
	mac := hmac.New(sha256.New, h.grantKey)
	mac.Write(msg)
	if !hmac.Equal(mac.Sum(nil), want) {
		return false
	}
	gotSID, expStr, ok := strings.Cut(string(msg), "|")
	if !ok || gotSID != sid.String() {
		return false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	return err == nil && time.Now().Unix() <= exp
}
