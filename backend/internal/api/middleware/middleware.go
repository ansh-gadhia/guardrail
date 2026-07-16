// Package middleware holds cross-cutting HTTP middleware: request correlation,
// security headers, structured access logging, and panic recovery. Authn/authz
// middleware are added in the IAM milestone (M2).
package middleware

import (
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// RequestIDHeader is the header carrying the correlation id in and out.
const RequestIDHeader = "X-Request-ID"

// ctxRequestID is the gin context key for the request id.
const ctxRequestID = "request_id"

// RequestID ensures every request has a correlation id, echoing an inbound one
// when present (and valid) or generating a UUIDv4 otherwise.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(RequestIDHeader)
		if _, err := uuid.Parse(id); err != nil {
			id = uuid.NewString()
		}
		c.Set(ctxRequestID, id)
		c.Header(RequestIDHeader, id)
		c.Next()
	}
}

// RequestIDFrom returns the request id stored in the context, if any.
func RequestIDFrom(c *gin.Context) string {
	if v, ok := c.Get(ctxRequestID); ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// spaCSP allows the served web console (HTML + hashed assets) to run while still
// confining it to same-origin resources. 'unsafe-inline' is permitted for styles
// only (React/Tailwind inject style tags); scripts stay 'self'-only.
const spaCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; font-src 'self' data:; connect-src 'self'; " +
	"base-uri 'self'; form-action 'self'; frame-ancestors 'none'"

// apiCSP is the strict policy for JSON API and operational endpoints, which never
// load any resource.
const apiCSP = "default-src 'none'; frame-ancestors 'none'"

// SecurityHeaders sets conservative, secure-by-default response headers. The CSP
// is chosen per route class: strict for the JSON API, a same-origin policy for
// the served SPA, and no GuardRail-imposed CSP/framing rules for the device proxy
// (whose upstream UI ships and governs its own content).
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		// HSTS only over a genuinely secure transport. Sending it over plain HTTP
		// is spec-invalid and can push browsers to force-upgrade to https:// on a
		// host that has no TLS listener, yielding "connection refused".
		if c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https") {
			h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		}

		p := c.Request.URL.Path
		switch {
		case p == "/proxy" || strings.HasPrefix(p, "/proxy/"):
			// Brokered device UI: let the upstream's own security headers stand.
			// Imposing default-src 'none' or X-Frame-Options here would break the
			// device's scripts, styles, and internal frames.
			//
			// The referrer must survive on this route class, and only this one.
			// A device UI hard-navigates to root-absolute URLs via window.location
			// (a FortiGate's login page does exactly this: "location.href =
			// '/logout?redir=...'"). location.href assignment cannot be intercepted
			// client-side — Location is unforgeable — so the router's NoRoute
			// containment catches the escape server-side and redirects it back into
			// /proxy/<sid>/. It identifies the session from the Referer, and under
			// "no-referrer" the browser sends none: the containment silently never
			// fired, and the device UI was served the GuardRail console instead.
			//
			// "same-origin" restores it without weakening the guarantee that
			// matters: the referrer still never crosses an origin boundary. The
			// device does not receive it either — the proxy director rewrites
			// Referer/Origin to the device's own origin before forwarding.
			h.Set("Referrer-Policy", "same-origin")
		case isAPIPath(p):
			h.Set("X-Frame-Options", "DENY")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Cross-Origin-Resource-Policy", "same-origin")
			h.Set("Content-Security-Policy", apiCSP)
		default:
			// Served web console.
			h.Set("X-Frame-Options", "DENY")
			h.Set("Cross-Origin-Opener-Policy", "same-origin")
			h.Set("Content-Security-Policy", spaCSP)
		}
		c.Next()
	}
}

// isAPIPath reports whether p is served by the JSON API or an operational probe
// (as opposed to the SPA or the device proxy).
func isAPIPath(p string) bool {
	for _, pre := range []string{"/api", "/healthz", "/readyz", "/metrics"} {
		if p == pre || strings.HasPrefix(p, pre+"/") {
			return true
		}
	}
	return false
}

// AccessLog emits one structured JSON line per request with correlation id,
// latency, status and client metadata. It never logs request bodies.
func AccessLog(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		fields := []zap.Field{
			zap.String("request_id", RequestIDFrom(c)),
			zap.String("method", c.Request.Method),
			zap.String("path", c.Request.URL.Path),
			zap.Int("status", c.Writer.Status()),
			zap.Duration("latency", time.Since(start)),
			zap.String("client_ip", c.ClientIP()),
			zap.String("user_agent", c.Request.UserAgent()),
		}
		if len(c.Errors) > 0 {
			fields = append(fields, zap.String("errors", c.Errors.String()))
		}
		log.Info("http_request", fields...)
	}
}

// Recovery converts panics into a 500 problem response and logs them with the
// correlation id, keeping the process alive.
func Recovery(log *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if r := recover(); r != nil {
				log.Error("panic_recovered",
					zap.String("request_id", RequestIDFrom(c)),
					zap.Any("panic", r),
					zap.String("path", c.Request.URL.Path),
				)
				c.AbortWithStatusJSON(500, gin.H{
					"type":   "about:blank",
					"title":  "Internal Server Error",
					"status": 500,
				})
			}
		}()
		c.Next()
	}
}
