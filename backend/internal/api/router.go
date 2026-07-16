// Package api wires the HTTP delivery layer: middleware stack and versioned
// route groups. Feature handlers register themselves onto the /api/v1 group as
// milestones land, keeping this file free of business logic.
package api

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/api/health"
	"github.com/guardrail/guardrail/internal/api/middleware"
	v1 "github.com/guardrail/guardrail/internal/api/v1"
	"github.com/guardrail/guardrail/internal/config"
	"github.com/guardrail/guardrail/internal/platform/metrics"
)

// Deps are the collaborators the router needs. Adding a feature module means
// adding its service here and mounting its routes in New — nothing else changes.
type Deps struct {
	Config        *config.Config
	Logger        *zap.Logger
	Metrics       *metrics.Registry
	Health        *health.Handler
	IAM           *v1.Handler              // IAM routes (auth, users, orgs, roles)
	Assets        *v1.AssetsHandler        // device + asset-group routes (a device owns its credential)
	Access        *v1.AccessHandler        // connect/session routes + proxy endpoint
	Notify        *v1.NotifyHandler        // notification-channel routes
	Analytics     *v1.AnalyticsHandler     // dashboard, search, audit, reports
	Authenticator middleware.Authenticator // verifies access tokens
	Version       string                   // build version, surfaced at /api/v1/version
	WebDir        string                   // if set, serve the SPA/console from this dir
}

// New builds the fully-configured Gin engine for the public API listener.
func New(d Deps) (*gin.Engine, error) {
	if d.Config.IsProduction() {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	// Trust only the configured edge proxies for client-IP derivation.
	if err := r.SetTrustedProxies(d.Config.HTTP.TrustedProxies); err != nil {
		return nil, err
	}

	// Order matters: correlation first, then recovery, security headers,
	// metrics, and access logging.
	r.Use(middleware.RequestID())
	r.Use(middleware.Recovery(d.Logger))
	r.Use(middleware.SecurityHeaders())
	r.Use(d.Metrics.Middleware())
	r.Use(middleware.AccessLog(d.Logger))

	// Operational probes live at the root (not under /api/v1) so orchestrators
	// and load balancers reach them independently of API versioning.
	d.Health.Routes(r)

	// Versioned API surface.
	apiV1 := r.Group("/api/v1")
	apiV1.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "pong"})
	})
	apiV1.GET("/version", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"name": "GuardRail", "version": d.Version})
	})

	// Feature routes. The authentication middleware is built once from the
	// injected token verifier and shared by every protected module.
	if d.Authenticator != nil {
		authMW := middleware.Authenticate(d.Authenticator)
		if d.IAM != nil {
			d.IAM.Register(apiV1, authMW)
		}
		if d.Assets != nil {
			d.Assets.Register(apiV1, authMW)
		}
		if d.Access != nil {
			d.Access.Register(apiV1, authMW)
			// The proxy endpoint mounts on the root engine (browser-facing,
			// cookie-authenticated), outside /api/v1.
			d.Access.RegisterProxy(r)
		}
		if d.Notify != nil {
			d.Notify.Register(apiV1, authMW)
		}
		if d.Analytics != nil {
			d.Analytics.Register(apiV1, authMW)
		}
	}

	// Static web console: serve built SPA/console assets and fall back to
	// index.html for client-side routes. Operational and API paths are excluded
	// so they keep their own handlers / 404s.
	if d.WebDir != "" {
		serveWeb(r, d.WebDir)
	}

	return r, nil
}

// serveWeb registers a NoRoute handler that serves static files from dir, with a
// single-page-app fallback to index.html. API/ops/proxy paths keep their own
// handlers.
func serveWeb(r *gin.Engine, dir string) {
	index := filepath.Join(dir, "index.html")
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		for _, pre := range []string{"/api", "/proxy", "/healthz", "/readyz", "/metrics"} {
			if p == pre || strings.HasPrefix(p, pre+"/") {
				c.JSON(http.StatusNotFound, gin.H{"title": "Not Found", "status": http.StatusNotFound})
				return
			}
		}
		// Containment: a proxied device UI (e.g. a FortiGate SPA) may hard-navigate
		// to a root-absolute URL ("/", "/ng/...") via window.location, which the
		// client-side <base>/shim cannot intercept. Such a request escapes the
		// session prefix and would otherwise be served the GuardRail console. When
		// the Referer shows the request originated inside a /proxy/<sid>/ frame,
		// redirect it back into that session so the device UI stays contained.
		if sid := proxySIDFromReferer(c.GetHeader("Referer")); sid != "" {
			target := "/proxy/" + sid + p
			if q := c.Request.URL.RawQuery; q != "" {
				target += "?" + q
			}
			c.Redirect(http.StatusFound, target)
			return
		}
		if p != "/" {
			clean := filepath.Join(dir, filepath.Clean("/"+p))
			if rel, err := filepath.Rel(dir, clean); err == nil && !strings.HasPrefix(rel, "..") {
				if fi, err := os.Stat(clean); err == nil && !fi.IsDir() {
					c.File(clean)
					return
				}
			}
		}
		c.File(index)
	})
}

// proxySIDFromReferer extracts the session id from a Referer whose path is under
// /proxy/<sid>/, or "" if the Referer is absent or not a proxy URL.
func proxySIDFromReferer(referer string) string {
	if referer == "" {
		return ""
	}
	u, err := url.Parse(referer)
	if err != nil {
		return ""
	}
	const pfx = "/proxy/"
	if !strings.HasPrefix(u.Path, pfx) {
		return ""
	}
	rest := u.Path[len(pfx):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}
