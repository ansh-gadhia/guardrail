// Package health implements liveness and readiness probes. Liveness reports the
// process is up; readiness verifies critical backing services (Twelve-Factor
// attached resources) so orchestrators only route traffic when the app can serve.
package health

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Checker is a named dependency whose health can be probed. Any backing service
// (Postgres, Redis, object store) implements this via a small adapter.
type Checker interface {
	Health(ctx context.Context) error
}

// namedChecker binds a human-readable name to a Checker.
type namedChecker struct {
	name    string
	checker Checker
}

// Handler serves the probe endpoints.
type Handler struct {
	version  string
	checkers []namedChecker
	timeout  time.Duration
}

// New builds a health handler with a per-check timeout.
func New(version string) *Handler {
	return &Handler{version: version, timeout: 3 * time.Second}
}

// Register adds a named dependency to the readiness set.
func (h *Handler) Register(name string, c Checker) *Handler {
	h.checkers = append(h.checkers, namedChecker{name: name, checker: c})
	return h
}

// Routes mounts the probe endpoints on the given router group.
func (h *Handler) Routes(r gin.IRoutes) {
	r.GET("/healthz", h.live)
	r.GET("/readyz", h.ready)
}

// live is the liveness probe: always 200 while the process runs.
func (h *Handler) live(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": h.version})
}

// ready is the readiness probe: 200 only if every dependency is healthy,
// otherwise 503 with a per-dependency breakdown.
func (h *Handler) ready(c *gin.Context) {
	results := make(map[string]string, len(h.checkers))
	healthy := true

	for _, nc := range h.checkers {
		ctx, cancel := context.WithTimeout(c.Request.Context(), h.timeout)
		err := nc.checker.Health(ctx)
		cancel()
		if err != nil {
			healthy = false
			results[nc.name] = "error: " + err.Error()
			continue
		}
		results[nc.name] = "ok"
	}

	status := http.StatusOK
	overall := "ok"
	if !healthy {
		status = http.StatusServiceUnavailable
		overall = "unavailable"
	}
	c.JSON(status, gin.H{"status": overall, "version": h.version, "checks": results})
}
