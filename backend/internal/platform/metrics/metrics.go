// Package metrics defines Prometheus collectors and the HTTP middleware that
// records RED metrics (Rate, Errors, Duration) for the API.
package metrics

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Registry is the process-wide collector registry. Using a dedicated registry
// (rather than the default global) keeps tests isolated and avoids duplicate
// registration panics.
type Registry struct {
	Prom           *prometheus.Registry
	reqTotal       *prometheus.CounterVec
	reqDuration    *prometheus.HistogramVec
	activeSessions prometheus.Gauge
}

// New creates a Registry with the standard Go/process collectors plus GuardRail
// application metrics.
func New() *Registry {
	r := prometheus.NewRegistry()
	factory := promauto.With(r)

	r.MustRegister(collectors.NewGoCollector())
	r.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	return &Registry{
		Prom: r,
		reqTotal: factory.NewCounterVec(prometheus.CounterOpts{
			Name: "guardrail_http_requests_total",
			Help: "Total HTTP requests by method, route and status.",
		}, []string{"method", "route", "status"}),
		reqDuration: factory.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "guardrail_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"method", "route"}),
		activeSessions: factory.NewGauge(prometheus.GaugeOpts{
			Name: "guardrail_active_sessions",
			Help: "Number of currently active brokered access sessions.",
		}),
	}
}

// SetActiveSessions updates the active-session gauge.
func (r *Registry) SetActiveSessions(n float64) { r.activeSessions.Set(n) }

// Middleware records request count and latency. It uses the matched route
// template (not the raw path) as a label to keep cardinality bounded.
func (r *Registry) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		r.reqDuration.WithLabelValues(c.Request.Method, route).
			Observe(time.Since(start).Seconds())
		r.reqTotal.WithLabelValues(c.Request.Method, route, strconv.Itoa(c.Writer.Status())).
			Inc()
	}
}
