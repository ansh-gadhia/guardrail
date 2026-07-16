package v1

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/guardrail/guardrail/internal/api/middleware"
	"github.com/guardrail/guardrail/internal/app/analytics"
)

// AnalyticsHandler exposes the dashboard, global search, audit log, and report
// endpoints — the read-model surface for M8.
type AnalyticsHandler struct{ svc *analytics.Service }

// NewAnalyticsHandler constructs an AnalyticsHandler.
func NewAnalyticsHandler(svc *analytics.Service) *AnalyticsHandler {
	return &AnalyticsHandler{svc: svc}
}

// Register mounts analytics routes.
func (h *AnalyticsHandler) Register(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	rg.GET("/dashboard/summary", authMW, h.dashboard)
	rg.GET("/search", authMW, h.search)
	rg.GET("/audit", authMW, middleware.RequirePermission("log:read"), h.audit)
	rg.POST("/reports", authMW, middleware.RequirePermission("report:read"), h.report)
}

func (h *AnalyticsHandler) dashboard(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	sum, err := h.svc.Dashboard(c.Request.Context(), actor)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, sum)
}

func (h *AnalyticsHandler) search(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	q := c.Query("q")
	if len(q) < 2 {
		badRequest(c, "query must be at least 2 characters")
		return
	}
	res, err := h.svc.Search(c.Request.Context(), actor, q, searchLimit(c))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, res)
}

func (h *AnalyticsHandler) audit(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	f := analytics.AuditFilter{
		Action:     c.Query("action"),
		Actor:      c.Query("actor"),
		Result:     c.Query("result"),
		TargetType: c.Query("target_type"),
		TargetID:   c.Query("target_id"),
		Limit:      queryLimit(c),
	}
	if from := parseTime(c.Query("from")); from != nil {
		f.From = from
	}
	if to := parseTime(c.Query("to")); to != nil {
		f.To = to
	}
	rows, err := h.svc.ListAudit(c.Request.Context(), actor, f)
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(rows))
	for _, r := range rows {
		out = append(out, gin.H{
			"ts": r.Timestamp, "actor": r.ActorEmail, "action": r.Action, "category": r.Category,
			"target_type": r.TargetType, "target_id": r.TargetID, "ip": r.IP,
			"user_agent": r.UserAgent, "result": r.Result, "detail": r.Detail,
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

type reportRequest struct {
	Type   string `json:"type" binding:"required"`
	Format string `json:"format"`
	From   string `json:"from"`
	To     string `json:"to"`
}

func (h *AnalyticsHandler) report(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req reportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid report payload")
		return
	}
	if req.Format != "" && req.Format != "csv" {
		badRequest(c, "only csv format is supported")
		return
	}
	data, filename, err := h.svc.GenerateCSV(c.Request.Context(), actor,
		analytics.ReportType(req.Type), parseTime(req.From), parseTime(req.To))
	if err != nil {
		badRequest(c, err.Error())
		return
	}
	c.Header("Content-Disposition", "attachment; filename=\""+filename+"\"")
	c.Data(http.StatusOK, "text/csv; charset=utf-8", data)
}

// parseTime accepts RFC3339 or date-only; returns nil on empty/invalid input.
func parseTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return &t
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return &t
	}
	return nil
}

// searchLimit reads ?limit with a sensible default and cap for search results.
func searchLimit(c *gin.Context) int {
	v := c.Query("limit")
	if v == "" {
		return 10
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 10
	}
	if n > 50 {
		return 50
	}
	return n
}
