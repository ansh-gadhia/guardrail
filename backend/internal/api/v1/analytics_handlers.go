package v1

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	"github.com/guardrail/guardrail/internal/app/analytics"
	"github.com/guardrail/guardrail/internal/domain/audit"
)

// AnalyticsHandler exposes the dashboard, global search, audit log, and report
// endpoints — the read-model surface for M8.
type AnalyticsHandler struct {
	svc *analytics.Service
	// verifier recomputes the audit hash chain. Optional: nil simply omits the
	// endpoint rather than mounting one that always fails.
	verifier audit.ChainVerifier
}

// NewAnalyticsHandler constructs an AnalyticsHandler.
func NewAnalyticsHandler(svc *analytics.Service, verifier audit.ChainVerifier) *AnalyticsHandler {
	return &AnalyticsHandler{svc: svc, verifier: verifier}
}

// Register mounts analytics routes.
func (h *AnalyticsHandler) Register(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	rg.GET("/dashboard/summary", authMW, h.dashboard)
	rg.GET("/search", authMW, h.search)
	rg.GET("/audit", authMW, middleware.RequirePermission("log:read"), h.audit)
	rg.POST("/reports", authMW, middleware.RequirePermission("report:read"), h.report)
	if h.verifier != nil {
		// Behind log:read, the same permission as reading the events: verifying
		// the chain reveals nothing the log itself does not.
		rg.POST("/audit/verify", authMW, middleware.RequirePermission("log:read"), h.verifyChain)
	}
}

// verifyChain recomputes the caller's organization chain and reports the first
// event that does not follow the one before it, or whose contents no longer
// match its own hash.
//
// A POST rather than a GET: it is a full table walk, and making it trivially
// cacheable or prefetchable would invite exactly that.
func (h *AnalyticsHandler) verifyChain(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)

	// Events that belong to no tenant — a refresh-token failure with no
	// resolvable account behind it — form their own chain. Only a super admin can
	// read those rows, so only a super admin can ask for that chain.
	var org *uuid.UUID
	if !actor.IsSuperAdmin || c.Query("scope") != "system" {
		id := actor.OrganizationID
		org = &id
	}

	rep, err := h.verifier.VerifyChain(c.Request.Context(), org, queryLimit(c))
	if err != nil {
		fail(c, err)
		return
	}
	out := gin.H{
		"ok": rep.OK, "checked": rep.Checked,
		"truncated": rep.Truncated, "unverifiable": rep.Unverifiable,
	}
	if rep.Checked > 0 {
		out["from"] = rfc3339UTC(rep.From)
		out["to"] = rfc3339UTC(rep.To)
	}
	if !rep.OK {
		out["reason"] = rep.Reason
		// A chain can fail in ways that name no single row — no first event, or
		// several claiming to be it. Reaching through the nil pointer to render a
		// row that does not exist would turn a report about a damaged log into a
		// 500 with no report at all.
		if rep.BrokenAt != nil {
			out["broken_at"] = rep.BrokenAt.String()
		}
		if rep.BrokenAtTS != nil && !rep.BrokenAtTS.IsZero() {
			out["broken_at_ts"] = rfc3339UTC(*rep.BrokenAtTS)
		}
	}
	c.JSON(http.StatusOK, out)
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
			"target_type": r.TargetType, "target_id": r.TargetID, "target_label": r.TargetLabel,
			// Present only for events that happened inside a session. The console
			// turns it into a link to that session's recording and timeline.
			"session_id": r.SessionID,
			"ip":         r.IP,
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
