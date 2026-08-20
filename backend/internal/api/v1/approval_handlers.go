package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	appaccess "github.com/guardrail/guardrail/internal/app/access"
	"github.com/guardrail/guardrail/internal/domain/access"
)

// RegisterApprovals mounts the access-request and standing-grant endpoints.
func (h *AccessHandler) RegisterApprovals(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	r := rg.Group("/access-requests", authMW)
	{
		// Deliberately not behind approval:read. A requester has to be able to
		// watch their own request, and the service narrows the listing to their
		// own rows for anybody without the permission.
		r.GET("", h.listRequests)
		r.GET("/:id", h.getRequest)
		r.POST("/:id/decide", middleware.RequirePermission("approval:decide"), h.decideRequest)
		r.POST("/:id/cancel", h.cancelRequest)
		r.POST("/:id/review", middleware.RequirePermission("approval:decide"), h.reviewRequest)
	}

	g := rg.Group("/access-grants", authMW)
	{
		g.GET("", middleware.RequirePermission("approval:read"), h.listGrants)
		g.DELETE("/:id", middleware.RequirePermission("approval:decide"), h.revokeGrant)
	}
}

// requestBody is the wire shape of an access request.
type requestBody struct {
	ID       string `json:"id"`
	UserID   string `json:"user_id"`
	DeviceID string `json:"device_id"`
	// Requester and Device are denormalized labels so a queue row needs no
	// second call to be readable.
	Requester        string  `json:"requester"`
	Device           string  `json:"device"`
	Status           string  `json:"status"`
	Reason           string  `json:"reason"`
	RequestedMinutes int     `json:"requested_minutes"`
	GrantedMinutes   *int    `json:"granted_minutes,omitempty"`
	GrantScope       *string `json:"grant_scope,omitempty"`
	Approvals        int     `json:"approvals"`
	MinApprovals     int     `json:"min_approvals"`
	RequesterLevel   int     `json:"requester_level"`
	IsEmergency      bool    `json:"is_emergency"`
	Reviewed         bool    `json:"reviewed"`
	ReviewNote       string  `json:"review_note,omitempty"`
	EscalatedLevel   *int    `json:"escalated_level,omitempty"`
	SessionID        *string `json:"session_id,omitempty"`
	// SessionActive says whether that session is still open. It is deliberately
	// not omitempty: a console needs to tell "ended" from "this server is too
	// old to know", and an absent field is the safer of the two to read as not
	// live.
	SessionActive bool           `json:"session_active"`
	ExpiresAt     string         `json:"expires_at"`
	CreatedAt     string         `json:"created_at"`
	Decisions     []decisionBody `json:"decisions"`
}

// decisionBody is one approver's vote as it goes over the wire.
type decisionBody struct {
	By        string `json:"by"`
	Decision  string `json:"decision"`
	Note      string `json:"note,omitempty"`
	DecidedAt string `json:"decided_at"`
}

func requestView(r *access.Request) requestBody {
	b := requestBody{
		// Non-nil so a request with no decisions yet serializes as [] rather than
		// null. Clients treat this as a list, and null is a crash — the same rule
		// User.Permissions already follows for the same reason.
		Decisions: []decisionBody{},
		ID:        r.ID.String(), UserID: r.UserID.String(), DeviceID: r.DeviceID.String(),
		Requester: r.RequesterEmail, Device: r.DeviceName,
		Status: string(r.Status), Reason: r.Reason,
		RequestedMinutes: r.RequestedMinutes, GrantedMinutes: r.GrantedMinutes,
		Approvals: r.Approvals(), MinApprovals: r.EffectiveMinApprovals(),
		RequesterLevel: r.RequesterLevel, IsEmergency: r.IsEmergency,
		Reviewed: r.ReviewedAt != nil, ReviewNote: r.ReviewNote,
		EscalatedLevel: r.EscalatedLevel,
		ExpiresAt:      isoTime(r.ExpiresAt), CreatedAt: isoTime(r.CreatedAt),
	}
	if r.GrantScope != nil {
		v := string(*r.GrantScope)
		b.GrantScope = &v
	}
	if r.SessionID != nil {
		v := r.SessionID.String()
		b.SessionID = &v
		b.SessionActive = r.SessionActive
	}
	for i := range r.Decisions {
		d := &r.Decisions[i]
		b.Decisions = append(b.Decisions, decisionBody{
			By: d.DecidedByEmail, Decision: d.Decision, Note: d.Note, DecidedAt: isoTime(d.DecidedAt),
		})
	}
	return b
}

func isoTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func (h *AccessHandler) listRequests(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	f := access.RequestFilter{Limit: queryLimit(c)}
	if c.Query("pending") == "true" {
		f.PendingOnly = true
	}
	if c.Query("unreviewed") == "true" {
		f.UnreviewedEmergency = true
	}
	if s := c.Query("status"); s != "" {
		f.Status = access.RequestStatus(s)
	}
	if v := c.Query("device_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.DeviceID = &id
		}
	}
	// Without this the console's "My requests" tab showed an administrator
	// everybody's requests: the service only narrows to the caller's own rows for
	// somebody who lacks approval:read, so a privileged user asking for their own
	// list got the whole tenant's.
	if v := c.Query("user_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.UserID = &id
		}
	}
	// Lets a session say how it was authorized. Scoping is unchanged: the service
	// still narrows to the caller's own requests without approval:read, so this
	// cannot be used to read somebody else's reason by guessing session ids.
	if v := c.Query("session_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.SessionID = &id
		}
	}
	list, err := h.svc.ListRequests(c.Request.Context(), actor, f)
	if err != nil {
		failAccess(c, err)
		return
	}
	out := make([]requestBody, 0, len(list))
	for i := range list {
		out = append(out, requestView(&list[i]))
	}
	c.JSON(http.StatusOK, gin.H{"requests": out})
}

func (h *AccessHandler) getRequest(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid request id")
		return
	}
	req, err := h.svc.GetRequest(c.Request.Context(), actor, id)
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, requestView(req))
}

type decideRequestBody struct {
	Decision string `json:"decision" binding:"required,oneof=approve deny"`
	// Scope is "once" or "always". Ignored on a denial.
	Scope string `json:"scope"`
	// Minutes may shorten the requested window, never lengthen it.
	Minutes int    `json:"minutes"`
	Note    string `json:"note"`
}

func (h *AccessHandler) decideRequest(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid request id")
		return
	}
	var body decideRequestBody
	if err := c.ShouldBindJSON(&body); err != nil {
		badRequest(c, "decision must be approve or deny")
		return
	}
	scope := access.GrantOnce
	if body.Scope == string(access.GrantAlways) {
		scope = access.GrantAlways
	}
	req, err := h.svc.Decide(c.Request.Context(), actor, id, appaccess.DecideInput{
		Approve: body.Decision == access.DecisionApprove,
		Scope:   scope, Minutes: body.Minutes, Note: body.Note,
		Meta: accessMeta(c),
	})
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, requestView(req))
}

func (h *AccessHandler) cancelRequest(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid request id")
		return
	}
	if err := h.svc.CancelRequest(c.Request.Context(), actor, id); err != nil {
		failAccess(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

type reviewBody struct {
	Note string `json:"note"`
}

func (h *AccessHandler) reviewRequest(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid request id")
		return
	}
	var body reviewBody
	_ = c.ShouldBindJSON(&body)
	if err := h.svc.ReviewEmergency(c.Request.Context(), actor, id, body.Note, accessMeta(c)); err != nil {
		failAccess(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

type grantBody struct {
	ID        string  `json:"id"`
	UserID    string  `json:"user_id"`
	User      string  `json:"user"`
	DeviceID  string  `json:"device_id"`
	Device    string  `json:"device"`
	GrantedBy string  `json:"granted_by,omitempty"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	RevokedAt *string `json:"revoked_at,omitempty"`
	Live      bool    `json:"live"`
	CreatedAt string  `json:"created_at"`
}

func (h *AccessHandler) listGrants(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	f := access.GrantFilter{Limit: queryLimit(c), LiveOnly: c.Query("live") == "true"}
	if v := c.Query("device_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.DeviceID = &id
		}
	}
	if v := c.Query("user_id"); v != "" {
		if id, err := uuid.Parse(v); err == nil {
			f.UserID = &id
		}
	}
	list, err := h.svc.ListGrants(c.Request.Context(), actor, f)
	if err != nil {
		failAccess(c, err)
		return
	}
	now := time.Now()
	out := make([]grantBody, 0, len(list))
	for i := range list {
		g := &list[i]
		b := grantBody{
			ID: g.ID.String(), UserID: g.UserID.String(), User: g.UserEmail,
			DeviceID: g.DeviceID.String(), Device: g.DeviceName,
			GrantedBy: g.GrantedByEmail, Live: g.Live(now), CreatedAt: isoTime(g.CreatedAt),
		}
		if g.ExpiresAt != nil {
			v := isoTime(*g.ExpiresAt)
			b.ExpiresAt = &v
		}
		if g.RevokedAt != nil {
			v := isoTime(*g.RevokedAt)
			b.RevokedAt = &v
		}
		out = append(out, b)
	}
	c.JSON(http.StatusOK, gin.H{"grants": out})
}

func (h *AccessHandler) revokeGrant(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid grant id")
		return
	}
	if err := h.svc.RevokeGrant(c.Request.Context(), actor, id, accessMeta(c)); err != nil {
		failAccess(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
