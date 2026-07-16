package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
)

// rfc3339UTC formats an instant as RFC3339 in UTC. All session timestamps cross
// the wire in UTC; the browser renders them in the viewer's local zone, so the
// API never has to know or care about timezones.
func rfc3339UTC(t time.Time) string { return t.UTC().Format(time.RFC3339) }

type loginSessionDTO struct {
	ID         string `json:"id"` // family id
	UserID     string `json:"user_id"`
	Email      string `json:"email"`
	IP         string `json:"ip"`
	UserAgent  string `json:"user_agent"`
	SignedInAt string `json:"signed_in_at"`
	LastSeenAt string `json:"last_seen_at"`
	ExpiresAt  string `json:"expires_at"`
	Current    bool   `json:"current"`
	Self       bool   `json:"self"`
}

// listSessions returns the live login sessions the caller may see. An operator
// with user:read sees everyone (their tenant); anyone else, or ?scope=self, sees
// only their own. The refresh cookie is read here purely to flag which row is the
// caller's current session — the request itself is authenticated by the bearer
// token via authMW.
func (h *Handler) listSessions(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	currentRefresh, _ := c.Cookie(refreshCookieName)
	selfOnly := c.Query("scope") == "self"

	views, err := h.svc.ListSessions(c.Request.Context(), actor, currentRefresh, selfOnly)
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]loginSessionDTO, 0, len(views))
	for _, v := range views {
		out = append(out, loginSessionDTO{
			ID: v.ID.String(), UserID: v.UserID.String(), Email: v.Email, IP: v.IP,
			UserAgent: v.UserAgent, SignedInAt: rfc3339UTC(v.SignedInAt),
			LastSeenAt: rfc3339UTC(v.LastSeenAt), ExpiresAt: rfc3339UTC(v.ExpiresAt),
			Current: v.Current, Self: v.Self,
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// revokeSession force-signs-out a login session by family id.
func (h *Handler) revokeSession(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	familyID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid session id")
		return
	}
	if err := h.svc.RevokeSession(c.Request.Context(), actor, familyID, metaFrom(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
