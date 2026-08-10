package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	domiam "github.com/guardrail/guardrail/internal/domain/iam"
)

// RegisterAPITokens mounts machine-token management.
//
// Every route here is super-admin only, enforced in the service rather than by a
// permission key: the catalogue has no key for "may issue a credential that
// bypasses login", and adding one would silently widen whichever roles already
// held something similar.
func (h *Handler) RegisterAPITokens(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	t := rg.Group("/api-tokens", authMW)
	{
		t.GET("", h.listAPITokens)
		t.POST("", h.createAPIToken)
		t.DELETE("/:id", h.revokeAPIToken)
	}
}

type createAPITokenRequest struct {
	Name   string   `json:"name" binding:"required"`
	Scopes []string `json:"scopes" binding:"required"`
	// ExpiresAt is optional; omitting it means the token does not expire. That is
	// the common case for a monitoring integration, and it is why revocation
	// exists.
	ExpiresAt string `json:"expires_at"`
}

func (h *Handler) createAPIToken(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req createAPITokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid token payload")
		return
	}
	var expires *time.Time
	if req.ExpiresAt != "" {
		ts, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			badRequest(c, "expires_at must be RFC3339, e.g. 2027-01-01T00:00:00Z")
			return
		}
		expires = &ts
	}

	res, err := h.svc.CreateAPIToken(c.Request.Context(), actor, req.Name, req.Scopes, expires, metaFrom(c))
	if err != nil {
		fail(c, err)
		return
	}
	// The raw token appears here and nowhere else, ever. Said plainly in the
	// response because a client that assumes it can re-read it later will
	// discover otherwise at the worst possible moment.
	out := apiTokenDTO(&res.Token)
	out["token"] = res.Raw
	out["warning"] = "Copy this token now — it is not stored and cannot be shown again."
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusCreated, out)
}

func (h *Handler) listAPITokens(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	tokens, err := h.svc.ListAPITokens(c.Request.Context(), actor)
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(tokens))
	for i := range tokens {
		out = append(out, apiTokenDTO(&tokens[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (h *Handler) revokeAPIToken(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid token id")
		return
	}
	if err := h.svc.RevokeAPIToken(c.Request.Context(), actor, id, metaFrom(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// apiTokenDTO renders a token's metadata. The hash is never included: it is not
// reversible, but it is also of no use to anyone except the verifier, and
// shipping it would only invite someone to treat it as an identifier.
func apiTokenDTO(t *domiam.APIToken) gin.H {
	out := gin.H{
		"id":     t.ID.String(),
		"name":   t.Name,
		"prefix": t.Prefix,
		"scopes": t.Scopes,
		// A revoked token keeps its row so the audit trail can still answer what
		// this credential was and when it stopped working.
		"revoked":    t.RevokedAt != nil,
		"created_at": rfc3339UTC(t.CreatedAt),
	}
	if t.CreatedBy != nil {
		out["created_by"] = t.CreatedBy.String()
	}
	if t.ExpiresAt != nil {
		out["expires_at"] = rfc3339UTC(*t.ExpiresAt)
	}
	if t.LastUsedAt != nil {
		out["last_used_at"] = rfc3339UTC(*t.LastUsedAt)
	}
	if t.RevokedAt != nil {
		out["revoked_at"] = rfc3339UTC(*t.RevokedAt)
	}
	return out
}
