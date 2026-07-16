package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

const ctxClaims = "iam_claims"

// Authenticator verifies access tokens.
type Authenticator interface {
	Verify(token string) (iam.Claims, error)
}

// Authenticate extracts and validates the Bearer access token, storing the
// resulting claims in the request context. Unauthenticated requests are
// rejected with 401.
func Authenticate(a Authenticator) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		token, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || strings.TrimSpace(token) == "" {
			abortProblem(c, http.StatusUnauthorized, "Unauthorized", "missing bearer token")
			return
		}
		claims, err := a.Verify(strings.TrimSpace(token))
		if err != nil {
			abortProblem(c, http.StatusUnauthorized, "Unauthorized", "invalid or expired token")
			return
		}
		c.Set(ctxClaims, claims)
		c.Next()
	}
}

// ClaimsFrom returns the authenticated principal's claims from the context.
func ClaimsFrom(c *gin.Context) (iam.Claims, bool) {
	v, ok := c.Get(ctxClaims)
	if !ok {
		return iam.Claims{}, false
	}
	claims, ok := v.(iam.Claims)
	return claims, ok
}

// abortProblem writes a minimal RFC 9457 problem response and aborts.
func abortProblem(c *gin.Context, status int, title, detail string) {
	c.Header("Content-Type", "application/problem+json")
	c.AbortWithStatusJSON(status, gin.H{
		"type": "about:blank", "title": title, "status": status, "detail": detail,
	})
}
