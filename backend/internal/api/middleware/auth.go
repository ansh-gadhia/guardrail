package middleware

import (
	"context"
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

// APITokenVerifier resolves a long-lived machine token to a principal. Optional:
// when nil, only JWTs are accepted and API tokens are simply not a thing this
// deployment has.
type APITokenVerifier interface {
	VerifyAPIToken(ctx context.Context, raw string) (iam.Claims, error)
}

// Authenticate extracts and validates the Bearer credential, storing the
// resulting claims in the request context. Unauthenticated requests are
// rejected with 401.
//
// Two credentials are accepted on the same header, told apart by prefix rather
// than by trying one and falling back to the other. Fallback would make an
// expired session token and a malformed API token produce the same log line, and
// would run every machine token through a JWT parse first for no reason.
func Authenticate(a Authenticator, tokens APITokenVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.GetHeader("Authorization")
		token, ok := strings.CutPrefix(h, "Bearer ")
		token = strings.TrimSpace(token)
		if !ok || token == "" {
			abortProblem(c, http.StatusUnauthorized, "Unauthorized", "missing bearer token")
			return
		}

		var claims iam.Claims
		var err error
		if iam.LooksLikeAPIToken(token) {
			if tokens == nil {
				abortProblem(c, http.StatusUnauthorized, "Unauthorized", "API tokens are not enabled")
				return
			}
			claims, err = tokens.VerifyAPIToken(c.Request.Context(), token)
		} else {
			claims, err = a.Verify(token)
		}
		if err != nil {
			// One message for both paths: which credential was wrong, and why, is
			// not something an unauthenticated caller gets to learn.
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
