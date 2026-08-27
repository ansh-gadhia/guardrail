package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

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
func Authenticate(a Authenticator, tokens APITokenVerifier, guard SourceGuard, ssoBypass bool) gin.HandlerFunc {
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
		if !enforceSource(c, guard, claims, ssoBypass) {
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

// SourceGuard decides whether an authenticated principal may act from the
// address their request arrived from, and records the refusal when they may not.
//
// It is consulted inside Authenticate rather than as a middleware of its own
// because the decision needs the claims, and claims only exist once the
// credential has been verified. A separate handler would either have to re-parse
// the token or run after the route it is meant to guard.
type SourceGuard interface {
	CheckNetworkSource(ctx context.Context, orgID uuid.UUID, isSuperAdmin bool, ip string) (bool, string)
	AuditNetworkRefusal(ctx context.Context, actor iam.Claims, reason, path, ip, userAgent string)
}

// enforceSource applies the organization's network policy to a verified caller.
// Reports whether the request may continue.
//
// ssoBypass exempts a session the SIEM vouched for. It is OFF by default, which
// is the opposite of the obvious choice and deliberate: on a broker whose job is
// standing between people and privileged devices, an address allowlist is doing
// real work, and a bypass that defaulted on would quietly delete an
// administrator's control the day SSO was switched on.
//
// It exists at all because the failure it prevents is a bad one. With the
// allowlist in force and no bypass, an off-network analyst exchanges their token
// successfully, lands on the console, and is then refused on every single API
// call — a working sign-in attached to a dead console, which reads as the
// product being broken rather than as the network policy doing its job.
// Exempting only the exchange endpoint would fix the first request and nothing
// after it, which is why the marker rides the whole session and its refresh
// token (see iam.AuthSession.SSO).
func enforceSource(c *gin.Context, guard SourceGuard, claims iam.Claims, ssoBypass bool) bool {
	if guard == nil {
		return true
	}
	if ssoBypass && claims.SSO {
		return true
	}
	ip := c.ClientIP()
	ok, reason := guard.CheckNetworkSource(c.Request.Context(), claims.OrganizationID, claims.IsSuperAdmin, ip)
	if ok {
		return true
	}
	guard.AuditNetworkRefusal(c.Request.Context(), claims, reason, c.Request.URL.Path, ip, c.Request.UserAgent())
	// 403, not 401. The credential is valid and re-authenticating will not help;
	// telling the console otherwise would send it round a refresh loop.
	abortProblem(c, http.StatusForbidden, "Forbidden",
		"your organization's network policy does not permit access from this address")
	return false
}
