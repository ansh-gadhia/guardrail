package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// RequirePermission enforces that the authenticated principal holds the given
// permission (super admin implicitly holds all). Deny-by-default: it must run
// after Authenticate, and a missing/insufficient principal yields 403.
func RequirePermission(permission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ClaimsFrom(c)
		if !ok {
			abortProblem(c, http.StatusUnauthorized, "Unauthorized", "authentication required")
			return
		}
		if !claims.Has(permission) {
			abortProblem(c, http.StatusForbidden, "Forbidden",
				"missing required permission: "+permission)
			return
		}
		c.Next()
	}
}

// RequireSuperAdmin restricts a route to super administrators.
func RequireSuperAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, ok := ClaimsFrom(c)
		if !ok || !claims.IsSuperAdmin {
			abortProblem(c, http.StatusForbidden, "Forbidden", "super admin required")
			return
		}
		c.Next()
	}
}
