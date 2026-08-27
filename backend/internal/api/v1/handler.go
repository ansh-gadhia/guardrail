package v1

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/guardrail/guardrail/internal/api/middleware"
	appiam "github.com/guardrail/guardrail/internal/app/iam"
)

// refreshCookieName is the name of the HttpOnly refresh-token cookie.
const refreshCookieName = "guardrail_refresh"

// CookieConfig controls refresh-cookie attributes.
type CookieConfig struct {
	Domain     string
	Secure     bool
	RefreshTTL time.Duration
}

// OIDCCookieSigner signs the short-lived OIDC transaction cookie.
type OIDCCookieSigner interface {
	Sign(value string) string
	Verify(signed string) (string, bool)
}

// Handler wires the IAM application service into HTTP routes.
type Handler struct {
	svc     *appiam.Service
	cookie  CookieConfig
	oidcSig OIDCCookieSigner
}

// NewHandler constructs the IAM HTTP handler.
func NewHandler(svc *appiam.Service, cookie CookieConfig, oidcSig OIDCCookieSigner) *Handler {
	return &Handler{svc: svc, cookie: cookie, oidcSig: oidcSig}
}

// Register mounts all IAM routes under the given group. Protected routes are
// wrapped with the provided authentication middleware and per-route permissions.
func (h *Handler) Register(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	auth := rg.Group("/auth")
	{
		auth.POST("/login", h.login)
		auth.POST("/mfa/verify", h.mfaVerify)
		auth.POST("/refresh", h.refresh)
		auth.POST("/logout", h.logout)
		auth.GET("/me", authMW, h.me)
		auth.POST("/change-password", authMW, h.changePassword)
		// Login-session visibility + force-logout. Mounted under /auth so the
		// refresh cookie (path-scoped to /api/v1/auth) reaches listSessions and can
		// flag the caller's current session. Cross-user scope is enforced in the
		// service by permission, not the route.
		auth.GET("/sessions", authMW, h.listSessions)
		auth.POST("/sessions/:id/revoke", authMW, h.revokeSession)
		// Federation (M3): capability probe, LDAP direct login, OIDC redirect flow.
		auth.GET("/providers", h.authProviders)
		auth.POST("/ldap/login", h.ldapLogin)
		auth.GET("/oidc/start", h.oidcStart)
		auth.GET("/oidc/callback", h.oidcCallback)
		// SIEM single sign-on: the console redirects here from the SIEM with a
		// short-lived signed assertion and trades it for a session. Public, like
		// /login — the caller has no GuardRail credential yet, and the token is
		// the entire claim.
		auth.POST("/sso/exchange", h.ssoExchange)
	}

	// Self-service MFA management (the acting user manages their own factor).
	mfa := rg.Group("/mfa", authMW)
	{
		mfa.GET("", h.mfaStatus)
		mfa.POST("/totp/enroll", h.mfaEnroll)
		mfa.POST("/totp/confirm", h.mfaConfirm)
		mfa.POST("/recovery-codes", h.mfaRegenerateRecovery)
		mfa.POST("/disable", h.mfaDisable)
	}

	users := rg.Group("/users", authMW)
	{
		users.GET("", middleware.RequirePermission("user:read"), h.listUsers)
		users.POST("", middleware.RequirePermission("user:write"), h.createUser)
		users.GET("/:id", middleware.RequirePermission("user:read"), h.getUser)
		users.DELETE("/:id", middleware.RequirePermission("user:write"), h.deleteUser)
		users.PUT("/:id/roles", middleware.RequirePermission("user:write"), h.assignRoles)
		// Sets a temporary password for somebody who has locked themselves out.
		// The service refuses the installation account and anybody who outranks
		// the caller, so user:write is the floor rather than the whole rule.
		users.POST("/:id/reset-password", middleware.RequirePermission("user:write"), h.resetPassword)
	}

	orgs := rg.Group("/organizations", authMW)
	{
		orgs.GET("", middleware.RequirePermission("org:read"), h.listOrgs)
		orgs.POST("", middleware.RequireSuperAdmin(), h.createOrg)
		orgs.GET("/:id", middleware.RequirePermission("org:read"), h.getOrg)
	}

	roles := rg.Group("", authMW)
	{
		roles.GET("/roles", middleware.RequirePermission("role:read"), h.listRoles)
		roles.GET("/permissions", middleware.RequirePermission("role:read"), h.listPermissions)
		roles.GET("/roles/:id/device-access", middleware.RequirePermission("role:read"), h.getRoleDeviceAccess)
		roles.PUT("/roles/:id/device-access", middleware.RequirePermission("role:write"), h.setRoleDeviceAccess)
		// Rank in the approval hierarchy. Writing it is a role:write act — it
		// decides who can sign off whose access.
		roles.PUT("/roles/:id/approval-level", middleware.RequirePermission("role:write"), h.setRoleApprovalLevel)
		// Who can approve whom, so the device form can refuse to gate a device
		// that nobody could ever be approved onto.
		roles.GET("/approval-coverage", middleware.RequirePermission("role:read"), h.approvalCoverage)
	}
}

// metaFrom extracts request metadata for auditing.
func metaFrom(c *gin.Context) appiam.ReqMeta {
	return appiam.ReqMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

// queryLimit parses an optional ?limit= query parameter.
func queryLimit(c *gin.Context) int {
	if v := c.Query("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return 0
}

// queryOffset reads ?offset for paging. A negative or unparsable value is 0
// rather than an error: a bad offset should show the first page, not a 400.
func queryOffset(c *gin.Context) int {
	if v := c.Query("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// setRefreshCookie writes the rotated refresh token as a hardened cookie scoped
// to the auth endpoints only.
func (h *Handler) setRefreshCookie(c *gin.Context, token string) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(refreshCookieName, token, int(h.cookie.RefreshTTL.Seconds()),
		"/api/v1/auth", h.cookie.Domain, h.cookie.Secure, true /* httpOnly */)
}

// clearRefreshCookie expires the refresh cookie.
func (h *Handler) clearRefreshCookie(c *gin.Context) {
	c.SetSameSite(http.SameSiteStrictMode)
	c.SetCookie(refreshCookieName, "", -1, "/api/v1/auth", h.cookie.Domain, h.cookie.Secure, true)
}
