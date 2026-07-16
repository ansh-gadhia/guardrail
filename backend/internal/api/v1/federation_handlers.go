package v1

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const oidcTxnCookie = "guardrail_oidc_txn"

// authProviders advertises which login methods are enabled so the SPA can render
// the right buttons.
func (h *Handler) authProviders(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"local": true,
		"ldap":  h.svc.LDAPEnabled(),
		"oidc":  h.svc.OIDCEnabled(),
	})
}

type ldapLoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

// ldapLogin authenticates against the directory and issues tokens (JIT-
// provisioning the user on first sign-in).
func (h *Handler) ldapLogin(c *gin.Context) {
	var req ldapLoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid ldap payload")
		return
	}
	pair, err := h.svc.LoginWithLDAP(c.Request.Context(), req.Username, req.Password, metaFrom(c))
	if err != nil {
		fail(c, err)
		return
	}
	h.setRefreshCookie(c, pair.RefreshToken)
	c.JSON(http.StatusOK, tokenResponse{
		AccessToken: pair.AccessToken, TokenType: "Bearer",
		ExpiresAt: pair.AccessExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Principal: toPrincipalDTO(pair.Principal),
	})
}

// oidcStart begins the Authorization Code + PKCE flow: it stores the CSRF/PKCE
// material in a signed, HttpOnly cookie and redirects the browser to the IdP.
func (h *Handler) oidcStart(c *gin.Context) {
	if h.oidcSig == nil || !h.svc.OIDCEnabled() {
		problem(c, http.StatusNotFound, "Not Found", "OIDC is not configured")
		return
	}
	txn, err := h.svc.BeginOIDCLogin(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	// state | nonce | verifier, signed and set as a short-lived HttpOnly cookie.
	payload := strings.Join([]string{txn.State, txn.Nonce, txn.CodeVerifier}, "|")
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(oidcTxnCookie, h.oidcSig.Sign(payload), 300, "/api/v1/auth", h.cookie.Domain, h.cookie.Secure, true)
	c.Redirect(http.StatusFound, txn.AuthURL)
}

// oidcCallback handles the IdP redirect: it validates the signed transaction
// cookie and state, exchanges the code, and issues tokens.
func (h *Handler) oidcCallback(c *gin.Context) {
	if h.oidcSig == nil || !h.svc.OIDCEnabled() {
		problem(c, http.StatusNotFound, "Not Found", "OIDC is not configured")
		return
	}
	if e := c.Query("error"); e != "" {
		problem(c, http.StatusUnauthorized, "Login Failed", "identity provider returned an error")
		return
	}
	raw, err := c.Cookie(oidcTxnCookie)
	if err != nil {
		problem(c, http.StatusBadRequest, "Bad Request", "missing OIDC transaction")
		return
	}
	// Clear the transaction cookie regardless of outcome.
	c.SetCookie(oidcTxnCookie, "", -1, "/api/v1/auth", h.cookie.Domain, h.cookie.Secure, true)

	payload, ok := h.oidcSig.Verify(raw)
	if !ok {
		problem(c, http.StatusBadRequest, "Bad Request", "invalid OIDC transaction")
		return
	}
	parts := strings.SplitN(payload, "|", 3)
	if len(parts) != 3 || c.Query("state") != parts[0] {
		problem(c, http.StatusBadRequest, "Bad Request", "OIDC state mismatch")
		return
	}
	pair, err := h.svc.CompleteOIDCLogin(c.Request.Context(), c.Query("code"), parts[2], parts[1], metaFrom(c))
	if err != nil {
		fail(c, err)
		return
	}
	h.setRefreshCookie(c, pair.RefreshToken)
	c.JSON(http.StatusOK, tokenResponse{
		AccessToken: pair.AccessToken, TokenType: "Bearer",
		ExpiresAt: pair.AccessExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Principal: toPrincipalDTO(pair.Principal),
	})
}
