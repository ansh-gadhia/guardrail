package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// ssoExchangeRequest is the whole request body: one token.
//
// It arrives in a POST body rather than as a query parameter for the same reason
// the console reads it out of the URL fragment — see the callback page. A live
// credential in a URL is written verbatim into the reverse proxy's access log,
// kept in browser history, and attached to the Referer of whatever the page
// loads next.
type ssoExchangeRequest struct {
	Token string `json:"token" binding:"required"`
}

// ssoExchange trades a SIEM exchange token for a GuardRail session.
//
// Public — no Authorization header. That is the point of it: the caller has no
// GuardRail credential yet, and the token in the body is the entire claim. Every
// defence therefore lives in the verification chain behind it (see
// app/iam.LoginWithSIEM), not in a middleware in front of it.
func (h *Handler) ssoExchange(c *gin.Context) {
	var req ssoExchangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "expected a JSON body of the form {\"token\": \"<exchange token>\"}")
		return
	}
	pair, err := h.svc.LoginWithSIEM(c.Request.Context(), req.Token, metaFrom(c))
	if err != nil {
		fail(c, err)
		return
	}
	// A SIEM-vouched sign-in still meets this account's own second factor. The
	// response is byte-identical to the one a password login produces, so the
	// console's existing MFA screen handles it with no special case.
	if pair.MFARequired {
		c.JSON(http.StatusOK, gin.H{"mfa_required": true, "mfa_token": pair.MFAToken})
		return
	}
	h.setRefreshCookie(c, pair.RefreshToken)
	// Not cacheable, and said out loud. The body carries a bearer token, and an
	// intermediary that held it would be handing one person's session to whoever
	// asked next.
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, tokenResponse{
		AccessToken: pair.AccessToken, TokenType: "Bearer",
		ExpiresAt: pair.AccessExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Principal: toPrincipalDTO(pair.Principal),
	})
}
