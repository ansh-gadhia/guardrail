package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/guardrail/guardrail/internal/api/middleware"
	appiam "github.com/guardrail/guardrail/internal/app/iam"
)

type loginRequest struct {
	Email        string `json:"email" binding:"required,email"`
	Password     string `json:"password" binding:"required"`
	Organization string `json:"organization"`
}

type tokenResponse struct {
	AccessToken string       `json:"access_token"`
	TokenType   string       `json:"token_type"`
	ExpiresAt   string       `json:"expires_at"`
	Principal   principalDTO `json:"principal"`
}

type principalDTO struct {
	UserID             string   `json:"user_id"`
	OrganizationID     string   `json:"organization_id"`
	Email              string   `json:"email"`
	Username           string   `json:"username"`
	IsSuperAdmin       bool     `json:"is_super_admin"`
	Roles              []string `json:"roles"`
	Permissions        []string `json:"permissions"`
	MustChangePassword bool     `json:"must_change_password"`
}

func toPrincipalDTO(p appiam.Principal) principalDTO {
	return principalDTO{
		UserID:             p.UserID.String(),
		OrganizationID:     p.OrganizationID.String(),
		Email:              p.Email,
		Username:           p.Username,
		IsSuperAdmin:       p.IsSuperAdmin,
		Roles:              p.Roles,
		Permissions:        p.Permissions,
		MustChangePassword: p.MustChangePassword,
	}
}

// login authenticates and returns an access token (refresh token set as cookie).
func (h *Handler) login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid login payload")
		return
	}
	pair, err := h.svc.Login(c.Request.Context(), appiam.LoginInput{
		Email: req.Email, Password: req.Password, Organization: req.Organization, Meta: metaFrom(c),
	})
	if err != nil {
		fail(c, err)
		return
	}
	if pair.MFARequired {
		c.JSON(http.StatusOK, gin.H{
			"mfa_required": true,
			"mfa_token":    pair.MFAToken,
		})
		return
	}
	h.setRefreshCookie(c, pair.RefreshToken)
	c.JSON(http.StatusOK, tokenResponse{
		AccessToken: pair.AccessToken, TokenType: "Bearer",
		ExpiresAt: pair.AccessExpiresAt.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Principal: toPrincipalDTO(pair.Principal),
	})
}

type mfaVerifyRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code" binding:"required"`
}

// mfaVerify completes a login challenge with a TOTP or recovery code.
func (h *Handler) mfaVerify(c *gin.Context) {
	var req mfaVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid mfa payload")
		return
	}
	pair, err := h.svc.VerifyMFA(c.Request.Context(), appiam.MFAVerifyInput{
		MFAToken: req.MFAToken, Code: req.Code, Meta: metaFrom(c),
	})
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

// refresh rotates the refresh token and issues a fresh access token.
func (h *Handler) refresh(c *gin.Context) {
	raw, err := c.Cookie(refreshCookieName)
	if err != nil || raw == "" {
		problem(c, http.StatusUnauthorized, "Unauthorized", "missing refresh token")
		return
	}
	pair, err := h.svc.Refresh(c.Request.Context(), raw, metaFrom(c))
	if err != nil {
		h.clearRefreshCookie(c)
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

// logout revokes the presented refresh-token family.
func (h *Handler) logout(c *gin.Context) {
	if raw, err := c.Cookie(refreshCookieName); err == nil && raw != "" {
		_ = h.svc.Logout(c.Request.Context(), raw, metaFrom(c))
	}
	h.clearRefreshCookie(c)
	c.Status(http.StatusNoContent)
}

type changePasswordRequest struct {
	CurrentPassword string `json:"current_password" binding:"required"`
	NewPassword     string `json:"new_password" binding:"required"`
}

// changePassword lets the authenticated user rotate their own local password. On
// success it re-issues the session (new refresh cookie + access token) so the
// caller stays signed in while all other sessions are revoked.
func (h *Handler) changePassword(c *gin.Context) {
	claims, _ := middleware.ClaimsFrom(c)
	var req changePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid password payload")
		return
	}
	pair, err := h.svc.ChangePassword(c.Request.Context(), claims, req.CurrentPassword, req.NewPassword, metaFrom(c))
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

// me returns the authenticated principal.
func (h *Handler) me(c *gin.Context) {
	claims, _ := middleware.ClaimsFrom(c)
	p, err := h.svc.Me(c.Request.Context(), claims)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, toPrincipalDTO(*p))
}
