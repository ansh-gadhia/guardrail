package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/guardrail/guardrail/internal/api/middleware"
)

// mfaStatus returns the caller's current second-factor state.
func (h *Handler) mfaStatus(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	st, err := h.svc.MFAStatusFor(c.Request.Context(), actor)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"enabled":             st.Enabled,
		"confirmed":           st.Confirmed,
		"recovery_codes_left": st.RecoveryCodesLeft,
	})
}

// mfaEnroll begins TOTP enrollment, returning the secret + provisioning URI.
func (h *Handler) mfaEnroll(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	enr, err := h.svc.BeginTOTPEnrollment(c.Request.Context(), actor)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"secret":           enr.Secret,
		"provisioning_uri": enr.ProvisioningURI,
	})
}

type mfaConfirmRequest struct {
	Code     string `json:"code" binding:"required"`
	NextCode string `json:"next_code" binding:"required"`
}

// mfaConfirm verifies two consecutive codes, activates MFA, and returns recovery
// codes once. Requiring a back-to-back pair confirms the authenticator's clock is
// in step before we start enforcing it at sign-in.
func (h *Handler) mfaConfirm(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req mfaConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "enter both codes from your authenticator, one after the other")
		return
	}
	codes, err := h.svc.ConfirmTOTPEnrollment(c.Request.Context(), actor, req.Code, req.NextCode)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"recovery_codes": codes})
}

type mfaDisableRequest struct {
	Code string `json:"code" binding:"required"`
}

// mfaDisable removes the caller's second factor after verifying a current code,
// so disabling MFA is itself protected by the second factor.
func (h *Handler) mfaDisable(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req mfaDisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "enter a code from your authenticator to turn two-factor off")
		return
	}
	if err := h.svc.DisableMFA(c.Request.Context(), actor, req.Code); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// mfaRegenerateRecovery issues a fresh set of recovery codes.
func (h *Handler) mfaRegenerateRecovery(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	codes, err := h.svc.RegenerateRecoveryCodes(c.Request.Context(), actor)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"recovery_codes": codes})
}
