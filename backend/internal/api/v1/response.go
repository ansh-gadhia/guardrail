// Package v1 implements the versioned REST delivery layer (/api/v1). Handlers
// translate HTTP to application use-case calls and back, mapping domain errors
// to RFC 9457 problem responses. No business logic lives here.
package v1

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	appiam "github.com/guardrail/guardrail/internal/app/iam"
	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/assets"
	"github.com/guardrail/guardrail/internal/domain/iam"
	"github.com/guardrail/guardrail/internal/domain/vault"
)

// problem writes an RFC 9457 application/problem+json body.
func problem(c *gin.Context, status int, title, detail string) {
	c.Header("Content-Type", "application/problem+json")
	c.JSON(status, gin.H{"type": "about:blank", "title": title, "status": status, "detail": detail})
}

// fail maps a domain/application error to the appropriate HTTP problem response.
func fail(c *gin.Context, err error) {
	switch {
	case errors.Is(err, iam.ErrNotFound):
		problem(c, http.StatusNotFound, "Not Found", "resource not found")
	case errors.Is(err, iam.ErrInvalidInput):
		problem(c, http.StatusBadRequest, "Bad Request", "invalid input")
	case errors.Is(err, iam.ErrConflict):
		problem(c, http.StatusConflict, "Conflict", "resource already exists")
	case errors.Is(err, iam.ErrEmailAmbiguous):
		problem(c, http.StatusConflict, "Ambiguous", "email exists in multiple organizations; specify organization")
	case errors.Is(err, iam.ErrInvalidCredentials):
		problem(c, http.StatusUnauthorized, "Unauthorized", "invalid credentials")
	case errors.Is(err, iam.ErrAccountLocked):
		problem(c, http.StatusUnauthorized, "Account Locked", "too many failed attempts; try again later")
	case errors.Is(err, iam.ErrAccountInactive):
		problem(c, http.StatusUnauthorized, "Account Inactive", "account is not active")
	case errors.Is(err, iam.ErrRefreshReuse), errors.Is(err, iam.ErrRefreshInvalid):
		problem(c, http.StatusUnauthorized, "Session Expired", "please sign in again")
	case errors.Is(err, iam.ErrPermissionDenied):
		problem(c, http.StatusForbidden, "Forbidden", "permission denied")
	case errors.Is(err, iam.ErrPasswordPolicy):
		problem(c, http.StatusUnprocessableEntity, "Weak Password", "password does not meet policy (min 12 chars)")
	case errors.Is(err, iam.ErrPasswordReuse):
		problem(c, http.StatusUnprocessableEntity, "Password Reuse", "the new password must differ from the current one")
	case errors.Is(err, iam.ErrPasswordUnsupported):
		problem(c, http.StatusConflict, "Not Supported", "this account signs in via an external identity provider; change your password there")
	case errors.Is(err, iam.ErrMFAInvalidCode):
		problem(c, http.StatusUnauthorized, "Invalid Code", "the second-factor code is incorrect")
	case errors.Is(err, iam.ErrMFAChallengeInvalid):
		problem(c, http.StatusUnauthorized, "Challenge Expired", "restart sign-in and try again")
	case errors.Is(err, iam.ErrMFANotEnrolled):
		problem(c, http.StatusConflict, "Not Enrolled", "multi-factor authentication is not enrolled")
	case errors.Is(err, iam.ErrMFAAlreadyEnrolled):
		problem(c, http.StatusConflict, "Already Enrolled", "multi-factor authentication is already active")
	case errors.Is(err, appiam.ErrThrottled):
		c.Header("Retry-After", "60")
		problem(c, http.StatusTooManyRequests, "Too Many Requests", "rate limit exceeded")
	default:
		problem(c, http.StatusInternalServerError, "Internal Server Error", "unexpected error")
	}
}

// badRequest is a convenience for request-binding/validation failures.
func badRequest(c *gin.Context, detail string) {
	problem(c, http.StatusBadRequest, "Bad Request", detail)
}

// failAssets maps assets/vault domain errors to problem responses.
func failAssets(c *gin.Context, err error) {
	switch {
	case errors.Is(err, assets.ErrNotFound), errors.Is(err, vault.ErrNotFound):
		problem(c, http.StatusNotFound, "Not Found", "resource not found")
	case errors.Is(err, assets.ErrForbidden):
		problem(c, http.StatusForbidden, "Forbidden",
			"only the person who added this device, or a super admin, can change its recording setting")
	case errors.Is(err, assets.ErrInvalid):
		// The message carries the offending value and the allowed set, which is
		// the whole point of refusing rather than silently substituting a default.
		problem(c, http.StatusBadRequest, "Bad Request", err.Error())
	case errors.Is(err, vault.ErrSecretRequired):
		problem(c, http.StatusBadRequest, "Bad Request", "a password or secret is required to create a credential")
	case errors.Is(err, vault.ErrInjectionMismatch):
		// The message names the protocol and what would work: the operator's next
		// question is "then what should I have picked?", and a status code alone
		// does not answer it. It quotes the method, never the secret.
		problem(c, http.StatusUnprocessableEntity, "Credential Cannot Authenticate This Device", err.Error())
	case errors.Is(err, iam.ErrConflict):
		problem(c, http.StatusConflict, "Conflict", "resource already exists")
	default:
		fail(c, err)
	}
}

// failAccess maps access-broker domain errors to problem responses.
func failAccess(c *gin.Context, err error) {
	switch {
	case errors.Is(err, access.ErrNotFound):
		problem(c, http.StatusNotFound, "Not Found", "session not found")
	case errors.Is(err, access.ErrNoGateway):
		problem(c, http.StatusBadRequest, "Unsupported", "no gateway for this device protocol")
	case errors.Is(err, access.ErrNotActive), errors.Is(err, access.ErrExpired):
		problem(c, http.StatusGone, "Session Closed", "the access session is no longer active")
	case errors.Is(err, access.ErrForbidden):
		problem(c, http.StatusForbidden, "Forbidden", "you are not entitled to access this device")
	case errors.Is(err, access.ErrNoCredential), errors.Is(err, vault.ErrNotFound):
		problem(c, http.StatusPreconditionFailed, "No Credential",
			"no credential is bound to this device; bind one, or enable break-glass unmanaged access on the device")
	case errors.Is(err, access.ErrCapacity):
		// Say what to do about it. "503" on its own reads as a transient blip an
		// operator should retry through, when the actual remedy is to give the
		// server more memory or wait for a recorded session to finish.
		problem(c, http.StatusServiceUnavailable, "Server At Capacity",
			"this server does not have enough memory left to start another recorded session; "+
				"wait for a recorded session to end, or give the GuardRail server more memory")
	case errors.Is(err, access.ErrRecordingUnavailable):
		// Refused rather than served unrecorded. The device's policy promises
		// evidence this host cannot produce, and a session that quietly captures
		// nothing while the policy still reads "on" is the failure nobody notices
		// until they go looking for the recording of an incident.
		// Do NOT name a cause here. This handler knows only that the gateway for
		// this device cannot capture; it does not know which gateway, and the
		// reasons are per-protocol and unrelated. Asserting Chromium — as this did —
		// told RDP and VNC operators to install a browser that has nothing to do
		// with their device: guacd records desktops itself, and its blocker is the
		// recording directory. A confidently wrong diagnosis costs more than a
		// general one, because it sends people to fix the wrong thing.
		problem(c, http.StatusServiceUnavailable, "Recording Unavailable",
			"this device is set to record sessions, but this server cannot capture them for this "+
				"device's protocol, so nothing would be saved. For web devices this usually means no "+
				"usable Chromium (install it, or set GUARDRAIL_CHROME_PATH). For RDP and VNC it means "+
				"the desktop recording directory is unset or unreadable (see GUARDRAIL_GUACD_RECORDING_DIR; "+
				"the server log names the reason at startup). Or turn off Record sessions for this device "+
				"to connect without a recording.")
	case errors.Is(err, access.ErrCredentialUnusable):
		// 422, not 500: the request is well-formed and the server is fine — the
		// stored credential just cannot log into this kind of device. The message
		// names the protocol and the methods that would work, because "unexpected
		// error" is what this used to say and it sent people to the logs for a
		// two-click fix.
		problem(c, http.StatusUnprocessableEntity, "Credential Cannot Authenticate This Device", err.Error())
	case errors.Is(err, access.ErrInjectionUnsupported):
		// Name both ways out. The operator's real question is "I bound a
		// credential, why am I being asked to log in?", and the answer is that this
		// delivery mode cannot type into a page without handing them the secret.
		problem(c, http.StatusPreconditionFailed, "Credential Cannot Be Injected",
			"this device's credential uses login-form fill, which only works with browser isolation: "+
				"the secret is typed into the page by a browser on the server, never sent to you. "+
				"Turn on session recording for this device to use isolation, or change the credential to "+
				"HTTP Basic auth or an Authorization header, which the reverse proxy can inject directly.")
	case errors.Is(err, access.ErrHostKeyMismatch):
		// 502: GuardRail is the gateway, and the host answering for this device
		// failed identity verification. The full error text is passed through on
		// purpose — it carries the fingerprint presented and the remedy, and this
		// is the one failure where an operator must be told exactly what happened
		// rather than handed a status code to retry through. It names no secret:
		// the check runs before any credential is offered.
		problem(c, http.StatusBadGateway, "Device Identity Changed", err.Error())
	default:
		failAssets(c, err)
	}
}
