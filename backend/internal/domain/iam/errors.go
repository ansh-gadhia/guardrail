package iam

import "errors"

// Domain sentinel errors. The application layer maps these to transport-level
// responses; the domain never knows about HTTP status codes.
var (
	ErrNotFound            = errors.New("iam: not found")
	ErrInvalidInput        = errors.New("iam: invalid input")
	ErrEmailAmbiguous      = errors.New("iam: email matches multiple organizations")
	ErrInvalidCredentials  = errors.New("iam: invalid credentials")
	ErrAccountLocked       = errors.New("iam: account locked")
	ErrAccountInactive     = errors.New("iam: account inactive")
	ErrConflict            = errors.New("iam: conflict")
	ErrRefreshReuse        = errors.New("iam: refresh token reuse detected")
	ErrRefreshInvalid      = errors.New("iam: refresh token invalid or expired")
	ErrPermissionDenied    = errors.New("iam: permission denied")
	ErrPasswordPolicy      = errors.New("iam: password does not meet policy")
	ErrPasswordReuse       = errors.New("iam: new password must differ from current")
	ErrPasswordUnsupported = errors.New("iam: password change not supported for this account")
	ErrMFARequired         = errors.New("iam: second factor required")
	ErrMFAInvalidCode      = errors.New("iam: invalid second-factor code")
	ErrMFAChallengeInvalid = errors.New("iam: mfa challenge invalid or expired")
	ErrMFANotEnrolled      = errors.New("iam: mfa not enrolled")
	ErrMFAAlreadyEnrolled  = errors.New("iam: mfa already enrolled")
	// ErrProtectedAccount is returned when somebody tries to change the roles or
	// password of the account the platform was installed with. Removing it is
	// allowed — it is recoverable. See User.IsBootstrapAdmin.
	ErrProtectedAccount = errors.New("iam: this account is protected")

	// ---- SIEM single sign-on ----
	//
	// Three sentinels, and the split between them is the contract: ErrSSOToken
	// says the caller's token is bad and no retry will help (401), while
	// ErrSSOUnavailable says GuardRail could not check and a retry is reasonable
	// (503). Reporting the second as the first sends the issuer looking for a
	// signature fault that is not there; reporting the first as the second
	// invites a client to retry a forgery forever and hides real rejections
	// inside GuardRail's own error budget.

	// ErrSSONotConfigured means no SIEM key material is wired on this deployment.
	ErrSSONotConfigured = errors.New("iam: siem sso is not configured")
	// ErrSSOUnavailable means the key material could not be reached and nothing
	// usable was cached. A key set that failed to fetch is not evidence that a
	// signature is good, so this fails closed.
	ErrSSOUnavailable = errors.New("iam: siem sso verification is temporarily unavailable")
	// ErrSSOToken means the exchange token was rejected. It is always wrapped
	// with the specific reason, which is written to be shown to a person: the
	// people who read it are the engineers on the SIEM's side of the integration
	// and a status code alone tells them nothing.
	ErrSSOToken = errors.New("iam: siem exchange token rejected")
)
