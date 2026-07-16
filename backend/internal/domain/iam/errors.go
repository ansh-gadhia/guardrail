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
)
