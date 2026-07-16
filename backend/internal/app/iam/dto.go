package iam

import (
	"time"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// ReqMeta carries request metadata for auditing (never trusted for authz).
type ReqMeta struct {
	IP        string
	UserAgent string
}

// LoginInput is a login attempt.
type LoginInput struct {
	Email        string
	Password     string
	Organization string // optional org slug to disambiguate
	Meta         ReqMeta
}

// TokenPair is the result of a successful authentication or refresh. When a
// second factor is required, MFARequired is true and MFAToken carries the
// short-lived challenge; the token fields are empty until MFA is completed via
// VerifyMFA.
type TokenPair struct {
	AccessToken      string
	AccessExpiresAt  time.Time
	RefreshToken     string
	RefreshExpiresAt time.Time
	Principal        Principal

	MFARequired bool
	MFAToken    string
}

// MFAVerifyInput completes an MFA challenge with either a TOTP code or a
// single-use recovery code.
type MFAVerifyInput struct {
	MFAToken string
	Code     string
	Meta     ReqMeta
}

// MFAEnrollment is returned when a user begins TOTP enrollment: the secret is
// shown once (for manual entry) alongside the otpauth URI for a QR code.
type MFAEnrollment struct {
	Secret          string
	ProvisioningURI string
}

// MFAStatus describes a user's current second-factor state.
type MFAStatus struct {
	Enabled           bool
	Confirmed         bool
	RecoveryCodesLeft int
}

// SessionView is a live login session presented to the console, with two flags
// derived for the caller: Self (the session belongs to them) and Current (it is
// the very session making this request, matched by the refresh cookie).
type SessionView struct {
	ID         iam.ID // family id — the stable identifier of a logical sign-in
	UserID     iam.ID
	Email      string
	IP         string
	UserAgent  string
	SignedInAt time.Time
	LastSeenAt time.Time
	ExpiresAt  time.Time
	Current    bool
	Self       bool
}

// Principal is the public view of the authenticated user.
type Principal struct {
	UserID         iam.ID
	OrganizationID iam.ID
	Email          string
	Username       string
	IsSuperAdmin   bool
	Roles          []string
	Permissions    []string
	// MustChangePassword tells the console to force a password change before
	// letting this person do anything else.
	MustChangePassword bool
}

func principalFromUser(u *iam.User) Principal {
	return Principal{
		UserID:             u.ID,
		OrganizationID:     u.OrganizationID,
		Email:              u.Email.String(),
		Username:           u.Username,
		IsSuperAdmin:       u.HasSuperAdmin(),
		Roles:              u.RoleNames(),
		Permissions:        u.Permissions(),
		MustChangePassword: u.MustChangePassword,
	}
}

func claimsFromUser(u *iam.User) iam.Claims {
	return iam.Claims{
		UserID:         u.ID,
		OrganizationID: u.OrganizationID,
		Email:          u.Email.String(),
		IsSuperAdmin:   u.HasSuperAdmin(),
		Roles:          u.RoleNames(),
		Permissions:    u.Permissions(),
	}
}

// CreateUserInput describes a new user.
type CreateUserInput struct {
	Email        string
	Username     string
	Password     string
	RoleIDs      []iam.ID
	IsSuperAdmin bool
	Meta         ReqMeta
}

// CreateOrgInput describes a new organization.
type CreateOrgInput struct {
	Name string
	Slug string
	Meta ReqMeta
}
