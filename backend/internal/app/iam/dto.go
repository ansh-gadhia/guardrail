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
	// ApprovalLevel is this person's rank in the approval hierarchy, so the
	// console can say who they are able to decide for.
	ApprovalLevel int
	// IsBootstrapAdmin marks the account the platform was installed with. The
	// console uses it to explain why its roles cannot be edited, rather than
	// silently hiding the control and leaving somebody hunting for it.
	IsBootstrapAdmin bool
	// MustChangePassword tells the console to force a password change before
	// letting this person do anything else.
	MustChangePassword bool
	// AuthProvider is how this person signs in: local, siem, oidc, ldap. The
	// console needs it to stop offering things that cannot work — a password
	// change to somebody who has no password, and a "set a password first" step
	// to somebody whose first step is the second factor.
	AuthProvider string
	// MFAEnabled reports a CONFIRMED second factor. Enrollment that was started
	// and abandoned does not count: a pending secret protects nothing, and
	// treating it as done would silently stop offering the one prompt that would
	// have finished it.
	MFAEnabled bool
	// FirstLogin marks the sign-in that is this account's first, of any kind.
	//
	// It is what the two-factor offer is keyed on, and it is deliberately the
	// same signal for every account. A local account has always had one — the
	// temporary password its owner has to replace — and the offer rode along at
	// the end of replacing it. An account provisioned by an identity provider has
	// no password and so had nothing to ride on, which is the only reason it was
	// never asked.
	//
	// Derived from last_login_at rather than stored: RecordLoginSuccess stamps
	// the row by id and leaves the loaded struct alone, so at the moment a
	// principal is built this still reads as it did before the sign-in that is
	// happening now.
	FirstLogin bool
}

func principalFromUser(u *iam.User) Principal {
	return Principal{
		UserID:             u.ID,
		OrganizationID:     u.OrganizationID,
		Email:              u.Email.String(),
		Username:           u.Username,
		IsSuperAdmin:       u.HasSuperAdmin(),
		IsBootstrapAdmin:   u.IsBootstrapAdmin(),
		Roles:              u.RoleNames(),
		Permissions:        u.Permissions(),
		ApprovalLevel:      u.ApprovalLevel(),
		MustChangePassword: u.MustChangePassword,
		AuthProvider:       string(u.AuthProvider),
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
		ApprovalLevel:  u.ApprovalLevel(),
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
