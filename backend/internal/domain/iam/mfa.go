package iam

import (
	"context"
	"time"
)

// MFAType enumerates supported second factors. Only TOTP ships now; the type is
// carried explicitly so passkeys/WebAuthn can be added without a schema change.
type MFAType string

// MFATypeTOTP is a time-based one-time password (RFC 6238) authenticator.
const MFATypeTOTP MFAType = "totp"

// MFAMethod is a user's enrolled second factor. Secret holds the encrypted TOTP
// shared secret (never stored in plaintext). ConfirmedAt is nil until the user
// proves possession by entering a valid code during enrollment.
type MFAMethod struct {
	UserID      ID
	Type        MFAType
	Secret      []byte // encrypted via Cipher; opaque at rest
	ConfirmedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Confirmed reports whether enrollment has been completed.
func (m *MFAMethod) Confirmed() bool { return m != nil && m.ConfirmedAt != nil }

// MFARepository persists MFA enrollment and single-use recovery codes. It is
// keyed by user id and accessed via the trusted system scope (like auth
// sessions), since the acting user is the subject and no tenant GUC is required.
type MFARepository interface {
	Get(ctx context.Context, userID ID) (*MFAMethod, error)
	Upsert(ctx context.Context, m *MFAMethod) error
	Confirm(ctx context.Context, userID ID, at time.Time) error
	Delete(ctx context.Context, userID ID) error

	// ReplaceRecoveryCodes atomically discards existing codes and stores the new
	// set of SHA-256 hashes.
	ReplaceRecoveryCodes(ctx context.Context, userID ID, hashes [][]byte) error
	// ConsumeRecoveryCode marks the matching unused code as used, returning true
	// if a valid, previously-unused code was consumed.
	ConsumeRecoveryCode(ctx context.Context, userID ID, hash []byte, at time.Time) (bool, error)
	// CountRecoveryCodes returns how many unused recovery codes remain.
	CountRecoveryCodes(ctx context.Context, userID ID) (int, error)
}

// TOTP generates and validates time-based one-time passwords. Implemented in
// infra/security with no external dependency (RFC 6238 over HMAC-SHA1).
type TOTP interface {
	// GenerateSecret returns a fresh base32-encoded shared secret.
	GenerateSecret() (string, error)
	// Validate reports whether code is valid for secret at the current time,
	// tolerating small clock skew.
	Validate(secret, code string) bool
	// ValidateConsecutive reports whether code1 and code2 are valid codes for two
	// consecutive time steps (code1 then code2). Used at enrollment to prove the
	// authenticator's clock tracks the server across a full period rollover.
	ValidateConsecutive(secret, code1, code2 string) bool
	// ProvisioningURI builds an otpauth:// URI for authenticator-app enrollment.
	ProvisioningURI(issuer, account, secret string) string
}

// Cipher provides symmetric encryption for small secrets at rest (the TOTP
// shared secret). Implemented by the envelope encryptor so MFA secrets are
// protected by the same KEK as the credential vault.
type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(blob []byte) ([]byte, error)
}

// MFAChallenger issues and verifies the short-lived, signed token handed to a
// client after a correct password when a second factor is still required.
type MFAChallenger interface {
	Issue(userID ID, now time.Time) (string, error)
	Verify(token string, now time.Time) (ID, error)
}
