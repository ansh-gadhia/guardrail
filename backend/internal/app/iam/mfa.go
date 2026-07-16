package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// recoveryCodeCount is how many single-use recovery codes are minted on
// enrollment (and regeneration).
const recoveryCodeCount = 10

// mfaEnabled reports whether the MFA collaborators are wired.
func (s *Service) mfaEnabled() bool {
	return s.mfa != nil && s.totp != nil && s.cipher != nil && s.mfaChal != nil
}

// BeginTOTPEnrollment generates a fresh TOTP secret, stores it encrypted and
// unconfirmed, and returns the secret plus provisioning URI for the QR code.
// Re-enrolling before confirmation simply replaces the pending secret.
func (s *Service) BeginTOTPEnrollment(ctx context.Context, actor iam.Claims) (*MFAEnrollment, error) {
	if !s.mfaEnabled() {
		return nil, iam.ErrMFANotEnrolled
	}
	if existing, err := s.mfa.Get(ctx, actor.UserID); err == nil && existing.Confirmed() {
		return nil, iam.ErrMFAAlreadyEnrolled
	}

	secret, err := s.totp.GenerateSecret()
	if err != nil {
		return nil, err
	}
	enc, err := s.cipher.Encrypt([]byte(secret))
	if err != nil {
		return nil, err
	}
	if err := s.mfa.Upsert(ctx, &iam.MFAMethod{
		UserID: actor.UserID, Type: iam.MFATypeTOTP, Secret: enc, ConfirmedAt: nil,
	}); err != nil {
		return nil, err
	}
	// Record that enrollment started, distinctly from mfa.enroll (which means it
	// finished). Confirmation needs two consecutive codes, so abandoning halfway
	// is easy and leaves a pending, non-protecting credential. Without this event
	// the trail shows nothing at all for that user, and "I set up 2FA but it says
	// disabled" cannot be answered from the log — only guessed at.
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "mfa.enroll.begin",
		Category: audit.CategoryAuth, ActorID: &actor.UserID, ActorEmail: actor.Email,
		Result: audit.ResultSuccess})

	uri := s.totp.ProvisioningURI(s.mfaIssuer, actor.Email, secret)
	return &MFAEnrollment{Secret: secret, ProvisioningURI: uri}, nil
}

// ConfirmTOTPEnrollment verifies two consecutive codes against the pending
// secret, activates the method, and returns a fresh set of single-use recovery
// codes (shown once). Two back-to-back codes (rather than one) are required at
// enrollment to prove the authenticator's clock genuinely tracks the server
// across a period rollover, so a time-drifted device is caught here rather than
// locking the user out at their next sign-in. Login still takes a single code.
func (s *Service) ConfirmTOTPEnrollment(ctx context.Context, actor iam.Claims, code, nextCode string) ([]string, error) {
	if !s.mfaEnabled() {
		return nil, iam.ErrMFANotEnrolled
	}
	m, err := s.mfa.Get(ctx, actor.UserID)
	if err != nil {
		return nil, err
	}
	if m.Confirmed() {
		return nil, iam.ErrMFAAlreadyEnrolled
	}
	secret, err := s.cipher.Decrypt(m.Secret)
	if err != nil {
		return nil, err
	}
	if !s.totp.ValidateConsecutive(string(secret), code, nextCode) {
		return nil, iam.ErrMFAInvalidCode
	}
	if err := s.mfa.Confirm(ctx, actor.UserID, s.clock.Now()); err != nil {
		return nil, err
	}
	codes, err := s.regenerateRecoveryCodes(ctx, actor.UserID)
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "mfa.enroll",
		Category: audit.CategoryAuth, ActorID: &actor.UserID, ActorEmail: actor.Email,
		Result: audit.ResultSuccess})
	return codes, nil
}

// VerifyMFA completes a login challenge with a TOTP or recovery code, issuing
// tokens on success.
func (s *Service) VerifyMFA(ctx context.Context, in MFAVerifyInput) (*TokenPair, error) {
	if !s.mfaEnabled() {
		return nil, iam.ErrMFAChallengeInvalid
	}
	now := s.clock.Now()
	userID, err := s.mfaChal.Verify(in.MFAToken, now)
	if err != nil {
		return nil, iam.ErrMFAChallengeInvalid
	}

	throttleKey := "mfa:" + in.Meta.IP + ":" + userID.String()
	if s.throttle != nil {
		if ok, _, e := s.throttle.Allow(ctx, throttleKey); e == nil && !ok {
			return nil, ErrThrottled
		}
	}

	user, err := s.users.GetByID(ctx, iam.TenantScope{IsSuperAdmin: true}, userID)
	if err != nil {
		return nil, iam.ErrMFAChallengeInvalid
	}
	m, err := s.mfa.Get(ctx, userID)
	if err != nil || !m.Confirmed() {
		return nil, iam.ErrMFAChallengeInvalid
	}

	ok, used := s.checkSecondFactor(ctx, m, userID, in.Code)
	if !ok {
		if s.throttle != nil {
			_ = s.throttle.Fail(ctx, throttleKey)
		}
		s.record(ctx, s.authEvent(user, in.Meta, audit.ResultFailure, "mfa_bad_code"))
		return nil, iam.ErrMFAInvalidCode
	}
	if s.throttle != nil {
		_ = s.throttle.Reset(ctx, throttleKey)
	}

	pair, err := s.issueTokens(ctx, user, in.Meta, iam.NewID())
	if err != nil {
		return nil, err
	}
	s.record(ctx, s.authEvent(user, in.Meta, audit.ResultSuccess, "mfa_"+used))
	return pair, nil
}

// checkSecondFactor validates a TOTP code first, then falls back to consuming a
// recovery code. It returns whether the factor was valid and which method
// ("totp" or "recovery") succeeded.
func (s *Service) checkSecondFactor(ctx context.Context, m *iam.MFAMethod, userID iam.ID, code string) (bool, string) {
	secret, err := s.cipher.Decrypt(m.Secret)
	if err == nil && s.totp.Validate(string(secret), code) {
		return true, "totp"
	}
	consumed, err := s.mfa.ConsumeRecoveryCode(ctx, userID, hashRecoveryCode(code), s.clock.Now())
	if err == nil && consumed {
		return true, "recovery"
	}
	return false, ""
}

// DisableMFA removes the user's second factor and recovery codes. It requires a
// valid current code (TOTP or a recovery code) so that turning MFA off is itself
// gated by the second factor — a walk-up on an unlocked, already-signed-in
// session cannot silently weaken the account.
func (s *Service) DisableMFA(ctx context.Context, actor iam.Claims, code string) error {
	if !s.mfaEnabled() {
		return iam.ErrMFANotEnrolled
	}
	m, err := s.mfa.Get(ctx, actor.UserID)
	if err != nil {
		return err
	}
	if !m.Confirmed() {
		return iam.ErrMFANotEnrolled
	}
	ok, _ := s.checkSecondFactor(ctx, m, actor.UserID, code)
	if !ok {
		s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "mfa.disable",
			Category: audit.CategoryAuth, ActorID: &actor.UserID, ActorEmail: actor.Email,
			Result: audit.ResultFailure, Detail: map[string]any{"reason": "mfa_bad_code"}})
		return iam.ErrMFAInvalidCode
	}
	if err := s.mfa.Delete(ctx, actor.UserID); err != nil {
		return err
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "mfa.disable",
		Category: audit.CategoryAuth, ActorID: &actor.UserID, ActorEmail: actor.Email,
		Result: audit.ResultSuccess})
	return nil
}

// RegenerateRecoveryCodes issues a new set of recovery codes, invalidating the
// old set. Requires a confirmed enrollment.
func (s *Service) RegenerateRecoveryCodes(ctx context.Context, actor iam.Claims) ([]string, error) {
	if !s.mfaEnabled() {
		return nil, iam.ErrMFANotEnrolled
	}
	m, err := s.mfa.Get(ctx, actor.UserID)
	if err != nil {
		return nil, err
	}
	if !m.Confirmed() {
		return nil, iam.ErrMFANotEnrolled
	}
	codes, err := s.regenerateRecoveryCodes(ctx, actor.UserID)
	if err != nil {
		return nil, err
	}
	s.record(ctx, audit.Event{OrganizationID: &actor.OrganizationID, Action: "mfa.recovery_regenerate",
		Category: audit.CategoryAuth, ActorID: &actor.UserID, ActorEmail: actor.Email,
		Result: audit.ResultSuccess})
	return codes, nil
}

// MFAStatusFor reports the current second-factor state for the actor.
func (s *Service) MFAStatusFor(ctx context.Context, actor iam.Claims) (MFAStatus, error) {
	if !s.mfaEnabled() {
		return MFAStatus{}, nil
	}
	m, err := s.mfa.Get(ctx, actor.UserID)
	if errors.Is(err, iam.ErrMFANotEnrolled) {
		return MFAStatus{}, nil
	}
	if err != nil {
		return MFAStatus{}, err
	}
	left, _ := s.mfa.CountRecoveryCodes(ctx, actor.UserID)
	return MFAStatus{Enabled: true, Confirmed: m.Confirmed(), RecoveryCodesLeft: left}, nil
}

// regenerateRecoveryCodes mints, stores (hashed), and returns plaintext codes.
func (s *Service) regenerateRecoveryCodes(ctx context.Context, userID iam.ID) ([]string, error) {
	codes := make([]string, 0, recoveryCodeCount)
	hashes := make([][]byte, 0, recoveryCodeCount)
	for i := 0; i < recoveryCodeCount; i++ {
		code, err := newRecoveryCode()
		if err != nil {
			return nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, hashRecoveryCode(code))
	}
	if err := s.mfa.ReplaceRecoveryCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return codes, nil
}

// newRecoveryCode returns a random code formatted as "xxxxx-xxxxx" (base32-ish
// hex), easy to read and type.
func newRecoveryCode() (string, error) {
	buf := make([]byte, 5)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("iam: generate recovery code: %w", err)
	}
	h := hex.EncodeToString(buf) // 10 hex chars
	return h[:5] + "-" + h[5:], nil
}

// hashRecoveryCode normalizes and SHA-256-hashes a recovery code for storage and
// comparison. Normalization strips separators and lowercases.
func hashRecoveryCode(code string) []byte {
	norm := strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(norm))
	return sum[:]
}
