package security

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

func TestMFAChallenger_RoundTrip(t *testing.T) {
	c := NewMFAChallenger("a-signing-key-that-is-long-enough-123456", 5*time.Minute)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	uid := uuid.New()

	tok, err := c.Issue(uid, false, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, sso, err := c.Verify(tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != uid {
		t.Fatalf("uid mismatch: %s != %s", got, uid)
	}
	if sso {
		t.Fatalf("a challenge issued for a password login must not come back marked SSO")
	}
}

// A challenge issued for a SIEM-vouched sign-in has to carry that fact across the
// second factor, or the session minted afterwards silently becomes an ordinary
// local one — and any behaviour keyed off the marker is then wrong for exactly
// the users who enrolled a second factor.
func TestMFAChallenger_CarriesSSOMarker(t *testing.T) {
	c := NewMFAChallenger("a-signing-key-that-is-long-enough-123456", 5*time.Minute)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	uid := uuid.New()

	tok, err := c.Issue(uid, true, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, sso, err := c.Verify(tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != uid || !sso {
		t.Fatalf("want (%s, true), got (%s, %v)", uid, got, sso)
	}
}

// The marker is inside the signed payload, so flipping it invalidates the token
// rather than upgrading the session. Without this, anyone holding a challenge
// could declare their own sign-in SIEM-vouched.
func TestMFAChallenger_SSOMarkerIsSigned(t *testing.T) {
	c := NewMFAChallenger("a-signing-key-that-is-long-enough-123456", 5*time.Minute)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	uid := uuid.New()

	tok, _ := c.Issue(uid, false, now)
	parts := strings.SplitN(tok, ".", 2)
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	forged := base64.RawURLEncoding.EncodeToString([]byte(
		strings.TrimSuffix(string(raw), ":0")+":1")) + "." + parts[1]

	if _, _, err := c.Verify(forged, now); err != iam.ErrMFAChallengeInvalid {
		t.Fatalf("a flipped sso segment must invalidate the challenge, got %v", err)
	}
}

func TestMFAChallenger_Expired(t *testing.T) {
	c := NewMFAChallenger("a-signing-key-that-is-long-enough-123456", 5*time.Minute)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tok, _ := c.Issue(uuid.New(), false, now)
	if _, _, err := c.Verify(tok, now.Add(6*time.Minute)); err != iam.ErrMFAChallengeInvalid {
		t.Fatalf("expected ErrMFAChallengeInvalid, got %v", err)
	}
}

func TestMFAChallenger_Tampered(t *testing.T) {
	c := NewMFAChallenger("a-signing-key-that-is-long-enough-123456", 5*time.Minute)
	other := NewMFAChallenger("a-DIFFERENT-signing-key-long-enough-1234", 5*time.Minute)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tok, _ := c.Issue(uuid.New(), false, now)

	// A token signed with a different key must not verify.
	if _, _, err := other.Verify(tok, now); err != iam.ErrMFAChallengeInvalid {
		t.Fatalf("cross-key verify: expected invalid, got %v", err)
	}
	// Garbage tokens are rejected.
	if _, _, err := c.Verify("not.a.token", now); err != iam.ErrMFAChallengeInvalid {
		t.Fatalf("garbage token: expected invalid, got %v", err)
	}
}
