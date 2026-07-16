package security

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

func TestMFAChallenger_RoundTrip(t *testing.T) {
	c := NewMFAChallenger("a-signing-key-that-is-long-enough-123456", 5*time.Minute)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	uid := uuid.New()

	tok, err := c.Issue(uid, now)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	got, err := c.Verify(tok, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got != uid {
		t.Fatalf("uid mismatch: %s != %s", got, uid)
	}
}

func TestMFAChallenger_Expired(t *testing.T) {
	c := NewMFAChallenger("a-signing-key-that-is-long-enough-123456", 5*time.Minute)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tok, _ := c.Issue(uuid.New(), now)
	if _, err := c.Verify(tok, now.Add(6*time.Minute)); err != iam.ErrMFAChallengeInvalid {
		t.Fatalf("expected ErrMFAChallengeInvalid, got %v", err)
	}
}

func TestMFAChallenger_Tampered(t *testing.T) {
	c := NewMFAChallenger("a-signing-key-that-is-long-enough-123456", 5*time.Minute)
	other := NewMFAChallenger("a-DIFFERENT-signing-key-long-enough-1234", 5*time.Minute)
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tok, _ := c.Issue(uuid.New(), now)

	// A token signed with a different key must not verify.
	if _, err := other.Verify(tok, now); err != iam.ErrMFAChallengeInvalid {
		t.Fatalf("cross-key verify: expected invalid, got %v", err)
	}
	// Garbage tokens are rejected.
	if _, err := c.Verify("not.a.token", now); err != iam.ErrMFAChallengeInvalid {
		t.Fatalf("garbage token: expected invalid, got %v", err)
	}
}
