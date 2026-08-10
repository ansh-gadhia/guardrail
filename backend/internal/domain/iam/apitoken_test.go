package iam

import (
	"strings"
	"testing"
	"time"
)

func TestNewAPITokenSecretShape(t *testing.T) {
	raw, hash, prefix, err := NewAPITokenSecret()
	if err != nil {
		t.Fatalf("NewAPITokenSecret: %v", err)
	}
	if !strings.HasPrefix(raw, APITokenPrefix) {
		t.Errorf("token %q lacks the %q prefix that lets the middleware route it", raw, APITokenPrefix)
	}
	if !LooksLikeAPIToken(raw) {
		t.Error("LooksLikeAPIToken rejected a token it just minted")
	}
	// 32 random bytes is base64url-encoded to 43 chars, unpadded.
	if len(raw) != len(APITokenPrefix)+43 {
		t.Errorf("token length %d — entropy is not what it should be", len(raw))
	}
	if len(hash) != 32 {
		t.Errorf("hash is %d bytes, want a 32-byte SHA-256", len(hash))
	}
	// The prefix identifies a token in a list; it must never be enough to
	// reconstruct one.
	if !strings.HasPrefix(raw, prefix) || len(prefix) >= len(raw) {
		t.Errorf("prefix %q is not a short leading fragment of the token", prefix)
	}
}

func TestAPITokensAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 200; i++ {
		raw, _, _, err := NewAPITokenSecret()
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if seen[raw] {
			t.Fatal("minted the same token twice")
		}
		seen[raw] = true
	}
}

func TestHashAPITokenIsStableAndSpecific(t *testing.T) {
	a := HashAPIToken("grt_example")
	if string(a) != string(HashAPIToken("grt_example")) {
		t.Error("hashing is not deterministic — no token would ever verify")
	}
	if string(a) == string(HashAPIToken("grt_examplf")) {
		t.Error("one-character difference collided")
	}
}

// A JWT must not be mistaken for a machine token, or an expired session would be
// looked up in the wrong place and reported with the wrong reason.
func TestLooksLikeAPITokenRejectsJWTs(t *testing.T) {
	if LooksLikeAPIToken("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.abc.def") {
		t.Error("a JWT was routed to the API-token verifier")
	}
	if LooksLikeAPIToken("") {
		t.Error("an empty bearer was treated as an API token")
	}
}

func TestValidateScopes(t *testing.T) {
	got, err := ValidateScopes([]string{"device:read", "device:read", "session:read"})
	if err != nil {
		t.Fatalf("ValidateScopes: %v", err)
	}
	if len(got) != 2 || got[0] != "device:read" || got[1] != "session:read" {
		t.Errorf("got %v, want de-duplicated [device:read session:read]", got)
	}

	if _, err := ValidateScopes(nil); err == nil {
		t.Error("a token with no scopes was accepted; it could read nothing")
	}
}

// The load-bearing restriction. A machine credential that could open a brokered
// session is a much larger decision than a status feed — and it would fail at
// the database anyway, since access_sessions.user_id references users.
func TestValidateScopesRefusesWriteAndConnect(t *testing.T) {
	for _, s := range []string{
		"device:connect", "device:write", "session:terminate",
		"credential:write", "recording:delete", "user:write", "role:write",
	} {
		if _, err := ValidateScopes([]string{"device:read", s}); err == nil {
			t.Errorf("scope %q was accepted for a machine token", s)
		}
	}
}

func TestAPITokenUsability(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	if tok := (&APIToken{}); !tok.IsUsable(now) {
		t.Error("a fresh token with no expiry should be usable")
	}
	if tok := (&APIToken{ExpiresAt: &future}); !tok.IsUsable(now) {
		t.Error("a token expiring later should be usable")
	}
	if tok := (&APIToken{ExpiresAt: &past}); tok.IsUsable(now) {
		t.Error("an expired token was usable")
	}
	if tok := (&APIToken{RevokedAt: &past}); tok.IsUsable(now) {
		t.Error("a revoked token was usable")
	}
	// Revocation must win even when the expiry has not passed — revoking is the
	// emergency control, and "it expires next year" is not an answer to it.
	if tok := (&APIToken{ExpiresAt: &future, RevokedAt: &past}); tok.IsUsable(now) {
		t.Error("revocation did not override a future expiry")
	}
}

// A token's actions must be attributed to the token, never to whoever created
// it: putting a person's name on what a script did is the confusion an audit
// trail exists to prevent.
func TestAPITokenClaims(t *testing.T) {
	issuer := NewID()
	tok := &APIToken{
		ID: NewID(), OrganizationID: NewID(), Name: "noc-dashboard",
		Scopes: []string{"device:read"}, CreatedBy: &issuer,
	}
	c := tok.Claims()

	if c.UserID != tok.ID {
		t.Error("claims identify the issuer rather than the token")
	}
	if c.UserID == issuer {
		t.Error("the token's actions would be attributed to the human who made it")
	}
	if c.IsSuperAdmin {
		t.Error("a machine token claimed super admin")
	}
	if !c.Has("device:read") {
		t.Error("scope did not become a permission")
	}
	if c.Has("device:connect") {
		t.Error("a permission appeared that was never granted")
	}
	if c.Email != "apitoken:noc-dashboard" {
		t.Errorf("Email = %q, want apitoken:noc-dashboard so logs are readable", c.Email)
	}
	// Claims must not alias the token's slice; a handler mutating permissions
	// would otherwise rewrite the stored scopes.
	c.Permissions[0] = "tampered"
	if tok.Scopes[0] != "device:read" {
		t.Error("Claims aliased the token's scope slice")
	}
}
