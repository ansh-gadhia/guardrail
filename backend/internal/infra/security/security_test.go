package security

import (
	"strings"
	"testing"
	"time"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

func testParams() Argon2Params {
	// Small params keep tests fast while exercising the full code path.
	return Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

func TestArgon2_HashAndVerify(t *testing.T) {
	h := NewArgon2Hasher(testParams())
	enc, err := h.Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(enc, "$argon2id$") {
		t.Fatalf("unexpected encoding: %s", enc)
	}
	ok, err := h.Verify("correct horse battery staple", enc)
	if err != nil || !ok {
		t.Fatalf("verify correct password: ok=%v err=%v", ok, err)
	}
	bad, err := h.Verify("wrong password", enc)
	if err != nil {
		t.Fatalf("verify wrong: %v", err)
	}
	if bad {
		t.Fatal("verify returned true for wrong password")
	}
}

func TestArgon2_UniqueSalts(t *testing.T) {
	h := NewArgon2Hasher(testParams())
	a, _ := h.Hash("same")
	b, _ := h.Hash("same")
	if a == b {
		t.Fatal("expected unique salts to produce different encodings")
	}
}

func TestArgon2_NeedsRehash(t *testing.T) {
	weak := NewArgon2Hasher(Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32})
	strong := NewArgon2Hasher(Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32})
	enc, _ := weak.Hash("pw")
	if !strong.NeedsRehash(enc) {
		t.Fatal("expected weak hash to need rehash under stronger policy")
	}
	if weak.NeedsRehash(enc) {
		t.Fatal("hash should not need rehash under its own policy")
	}
}

func TestArgon2_InvalidEncoding(t *testing.T) {
	h := NewArgon2Hasher(testParams())
	if _, err := h.Verify("x", "not-a-valid-hash"); err == nil {
		t.Fatal("expected error verifying malformed hash")
	}
}

func TestJWT_IssueVerifyRoundTrip(t *testing.T) {
	issuer := NewJWTIssuer(strings.Repeat("k", 32), "guardrail", 15*time.Minute)
	claims := iam.Claims{
		UserID: iam.NewID(), OrganizationID: iam.NewID(), Email: "a@b.com",
		IsSuperAdmin: false, Roles: []string{"Operator"}, Permissions: []string{"device:connect"},
	}
	tok, exp, err := issuer.Issue(claims, time.Now())
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if !exp.After(time.Now()) {
		t.Fatal("expiry should be in the future")
	}
	got, err := issuer.Verify(tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.UserID != claims.UserID || got.OrganizationID != claims.OrganizationID {
		t.Fatal("subject/org mismatch after round trip")
	}
	if !got.Has("device:connect") || got.Has("device:write") {
		t.Fatal("permission snapshot not preserved")
	}
}

func TestJWT_RejectsTamperedToken(t *testing.T) {
	issuer := NewJWTIssuer(strings.Repeat("k", 32), "guardrail", time.Minute)
	tok, _, _ := issuer.Issue(iam.Claims{UserID: iam.NewID(), OrganizationID: iam.NewID()}, time.Now())
	if _, err := issuer.Verify(tok + "x"); err == nil {
		t.Fatal("expected verification failure for tampered token")
	}
}

func TestJWT_RejectsWrongKey(t *testing.T) {
	a := NewJWTIssuer(strings.Repeat("a", 32), "guardrail", time.Minute)
	b := NewJWTIssuer(strings.Repeat("b", 32), "guardrail", time.Minute)
	tok, _, _ := a.Issue(iam.Claims{UserID: iam.NewID(), OrganizationID: iam.NewID()}, time.Now())
	if _, err := b.Verify(tok); err == nil {
		t.Fatal("expected verification failure with wrong signing key")
	}
}

func TestJWT_RejectsExpired(t *testing.T) {
	issuer := NewJWTIssuer(strings.Repeat("k", 32), "guardrail", time.Minute)
	tok, _, _ := issuer.Issue(iam.Claims{UserID: iam.NewID(), OrganizationID: iam.NewID()}, time.Now().Add(-2*time.Hour))
	if _, err := issuer.Verify(tok); err == nil {
		t.Fatal("expected verification failure for expired token")
	}
}

func TestRefreshToken_GenerateAndHash(t *testing.T) {
	g := NewRefreshGenerator()
	raw, hash, err := g.Generate()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if len(raw) < 40 {
		t.Fatalf("token too short: %d", len(raw))
	}
	if len(hash) != 32 {
		t.Fatalf("hash length = %d, want 32", len(hash))
	}
	// Hashing the same token reproduces the stored hash (for lookup).
	rehash := g.Hash(raw)
	if string(rehash) != string(hash) {
		t.Fatal("hash is not deterministic for the same token")
	}
	// Different tokens hash differently.
	raw2, _, _ := g.Generate()
	if string(g.Hash(raw2)) == string(hash) {
		t.Fatal("distinct tokens produced identical hashes")
	}
}
