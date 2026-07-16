package security

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// rfcSecret is the ASCII secret "12345678901234567890" from RFC 6238 Appendix B,
// encoded as base32 (what our Validate expects).
var rfcSecret = strings.TrimRight(base32.StdEncoding.EncodeToString([]byte("12345678901234567890")), "=")

// TestTOTP_RFC6238Vectors checks known SHA-1 test vectors from RFC 6238 (6-digit
// truncation of the published 8-digit values).
func TestTOTP_RFC6238Vectors(t *testing.T) {
	cases := []struct {
		unix int64
		want string // last 6 digits of the RFC's 8-digit value
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
	}
	for _, tc := range cases {
		a := &TOTPAuthenticator{digits: 6, period: 30, skew: 0,
			now: func() time.Time { return time.Unix(tc.unix, 0) }}
		if !a.Validate(rfcSecret, tc.want) {
			// Surface the actually-computed code for debugging.
			got := hotp(mustDecode(t, rfcSecret), tc.unix/30, 6)
			t.Fatalf("unix=%d: Validate failed; want %s got %s", tc.unix, tc.want, got)
		}
	}
}

func TestTOTP_SkewWindow(t *testing.T) {
	base := int64(1111111109)
	a := &TOTPAuthenticator{digits: 6, period: 30, skew: 1,
		now: func() time.Time { return time.Unix(base, 0) }}
	// The code from the previous 30s step must still validate with skew=1.
	prev := hotp(mustDecode(t, rfcSecret), (base/30)-1, 6)
	if !a.Validate(rfcSecret, prev) {
		t.Fatal("expected previous-step code to validate within skew window")
	}
	// A code two steps away must NOT validate.
	old := hotp(mustDecode(t, rfcSecret), (base/30)-2, 6)
	if a.Validate(rfcSecret, old) {
		t.Fatal("code two steps away should be rejected")
	}
}

func TestTOTP_GenerateAndRoundTrip(t *testing.T) {
	a := NewTOTP()
	secret, err := a.GenerateSecret()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if secret == "" {
		t.Fatal("empty secret")
	}
	code := hotp(mustDecode(t, secret), time.Now().Unix()/30, 6)
	if !a.Validate(secret, code) {
		t.Fatal("freshly generated secret failed to validate its own code")
	}
	if a.Validate(secret, "000000") && a.Validate(secret, "111111") {
		t.Fatal("validator accepts arbitrary codes")
	}
}

func TestTOTP_ValidateConsecutive(t *testing.T) {
	base := int64(1111111109)
	key := mustDecode(t, rfcSecret)
	step := base / 30
	a := &TOTPAuthenticator{digits: 6, period: 30, skew: 1,
		now: func() time.Time { return time.Unix(base, 0) }}

	c0 := hotp(key, step, 6)   // code for the current step
	c1 := hotp(key, step+1, 6) // code for the next step
	cPrev := hotp(key, step-1, 6)

	// A correctly-ordered consecutive pair validates (here the pair sits one step
	// behind "now", as it would after the user waited for the rollover).
	if !a.ValidateConsecutive(rfcSecret, cPrev, c0) {
		t.Fatal("expected a valid consecutive pair to pass")
	}
	// The current step followed by the next also validates (fast typist).
	if !a.ValidateConsecutive(rfcSecret, c0, c1) {
		t.Fatal("expected current+next pair to pass")
	}
	// Reversed order (next then current) must fail — order carries the proof.
	if a.ValidateConsecutive(rfcSecret, c1, c0) {
		t.Fatal("reversed pair should be rejected")
	}
	// The same code entered twice must fail — the user has to wait for a rollover.
	if a.ValidateConsecutive(rfcSecret, c0, c0) {
		t.Fatal("identical codes should be rejected")
	}
	// Two valid-but-non-adjacent codes must fail.
	c2 := hotp(key, step+2, 6)
	if a.ValidateConsecutive(rfcSecret, c0, c2) {
		t.Fatal("non-adjacent codes should be rejected")
	}
	// Garbage fails.
	if a.ValidateConsecutive(rfcSecret, "000000", "111111") {
		t.Fatal("arbitrary codes should be rejected")
	}
}

func TestTOTP_ProvisioningURI(t *testing.T) {
	a := NewTOTP()
	uri := a.ProvisioningURI("GuardRail", "user@acme.com", "ABCDEF")
	for _, want := range []string{"otpauth://totp/", "issuer=GuardRail", "secret=ABCDEF", "period=30"} {
		if !strings.Contains(uri, want) {
			t.Fatalf("uri %q missing %q", uri, want)
		}
	}
}

func mustDecode(t *testing.T, secret string) []byte {
	t.Helper()
	b, err := decodeBase32(secret)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return b
}
