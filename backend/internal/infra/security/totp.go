package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTPAuthenticator implements RFC 6238 time-based one-time passwords over
// HMAC-SHA1 with a 30-second step and 6 digits — the parameters every
// authenticator app (Google Authenticator, Authy, 1Password, ...) defaults to.
// It has no external dependency.
type TOTPAuthenticator struct {
	digits int
	period int64
	skew   int64 // number of steps of tolerance on each side
	now    func() time.Time
}

// NewTOTP builds an authenticator with standard parameters and ±1 step skew.
func NewTOTP() *TOTPAuthenticator {
	return &TOTPAuthenticator{digits: 6, period: 30, skew: 1, now: time.Now}
}

// GenerateSecret returns a fresh 160-bit secret, base32-encoded (no padding) as
// authenticator apps expect.
func (a *TOTPAuthenticator) GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("security: generate totp secret: %w", err)
	}
	return strings.TrimRight(base32.StdEncoding.EncodeToString(buf), "="), nil
}

// Validate reports whether code matches secret at the current time within the
// configured skew. Comparison is constant-time.
func (a *TOTPAuthenticator) Validate(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != a.digits {
		return false
	}
	key, err := decodeBase32(secret)
	if err != nil {
		return false
	}
	counter := a.now().Unix() / a.period
	for delta := -a.skew; delta <= a.skew; delta++ {
		want := hotp(key, counter+delta, a.digits)
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// ValidateConsecutive reports whether code1 and code2 are the one-time codes for
// two consecutive time steps (code1 for step N, code2 for step N+1). It is used
// only at enrollment: requiring two back-to-back codes proves the authenticator's
// clock is genuinely in step with the server across a period rollover — a device
// whose time has drifted can fluke one code but not a matched consecutive pair.
//
// The search window is wider than Validate's because entering the second code
// means waiting for the ~30s rollover, so by submit time the pair sits a step or
// two behind "now". Like all TOTP math here it runs on Unix epoch seconds, which
// are timezone-independent — the server's zone never enters into it.
func (a *TOTPAuthenticator) ValidateConsecutive(secret, code1, code2 string) bool {
	code1 = strings.TrimSpace(code1)
	code2 = strings.TrimSpace(code2)
	if len(code1) != a.digits || len(code2) != a.digits {
		return false
	}
	// Consecutive TOTP values differ; identical codes mean the same window was
	// entered twice instead of waiting for the code to roll over.
	if subtle.ConstantTimeCompare([]byte(code1), []byte(code2)) == 1 {
		return false
	}
	key, err := decodeBase32(secret)
	if err != nil {
		return false
	}
	counter := a.now().Unix() / a.period
	// Allow the first code's step to fall from 3 steps behind to 1 ahead of now,
	// covering the time to enter both codes plus modest skew in either direction.
	for delta := int64(-3); delta <= 1; delta++ {
		step := counter + delta
		m1 := subtle.ConstantTimeCompare([]byte(hotp(key, step, a.digits)), []byte(code1))
		m2 := subtle.ConstantTimeCompare([]byte(hotp(key, step+1, a.digits)), []byte(code2))
		if m1 == 1 && m2 == 1 {
			return true
		}
	}
	return false
}

// ProvisioningURI builds the otpauth:// URI encoded into the enrollment QR code.
func (a *TOTPAuthenticator) ProvisioningURI(issuer, account, secret string) string {
	label := url.PathEscape(issuer) + ":" + url.PathEscape(account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", a.digits))
	q.Set("period", fmt.Sprintf("%d", a.period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// hotp computes an RFC 4226 HMAC-based OTP for the given counter.
func hotp(key []byte, counter int64, digits int) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(counter))
	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)

	offset := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])

	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", digits, bin%mod)
}

// decodeBase32 accepts secrets with or without padding and any case.
func decodeBase32(secret string) ([]byte, error) {
	s := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if pad := len(s) % 8; pad != 0 {
		s += strings.Repeat("=", 8-pad)
	}
	return base32.StdEncoding.DecodeString(s)
}
