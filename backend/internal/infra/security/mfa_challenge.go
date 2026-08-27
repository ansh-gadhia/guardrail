package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// MFAChallenger issues the short-lived, HMAC-signed token that stands between a
// correct password and full authentication when a second factor is required.
// The token carries only the user id and an expiry; it grants nothing on its own
// and is single-purpose (completing MFA), so it is deliberately not a JWT.
type MFAChallenger struct {
	key []byte
	ttl time.Duration
}

// NewMFAChallenger builds a challenger from the JWT signing key and a TTL.
func NewMFAChallenger(signingKey string, ttl time.Duration) *MFAChallenger {
	// Domain-separate from the access-token signer even though the key is shared.
	sum := sha256.Sum256([]byte("guardrail/mfa-challenge\x00" + signingKey))
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &MFAChallenger{key: sum[:], ttl: ttl}
}

// Issue returns a signed challenge token valid for the configured TTL.
//
// sso records that the password half of this sign-in was a SIEM exchange, so the
// session minted after the second factor still knows what opened it. It is
// inside the signed payload, not alongside it: a flag a client could edit would
// let anybody holding a challenge decide their own session was SIEM-vouched.
func (m *MFAChallenger) Issue(userID iam.ID, sso bool, now time.Time) (string, error) {
	exp := now.Add(m.ttl).Unix()
	payload := userID.String() + ":" + strconv.FormatInt(exp, 10) + ":" + boolDigit(sso)
	sig := m.sign(payload)
	tok := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
	return tok, nil
}

// Verify checks the signature and expiry, returning the embedded user id and
// whether the sign-in it belongs to began at the SIEM.
func (m *MFAChallenger) Verify(token string, now time.Time) (iam.ID, bool, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return iam.ID{}, false, iam.ErrMFAChallengeInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return iam.ID{}, false, iam.ErrMFAChallengeInvalid
	}
	payload := string(raw)
	if subtle.ConstantTimeCompare([]byte(m.sign(payload)), []byte(parts[1])) != 1 {
		return iam.ID{}, false, iam.ErrMFAChallengeInvalid
	}
	// Two segments or three. A challenge minted by the previous build carries no
	// sso segment and is treated as not-SSO, which keeps the five-minute window
	// either side of a rolling restart from logging people out mid-sign-in.
	seg := strings.Split(payload, ":")
	if len(seg) != 2 && len(seg) != 3 {
		return iam.ID{}, false, iam.ErrMFAChallengeInvalid
	}
	exp, err := strconv.ParseInt(seg[1], 10, 64)
	if err != nil || now.Unix() > exp {
		return iam.ID{}, false, iam.ErrMFAChallengeInvalid
	}
	id, err := uuid.Parse(seg[0])
	if err != nil {
		return iam.ID{}, false, iam.ErrMFAChallengeInvalid
	}
	return id, len(seg) == 3 && seg[2] == "1", nil
}

func boolDigit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (m *MFAChallenger) sign(payload string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
