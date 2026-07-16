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
func (m *MFAChallenger) Issue(userID iam.ID, now time.Time) (string, error) {
	exp := now.Add(m.ttl).Unix()
	payload := userID.String() + ":" + strconv.FormatInt(exp, 10)
	sig := m.sign(payload)
	tok := base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
	return tok, nil
}

// Verify checks the signature and expiry, returning the embedded user id.
func (m *MFAChallenger) Verify(token string, now time.Time) (iam.ID, error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return iam.ID{}, iam.ErrMFAChallengeInvalid
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return iam.ID{}, iam.ErrMFAChallengeInvalid
	}
	payload := string(raw)
	if subtle.ConstantTimeCompare([]byte(m.sign(payload)), []byte(parts[1])) != 1 {
		return iam.ID{}, iam.ErrMFAChallengeInvalid
	}
	seg := strings.SplitN(payload, ":", 2)
	if len(seg) != 2 {
		return iam.ID{}, iam.ErrMFAChallengeInvalid
	}
	exp, err := strconv.ParseInt(seg[1], 10, 64)
	if err != nil || now.Unix() > exp {
		return iam.ID{}, iam.ErrMFAChallengeInvalid
	}
	id, err := uuid.Parse(seg[0])
	if err != nil {
		return iam.ID{}, iam.ErrMFAChallengeInvalid
	}
	return id, nil
}

func (m *MFAChallenger) sign(payload string) string {
	mac := hmac.New(sha256.New, m.key)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
