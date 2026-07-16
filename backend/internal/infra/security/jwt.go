package security

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// JWTIssuer implements iam.TokenIssuer using HMAC-SHA256 signing. The signing
// key comes from configuration (>= 32 bytes, enforced at startup). EdDSA can be
// swapped in later without changing callers.
type JWTIssuer struct {
	key    []byte
	issuer string
	ttl    time.Duration
}

// NewJWTIssuer builds an issuer.
func NewJWTIssuer(signingKey, issuer string, ttl time.Duration) *JWTIssuer {
	return &JWTIssuer{key: []byte(signingKey), issuer: issuer, ttl: ttl}
}

// guardrailClaims is the JWT payload. Registered claims cover sub/iss/exp/iat;
// custom claims carry the tenant and authorization snapshot.
type guardrailClaims struct {
	jwt.RegisteredClaims
	Org         string   `json:"org"`
	Email       string   `json:"email"`
	SuperAdmin  bool     `json:"sadmin"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"perms"`
}

// Issue signs an access token for the given claims and returns it with its
// expiry.
func (j *JWTIssuer) Issue(c iam.Claims, now time.Time) (string, time.Time, error) {
	exp := now.Add(j.ttl)
	claims := guardrailClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    j.issuer,
			Subject:   c.UserID.String(),
			ID:        uuid.NewString(),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
		},
		Org:         c.OrganizationID.String(),
		Email:       c.Email,
		SuperAdmin:  c.IsSuperAdmin,
		Roles:       c.Roles,
		Permissions: c.Permissions,
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := tok.SignedString(j.key)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("security: sign token: %w", err)
	}
	return signed, exp, nil
}

// Verify parses and validates a token, returning the domain claims.
func (j *JWTIssuer) Verify(token string) (iam.Claims, error) {
	parsed, err := jwt.ParseWithClaims(token, &guardrailClaims{},
		func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("security: unexpected signing method %v", t.Header["alg"])
			}
			return j.key, nil
		},
		jwt.WithValidMethods([]string{"HS256"}),
		jwt.WithIssuer(j.issuer),
	)
	if err != nil {
		return iam.Claims{}, fmt.Errorf("security: verify token: %w", err)
	}
	claims, ok := parsed.Claims.(*guardrailClaims)
	if !ok || !parsed.Valid {
		return iam.Claims{}, errors.New("security: invalid token claims")
	}

	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return iam.Claims{}, errors.New("security: invalid subject")
	}
	orgID, err := uuid.Parse(claims.Org)
	if err != nil {
		return iam.Claims{}, errors.New("security: invalid org claim")
	}
	return iam.Claims{
		UserID:         uid,
		OrganizationID: orgID,
		Email:          claims.Email,
		IsSuperAdmin:   claims.SuperAdmin,
		Roles:          claims.Roles,
		Permissions:    claims.Permissions,
	}, nil
}
