package security

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// SSOVerifierConfig is the verification policy for SIEM exchange tokens.
type SSOVerifierConfig struct {
	// Issuer and Audience are exact string matches. Audience is per-consumer:
	// GuardRail must not share one with another product the SIEM signs for, or
	// the check stops meaning anything.
	Issuer   string
	Audience string
	// SharedSecret enables the symmetric (HS*) path. Empty leaves it off, which
	// is the intended state — see NewSSOVerifier.
	SharedSecret string
	// ClockLeeway is the skew tolerated on exp/nbf. It also lengthens how long a
	// spent nonce must be remembered; see SSOAssertion.ReplayRetention.
	ClockLeeway time.Duration
	// MaxTokenAge is the longest validity a token may CLAIM. A handoff token is
	// not a session: one asserting hours of life is either a misconfiguration or
	// somebody trying to obtain a durable credential from a one-shot exchange.
	MaxTokenAge time.Duration
}

// SSOTokenVerifier implements iam.SSOVerifier.
type SSOTokenVerifier struct {
	keys   *JWKSSource
	secret []byte
	cfg    SSOVerifierConfig
	now    func() time.Time
}

// NewSSOVerifier builds the verifier. Either key source may be absent; with
// neither, SSO is simply not configured on this deployment.
//
// The asymmetric path is the intended one. Under a shared secret GuardRail holds
// a key that can FORGE the SIEM's tokens rather than merely check them, and
// combined with just-in-time provisioning a leak of that one setting does not
// impersonate an existing person — it mints a new account at whatever role the
// forger writes into the claim. Under RS256 GuardRail holds only a public key: a
// total compromise of its configuration yields nothing that can sign anything,
// and the SIEM rotates keys without a flag day because every token names its own.
//
// Both can be configured at once, which is how a cutover happens with no
// outage: set the JWKS URL while the secret is still set, move the issuers, then
// clear the secret. From that moment HS* tokens are refused outright rather than
// quietly still working. That is a config action, not a release.
func NewSSOVerifier(keys *JWKSSource, cfg SSOVerifierConfig) *SSOTokenVerifier {
	if cfg.ClockLeeway <= 0 {
		cfg.ClockLeeway = 60 * time.Second
	}
	if cfg.MaxTokenAge <= 0 {
		cfg.MaxTokenAge = 10 * time.Minute
	}
	v := &SSOTokenVerifier{keys: keys, cfg: cfg, now: time.Now}
	if cfg.SharedSecret != "" {
		v.secret = []byte(cfg.SharedSecret)
	}
	return v
}

// Configured reports whether any key material is wired.
func (v *SSOTokenVerifier) Configured() bool { return v.keys != nil || len(v.secret) > 0 }

// asymmetricAlgs and symmetricAlgs are the accepted algorithm families,
// enumerated rather than derived.
//
// Two rules make routing on the token's own alg header safe, and both are load-
// bearing. The classic attack on a router like this is an algorithm-confusion
// downgrade: take the issuer's published RSA public key, sign HS256 using its
// bytes as the "secret", and let a verifier that accepts both families check an
// HMAC with a key it believed was for RSA. It cannot work here because
//
//  1. the two paths use DISJOINT key material — the symmetric path never touches
//     anything derived from the key set, and
//  2. the algorithm list handed to the parser is always the SINGLE routed
//     algorithm, never the union of both families, so a token can never nominate
//     a verifier that was not intended for it.
//
// Enumerating explicitly is the third rule: it means no algorithm is reachable
// by accident, and "none" is not a spelling of anything in either list.
var (
	asymmetricAlgs = map[string]struct{}{
		"RS256": {}, "RS384": {}, "RS512": {},
		"PS256": {}, "PS384": {}, "PS512": {},
		"ES256": {}, "ES384": {}, "ES512": {},
		"EdDSA": {},
	}
	symmetricAlgs = map[string]struct{}{
		"HS256": {}, "HS384": {}, "HS512": {},
	}
)

// ssoClaims is the exchange-token payload.
type ssoClaims struct {
	jwt.RegisteredClaims
	Purpose  string `json:"purpose"`
	Nonce    string `json:"nonce"`
	Email    string `json:"email"`
	Username string `json:"username"`
	// Two spellings accepted for the display name because issuers disagree and
	// this is cosmetic; full_name wins when both are present.
	FullName string   `json:"full_name"`
	Name     string   `json:"name"`
	Role     string   `json:"role"`
	Access   string   `json:"access"`
	AMR      []string `json:"amr"`
}

// VerifySSOToken runs the whole verification, in an order that is itself part of
// the contract: nothing is read out of the token before its signature has been
// checked, and every step distinguishes "your token is bad" (iam.ErrSSOToken)
// from "GuardRail cannot check right now" (iam.ErrSSOUnavailable).
func (v *SSOTokenVerifier) VerifySSOToken(ctx context.Context, raw string) (*iam.SSOAssertion, error) {
	// 1. Configured at all? Either scheme counts.
	if !v.Configured() {
		return nil, iam.ErrSSONotConfigured
	}

	// 2. Read the unverified header — ONLY to learn alg and kid. Nothing else in
	// this token is looked at until a signature has vouched for it.
	alg, kid, err := peekHeader(raw)
	if err != nil {
		return nil, reject("the token header could not be read")
	}

	// 3. Route to key material by algorithm family, and 4. resolve the key.
	key, err := v.keyFor(ctx, alg, kid)
	if err != nil {
		return nil, err
	}

	// 5. Verify the signature — with the single routed algorithm, never a list.
	var claims ssoClaims
	_, err = jwt.ParseWithClaims(raw, &claims, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{alg}),
		jwt.WithLeeway(v.cfg.ClockLeeway),
		jwt.WithExpirationRequired(),
		jwt.WithIssuer(v.cfg.Issuer),
		jwt.WithAudience(v.cfg.Audience),
	)
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrTokenExpired):
			return nil, reject("the exchange token has expired")
		case errors.Is(err, jwt.ErrTokenNotValidYet):
			return nil, reject("the exchange token is not valid yet — check the clocks on both sides")
		case errors.Is(err, jwt.ErrTokenInvalidAudience):
			return nil, reject(fmt.Sprintf("the token is addressed to another consumer; this one accepts aud %q", v.cfg.Audience))
		case errors.Is(err, jwt.ErrTokenInvalidIssuer):
			return nil, reject(fmt.Sprintf("wrong issuer; this deployment accepts iss %q", v.cfg.Issuer))
		case errors.Is(err, jwt.ErrTokenRequiredClaimMissing):
			return nil, reject("the token is missing a required claim (exp, aud and iss are all mandatory)")
		default:
			return nil, reject("the signature is not valid")
		}
	}

	// 6. Audience presence, checked by hand against the verified claims.
	//
	// This library does require the claim when an expected audience is given, so
	// today this is redundant — and it stays because the check must not depend on
	// that remaining true. Several widely used JWT libraries treat a missing aud
	// as acceptable and compare only when the token happens to carry one, which
	// makes "pass an expected audience to the parser" not an audience check at
	// all. One line here is cheaper than depending on a library's disposition.
	if len(claims.Audience) == 0 {
		return nil, reject("the token carries no aud claim")
	}

	// 7. Bound the CLAIMED lifetime, independently of whether it has expired.
	if claims.ExpiresAt == nil {
		return nil, reject("the token carries no exp claim")
	}
	now := v.now()
	if life := claims.ExpiresAt.Sub(now); life > v.cfg.MaxTokenAge {
		return nil, reject(fmt.Sprintf(
			"the token claims %s of validity; the maximum here is %s — a handoff token is not a session token",
			life.Round(time.Second), v.cfg.MaxTokenAge))
	}

	// 8. Purpose, then issuer. Exact strings, against verified claims. Purpose is
	// what stops a token the SIEM minted with the same key for some other job
	// from working as a sign-in: a signature says the SIEM produced it, not that
	// the SIEM meant it for GuardRail's front door.
	if claims.Purpose != iam.SSOPurpose {
		return nil, reject(fmt.Sprintf("wrong purpose; this endpoint accepts only purpose %q", iam.SSOPurpose))
	}

	// 9. A nonce must be present. Consuming it is the application layer's job —
	// it owns the replay store — but a token with nothing to consume can never be
	// made single-use, and accepting one would leave the whole replay defence
	// switchable off by the issuer.
	if strings.TrimSpace(claims.Nonce) == "" {
		return nil, reject("the token carries no nonce, so it cannot be made single-use")
	}

	return &iam.SSOAssertion{
		Subject:     strings.TrimSpace(claims.Subject),
		Email:       strings.TrimSpace(claims.Email),
		Username:    strings.TrimSpace(claims.Username),
		DisplayName: firstNonEmpty(claims.FullName, claims.Name),
		Role:        claims.Role,
		Access:      claims.Access,
		Nonce:       strings.TrimSpace(claims.Nonce),
		ExpiresAt:   claims.ExpiresAt.Time,
		Leeway:      v.cfg.ClockLeeway,
		AMR:         claims.AMR,
	}, nil
}

// keyFor routes an algorithm to its key material and resolves the key.
func (v *SSOTokenVerifier) keyFor(ctx context.Context, alg, kid string) (crypto.PublicKey, error) {
	if _, ok := asymmetricAlgs[alg]; ok {
		if v.keys == nil {
			// A token problem, not an outage: the SIEM has moved to asymmetric
			// signing ahead of this deployment being told where its keys are.
			return nil, reject(fmt.Sprintf("%s was presented but no SIEM JWKS URL is configured here", alg))
		}
		key, err := v.keys.Key(ctx, kid)
		switch {
		case err == nil:
			return key, nil
		case errors.Is(err, ErrJWKSKeyNotFound):
			return nil, reject(strings.TrimPrefix(err.Error(), "security: "))
		default:
			return nil, fmt.Errorf("%w: %v", iam.ErrSSOUnavailable, err)
		}
	}
	if _, ok := symmetricAlgs[alg]; ok {
		if len(v.secret) == 0 {
			return nil, reject("symmetric signing is not accepted here; the SIEM must sign with a key from its JWKS")
		}
		return v.secret, nil
	}
	// Everything else, "none" included. Named in the message because the SIEM's
	// engineers are who reads it and the algorithm is the whole answer.
	return nil, reject(fmt.Sprintf("unsupported signing algorithm %q", alg))
}

// peekHeader decodes the JOSE header without verifying anything, to learn which
// key and which algorithm the token is asking for.
func peekHeader(raw string) (alg, kid string, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", "", errors.New("security: token is not a three-part JWS")
	}
	blob, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("security: decode token header: %w", err)
	}
	var h struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(blob, &h); err != nil {
		return "", "", fmt.Errorf("security: parse token header: %w", err)
	}
	if h.Alg == "" {
		return "", "", errors.New("security: token header names no algorithm")
	}
	return h.Alg, h.Kid, nil
}

// reject wraps the token sentinel with a reason written to be read by a person —
// specifically by whoever is wiring the SIEM up, since they are the only ones
// who ever see it and a bare status code tells them nothing.
func reject(reason string) error {
	return fmt.Errorf("%w: %s", iam.ErrSSOToken, reason)
}

func firstNonEmpty(vals ...string) string {
	for _, s := range vals {
		if t := strings.TrimSpace(s); t != "" {
			return t
		}
	}
	return ""
}
