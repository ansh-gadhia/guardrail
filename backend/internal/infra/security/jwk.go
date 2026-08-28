package security

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// JWK parsing (RFC 7517 / RFC 7518), written out rather than pulled in.
//
// Three key types cover every algorithm this code will verify, the whole format
// is a handful of base64url integers, and a JWKS parser sits directly on the
// authentication path of a privileged-access broker. A dependency here would be
// a third party with a vote on who gets in; sixty lines of arithmetic is not.

// jwkSet is a JSON Web Key Set as published at a JWKS URL.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// jwk is one key. Unknown members are ignored, which is required: a key set is
// allowed to carry members this code has never heard of, and refusing the whole
// document over one would let the SIEM break every login by adding a field.
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Crv string `json:"crv"`

	N string `json:"n"` // RSA modulus
	E string `json:"e"` // RSA public exponent
	X string `json:"x"` // EC x / OKP public key
	Y string `json:"y"` // EC y
}

// verificationKey is one usable public key from a key set, with the identifiers
// a token uses to select it.
type verificationKey struct {
	kid string
	alg string // the key's own declared algorithm, "" when it does not declare one
	pub crypto.PublicKey
}

// parseJWKS decodes a key set and returns every key that can verify a signature.
//
// Keys that cannot are skipped rather than fatal. A real key set routinely holds
// encryption keys, key types this build does not implement, and keys published
// early for a rotation that has not happened yet; refusing the document because
// one member is unusable would take down every login for a key nobody is
// signing with. An empty result is the caller's problem to report.
func parseJWKS(body []byte) ([]verificationKey, error) {
	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, fmt.Errorf("security: parse jwks: %w", err)
	}
	out := make([]verificationKey, 0, len(set.Keys))
	for i := range set.Keys {
		k := &set.Keys[i]
		// "use" is optional; when present, anything but "sig" is a key published
		// for a different job and must not be pressed into verifying tokens.
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil || pub == nil {
			continue
		}
		out = append(out, verificationKey{kid: k.Kid, alg: k.Alg, pub: pub})
	}
	return out, nil
}

// publicKey converts one JWK to a crypto.PublicKey, or returns an error for a
// key type or curve this build does not verify.
func (k *jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		return k.rsaKey()
	case "EC":
		return k.ecKey()
	case "OKP":
		return k.okpKey()
	default:
		return nil, fmt.Errorf("security: unsupported jwk kty %q", k.Kty)
	}
}

func (k *jwk) rsaKey() (*rsa.PublicKey, error) {
	n, err := b64uint(k.N)
	if err != nil {
		return nil, err
	}
	e, err := b64uint(k.E)
	if err != nil {
		return nil, err
	}
	// A 2048-bit floor. Below it the key is not a key, it is a formality — and
	// accepting one because the SIEM published it would mean the weakest key in
	// the set decides how hard the front door is to forge.
	if n.BitLen() < 2048 {
		return nil, fmt.Errorf("security: rsa key is %d bits, minimum is 2048", n.BitLen())
	}
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, fmt.Errorf("security: implausible rsa exponent")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func (k *jwk) ecKey() (*ecdsa.PublicKey, error) {
	// Both spellings of the same curve: elliptic for the key ecdsa.Verify wants,
	// ecdh for the on-curve check below.
	var (
		curve     elliptic.Curve
		agreement ecdh.Curve
	)
	switch k.Crv {
	case "P-256":
		curve, agreement = elliptic.P256(), ecdh.P256()
	case "P-384":
		curve, agreement = elliptic.P384(), ecdh.P384()
	case "P-521":
		curve, agreement = elliptic.P521(), ecdh.P521()
	default:
		return nil, fmt.Errorf("security: unsupported ec curve %q", k.Crv)
	}
	x, err := b64uint(k.X)
	if err != nil {
		return nil, err
	}
	y, err := b64uint(k.Y)
	if err != nil {
		return nil, err
	}
	// Checked, not assumed. A pair of integers that is not on the curve is not a
	// public key, and handing one to a verifier is how invalid-curve attacks
	// start. This costs one check per key set fetch, not per token.
	//
	// Through crypto/ecdh rather than elliptic.IsOnCurve, which is deprecated as
	// a low-level unsafe API. NewPublicKey takes the SEC 1 uncompressed encoding
	// of the same point and applies the same check, so this is the supported
	// spelling of what was already here, not a change of mind about what is safe.
	size := (curve.Params().BitSize + 7) / 8
	// Bounds first: FillBytes PANICS on a coordinate too wide for the field, and
	// both of these arrived as base64 from a URL the SIEM controls.
	if x.BitLen() > size*8 || y.BitLen() > size*8 {
		return nil, fmt.Errorf("security: ec coordinate is too wide for curve %s", k.Crv)
	}
	point := make([]byte, 1+2*size)
	point[0] = 4 // uncompressed
	x.FillBytes(point[1 : 1+size])
	y.FillBytes(point[1+size:])
	if _, err := agreement.NewPublicKey(point); err != nil {
		return nil, fmt.Errorf("security: ec point is not on curve %s", k.Crv)
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

func (k *jwk) okpKey() (ed25519.PublicKey, error) {
	if k.Crv != "Ed25519" {
		return nil, fmt.Errorf("security: unsupported okp curve %q", k.Crv)
	}
	raw, err := b64bytes(k.X)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("security: ed25519 key is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// b64bytes decodes an unpadded base64url member.
//
// RawURLEncoding specifically: JOSE members are unpadded, and a decoder that
// tolerates padding would accept two spellings of the same key.
func b64bytes(s string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("security: empty jwk member")
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("security: decode jwk member: %w", err)
	}
	return b, nil
}

// b64uint decodes an unpadded base64url member as a big-endian unsigned integer.
func b64uint(s string) (*big.Int, error) {
	b, err := b64bytes(s)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(b), nil
}
