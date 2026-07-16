// Package federation implements external identity-provider adapters: an OIDC
// relying party (Authorization Code + PKCE) and an LDAP/AD bind authenticator.
// Adapters return a verified iam.ExternalIdentity; JIT user provisioning and
// token issuance happen in the IAM application layer.
package federation

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/guardrail/guardrail/internal/domain/iam"
)

// OIDCConfig configures the relying party.
type OIDCConfig struct {
	Issuer       string   // e.g. https://accounts.example.com
	ClientID     string   // registered client id
	ClientSecret string   // client secret (confidential client)
	RedirectURL  string   // this app's callback URL
	Scopes       []string // defaults to [openid, email, profile]
}

// discovery is the subset of the OIDC discovery document we consume.
type discovery struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
}

// OIDCProvider is a minimal, dependency-free OIDC relying party supporting the
// Authorization Code flow with PKCE (S256) and RS256 ID-token verification.
type OIDCProvider struct {
	cfg    OIDCConfig
	client *http.Client

	mu    sync.Mutex
	disco *discovery
	keys  map[string]*rsa.PublicKey
}

// NewOIDCProvider builds a provider. Discovery and JWKS are fetched lazily and
// cached. The HTTP client carries a sane timeout.
func NewOIDCProvider(cfg OIDCConfig) *OIDCProvider {
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	return &OIDCProvider{
		cfg:    cfg,
		client: &http.Client{Timeout: 10 * time.Second},
		keys:   map[string]*rsa.PublicKey{},
	}
}

// SetHTTPClient overrides the HTTP client (used by tests to target httptest).
func (p *OIDCProvider) SetHTTPClient(c *http.Client) { p.client = c }

// AuthCodeURL builds the authorization-request URL for the given state, nonce,
// and PKCE code challenge (S256).
func (p *OIDCProvider) AuthCodeURL(state, nonce, codeChallenge string) string {
	d, err := p.discover(context.Background())
	if err != nil {
		return ""
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURL)
	q.Set("scope", strings.Join(p.cfg.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	return d.AuthEndpoint + "?" + q.Encode()
}

// Exchange trades an authorization code for tokens, verifies the ID token
// (signature, issuer, audience, expiry, nonce) and returns the identity.
func (p *OIDCProvider) Exchange(ctx context.Context, code, codeVerifier, nonce string) (*iam.ExternalIdentity, error) {
	d, err := p.discover(ctx)
	if err != nil {
		return nil, err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", p.cfg.RedirectURL)
	form.Set("client_id", p.cfg.ClientID)
	form.Set("code_verifier", codeVerifier)
	if p.cfg.ClientSecret != "" {
		form.Set("client_secret", p.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: token request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: token endpoint status %d", resp.StatusCode)
	}
	var tok struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return nil, fmt.Errorf("oidc: decode token response: %w", err)
	}
	if tok.IDToken == "" {
		return nil, fmt.Errorf("oidc: no id_token in response")
	}
	return p.verifyIDToken(ctx, tok.IDToken, nonce)
}

// idTokenClaims are the non-standard claims we read from a verified ID token.
// Standard claims (iss/sub/aud/exp/iat) live in the embedded RegisteredClaims so
// the jwt validator enforces them.
type idTokenClaims struct {
	Email    string `json:"email"`
	Username string `json:"preferred_username"`
	Name     string `json:"name"`
	Nonce    string `json:"nonce"`
	jwt.RegisteredClaims
}

func (p *OIDCProvider) verifyIDToken(ctx context.Context, raw, nonce string) (*iam.ExternalIdentity, error) {
	var claims idTokenClaims
	_, err := jwt.ParseWithClaims(raw, &claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("oidc: unexpected signing method %q", t.Header["alg"])
		}
		kid, _ := t.Header["kid"].(string)
		return p.keyByID(ctx, kid)
	}, jwt.WithAudience(p.cfg.ClientID), jwt.WithIssuer(p.cfg.Issuer))
	if err != nil {
		return nil, fmt.Errorf("oidc: verify id_token: %w", err)
	}
	if nonce != "" && claims.Nonce != nonce {
		return nil, fmt.Errorf("oidc: nonce mismatch")
	}
	if claims.Subject == "" {
		return nil, fmt.Errorf("oidc: id_token missing sub")
	}
	return &iam.ExternalIdentity{
		Provider:    "oidc",
		Subject:     claims.RegisteredClaims.Subject,
		Email:       claims.Email,
		Username:    claims.Username,
		DisplayName: claims.Name,
	}, nil
}

// discover fetches and caches the discovery document.
func (p *OIDCProvider) discover(ctx context.Context) (*discovery, error) {
	p.mu.Lock()
	if p.disco != nil {
		d := p.disco
		p.mu.Unlock()
		return d, nil
	}
	p.mu.Unlock()

	u := strings.TrimRight(p.cfg.Issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: discovery status %d", resp.StatusCode)
	}
	var d discovery
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return nil, fmt.Errorf("oidc: decode discovery: %w", err)
	}
	p.mu.Lock()
	p.disco = &d
	p.mu.Unlock()
	return &d, nil
}

// keyByID returns the RSA public key for a JWKS key id, fetching JWKS on a miss.
func (p *OIDCProvider) keyByID(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	p.mu.Lock()
	if k, ok := p.keys[kid]; ok {
		p.mu.Unlock()
		return k, nil
	}
	p.mu.Unlock()

	if err := p.refreshJWKS(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[kid]; ok {
		return k, nil
	}
	// Single-key providers may omit kid; fall back to any cached key.
	if kid == "" {
		for _, k := range p.keys {
			return k, nil
		}
	}
	return nil, fmt.Errorf("oidc: no JWKS key for kid %q", kid)
}

// jwk is a single JSON Web Key (RSA).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (p *OIDCProvider) refreshJWKS(ctx context.Context) error {
	d, err := p.discover(ctx)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.JWKSURI, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: jwks: %w", err)
	}
	defer resp.Body.Close()
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&set); err != nil {
		return fmt.Errorf("oidc: decode jwks: %w", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaFromJWK(k)
		if err != nil {
			continue
		}
		p.keys[k.Kid] = pub
	}
	return nil
}

// rsaFromJWK reconstructs an RSA public key from a JWK's base64url n and e.
func rsaFromJWK(k jwk) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, err
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, err
	}
	e := 0
	for _, b := range eb {
		e = e<<8 | int(b)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: e}, nil
}

var _ iam.OIDCAuthenticator = (*OIDCProvider)(nil)
