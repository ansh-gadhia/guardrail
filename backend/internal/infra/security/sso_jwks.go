package security

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// The JWKS fetch is the trust anchor for every SIEM-vouched sign-in.
//
// Whoever can answer this URL chooses the public key GuardRail will thereafter
// accept, and so mints tokens it treats as genuine. That turns "needs the SIEM's
// private key" into "needs to be on the network path", which on a
// privileged-access broker is the difference between a hard attack and a
// Tuesday. Everything careful in this file is downstream of that one sentence.

var (
	// ErrJWKSUnavailable means the key set could not be reached and nothing
	// usable was cached. GuardRail's outage, not the caller's — 503.
	ErrJWKSUnavailable = errors.New("security: jwks unavailable")
	// ErrJWKSKeyNotFound means the key set was read and does not contain the key
	// the token names. The token's problem, not GuardRail's — 401.
	//
	// Kept distinct from the above deliberately. Reporting "we cannot fetch" as
	// "your key is unknown" sends the SIEM's engineers to rotate a key that was
	// never the issue; reporting "unknown key" as a server fault invites a client
	// to retry a forgery forever inside GuardRail's own error budget.
	ErrJWKSKeyNotFound = errors.New("security: no key matches kid")
)

// JWKSConfig configures the key source.
type JWKSConfig struct {
	// URL is the SIEM's JWKS endpoint. HTTPS only — see NewJWKSSource.
	URL string
	// CABundlePath is a PEM file holding the certificate that must have signed
	// the JWKS host's TLS certificate, or that certificate itself when it is
	// self-signed. Empty uses the system trust store.
	CABundlePath string
	// CacheTTL is how long a fetched key set is served without refetching.
	CacheTTL time.Duration
	// RefetchCooldown is the minimum gap between the forced refetches an unknown
	// kid triggers, so a stream of unknown-kid tokens cannot turn GuardRail into
	// an amplifier aimed at the SIEM.
	RefetchCooldown time.Duration
	// Timeout bounds one fetch.
	Timeout time.Duration
}

func (c *JWKSConfig) withDefaults() {
	if c.CacheTTL <= 0 {
		c.CacheTTL = 10 * time.Minute
	}
	if c.RefetchCooldown <= 0 {
		c.RefetchCooldown = 30 * time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = 10 * time.Second
	}
}

// JWKSSource resolves a token's kid to a public key, keeping a cached copy of
// the SIEM's key set and refetching on rotation.
type JWKSSource struct {
	url             string
	client          *http.Client
	cacheTTL        time.Duration
	refetchCooldown time.Duration
	now             func() time.Time

	mu         sync.Mutex
	keys       []verificationKey
	fetchedAt  time.Time
	lastForced time.Time

	fetchMu sync.Mutex
}

// NewJWKSSource builds a key source, failing closed on anything it cannot make
// safe at construction time.
//
// Both refusals here are deliberate and neither has an override:
//
//   - Plain HTTP is refused. The entire value of this fetch is that the answer
//     came from the SIEM, and over HTTP it did not come from anywhere in
//     particular. A private network is not a substitute; it is precisely where
//     the attacker who benefits already is.
//   - A named-but-unreadable CA bundle is refused. Falling back to the system
//     trust store would mean a trust anchor that silently disappeared — a
//     deleted file, a bad mount, a typo — leaves the deployment trusting a
//     completely different set of issuers while every log line still says SSO is
//     configured. There is no verify-off switch for the same reason.
func NewJWKSSource(cfg JWKSConfig) (*JWKSSource, error) {
	cfg.withDefaults()
	if cfg.URL == "" {
		return nil, errors.New("security: jwks url is required")
	}
	if !strings.HasPrefix(strings.ToLower(cfg.URL), "https://") {
		return nil, fmt.Errorf("security: jwks url must be https, got %q", cfg.URL)
	}

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if cfg.CABundlePath != "" {
		pem, err := os.ReadFile(cfg.CABundlePath)
		if err != nil {
			return nil, fmt.Errorf("security: read jwks ca bundle: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("security: jwks ca bundle %s contains no certificate", cfg.CABundlePath)
		}
		// The pinned certificate replaces the system roots rather than adding to
		// them. Adding would leave every public CA still able to vouch for the
		// JWKS host, which is most of what pinning was for.
		tlsCfg.RootCAs = pool
	}

	return &JWKSSource{
		url: cfg.URL,
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig:     tlsCfg,
				DisableKeepAlives:   false,
				TLSHandshakeTimeout: cfg.Timeout,
			},
			// A JWKS endpoint has no business redirecting, and following one would
			// let whoever answers the configured URL move the fetch to a host the
			// pinned certificate was never checked against.
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return errors.New("security: jwks endpoint attempted a redirect")
			},
		},
		cacheTTL:        cfg.CacheTTL,
		refetchCooldown: cfg.RefetchCooldown,
		now:             time.Now,
	}, nil
}

// Key resolves the public key a token names.
//
// kid may be empty, which is only answerable when the key set holds exactly one
// key. With several, "whichever one works" is not a key selection — it is trying
// every key the issuer publishes against an attacker's signature, which is the
// opposite of what naming a key is for.
func (s *JWKSSource) Key(ctx context.Context, kid string) (crypto.PublicKey, error) {
	now := s.now()

	s.mu.Lock()
	keys, fetchedAt := s.keys, s.fetchedAt
	s.mu.Unlock()

	fresh := !fetchedAt.IsZero() && now.Sub(fetchedAt) < s.cacheTTL
	if fresh {
		if k, ok := pick(keys, kid); ok {
			return k, nil
		}
		// Fresh cache, unknown kid: the SIEM has probably just rotated. One forced
		// refetch, rate-limited.
		if !s.forceAllowed(now) {
			return nil, keyMiss(keys, kid)
		}
	}

	refreshed, err := s.refresh(ctx, now)
	if err != nil {
		// Fetch failed. A stale-but-real key set still verifies genuine tokens, so
		// it is served through a blip — but only when it actually holds the key
		// the token names. When it does not, "rotated to a key we cannot see" and
		// "kid invented by an attacker" are indistinguishable from here, and the
		// honest answer is that GuardRail cannot check right now.
		if k, ok := pick(keys, kid); ok {
			return k, nil
		}
		return nil, fmt.Errorf("%w: %v", ErrJWKSUnavailable, err)
	}
	if k, ok := pick(refreshed, kid); ok {
		return k, nil
	}
	return nil, keyMiss(refreshed, kid)
}

// keyMiss explains a lookup that failed against a key set that was read fine.
func keyMiss(keys []verificationKey, kid string) error {
	if kid == "" && len(keys) > 1 {
		return fmt.Errorf("%w: token carries no kid and the key set holds %d keys",
			ErrJWKSKeyNotFound, len(keys))
	}
	return fmt.Errorf("%w: %q", ErrJWKSKeyNotFound, kid)
}

// forceAllowed reports whether an unknown kid may trigger a refetch now, and
// records the attempt when it may.
func (s *JWKSSource) forceAllowed(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.lastForced.IsZero() && now.Sub(s.lastForced) < s.refetchCooldown {
		return false
	}
	s.lastForced = now
	return true
}

// refresh fetches and stores the key set. Concurrent callers collapse onto one
// fetch: the second waits, then finds the first one's result already fresh.
func (s *JWKSSource) refresh(ctx context.Context, since time.Time) ([]verificationKey, error) {
	s.fetchMu.Lock()
	defer s.fetchMu.Unlock()

	s.mu.Lock()
	keys, fetchedAt := s.keys, s.fetchedAt
	s.mu.Unlock()
	if !fetchedAt.Before(since) {
		return keys, nil // somebody fetched while this call was waiting
	}

	fetched, err := s.fetch(ctx)
	if err != nil {
		return nil, err
	}
	now := s.now()
	s.mu.Lock()
	s.keys, s.fetchedAt = fetched, now
	s.mu.Unlock()
	return fetched, nil
}

// maxJWKSBytes bounds the response body. A key set is a few kilobytes; without a
// limit, whatever answers this URL chooses how much memory GuardRail spends.
const maxJWKSBytes = 512 << 10

func (s *JWKSSource) fetch(ctx context.Context) ([]verificationKey, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("jwks endpoint returned %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxJWKSBytes {
		return nil, fmt.Errorf("jwks response exceeds %d bytes", maxJWKSBytes)
	}
	keys, err := parseJWKS(body)
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		// Not cached. An empty key set replacing a good one would silently end
		// every SSO sign-in until the next rotation, and a fetch that returns
		// nothing usable is far more likely to be a wrong URL or an error page
		// with a 200 on it than a genuine "we publish no keys".
		return nil, errors.New("jwks response contains no usable verification key")
	}
	return keys, nil
}

// pick selects the key a token named.
func pick(keys []verificationKey, kid string) (crypto.PublicKey, bool) {
	if len(keys) == 0 {
		return nil, false
	}
	if kid == "" {
		if len(keys) == 1 {
			return keys[0].pub, true
		}
		return nil, false
	}
	for i := range keys {
		if keys[i].kid == kid {
			return keys[i].pub, true
		}
	}
	return nil, false
}
