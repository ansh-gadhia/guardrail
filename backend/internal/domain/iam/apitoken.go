package iam

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"
)

// APITokenPrefix marks a credential as a GuardRail machine token.
//
// It exists so the auth middleware can tell an API token from a JWT by looking
// at it, instead of trying to parse every bearer as a JWT and falling back on
// failure — which would make an expired session token and a valid API token
// indistinguishable in the logs. It also makes a leaked token greppable: secret
// scanners key off exactly this kind of fixed prefix.
const APITokenPrefix = "grt_"

// APITokenBytes is the entropy behind a token. 32 bytes is not negotiable
// downwards: this credential does not expire by default and is verified with a
// plain hash, so its only defence is being unguessable.
const APITokenBytes = 32

// ErrTokenScope is returned when a token is asked to carry a permission machine
// credentials may not hold.
var ErrTokenScope = errors.New("iam: permission not allowed for an API token")

// APIToken is a long-lived credential belonging to an organization rather than
// to a person.
//
// It authenticates directly — no login, no refresh — which is the entire point:
// a monitoring script polling every thirty seconds should not be minting a
// session and an audit event each time.
type APIToken struct {
	ID             ID
	OrganizationID ID
	Name           string
	// Prefix is the visible leading fragment, stored in clear so a human can
	// tell two tokens apart when deciding which to revoke.
	Prefix string
	Hash   []byte
	Scopes []string
	// CreatedBy is the human who issued it; nil once that account is deleted.
	// Issuing a machine credential is an act somebody is accountable for.
	CreatedBy  *ID
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
	CreatedAt  time.Time
}

// IsUsable reports whether the token may authenticate right now.
func (t *APIToken) IsUsable(now time.Time) bool {
	if t.RevokedAt != nil {
		return false
	}
	if t.ExpiresAt != nil && !now.Before(*t.ExpiresAt) {
		return false
	}
	return true
}

// Claims renders the token as a principal.
//
// UserID is the TOKEN's id, not the issuer's. Attributing a token's actions to
// the human who created it would put their name on things they did not do, which
// is precisely the confusion an audit trail exists to prevent. Email carries the
// token's name so log lines read "apitoken:noc-dashboard" instead of a bare UUID.
//
// IsSuperAdmin is always false. A token is a fixed list of permissions and
// nothing else: super admin means "everything, including permissions that do not
// exist yet", which is not a thing to hand a script.
func (t *APIToken) Claims() Claims {
	return Claims{
		UserID:         t.ID,
		OrganizationID: t.OrganizationID,
		Email:          "apitoken:" + t.Name,
		IsSuperAdmin:   false,
		Permissions:    append([]string(nil), t.Scopes...),
	}
}

// AllowedTokenScopes is the closed set of permissions a machine token may carry.
//
// Reads only, and that is a deliberate limit rather than an oversight. Two
// reasons, either sufficient:
//
//   - access_sessions.user_id is a foreign key to users, so a token literally
//     cannot be the actor on a brokered session. device:connect would fail at
//     the database, at connect time, in front of somebody who needed access.
//   - a credential that never expires, lives in a config file on a monitoring
//     box, and can open a privileged session to a firewall is a different and
//     much larger decision than "let the dashboard see what is online".
//
// Widening this means answering who owns a session a machine opened, and what
// the recording of it is evidence of. Until there is an answer, reads only.
var AllowedTokenScopes = map[string]struct{}{
	"device:read":    {},
	"session:read":   {},
	"recording:read": {},
	"group:read":     {},
	"log:read":       {},
	"report:read":    {},
	"user:read":      {},
	"role:read":      {},
	"team:read":      {},
	"org:read":       {},
}

// ValidateScopes checks a requested scope set, returning it de-duplicated and in
// the caller's order. An empty request is an error rather than a token that can
// read nothing: silently issuing a useless credential wastes somebody's
// afternoon working out why their dashboard is empty.
//
// Both failures wrap a sentinel the delivery layer already maps. They used to be
// bare errors, which fell through to the default case and answered 500 — so a
// console asking for a scope that is simply not allowed was told the server had
// broken, rather than told which scope to drop.
func ValidateScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: an API token needs at least one scope", ErrInvalidInput)
	}
	seen := make(map[string]bool, len(scopes))
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := AllowedTokenScopes[s]; !ok {
			return nil, ErrTokenScope
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%w: an API token needs at least one scope", ErrInvalidInput)
	}
	return out, nil
}

// NewAPITokenSecret mints a token, returning the value to show the caller once
// and the hash to store.
func NewAPITokenSecret() (raw string, hash []byte, prefix string, err error) {
	buf := make([]byte, APITokenBytes)
	if _, err = rand.Read(buf); err != nil {
		return "", nil, "", err
	}
	raw = APITokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	sum := HashAPIToken(raw)
	// Long enough to identify a token among a handful, far too short to be
	// brute-forced back into the whole value.
	return raw, sum, raw[:len(APITokenPrefix)+8], nil
}

// HashAPIToken is the stored form of a token.
func HashAPIToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// LooksLikeAPIToken reports whether a bearer value is one of ours.
func LooksLikeAPIToken(bearer string) bool {
	return strings.HasPrefix(bearer, APITokenPrefix)
}

// APITokenRepository persists machine tokens (tenant-scoped except for the
// lookup, which cannot be: authentication is what establishes the tenant).
type APITokenRepository interface {
	Create(ctx context.Context, s TenantScope, t *APIToken) error
	List(ctx context.Context, s TenantScope) ([]APIToken, error)
	Revoke(ctx context.Context, s TenantScope, id ID, at time.Time) error
	// FindByHash resolves a presented token. It runs unscoped by necessity —
	// there is no organization to scope to until the token identifies one.
	FindByHash(ctx context.Context, hash []byte) (*APIToken, error)
	// TouchUsed records that a token authenticated. Callers throttle: this is on
	// the path of every request a token makes.
	TouchUsed(ctx context.Context, id ID, at time.Time) error
}
