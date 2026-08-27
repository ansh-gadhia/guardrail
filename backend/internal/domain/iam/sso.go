package iam

import (
	"context"
	"strings"
	"time"
)

// ---- SIEM single sign-on ----
//
// The SIEM authenticates the person. GuardRail never sees their password, never
// runs a redirect dance with the SIEM, and never calls back to ask a question.
// The SIEM mints a short-lived signed assertion — an exchange token — and
// GuardRail trades it for a session of its own.
//
// This is deliberately not OIDC (GuardRail has OIDC already, see federation.go,
// and it is the right answer when the identity provider IS an OIDC provider).
// There is no authorization code, no redirect back to the issuer, no client
// secret and no discovery document. One JWT, one POST, one session back. What it
// costs the far side is an HTTP endpoint, a JWT library and a key.

// SSOPurpose is the exact value the "purpose" claim must carry.
//
// It exists so that a token the SIEM mints with the same key for some other
// reason — a webhook signature, an internal service call — cannot be replayed
// here as a login. A key is not a permission, and a signature alone says only
// "the SIEM produced this", not "the SIEM meant this for GuardRail's front door".
const SSOPurpose = "sso_exchange"

// SSOAssertion is a verified exchange token: what the SIEM said about a person,
// after the signature, the audience, the issuer, the purpose and the expiry have
// all been checked.
//
// Every field here is ASSERTED, not decided. Nothing in this struct is a
// GuardRail privilege — Role and Access are the SIEM's own vocabulary, and the
// translation into a GuardRail role happens in the application layer where the
// ceiling is applied. Keeping the two apart is what makes it possible to read
// this type and know that constructing one grants nothing.
type SSOAssertion struct {
	// Subject is the SIEM's immutable identifier for the person. It is the join
	// key: see SSOIdentity for why it, and not the email address, is what a
	// GuardRail account is linked by.
	Subject string
	Email   string
	// Username and DisplayName are cosmetic. A collision on Username is dropped
	// rather than failing the login.
	Username    string
	DisplayName string

	// Role and Access are the SIEM's role vocabulary ("L2", "read-only"). They
	// are translated by SSORoleMap; unrecognised values fall to the default role
	// rather than failing a sign-in.
	Role   string
	Access string

	// Nonce is the token's single-use marker, consumed against the replay store.
	Nonce string
	// ExpiresAt is the token's own expiry, used to derive how long the nonce must
	// be remembered. Remembering it for a fixed period instead is the mistake
	// that quietly reopens the replay window; see ReplayRetention.
	ExpiresAt time.Time
	// Leeway is the clock skew that was granted when the signature was checked.
	// It extends the replay window for exactly the same reason it extends the
	// validity window: a token still accepted at T must still be remembered at T.
	Leeway time.Duration

	// AMR is the authentication-methods-references claim, if the SIEM sends one.
	// It is consulted only when this deployment has been told to trust it; see
	// SSOTrustAMR in the config. Absent or untrusted, GuardRail asks for its own
	// second factor.
	AMR []string
}

// AssertsMFA reports whether the SIEM claims it verified a second factor.
//
// Read only where the deployment has opted into trusting it. On a privileged
// access broker the default is not to: "the SIEM says they did MFA" and "this
// person proved possession of a factor GuardRail knows about" are different
// claims, and only the second survives the SIEM being wrong.
func (a *SSOAssertion) AssertsMFA() bool {
	for _, m := range a.AMR {
		switch strings.ToLower(strings.TrimSpace(m)) {
		case "mfa", "otp", "totp", "hwk", "swk", "pop":
			return true
		}
	}
	return false
}

// ReplayRetention is how long this token's nonce must be remembered for a replay
// to be impossible: until the last instant the token itself would still verify.
//
// Derived from the token rather than fixed, and that is the whole point. A flat
// retention ("60 seconds, double the 30-second TTL") is correct only for the
// clock leeway it was written against. Someone widens the leeway later, in a
// different file, for a good reason — and the arithmetic silently breaks: the
// token stays valid past the moment its nonce was forgotten, and a replay window
// opens that no line of code announces.
//
// floor and ceiling bound the result: floor so a token that has already nearly
// expired still leaves a mark, ceiling so a token claiming a year of validity
// cannot pin an entry in the replay store for a year. The ceiling can never be
// what reopens the window, because SSOMaxTokenAge refuses such a token outright
// before this is ever reached.
func (a *SSOAssertion) ReplayRetention(now time.Time, floor, ceiling time.Duration) time.Duration {
	d := a.ExpiresAt.Add(a.Leeway).Sub(now)
	if d < floor {
		d = floor
	}
	if ceiling > 0 && d > ceiling {
		d = ceiling
	}
	return d
}

// SSOIdentity is the link between a GuardRail account and the SIEM's idea of the
// same person.
//
// Subject is what the account is FOUND by. Email is a display attribute that
// changes — people marry, companies migrate domains, an address is corrected —
// and an account keyed on it is orphaned by every one of those. The next sign-in
// then finds nothing, provisions a second account, and the original's roles,
// approval rank and history belong to somebody who can no longer reach them.
// Nothing errors. It surfaces weeks later as "why can't I get to anything".
type SSOIdentity struct {
	// Subject is the SIEM's immutable user id. Empty on every account that has
	// never signed in through the SIEM, which is most of them.
	Subject string
	// Managed marks an account whose role assignment tracks the SIEM. Cleared the
	// moment a GuardRail administrator edits the roles by hand: that edit is a
	// local decision, and letting the next sign-in overwrite it silently is how a
	// deliberate change lasts until the person next logs in and no longer.
	Managed bool
	// SourceRole records the SIEM-side role last seen, e.g. "L3:ro". Pure
	// provenance — it answers "why does this person hold this role" without
	// anybody having to reconstruct the mapping from memory.
	SourceRole string
}

// SSOVerifier turns a raw exchange token into a verified assertion, or explains
// why it could not.
//
// The distinction its errors must preserve is between "this token is bad" and
// "we cannot check right now". Collapsing the two sends the SIEM's engineers
// hunting for a signature fault that does not exist, or leaves a client retrying
// a forgery forever inside somebody else's error budget.
type SSOVerifier interface {
	VerifySSOToken(ctx context.Context, raw string) (*SSOAssertion, error)
	// Configured reports whether any key material is wired at all, so the
	// capability probe can advertise the button and the exchange can answer 503
	// rather than 401 when it is not.
	Configured() bool
}

// ReplayStore remembers the nonces of exchange tokens that have been spent.
//
// Consume must be atomic: it records the nonce and reports whether it was
// already there, in one operation. A read-then-write would let two copies of the
// same token arriving together both find it absent.
type ReplayStore interface {
	// Consume returns true when the nonce was unused (and is now recorded), false
	// when it had already been spent. An error means the store could not answer —
	// which is NOT the same as "unused", and callers must not treat it as such.
	Consume(ctx context.Context, nonce string, ttl time.Duration) (bool, error)
}
