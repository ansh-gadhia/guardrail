package proxy

import (
	"encoding/base64"
	"net/http"
	"sync"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// authHeader is the Authorization value injected into every proxied request for
// one session, held in memory that can actually be erased.
//
// # WHAT THIS REPLACES
//
// The director closure used to capture the whole access.Credential, and the
// closure lives in the session map for the life of the session — an hour, a
// day, whatever the grant allows. So a device's plaintext password sat in the
// API's heap for the entire session rather than just during injection, and
// End() could not do anything about it: it deleted the map entry and left the
// rest to the garbage collector. Credential.Secret is a Go string, and a string
// cannot be overwritten. There was no code anyone could write to erase it.
//
// That contradicted the product's own claim — docs/SECURITY.md: "Plaintext
// secrets exist only transiently in memory during inject" — which the SSH
// gateway honours by re-resolving from the vault on every dial. The HTTP proxy
// could not copy that approach: it would mean a vault decrypt and an audit
// record for every proxied image and stylesheet, hundreds per page.
//
// # WHY THE DERIVED HEADER RATHER THAN THE SECRET
//
// What the session actually needs is not the password, it is the header the
// password produces. Deriving it once at Establish means:
//
//   - the long-lived copy is a []byte, so End() can zero it, and does;
//   - the raw password string becomes garbage the moment Establish returns,
//     instead of being pinned for the session;
//   - it is FASTER. http.Request.SetBasicAuth base64-encodes on every single
//     call, so the old code re-encoded the same credential for every request of
//     every session. This encodes once.
//
// The transient string conversion in apply is unavoidable — net/http headers
// are strings — but it is per-request garbage, not a session-lifetime pin.
//
// This does not defend against an attacker reading process memory DURING a live
// session; nothing can, short of not holding the secret at all. It bounds the
// window to the session rather than to whenever the collector next runs, and it
// makes teardown mean something.
type authHeader struct {
	mu sync.RWMutex
	v  []byte
}

// newAuthHeader derives the Authorization value for a credential, or nil when
// the credential injects nothing.
func newAuthHeader(cred access.Credential) *authHeader {
	switch cred.Injection {
	case "basic":
		// Same encoding as http.Request.SetBasicAuth, computed once.
		raw := cred.Username + ":" + cred.Secret
		enc := base64.StdEncoding.EncodeToString([]byte(raw))
		return &authHeader{v: []byte("Basic " + enc)}
	case "header":
		// Secret carries the full header value, e.g. "Bearer <token>".
		return &authHeader{v: []byte(cred.Secret)}
	default:
		// "none", and anything this gateway does not apply. Holding nothing is
		// better than holding something unused.
		return nil
	}
}

// apply sets the header on an outbound request. A nil receiver injects nothing,
// so callers do not have to check.
func (a *authHeader) apply(req *http.Request) {
	if a == nil {
		return
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if len(a.v) == 0 {
		// Destroyed. A request that races teardown goes out without the header
		// and the device refuses it, which is the right way round: the
		// alternative is reading freed credential bytes.
		return
	}
	req.Header.Set("Authorization", string(a.v))
}

// destroy zeroes the header bytes. Safe to call more than once, and on nil.
func (a *authHeader) destroy() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for i := range a.v {
		a.v[i] = 0
	}
	a.v = nil
}
