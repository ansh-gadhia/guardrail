package access

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func approved(scope *GrantScope, expires time.Time) *Request {
	return &Request{Status: RequestApproved, GrantScope: scope, ExpiresAt: expires}
}

// A standing-grant approval must not double as a one-shot approval.
//
// Regression: revoking standing access left the original request redeemable, so
// the operator reconnected on it anyway. Revocation that the person being
// revoked can walk straight through is not revocation.
func TestApprovedAlwaysIsNotIndependentlyRedeemable(t *testing.T) {
	future := time.Now().Add(time.Hour)
	once, always := GrantOnce, GrantAlways

	if !approved(&once, future).Redeemable(time.Now()) {
		t.Fatal("an allow-once approval must be redeemable")
	}
	if approved(&always, future).Redeemable(time.Now()) {
		t.Fatal("an allow-all-time approval must NOT be redeemable on its own: its " +
			"authorization lives in the grant, which is the thing that gets revoked")
	}
	// A request approved before scopes existed carries none, and must still work.
	if !approved(nil, future).Redeemable(time.Now()) {
		t.Fatal("an approval with no scope recorded must remain redeemable")
	}
}

func TestRedeemableRefusesUsedAndExpired(t *testing.T) {
	once := GrantOnce
	future, past := time.Now().Add(time.Hour), time.Now().Add(-time.Hour)

	used := approved(&once, future)
	sid := uuid.New()
	used.SessionID = &sid
	if used.Redeemable(time.Now()) {
		t.Fatal("an approval already turned into a session must not be redeemable again")
	}
	if approved(&once, past).Redeemable(time.Now()) {
		t.Fatal("an expired approval must not be redeemable — otherwise 'allow once' " +
			"quietly becomes a standing grant nobody wrote down")
	}
	pending := &Request{Status: RequestPending, ExpiresAt: future}
	if pending.Redeemable(time.Now()) {
		t.Fatal("a pending request is not an approval")
	}
}

// The two-person rule counts distinct approvals, and a single denial settles it
// regardless of how many approvals were required.
func TestApprovalCounting(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	r := &Request{MinApprovals: 2}
	r.Decisions = []Decision{{DecidedBy: a, Decision: DecisionApprove}}
	if r.Satisfied() {
		t.Fatal("one of two approvals must not satisfy the rule")
	}
	if !r.DecidedBy(a) {
		t.Fatal("DecidedBy must recognise somebody who has already voted")
	}
	if r.DecidedBy(b) {
		t.Fatal("DecidedBy must not claim a vote nobody cast")
	}
	r.Decisions = append(r.Decisions, Decision{DecidedBy: b, Decision: DecisionApprove})
	if !r.Satisfied() {
		t.Fatal("two of two approvals must satisfy the rule")
	}

	denied := &Request{MinApprovals: 3, Decisions: []Decision{{Decision: DecisionDeny}}}
	if !denied.Denied() {
		t.Fatal("one denial settles it: raising the bar for granting access must " +
			"never raise the bar for refusing it")
	}
}

// A stored zero must never mean "gated, but nothing has to approve it".
func TestEffectiveMinApprovalsNeverZero(t *testing.T) {
	for _, n := range []int{-1, 0, 1} {
		if got := (&Request{MinApprovals: n}).EffectiveMinApprovals(); got < 1 {
			t.Fatalf("MinApprovals %d resolved to %d, which would gate a device and then open it", n, got)
		}
	}
}

// The window an approver settled on governs the session, falling back only when
// nothing was recorded.
func TestWindowPrefersWhatWasGranted(t *testing.T) {
	fallback := time.Hour
	granted := 15
	r := &Request{RequestedMinutes: 60, GrantedMinutes: &granted}
	if got := r.Window(fallback); got != 15*time.Minute {
		t.Fatalf("window = %v, want the 15 minutes granted", got)
	}
	r = &Request{RequestedMinutes: 30}
	if got := r.Window(fallback); got != 30*time.Minute {
		t.Fatalf("window = %v, want the 30 minutes asked for", got)
	}
	if got := (&Request{}).Window(fallback); got != fallback {
		t.Fatalf("window = %v, want the org default", got)
	}
}

func TestGrantLiveness(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Hour), now.Add(time.Hour)

	if !(&Grant{}).Live(now) {
		t.Fatal("a grant with no expiry is live — that is what 'allow all time' means")
	}
	if (&Grant{RevokedAt: &past}).Live(now) {
		t.Fatal("a revoked grant must stop authorizing immediately")
	}
	if (&Grant{ExpiresAt: &past}).Live(now) {
		t.Fatal("an expired grant must not be live")
	}
	if !(&Grant{ExpiresAt: &future}).Live(now) {
		t.Fatal("a grant that has not yet expired is live")
	}
}
