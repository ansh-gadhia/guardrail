package access

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// The console's first Connect on a gated device carries no reason. That is not a
// client bug: whether the gate applies at all is decided server-side — bypass
// permission, device ownership, a standing grant and an approval already in hand
// are all invisible from the browser — so the probe is how it finds out.
//
// It used to reach raiseRequest, come back as a bare access.ErrInvalid, and land
// as HTTP 500 "unexpected error" on every first click of an approval-gated
// device. The connect must instead come back asking for a reason.
func TestConnect_GatedDevice_ReasonlessProbeAsksForOne(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true, requiresApproval: true})

	res, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(),
		ReqMeta{IP: "203.0.113.9"}, ConnectOptions{})
	if err != nil {
		t.Fatalf("a reasonless probe must not fail: %v", err)
	}
	if !res.NeedsRequest {
		t.Error("NeedsRequest is false; the caller is never told they have to ask")
	}
	if res.Pending != nil {
		t.Error("a request was raised without a reason; an approver would be deciding blind")
	}
	if res.Session != nil {
		t.Error("a gated device handed out a session to somebody who never asked")
	}
	if n := len(h.requests.created); n != 0 {
		t.Errorf("%d request(s) stored for a probe that carried no reason, want 0", n)
	}
}

// Whitespace is not a reason. Trimming server-side matters because the rule is
// enforced here, not in the browser that happens to be calling today.
func TestConnect_GatedDevice_BlankReasonIsNotAReason(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true, requiresApproval: true})

	res, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(),
		ReqMeta{}, ConnectOptions{Reason: "   \t \n "})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.NeedsRequest {
		t.Error("a whitespace reason was accepted as one")
	}
}

// With a reason, the request is raised and the caller is told to wait.
func TestConnect_GatedDevice_WithAReasonRaisesTheRequest(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true, requiresApproval: true})

	res, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(),
		ReqMeta{}, ConnectOptions{Reason: "  investigating the outage  ", Minutes: 30})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.NeedsRequest {
		t.Error("NeedsRequest is set even though a reason was given")
	}
	if res.Pending == nil {
		t.Fatal("no pending request returned; the console has nothing to wait on")
	}
	if res.Session != nil {
		t.Error("a session was established while the request is still pending")
	}
	if got := res.Pending.Reason; got != "investigating the outage" {
		t.Errorf("stored reason = %q, want it trimmed", got)
	}
	if got := res.Pending.RequestedMinutes; got != 30 {
		t.Errorf("requested minutes = %d, want 30", got)
	}
}

// Pressing Connect again while a request is already in flight must surface that
// request, not demand a reason for one that has already been given. This is why
// the reason check sits below the outstanding-request branch rather than at the
// top of the gate.
func TestConnect_GatedDevice_SecondClickReturnsTheWaitingRequest(t *testing.T) {
	waiting := &access.Request{
		ID: uuid.New(), Status: access.RequestPending, Reason: "already asked",
		ExpiresAt: time.Date(2026, 7, 15, 12, 30, 0, 0, time.UTC),
	}
	h := newHarness(opts{
		entitled: true, hasCredential: true, requiresApproval: true, pendingRequest: waiting,
	})

	res, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(),
		ReqMeta{}, ConnectOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.NeedsRequest {
		t.Error("asked for a reason again while a request was already waiting")
	}
	if res.Pending == nil || res.Pending.ID != waiting.ID {
		t.Error("the request already in flight was not returned")
	}
	if n := len(h.requests.created); n != 0 {
		t.Errorf("%d duplicate request(s) raised, want 0", n)
	}
}

// A super admin never meets the gate, with or without a reason — the exemption
// the console cannot see, and the reason the probe has to exist.
func TestConnect_GatedDevice_SuperAdminConnectsWithoutAsking(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true, requiresApproval: true})

	res, err := h.svc.ConnectWith(context.Background(), superClaims(), uuid.New(),
		ReqMeta{}, ConnectOptions{})
	if err != nil {
		t.Fatalf("a super admin was gated: %v", err)
	}
	if res.NeedsRequest || res.Pending != nil {
		t.Error("a super admin was asked to justify a connect")
	}
	if res.Session == nil {
		t.Fatal("no session established for an exempt caller")
	}
}

// An ungated device is untouched by any of this: no reason, no request, no
// change from before approvals existed.
func TestConnect_UngatedDevice_IsUnaffected(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})

	res, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(),
		ReqMeta{}, ConnectOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.NeedsRequest || res.Pending != nil {
		t.Error("an ungated device asked for approval")
	}
	if res.Session == nil {
		t.Fatal("no session on an ungated device")
	}
}

// A gated device nobody can approve fails loudly at the moment somebody trips
// over it, rather than leaving them to wait out a TTL. Kept here so the reason
// gate above cannot quietly swallow it.
func TestConnect_GatedDevice_WithNoPossibleApproverIsRefused(t *testing.T) {
	none := 0
	h := newHarness(opts{
		entitled: true, hasCredential: true, requiresApproval: true, approversAbove: &none,
	})

	_, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(),
		ReqMeta{}, ConnectOptions{Reason: "need to reach the switch"})
	if !errors.Is(err, access.ErrNoApprover) {
		t.Fatalf("err = %v, want ErrNoApprover", err)
	}
}

// How long a session may run, and what actually ends one.
//
// Two limits with different jobs, and conflating them is what made a session in
// continuous use die at sixty minutes with work in it:
//
//   - An ordinary session gets the CEILING. It is not a countdown — the control
//     is the device's idle timeout, measured from the last keystroke, so nobody
//     is cut off mid-task. The ceiling only stops a session living forever.
//   - An approved session gets exactly the window that was granted, and activity
//     does not extend it. A window that stretches while you type is not a window,
//     and the approver who shortened it was answering a real question.
func TestConnect_SessionWindow(t *testing.T) {
	t.Run("an ordinary session runs to the ceiling, not the approval fallback", func(t *testing.T) {
		h := newHarness(opts{entitled: true, hasCredential: true})

		res, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(),
			ReqMeta{}, ConnectOptions{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := res.GrantedUntil.Sub(fixedNow)
		if got != DefaultConfig().MaxWindow {
			t.Errorf("window = %v, want the %v ceiling — a busy session must not die on the approval fallback",
				got, DefaultConfig().MaxWindow)
		}
	})

	t.Run("an approved window is honoured exactly", func(t *testing.T) {
		h := newHarness(opts{entitled: true, hasCredential: true, requiresApproval: true})
		actor := actorClaims()
		deviceID := uuid.New()

		// Ask, then approve for a shorter window than was requested.
		if _, err := h.svc.ConnectWith(context.Background(), actor, deviceID, ReqMeta{},
			ConnectOptions{Reason: "swapping the uplink", Minutes: 240}); err != nil {
			t.Fatalf("raise: %v", err)
		}
		raised := h.requests.created[0]
		granted := 30
		raised.Status, raised.GrantedMinutes = access.RequestApproved, &granted
		h.requests.pending = raised

		res, err := h.svc.ConnectWith(context.Background(), actor, deviceID, ReqMeta{}, ConnectOptions{})
		if err != nil {
			t.Fatalf("redeem: %v", err)
		}
		if res.Session == nil {
			t.Fatal("no session from an approved request")
		}
		if got := res.GrantedUntil.Sub(fixedNow); got != 30*time.Minute {
			t.Errorf("window = %v, want 30m — the approver shortened it and that has to bind", got)
		}
	})

	t.Run("an approved request with no window named falls back, not to the ceiling", func(t *testing.T) {
		h := newHarness(opts{entitled: true, hasCredential: true, requiresApproval: true})
		actor := actorClaims()
		deviceID := uuid.New()
		approved := &access.Request{
			ID: uuid.New(), Status: access.RequestApproved,
			Reason: "already approved", ExpiresAt: fixedNow.Add(10 * time.Minute),
		}
		h.requests.pending = approved

		res, err := h.svc.ConnectWith(context.Background(), actor, deviceID, ReqMeta{}, ConnectOptions{})
		if err != nil {
			t.Fatalf("redeem: %v", err)
		}
		if got := res.GrantedUntil.Sub(fixedNow); got != DefaultConfig().DefaultWindow {
			t.Errorf("window = %v, want the %v approval fallback", got, DefaultConfig().DefaultWindow)
		}
	})
}

// The emergency button is what keeps people from routing around approvals by
// sharing the break-glass credential — so it stays reachable by anybody the gate
// applies to. Reachable and unlimited are different settings though, and only
// the second one makes asking optional. The quota is the difference.
func TestConnect_EmergencyQuota(t *testing.T) {
	const reason = "site outage, need the switch now"

	t.Run("under the quota it still lets you in", func(t *testing.T) {
		h := newHarness(opts{
			entitled: true, hasCredential: true, requiresApproval: true,
			emergenciesTaken: []time.Time{fixedNow.Add(-48 * time.Hour)},
		})
		res, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(), ReqMeta{},
			ConnectOptions{Emergency: true, Reason: reason})
		if err != nil {
			t.Fatalf("one prior emergency must not block the second: %v", err)
		}
		if res.Session == nil {
			t.Fatal("emergency access did not produce a session")
		}
	})

	t.Run("at the quota it is refused", func(t *testing.T) {
		h := newHarness(opts{
			entitled: true, hasCredential: true, requiresApproval: true,
			emergenciesTaken: []time.Time{
				fixedNow.Add(-48 * time.Hour),
				fixedNow.Add(-24 * time.Hour),
			},
		})
		_, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(), ReqMeta{},
			ConnectOptions{Emergency: true, Reason: reason})
		if !errors.Is(err, access.ErrEmergencyQuota) {
			t.Fatalf("err = %v, want ErrEmergencyQuota", err)
		}
		// The refusal has to say when it frees up. During the incident somebody
		// pressed this button in, "denied" alone does not tell them whether to
		// wait or to go and wake an approver.
		if msg := err.Error(); !strings.Contains(msg, "frees up") {
			t.Errorf("refusal does not name when the quota frees up: %q", msg)
		}
		if n := len(h.requests.created); n != 0 {
			t.Errorf("%d request(s) raised despite the refusal, want 0", n)
		}
	})

	t.Run("emergencies outside the window have aged out", func(t *testing.T) {
		h := newHarness(opts{
			entitled: true, hasCredential: true, requiresApproval: true,
			emergenciesTaken: []time.Time{
				fixedNow.Add(-8 * 24 * time.Hour),
				fixedNow.Add(-9 * 24 * time.Hour),
			},
		})
		if _, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(), ReqMeta{},
			ConnectOptions{Emergency: true, Reason: reason}); err != nil {
			t.Fatalf("emergencies older than the window must not count: %v", err)
		}
	})

	t.Run("the ordinary request path is unaffected by a spent quota", func(t *testing.T) {
		// The whole point is to push somebody back to asking. If the quota also
		// blocked the ordinary route it would be a lockout, not a limit.
		h := newHarness(opts{
			entitled: true, hasCredential: true, requiresApproval: true,
			emergenciesTaken: []time.Time{fixedNow.Add(-1 * time.Hour), fixedNow.Add(-2 * time.Hour)},
		})
		res, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(), ReqMeta{},
			ConnectOptions{Reason: reason})
		if err != nil {
			t.Fatalf("asking properly must still work: %v", err)
		}
		if res.Pending == nil {
			t.Error("no request raised; somebody out of emergencies has no route left at all")
		}
	})

	t.Run("quota of zero disables the limit", func(t *testing.T) {
		h := newHarness(opts{
			entitled: true, hasCredential: true, requiresApproval: true, noEmergencyQuota: true,
			emergenciesTaken: []time.Time{fixedNow, fixedNow, fixedNow, fixedNow, fixedNow},
		})
		if _, err := h.svc.ConnectWith(context.Background(), actorClaims(), uuid.New(), ReqMeta{},
			ConnectOptions{Emergency: true, Reason: reason}); err != nil {
			t.Fatalf("quota 0 means unlimited: %v", err)
		}
	})
}
