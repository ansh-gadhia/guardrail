package access

import (
	"context"
	"errors"
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
