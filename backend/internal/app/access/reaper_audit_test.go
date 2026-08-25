package access

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/audit"
)

// A session that nobody closes by hand still ends, and the ledger has to say so.
// Both reapers used to flip the row and return a count: the audit log held
// session.start and then nothing at all, so every timed-out session read as
// still open to anyone reviewing the log rather than the sessions table.

func TestExpireOverdue_IsAudited(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	sid, org, dev := uuid.New(), uuid.New(), uuid.New()
	endedAt := time.Date(2026, 8, 18, 14, 8, 21, 0, time.UTC)
	h.sessions.overdueExpired = []access.ExpiredSession{
		{ID: sid, OrgID: org, DeviceID: dev, Protocol: access.ProtocolHTTPS, EndedAt: endedAt, Reason: "window_expired"},
	}

	n, err := h.svc.ExpireOverdue(context.Background())
	if err != nil {
		t.Fatalf("expire overdue: %v", err)
	}
	if n != 1 {
		t.Fatalf("expired count = %d, want 1", n)
	}

	ends := h.audit.findAll("session.end")
	if len(ends) != 1 {
		t.Fatalf("recorded %d session.end events, want 1", len(ends))
	}
	e := ends[0]
	if e.SessionID == nil || *e.SessionID != sid {
		t.Errorf("session = %v, want %s", e.SessionID, sid)
	}
	if e.TargetType != "device" || e.TargetID != dev.String() {
		t.Errorf("target = %s:%s, want device:%s", e.TargetType, e.TargetID, dev)
	}
	if e.OrganizationID == nil || *e.OrganizationID != org {
		t.Errorf("organization = %v, want %s", e.OrganizationID, org)
	}
	if e.Detail["reason"] != "window_expired" {
		t.Errorf("reason = %v, want window_expired", e.Detail["reason"])
	}
	// The moment authorization lapsed, not the moment the sweep noticed. The
	// sweep only runs while the API does, so "now" silently records however long
	// the process was down as time the session was open.
	if got := e.Detail["ended_at"]; got != endedAt.Format(time.RFC3339) {
		t.Errorf("ended_at = %v, want %s", got, endedAt.Format(time.RFC3339))
	}
	if e.Result != audit.ResultSuccess {
		t.Errorf("result = %q, want success", e.Result)
	}
}

// Housekeeping has no user behind it. Stamping the zero UUID as the actor names
// an account that has never existed — the same class of untruth as recording an
// outcome that never happened.
func TestExpireIdle_AuditsWithNoInventedActor(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	sid, org, dev := uuid.New(), uuid.New(), uuid.New()
	h.sessions.idleExpired = []access.ExpiredSession{
		{ID: sid, OrgID: org, DeviceID: dev, Protocol: access.ProtocolHTTPS, Reason: "idle_timeout"},
	}

	if _, err := h.svc.ExpireIdle(context.Background()); err != nil {
		t.Fatalf("expire idle: %v", err)
	}
	ends := h.audit.findAll("session.end")
	if len(ends) != 1 {
		t.Fatalf("recorded %d session.end events, want 1", len(ends))
	}
	if ends[0].ActorID != nil {
		t.Errorf("actor = %s, want none: no person ended this session", ends[0].ActorID)
	}
	if ends[0].ActorEmail != "" {
		t.Errorf("actor email = %q, want empty", ends[0].ActorEmail)
	}
	if ends[0].Detail["ended_by"] != "system" {
		t.Errorf("ended_by = %v, want system", ends[0].Detail["ended_by"])
	}
	if ends[0].Detail["reason"] != "idle_timeout" {
		t.Errorf("reason = %v, want idle_timeout", ends[0].Detail["reason"])
	}
}

// The timeline is not copied into the ledger — a web session records an event per
// proxied request, and mirroring that would bury every entry a reviewer reads.
// What goes in is the shape of the session, with the timeline a click away.
func TestSessionEnd_CarriesAnActivityDigest(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	sid, org, dev := uuid.New(), uuid.New(), uuid.New()
	ctx := context.Background()
	for _, p := range []string{"/admin", "/admin", "/admin/users", "/config"} {
		_ = h.events.RecordEvent(ctx, sid, "url_change", map[string]any{"path": p, "method": "GET"})
	}
	_ = h.events.RecordEvent(ctx, sid, "dialog", map[string]any{"message": "confirm"})
	h.sessions.idleExpired = []access.ExpiredSession{
		{ID: sid, OrgID: org, DeviceID: dev, Protocol: access.ProtocolHTTPS, Reason: "idle_timeout"},
	}

	if _, err := h.svc.ExpireIdle(ctx); err != nil {
		t.Fatalf("expire idle: %v", err)
	}
	ends := h.audit.findAll("session.end")
	if len(ends) != 1 {
		t.Fatalf("recorded %d session.end events, want 1", len(ends))
	}
	digest, ok := ends[0].Detail["activity"].(map[string]any)
	if !ok {
		t.Fatalf("no activity digest on session.end: %#v", ends[0].Detail)
	}
	if digest["events"] != 5 {
		t.Errorf("events = %v, want 5", digest["events"])
	}
	kinds, _ := digest["kinds"].(map[string]int)
	if kinds["url_change"] != 4 || kinds["dialog"] != 1 {
		t.Errorf("kinds = %v, want 4 url_change and 1 dialog", kinds)
	}
	paths, _ := digest["paths"].([]string)
	if len(paths) != 3 {
		t.Fatalf("paths = %v, want the three DISTINCT destinations", paths)
	}
	if paths[0] != "/admin" || paths[1] != "/admin/users" || paths[2] != "/config" {
		t.Errorf("paths = %v, want first-seen order", paths)
	}
}
