package access

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/audit"
)

// Connect is the platform's front door. Every test below pins one rule of it:
// entitlement is enforced per device, and a refusal never creates a session.

func TestConnect_EntitledUser_EstablishesSession(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	actor := actorClaims()
	deviceID := uuid.New()

	res, err := h.svc.Connect(context.Background(), actor, deviceID, ReqMeta{IP: "203.0.113.9"})
	if err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	if res.Session.Status != access.StatusActive {
		t.Errorf("status = %q, want %q", res.Session.Status, access.StatusActive)
	}
	if res.Session.DeviceID != deviceID {
		t.Errorf("session device = %v, want %v", res.Session.DeviceID, deviceID)
	}
	if res.ProxyToken == "" {
		t.Error("ProxyToken is empty; the browser has nothing to bind the session with")
	}
	// The default device is recorded, so isolation is the gateway that serves it.
	if len(h.isolated.established) != 1 {
		t.Errorf("gateway established %d sessions, want 1", len(h.isolated.established))
	}
	if len(h.recordings.started) != 1 {
		t.Errorf("started %d recordings, want 1 — every brokered session is recorded", len(h.recordings.started))
	}
	if got := h.audit.find("session.start"); got == nil {
		t.Error("no session.start audit event recorded")
	}
}

func TestConnect_UnentitledUser_IsDeniedAndCreatesNoSession(t *testing.T) {
	h := newHarness(opts{entitled: false, hasCredential: true})
	actor := actorClaims()
	deviceID := uuid.New()

	_, err := h.svc.Connect(context.Background(), actor, deviceID, ReqMeta{IP: "203.0.113.9"})
	if !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("Connect error = %v, want ErrForbidden", err)
	}
	// The security property: a denied connect leaves no trace of access.
	if len(h.sessions.created) != 0 {
		t.Errorf("created %d sessions on a denied connect, want 0", len(h.sessions.created))
	}
	if len(h.gateway.established) != 0 {
		t.Errorf("gateway established %d sessions on a denied connect, want 0", len(h.gateway.established))
	}
	if len(h.recordings.started) != 0 {
		t.Errorf("started %d recordings on a denied connect, want 0", len(h.recordings.started))
	}

	ev := h.audit.find("access.denied")
	if ev == nil {
		t.Fatal("no access.denied audit event recorded; a refused connection must be visible")
	}
	if ev.Result != audit.ResultDenied {
		t.Errorf("audit result = %q, want %q", ev.Result, audit.ResultDenied)
	}
	if ev.TargetID != deviceID.String() {
		t.Errorf("audit target = %q, want the device id %q", ev.TargetID, deviceID)
	}
}

func TestConnect_SuperAdmin_BypassesEntitlement(t *testing.T) {
	// The authorizer would refuse; a super admin must not even be asked.
	h := newHarness(opts{entitled: false, hasCredential: true})

	if _, err := h.svc.Connect(context.Background(), superClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("Connect as super admin: unexpected error: %v", err)
	}
	if h.authorizer.calls != 0 {
		t.Errorf("authorizer consulted %d times for a super admin, want 0", h.authorizer.calls)
	}
}

func TestConnect_AuthorizerError_FailsClosed(t *testing.T) {
	// An authorizer that can't answer must not be read as "yes".
	h := newHarness(opts{authorizerErr: errBoom, hasCredential: true})

	_, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{})
	if !errors.Is(err, errBoom) {
		t.Fatalf("Connect error = %v, want the authorizer's error", err)
	}
	if len(h.sessions.created) != 0 {
		t.Errorf("created %d sessions despite an authorizer failure, want 0", len(h.sessions.created))
	}
}

func TestConnect_NoAuthorizerConfigured_AllowsEntitledPath(t *testing.T) {
	// The Authorizer is an optional dep; with none wired the broker keeps its
	// pre-Track-B behaviour rather than locking everyone out.
	h := newHarness(opts{noAuthorizer: true, hasCredential: true})

	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("Connect with no authorizer: unexpected error: %v", err)
	}
}

func TestConnect_EntitlementCheckedBeforeCredentialPreflight(t *testing.T) {
	// An unentitled user must not learn whether a device has a credential — the
	// denial has to come first.
	h := newHarness(opts{entitled: false, hasCredential: false})

	_, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{})
	if !errors.Is(err, access.ErrForbidden) {
		t.Fatalf("Connect error = %v, want ErrForbidden (not ErrNoCredential)", err)
	}
}

func TestConnect_NoCredential_FailsClosed(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: false})

	_, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{})
	if !errors.Is(err, access.ErrNoCredential) {
		t.Fatalf("Connect error = %v, want ErrNoCredential", err)
	}
	if len(h.sessions.created) != 0 {
		t.Errorf("created %d sessions for a credential-less device, want 0", len(h.sessions.created))
	}
}

func TestConnect_BreakGlassDevice_ConnectsWithoutCredential(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: false, allowUnmanaged: true})

	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("Connect to a break-glass device: unexpected error: %v", err)
	}
}

func TestConnect_RecordingDisabledDevice_StartsNoRecording(t *testing.T) {
	// The recording row is what tells the gateway to capture, so a device with
	// recording switched off must not get one — that absence is the mechanism,
	// not just bookkeeping.
	h := newHarness(opts{entitled: true, hasCredential: true, noRecording: true})

	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	if len(h.recordings.started) != 0 {
		t.Errorf("started %d recordings for a device with recording off, want 0", len(h.recordings.started))
	}
	// The session itself must still be brokered and audited.
	if len(h.gateway.established) != 1 {
		t.Errorf("gateway established %d sessions, want 1 — recording is off, not access", len(h.gateway.established))
	}
	if h.audit.find("session.start") == nil {
		t.Error("no session.start audit event; an unrecorded session is still an audited one")
	}
}

func TestConnect_RecordingEnabledDevice_StartsRecording(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})

	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	if len(h.recordings.started) != 1 {
		t.Errorf("started %d recordings, want 1", len(h.recordings.started))
	}
}

func TestConnect_GrantIsTimeBoxed(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})

	res, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{})
	if err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	if res.Session.GrantedUntil == nil {
		t.Fatal("session has no expiry; a brokered grant must be time-boxed")
	}
	if got := res.GrantedUntil.Sub(*res.Session.GrantedFrom); got != DefaultConfig().DefaultWindow {
		t.Errorf("grant window = %v, want %v", got, DefaultConfig().DefaultWindow)
	}
}

func TestConnect_EstablishFailure_EndsTheSession(t *testing.T) {
	// A session row that outlives a failed gateway launch would read as live
	// access that never happened.
	h := newHarness(opts{entitled: true, hasCredential: true, establishErr: errBoom})

	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); !errors.Is(err, errBoom) {
		t.Fatalf("Connect error = %v, want the gateway's error", err)
	}
	if len(h.sessions.statuses) != 1 {
		t.Fatalf("recorded %d status updates, want 1 (the cleanup)", len(h.sessions.statuses))
	}
	if got := h.sessions.statuses[0]; got.status != access.StatusEnded || got.reason != "establish_failed" {
		t.Errorf("cleanup update = %+v, want status=ended reason=establish_failed", got)
	}
}

func TestConnect_UnknownProtocol_IsRefused(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	// Swap in a device speaking a protocol no gateway serves.
	h.svc.devices = fakeDevices{ep: access.Endpoint{Protocol: access.ProtocolSSH, Host: "10.0.0.1"}}

	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); !errors.Is(err, access.ErrNoGateway) {
		t.Fatalf("Connect error = %v, want ErrNoGateway", err)
	}
}

func TestTerminate_TearsDownEverything(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	actor := actorClaims()
	res, err := h.svc.Connect(context.Background(), actor, uuid.New(), ReqMeta{})
	if err != nil {
		t.Fatalf("Connect: unexpected error: %v", err)
	}
	id := res.Session.ID

	if err := h.svc.Terminate(context.Background(), actor, id, "admin_terminated", ReqMeta{}); err != nil {
		t.Fatalf("Terminate: unexpected error: %v", err)
	}
	if got := h.sessions.byID[id].Status; got != access.StatusEnded {
		t.Errorf("session status = %q, want %q", got, access.StatusEnded)
	}
	if len(h.gateway.ended) != 1 {
		t.Errorf("gateway ended %d sessions, want 1 — the proxy must stop serving", len(h.gateway.ended))
	}
	if len(h.registry.removed) != 1 || len(h.registry.terminated) != 1 {
		t.Errorf("registry removed=%d signalled=%d, want 1 and 1 — other nodes must hear about it",
			len(h.registry.removed), len(h.registry.terminated))
	}
	if len(h.recordings.finalized) != 1 {
		t.Errorf("finalized %d recordings, want 1", len(h.recordings.finalized))
	}
	if h.audit.find("session.end") == nil {
		t.Error("no session.end audit event recorded")
	}
}

// --- Delivery routing: recorded devices isolate, the rest are proxied ---

func TestConnectRoutesRecordedDeviceToIsolation(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(h.isolated.established) != 1 {
		t.Errorf("recorded device must be served by the isolated gateway, got %d establishes",
			len(h.isolated.established))
	}
	if len(h.gateway.established) != 0 {
		t.Errorf("recorded device must not touch the reverse proxy, got %d establishes",
			len(h.gateway.established))
	}
}

func TestConnectRoutesUnrecordedDeviceToProxy(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true, noRecording: true})
	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("connect: %v", err)
	}
	if len(h.gateway.established) != 1 {
		t.Errorf("unrecorded device must take the reverse proxy, got %d establishes",
			len(h.gateway.established))
	}
	if len(h.isolated.established) != 0 {
		t.Errorf("unrecorded device must not pay for a Chromium, got %d isolated establishes",
			len(h.isolated.established))
	}
}

// Delivery and evidence fail differently when the host has no Chromium, and the
// difference is the point of separating them. An isolated device still connects
// — the operator reaches it through the proxy, degraded but working. A recorded
// device does not, because the only thing worse than no session is a session
// whose policy says "recorded" and whose recording does not exist.

func TestConnectFallsBackToProxyWhenIsolationUnavailable(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true, noIsolation: true, noRecording: true, isolate: true})
	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("connect must not fail when isolation is unavailable: %v", err)
	}
	if len(h.gateway.established) != 1 {
		t.Errorf("expected fallback to the reverse proxy, got %d establishes", len(h.gateway.established))
	}
	if h.svc.IsolationAvailable() {
		t.Error("IsolationAvailable must report false so the console can warn")
	}
}

func TestConnectRefusesRecordedDeviceWhenNothingCanRecord(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true, noIsolation: true})
	_, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{})
	if !errors.Is(err, access.ErrRecordingUnavailable) {
		t.Fatalf("Connect error = %v, want ErrRecordingUnavailable", err)
	}
	// The refusal must land before anything exists: no session, no proxy fallback
	// quietly serving the device unrecorded.
	if len(h.sessions.created) != 0 {
		t.Errorf("created %d sessions on a refused connect, want 0", len(h.sessions.created))
	}
	if len(h.gateway.established) != 0 {
		t.Errorf("fell back to the proxy and served the session unrecorded: %d establishes",
			len(h.gateway.established))
	}
	ev := h.audit.find("access.denied")
	if ev == nil {
		t.Fatal("no access.denied audit event; a refused connection must be visible")
	}
	if ev.Result != audit.ResultDenied {
		t.Errorf("audit result = %q, want %q", ev.Result, audit.ResultDenied)
	}
	if got, _ := ev.Detail["reason"].(string); got != "recording_unavailable" {
		t.Errorf("audit reason = %q, want %q — the log must say why", got, "recording_unavailable")
	}
}

// The refusal is keyed on the gateway that will actually serve the session, not
// on the protocol. SSH keeps a transcript and needs no browser, so a recorded SSH
// device must still connect on a host with no Chromium at all.
func TestConnectAllowsRecordedSessionOnGatewayThatRecordsWithoutIsolation(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true, noIsolation: true})
	h.gateway.records = true

	if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
		t.Fatalf("connect: a gateway that records its own sessions needs no isolation: %v", err)
	}
	if len(h.recordings.started) != 1 {
		t.Errorf("started %d recordings, want 1", len(h.recordings.started))
	}
}

func TestIsolationAvailableReportsCapability(t *testing.T) {
	if newHarness(opts{}).svc.IsolationAvailable() != true {
		t.Error("want IsolationAvailable true when an isolated gateway is wired")
	}
	if newHarness(opts{noIsolation: true}).svc.IsolationAvailable() != false {
		t.Error("want IsolationAvailable false when none is wired")
	}
}

// A device owner can flip recording while a session is live. Teardown must not
// re-derive the mode from that policy, or it tears down the wrong gateway and
// leaves a live Chromium behind.
func TestTerminateTearsDownWhicheverGatewayHoldsIt(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	actor := actorClaims()
	res, err := h.svc.Connect(context.Background(), actor, uuid.New(), ReqMeta{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := h.svc.Terminate(context.Background(), actor, res.Session.ID, "user", ReqMeta{}); err != nil {
		t.Fatalf("terminate: %v", err)
	}
	if len(h.isolated.ended) != 1 {
		t.Errorf("isolated gateway was not torn down: %d ends", len(h.isolated.ended))
	}
	if len(h.gateway.ended) != 1 {
		t.Errorf("proxy gateway must also be asked (it ignores ids it never held): %d ends",
			len(h.gateway.ended))
	}
}

// --- Watermark attribution ---

func TestConnectStampsActorIdentityOnSession(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	actor := actorClaims()
	res, err := h.svc.Connect(context.Background(), actor, uuid.New(), ReqMeta{})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	wm := res.Session.Watermark
	if !strings.Contains(wm, actor.Email) {
		t.Errorf("watermark %q must name the operator", wm)
	}
	if !strings.Contains(wm, res.Session.ID.String()[:8]) {
		t.Errorf("watermark %q must carry the session id for audit join-up", wm)
	}
	if got := h.isolated.watermarks; len(got) != 1 || got[0] != wm {
		t.Errorf("gateway did not receive the watermark: %v", got)
	}
}

// The watermark must never be silently absent. A Session that reached a gateway
// without one (e.g. read back from the repository) still gets stamped.
func TestWatermarkFallsBackToSessionID(t *testing.T) {
	s := &access.Session{ID: uuid.New()}
	if got := s.WatermarkOr(); !strings.Contains(got, s.ID.String()) {
		t.Errorf("bare session must still yield attribution, got %q", got)
	}
	s.Watermark = "alice@example.com · 1a2b3c4d"
	if got := s.WatermarkOr(); got != s.Watermark {
		t.Errorf("explicit watermark must win, got %q", got)
	}
}

// --- Idle expiry ---

// Ending an idle session must release what it holds. Marking the row expired but
// leaving the gateway up reclaims the free thing (a database row) and leaks the
// expensive one (a whole Chromium), which is the opposite of the point.
func TestExpireIdleTearsDownGatewaysAndRegistry(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	sid, org := uuid.New(), uuid.New()
	h.sessions.idleExpired = []access.ExpiredSession{
		{ID: sid, OrgID: org, Protocol: access.ProtocolHTTPS},
	}

	n, err := h.svc.ExpireIdle(context.Background())
	if err != nil {
		t.Fatalf("expire idle: %v", err)
	}
	if n != 1 {
		t.Errorf("expired count = %d, want 1", n)
	}
	if len(h.isolated.ended) != 1 || h.isolated.ended[0] != sid {
		t.Errorf("isolated gateway not torn down: %v", h.isolated.ended)
	}
	if len(h.gateway.ended) != 1 {
		t.Errorf("proxy gateway must also be asked: %v", h.gateway.ended)
	}
	// Other nodes hold their own gateways and must be told.
	if len(h.registry.terminated) != 1 || h.registry.terminated[0] != sid {
		t.Errorf("terminate not signalled to other nodes: %v", h.registry.terminated)
	}
	if len(h.registry.removed) != 1 {
		t.Errorf("session not removed from the live registry: %v", h.registry.removed)
	}
	// A recording left in "recording" reads as still running forever.
	if len(h.recordings.finalized) != 1 || h.recordings.finalized[0] != sid {
		t.Errorf("recording not finalized: %v", h.recordings.finalized)
	}
}

func TestExpireIdleNoOpWhenNothingIsIdle(t *testing.T) {
	h := newHarness(opts{entitled: true, hasCredential: true})
	n, err := h.svc.ExpireIdle(context.Background())
	if err != nil {
		t.Fatalf("expire idle: %v", err)
	}
	if n != 0 {
		t.Errorf("expired %d sessions when none were idle", n)
	}
	if len(h.isolated.ended)+len(h.gateway.ended) != 0 {
		t.Error("tore down a gateway with nothing to expire")
	}
}
