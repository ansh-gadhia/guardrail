// Package access is the application layer for the access broker: it authorizes,
// time-boxes, establishes, records, and terminates brokered sessions, delegating
// the protocol-specific work to a registered Gateway. Adding a new protocol means
// registering another Gateway — the broker is unchanged.
package access

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// Config holds broker policy.
type Config struct {
	DefaultWindow      time.Duration // how long a session stays valid
	RecordingRetention time.Duration
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	return Config{DefaultWindow: time.Hour, RecordingRetention: 90 * 24 * time.Hour}
}

// Notifier receives broker events for fan-out to notification channels. It is
// best-effort; failures never block a session operation.
type Notifier interface {
	Notify(ctx context.Context, orgID uuid.UUID, event string, payload map[string]any)
}

// Service is the access broker.
type Service struct {
	sessions   access.SessionRepository
	authorizer access.Authorizer
	gateways   map[access.Protocol]access.Gateway
	isolated   map[access.Protocol]access.Gateway
	registry   access.LiveRegistry
	events     access.EventRecorder
	recordings access.RecordingStore
	blobs      access.BlobStore
	devices    access.DeviceLookup
	creds      access.CredentialResolver
	audit      audit.Recorder
	notifier   Notifier
	activity   *ActivityTracker
	clock      iam.Clock
	node       string
	cfg        Config
	log        *zap.Logger
}

// Deps bundles broker collaborators.
type Deps struct {
	Sessions   access.SessionRepository
	Authorizer access.Authorizer
	// Gateways serve ordinary sessions (the reverse proxy).
	Gateways []access.Gateway
	// IsolatedGateways serve sessions for devices set to be recorded. Recording
	// captures frames from a server-side browser, so it only exists in this
	// delivery mode; a device that is not recorded has no reason to pay for one.
	//
	// Empty is a valid deployment: the host may have no Chromium, or isolation
	// may be switched off. Recorded devices then fall back to the reverse proxy
	// and are served without capture, which is what happens today. The gap is
	// reported by IsolationAvailable, so the console can warn before an operator
	// sets a recording policy this host cannot honor.
	IsolatedGateways []access.Gateway
	Registry         access.LiveRegistry
	Events           access.EventRecorder
	Recordings       access.RecordingStore
	Blobs            access.BlobStore
	Devices          access.DeviceLookup
	Creds            access.CredentialResolver
	Audit            audit.Recorder
	Notifier         Notifier
	// Activity is the tracker the gateways touch. The broker holds it so ending a
	// session can drop its throttle state.
	Activity *ActivityTracker
	Clock    iam.Clock
	Node     string
	Config   Config
	// Log reports the things that are nobody's fault and everybody's problem: a
	// session that opens unrecorded because its recording row could not be
	// written. Optional — nil is a valid Deps, and every use is guarded.
	Log *zap.Logger
}

// NewService constructs the broker, indexing gateways by protocol.
func NewService(d Deps) *Service {
	clock := d.Clock
	if clock == nil {
		clock = iam.SystemClock{}
	}
	return &Service{
		sessions: d.Sessions, authorizer: d.Authorizer,
		gateways: indexGateways(d.Gateways), isolated: indexGateways(d.IsolatedGateways),
		registry: d.Registry,
		events:   d.Events, recordings: d.Recordings, blobs: d.Blobs, devices: d.Devices, creds: d.Creds,
		audit: d.Audit, notifier: d.Notifier, activity: d.Activity,
		clock: clock, node: d.Node, cfg: d.Config, log: d.Log,
	}
}

func indexGateways(gws []access.Gateway) map[access.Protocol]access.Gateway {
	out := make(map[access.Protocol]access.Gateway, len(gws))
	for _, g := range gws {
		out[g.Protocol()] = g
		// An HTTP gateway serves both schemes.
		if g.Protocol() == access.ProtocolHTTPS {
			out[access.ProtocolHTTP] = g
		}
	}
	return out
}

// gatewayFor picks the gateway for a protocol and delivery mode.
//
// isolate is the device's delivery mode, independent of whether the session is
// recorded. Isolation renders the device in a browser on the server and streams
// pixels; the reverse proxy is cheaper (no Chromium) and hands over the device's
// real UI, downloads and clipboard included — but it can only re-serve a site
// that tolerates living under a path prefix, which an appliance SPA does not.
//
// Falling back to the proxy when isolation is asked for but unavailable keeps a
// host with no Chromium serving sessions. That is a safe trade for delivery — the
// operator reaches the device either way — and an unsafe one for recording, which
// is why Connect refuses that combination up front rather than reaching here.
func (s *Service) gatewayFor(proto access.Protocol, isolate bool) (access.Gateway, bool) {
	if isolate {
		if gw, ok := s.isolated[proto]; ok {
			return gw, true
		}
	}
	gw, ok := s.gateways[proto]
	return gw, ok
}

// gatewayRecords reports whether gw captures the sessions it establishes. A
// gateway that does not implement RecordingGateway cannot, which is the safe
// default: a new gateway records nothing until it says otherwise, rather than
// being assumed to.
func gatewayRecords(gw access.Gateway) bool {
	rg, ok := gw.(access.RecordingGateway)
	return ok && rg.CanRecord()
}

// IsolationAvailable reports whether this deployment can serve isolated (and
// therefore recordable) sessions. The delivery layer surfaces it so the console
// can tell an operator that a recording policy will not be honored here, instead
// of letting them set one and find out from an empty player.
func (s *Service) IsolationAvailable() bool { return len(s.isolated) > 0 }

// ReqMeta carries request metadata for auditing.
type ReqMeta struct{ IP, UserAgent string }

// ConnectResult is returned to the caller after a Connect. The session is
// established immediately and the proxy path/token are ready for use.
type ConnectResult struct {
	Session      *access.Session
	Live         access.LiveSession
	ProxyPath    string
	ProxyToken   string
	GrantedUntil time.Time
}

func scopeOf(a iam.Claims) access.Scope {
	return access.Scope{OrganizationID: a.OrganizationID, IsSuperAdmin: a.IsSuperAdmin}
}

// watermarkFor builds the attribution text stamped over the device UI: who is in
// the session, and which session it is. The short session id is enough to join a
// screenshot back to the audit trail, and keeps the tiled text short enough to
// stay legible without covering the operator's work.
func watermarkFor(actor iam.Claims, sessionID uuid.UUID) string {
	who := actor.Email
	if who == "" {
		who = actor.UserID.String()
	}
	return who + " · " + sessionID.String()[:8]
}

// Connect authorizes and immediately establishes a brokered session to a device.
// The caller must already hold device:connect (enforced at the delivery layer);
// this additionally enforces resource-level entitlement — the actor must have a
// role whose device scope reaches this device, unless they are a super admin.
func (s *Service) Connect(ctx context.Context, actor iam.Claims, deviceID uuid.UUID, meta ReqMeta) (*ConnectResult, error) {
	ep, err := s.devices.Endpoint(ctx, scopeOf(actor), deviceID)
	if err != nil {
		return nil, err
	}
	gw, ok := s.gatewayFor(ep.Protocol, ep.Isolate)
	if !ok {
		return nil, access.ErrNoGateway
	}
	// A recorded device served by a gateway that captures nothing must not become
	// a session anyway. This asks the gateway that will actually serve it, not the
	// protocol: an isolated HTTPS device on a host with no Chromium falls back to
	// the reverse proxy here, which is fine for reaching the device and useless for
	// evidence, while SSH records on that same host with no browser at all.
	if ep.RecordSessions && !gatewayRecords(gw) {
		s.recordAuditDetail(ctx, actor, "access.denied", &access.Session{DeviceID: deviceID}, meta,
			audit.ResultDenied, map[string]any{"reason": "recording_unavailable"})
		return nil, access.ErrRecordingUnavailable
	}

	// Resource-level authorization: a coarse device:connect permission is not
	// enough — the actor's roles must actually grant access to this specific
	// device (by device type or asset-group membership). Super admins bypass.
	if !actor.IsSuperAdmin && s.authorizer != nil {
		ok, err := s.authorizer.CanAccessDevice(ctx, scopeOf(actor), actor.UserID, deviceID)
		if err != nil {
			return nil, err
		}
		if !ok {
			s.recordAudit(ctx, actor, "access.denied", &access.Session{DeviceID: deviceID}, meta, audit.ResultDenied)
			return nil, access.ErrForbidden
		}
	}

	// Fail closed: GuardRail exists to inject a vaulted credential server-side. A
	// device with no bound credential has nothing to inject, so a "session" would
	// just proxy the device's own login page — leaking the target to the user and
	// defeating the platform's guarantee. Refuse before creating any session,
	// unless the device explicitly opts into break-glass unmanaged access.
	if !ep.AllowUnmanaged {
		has, err := s.creds.HasCredential(ctx, scopeOf(actor), deviceID)
		if err != nil {
			return nil, err
		}
		if !has {
			return nil, access.ErrNoCredential
		}
	}

	now := s.clock.Now()
	sess := &access.Session{
		ID: uuid.New(), OrganizationID: actor.OrganizationID, UserID: actor.UserID, DeviceID: deviceID,
		Protocol: ep.Protocol, Status: access.StatusActive,
		ClientIP: meta.IP, UserAgent: meta.UserAgent,
	}
	sess.Watermark = watermarkFor(actor, sess.ID)
	until := now.Add(s.cfg.DefaultWindow)
	sess.GrantedFrom, sess.GrantedUntil, sess.GatewayNode, sess.StartedAt = &now, &until, s.node, &now
	if err := s.sessions.Create(ctx, scopeOf(actor), sess); err != nil {
		return nil, err
	}
	return s.establish(ctx, actor, sess, meta, ep.RecordSessions, ep.Isolate)
}

// establish brings a session live: starts recording (when the device is set to
// be recorded), launches the gateway, and registers it.
//
// The recording row must exist before the gateway starts, because the gateway
// looks it up to decide whether to capture frames — and its absence is exactly
// how "this device isn't recorded" is expressed downstream.
func (s *Service) establish(ctx context.Context, actor iam.Claims, sess *access.Session, meta ReqMeta, record, isolate bool) (*ConnectResult, error) {
	if s.recordings != nil && record {
		// The error was discarded here. If Start failed, no row existed for the
		// gateway to find, so it opened the session with recording switched off and
		// nothing anywhere said why — the device's policy read "recorded", the
		// console showed a session, and the evidence was never going to arrive.
		//
		// Still not fatal: refusing to connect because a recording row could not be
		// written would take access away over a failure the operator cannot act on,
		// and the gateway logs the unrecorded session it then opens. But the cause
		// belongs in the log next to the effect.
		if _, err := s.recordings.Start(ctx, scopeOf(actor), sess.ID, s.cfg.RecordingRetention); err != nil && s.log != nil {
			s.log.Error("the recording could not be started; this session will not be recorded",
				zap.String("session_id", sess.ID.String()),
				zap.String("device_id", sess.DeviceID.String()),
				zap.Error(err))
		}
	}
	gw, ok := s.gatewayFor(sess.Protocol, isolate)
	if !ok {
		_ = s.sessions.UpdateStatus(ctx, scopeOf(actor), sess.ID, access.StatusEnded, "no_gateway", s.clock.Now())
		return nil, access.ErrNoGateway
	}
	live, err := gw.Establish(ctx, sess, s.creds)
	if err != nil {
		// A failed establish used to end the session as a flat "establish_failed"
		// and return, recording nothing. That made a device whose host key changed
		// — the one signal that says the machine answering is not the machine we
		// trusted — indistinguishable in the audit trail from a typo'd password,
		// and left no record at all of a possible interception.
		reason, result := "establish_failed", audit.ResultFailure
		if errors.Is(err, access.ErrHostKeyMismatch) {
			// Denied, not failed: GuardRail made a security decision here.
			reason, result = "host_key_mismatch", audit.ResultDenied
		}
		_ = s.sessions.UpdateStatus(ctx, scopeOf(actor), sess.ID, access.StatusEnded, reason, s.clock.Now())
		// The error text is the forensics — which host, which fingerprint. Gateway
		// errors must never carry secret material for this reason; the SSH gateway
		// is deliberately vague about unusable key material for the same one.
		s.recordAuditDetail(ctx, actor, "session.establish_failed", sess, meta, result,
			map[string]any{"reason": reason, "error": err.Error()})
		return nil, err
	}
	if s.registry != nil {
		_ = s.registry.Add(ctx, actor.OrganizationID, sess.ID, s.cfg.DefaultWindow)
	}
	s.recordAudit(ctx, actor, "session.start", sess, meta, audit.ResultSuccess)
	until := s.clock.Now().Add(s.cfg.DefaultWindow)
	if sess.GrantedUntil != nil {
		until = *sess.GrantedUntil
	}
	return &ConnectResult{Session: sess, Live: live, ProxyPath: live.ProxyPath, ProxyToken: live.ProxyToken, GrantedUntil: until}, nil
}

// endOnAllGateways tears a session down on every gateway that could be holding
// it, rather than re-deriving which one owns it.
//
// Re-deriving would mean re-reading the device's recording policy, and that
// policy can be flipped by its owner while a session is live — which would send
// the teardown to the gateway that never had the session, and leave a live
// Chromium and an un-flushed recording behind on the one that did. End is keyed
// by session id and each gateway only knows its own sessions, so asking both is
// both cheap and immune to that.
func (s *Service) endOnAllGateways(ctx context.Context, proto access.Protocol, sessionID uuid.UUID) {
	if gw, ok := s.isolated[proto]; ok {
		_ = gw.End(ctx, sessionID)
	}
	if gw, ok := s.gateways[proto]; ok {
		_ = gw.End(ctx, sessionID)
	}
}

// Terminate ends a session (user- or admin-initiated) and tears down resources.
func (s *Service) Terminate(ctx context.Context, actor iam.Claims, sessionID uuid.UUID, reason string, meta ReqMeta) error {
	sess, err := s.sessions.GetByID(ctx, scopeOf(actor), sessionID)
	if err != nil {
		return err
	}
	if err := s.sessions.UpdateStatus(ctx, scopeOf(actor), sessionID, access.StatusEnded, reason, s.clock.Now()); err != nil {
		return err
	}
	s.endOnAllGateways(ctx, sess.Protocol, sessionID)
	if s.registry != nil {
		_ = s.registry.Remove(ctx, sess.OrganizationID, sessionID)
		_ = s.registry.SignalTerminate(ctx, sessionID)
	}
	if s.recordings != nil {
		_ = s.recordings.Finalize(ctx, sessionID, s.clock.Now())
	}
	if s.activity != nil {
		s.activity.forget(sessionID)
	}
	s.recordAudit(ctx, actor, "session.end", sess, meta, audit.ResultSuccess)
	return nil
}

// Get returns a session in scope.
func (s *Service) Get(ctx context.Context, actor iam.Claims, id uuid.UUID) (*access.Session, error) {
	return s.sessions.GetByID(ctx, scopeOf(actor), id)
}

// List returns sessions matching the filter.
func (s *Service) List(ctx context.Context, actor iam.Claims, f access.SessionFilter) ([]access.Session, error) {
	return s.sessions.List(ctx, scopeOf(actor), f)
}

// ListActive returns the live sessions for the actor's organization.
func (s *Service) ListActive(ctx context.Context, actor iam.Claims) ([]access.Session, error) {
	return s.sessions.List(ctx, scopeOf(actor), access.SessionFilter{Status: access.StatusActive, Limit: 200})
}

// CountActive returns the number of active sessions.
func (s *Service) CountActive(ctx context.Context, actor iam.Claims) (int, error) {
	return s.sessions.CountActive(ctx, scopeOf(actor))
}

// Events returns a session's playback timeline.
func (s *Service) Events(ctx context.Context, actor iam.Claims, sessionID uuid.UUID, limit int) ([]access.Event, error) {
	return s.events.ListEvents(ctx, scopeOf(actor), sessionID, limit)
}

// Recording returns a session's recording metadata, or ErrNotFound when the
// session was not recorded (the device's policy has recording off).
func (s *Service) Recording(ctx context.Context, actor iam.Claims, sessionID uuid.UUID) (*access.Recording, error) {
	if s.recordings == nil {
		return nil, access.ErrNotFound
	}
	return s.recordings.GetBySession(ctx, scopeOf(actor), sessionID)
}

// RecordingHasVideo reports whether a session's recording has playable frames.
// It reads artifact metadata only: this answers a yes/no question, so it must
// not fetch the frames or audit a view that isn't happening.
func (s *Service) RecordingHasVideo(ctx context.Context, actor iam.Claims, sessionID uuid.UUID) bool {
	return s.hasArtifact(ctx, actor, sessionID, access.ArtifactVideo)
}

// RecordingHasTranscript reports whether an SSH session's terminal output was
// stored. Same reasoning as RecordingHasVideo: the recording row exists from the
// moment the session starts, so its presence says nothing about whether there is
// anything to read yet.
func (s *Service) RecordingHasTranscript(ctx context.Context, actor iam.Claims, sessionID uuid.UUID) bool {
	return s.hasArtifact(ctx, actor, sessionID, access.ArtifactTranscript)
}

// RecordingHasDesktop reports whether an RDP/VNC session's Guacamole dump was
// stored. Unlike video and transcript, this one is written by guacd rather than
// by us, and only flushed when the session ends — so a desktop that is still
// live has a recording row, a file on guacd's disk, and nothing here to play.
func (s *Service) RecordingHasDesktop(ctx context.Context, actor iam.Claims, sessionID uuid.UUID) bool {
	return s.hasArtifact(ctx, actor, sessionID, access.ArtifactDesktop)
}

// hasArtifact answers "is there anything stored of this kind" from metadata
// alone. Fetching the object to answer a yes/no question would pull hundreds of
// megabytes and audit a view that never happened.
func (s *Service) hasArtifact(ctx context.Context, actor iam.Claims, sessionID uuid.UUID, kind string) bool {
	if s.recordings == nil {
		return false
	}
	art, err := s.recordings.GetArtifact(ctx, scopeOf(actor), sessionID, kind)
	return err == nil && art != nil && art.SizeBytes > 0
}

// RecordingArtifact returns the bytes of a recording artifact — the frame
// manifest or the frames themselves. Reading a recording is audited: watching
// what someone did is itself a privileged act.
func (s *Service) RecordingArtifact(ctx context.Context, actor iam.Claims, sessionID uuid.UUID, kind string, meta ReqMeta) ([]byte, string, error) {
	if s.recordings == nil || s.blobs == nil {
		return nil, "", access.ErrNotFound
	}
	art, err := s.recordings.GetArtifact(ctx, scopeOf(actor), sessionID, kind)
	if err != nil {
		return nil, "", err
	}
	data, err := s.blobs.Get(ctx, art.ObjectKey)
	if err != nil {
		return nil, "", err
	}
	// Audit the viewing, not the byte-range: the manifest fetch is the moment a
	// person opens a recording, and one event per playback is the useful record.
	if kind == access.ArtifactManifest {
		s.recordAudit(ctx, actor, "recording.view",
			&access.Session{ID: sessionID}, meta, audit.ResultSuccess)
	}
	return data, art.ContentType, nil
}

// ExpireOverdue is invoked by a background reaper to expire sessions past their
// window across all tenants.
func (s *Service) ExpireOverdue(ctx context.Context) (int, error) {
	return s.sessions.ExpireOverdue(ctx, s.clock.Now())
}

// ExpireIdle ends sessions that have gone untouched past their device's idle
// timeout and releases what they were holding.
//
// Unlike the window reaper this tears the gateway down rather than only flipping
// the row. An idle isolated session is holding a whole browser; marking it
// expired in the database while leaving the Chromium running would reclaim the
// one resource that costs nothing and leak the one that does. The terminate
// signal covers sessions belonging to another node, whose gateways are not in
// this process.
func (s *Service) ExpireIdle(ctx context.Context) (int, error) {
	expired, err := s.sessions.ExpireIdle(ctx, s.clock.Now())
	if err != nil {
		return 0, err
	}
	for _, e := range expired {
		s.endOnAllGateways(ctx, e.Protocol, e.ID)
		if s.registry != nil {
			_ = s.registry.Remove(ctx, e.OrgID, e.ID)
			_ = s.registry.SignalTerminate(ctx, e.ID)
		}
		if s.recordings != nil {
			// Finalize so the recording is playable. The frames were flushed by
			// the gateway teardown above; without this the recording stays in
			// "recording" forever and reads as still running.
			_ = s.recordings.Finalize(ctx, e.ID, s.clock.Now())
		}
		if s.activity != nil {
			s.activity.forget(e.ID)
		}
	}
	return len(expired), nil
}

// DeleteRecording removes a session's recording: its stored bytes first, then the
// rows that point at them.
//
// This destroys evidence, which makes it the most consequential thing in this
// service, so the shape is deliberate:
//
//   - It is audited BEFORE anything is removed, and the audit names what is about
//     to go and how big it was. Auditing afterwards would lose the record whenever
//     the delete is the thing that fails, and an untraceable evidence deletion is
//     worse than no delete feature at all.
//   - Blobs are freed BEFORE the rows. A row deleted first orphans its object:
//     nothing points to it, nothing lists it, and it occupies disk forever — the
//     exact opposite of why anyone deletes a recording.
//   - A blob that will not delete does NOT abort the operation. The rows still go,
//     and the failure is logged and audited. Refusing to finish would leave a
//     half-deleted recording that reads as intact.
func (s *Service) DeleteRecording(ctx context.Context, actor iam.Claims, sessionID uuid.UUID, meta ReqMeta) error {
	if s.recordings == nil {
		return access.ErrNotFound
	}
	sc := scopeOf(actor)
	rec, err := s.recordings.GetBySession(ctx, sc, sessionID)
	if err != nil {
		return err
	}
	if rec == nil {
		return access.ErrNotFound
	}

	arts, err := s.recordings.ListArtifacts(ctx, sc, sessionID)
	if err != nil {
		return err
	}
	var bytes int64
	kinds := make([]string, 0, len(arts))
	for _, a := range arts {
		bytes += a.SizeBytes
		kinds = append(kinds, a.Kind)
	}

	// Audited first, and on purpose. See above.
	s.recordAuditDetail(ctx, actor, "recording.delete", &access.Session{ID: sessionID}, meta,
		audit.ResultSuccess, map[string]any{
			"recording_id": rec.ID.String(),
			"artifacts":    kinds,
			"size_bytes":   bytes,
		})

	var orphaned []string
	if s.blobs != nil {
		for _, a := range arts {
			if a.ObjectKey == "" {
				continue
			}
			if derr := s.blobs.Delete(ctx, a.ObjectKey); derr != nil {
				// Not fatal: the rows must still go, or the recording reads as intact
				// while its bytes are already unreachable. But an object nobody can
				// reach and nobody knows about is exactly the kind of thing that turns
				// up in a storage audit years later, so it is recorded as an event
				// rather than swallowed.
				orphaned = append(orphaned, a.ObjectKey)
			}
		}
	}
	if len(orphaned) > 0 {
		s.recordAuditDetail(ctx, actor, "recording.delete", &access.Session{ID: sessionID}, meta,
			audit.ResultFailure, map[string]any{
				"reason":        "blob_delete_failed",
				"orphaned_keys": orphaned,
			})
	}

	return s.recordings.Delete(ctx, sc, sessionID)
}

func (s *Service) recordAudit(ctx context.Context, actor iam.Claims, action string, sess *access.Session, meta ReqMeta, result audit.Result) {
	s.recordAuditDetail(ctx, actor, action, sess, meta, result, nil)
}

// recordAuditDetail is recordAudit with the event's Detail populated, for the
// cases where "it failed" is not enough to investigate afterwards.
func (s *Service) recordAuditDetail(ctx context.Context, actor iam.Claims, action string, sess *access.Session, meta ReqMeta, result audit.Result, detail map[string]any) {
	if s.audit == nil {
		return
	}
	org := actor.OrganizationID
	uid := actor.UserID
	sid := sess.ID
	_ = s.audit.Record(ctx, audit.Event{
		ID: uuid.New(), OrganizationID: &org, ActorID: &uid, ActorEmail: actor.Email,
		Action: action, Category: audit.CategorySession, TargetType: "device", TargetID: sess.DeviceID.String(),
		SessionID: &sid, IP: meta.IP, UserAgent: meta.UserAgent, Result: result, Detail: detail,
	})
}
