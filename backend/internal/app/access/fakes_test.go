package access

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// fixedClock makes session timing assertions deterministic.
type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

// fakeSessions is an in-memory SessionRepository.
type fakeSessions struct {
	mu          sync.Mutex
	created     []*access.Session
	byID        map[uuid.UUID]*access.Session
	statuses    []statusUpdate
	createErr   error
	idleExpired []access.ExpiredSession
	touched     []uuid.UUID
	touchedAt   time.Time
}

type statusUpdate struct {
	id     uuid.UUID
	status access.Status
	reason string
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{byID: map[uuid.UUID]*access.Session{}}
}

func (f *fakeSessions) Create(_ context.Context, _ access.Scope, s *access.Session) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.created = append(f.created, s)
	f.byID[s.ID] = s
	return nil
}

func (f *fakeSessions) GetByID(_ context.Context, _ access.Scope, id uuid.UUID) (*access.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.byID[id]
	if !ok {
		return nil, access.ErrNotFound
	}
	return s, nil
}

func (f *fakeSessions) List(context.Context, access.Scope, access.SessionFilter) ([]access.Session, error) {
	return nil, nil
}

func (f *fakeSessions) UpdateStatus(_ context.Context, _ access.Scope, id uuid.UUID, st access.Status, reason string, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statuses = append(f.statuses, statusUpdate{id: id, status: st, reason: reason})
	if s, ok := f.byID[id]; ok {
		s.Status = st
	}
	return nil
}

func (f *fakeSessions) CountActive(context.Context, access.Scope) (int, error) { return 0, nil }
func (f *fakeSessions) ExpireOverdue(context.Context, time.Time) (int, error)  { return 0, nil }

// idleExpired is what the next ExpireIdle sweep will report; touched records the
// sessions marked as in use, so a test can assert activity actually reaches the
// repository rather than stopping at the throttle.
func (f *fakeSessions) ExpireIdle(context.Context, time.Time) ([]access.ExpiredSession, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.idleExpired
	f.idleExpired = nil
	return out, nil
}

func (f *fakeSessions) TouchActivity(_ context.Context, id uuid.UUID, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.touched = append(f.touched, id)
	f.touchedAt = at
	return nil
}

// fakeAuthorizer answers entitlement with a canned verdict (or error).
type fakeAuthorizer struct {
	allow bool
	err   error
	calls int
}

func (f *fakeAuthorizer) CanAccessDevice(context.Context, access.Scope, uuid.UUID, uuid.UUID) (bool, error) {
	f.calls++
	if f.err != nil {
		return false, f.err
	}
	return f.allow, nil
}

// fakeDevices resolves a canned endpoint.
type fakeDevices struct {
	ep  access.Endpoint
	err error
}

func (f fakeDevices) Endpoint(context.Context, access.Scope, uuid.UUID) (access.Endpoint, error) {
	if f.err != nil {
		return access.Endpoint{}, f.err
	}
	return f.ep, nil
}

// fakeCreds reports credential presence.
type fakeCreds struct{ has bool }

func (f fakeCreds) Resolve(context.Context, *access.Session) (access.Credential, error) {
	return access.Credential{Username: "admin", Secret: "s3cret", Injection: "basic"}, nil
}
func (f fakeCreds) HasCredential(context.Context, access.Scope, uuid.UUID) (bool, error) {
	return f.has, nil
}

// fakeGateway records establishes and ends.
type fakeGateway struct {
	proto        access.Protocol
	establishErr error
	established  []uuid.UUID
	ended        []uuid.UUID
	// records models a gateway that can capture the session (isolation, or SSH
	// keeping its transcript). Left false, the fake is a reverse proxy: it never
	// sees the pixels, so it cannot produce evidence.
	records bool
	// watermarks captures what the broker handed down for stamping, so a test can
	// assert the attribution actually reaches the gateway rather than trusting
	// that the field was set.
	watermarks []string
}

func (f *fakeGateway) Protocol() access.Protocol { return f.proto }

// CanRecord is what the broker asks before opening a recorded device. Only a
// fake with records=true satisfies access.RecordingGateway.
func (f *fakeGateway) CanRecord() bool { return f.records }

func (f *fakeGateway) Establish(_ context.Context, s *access.Session, _ access.CredentialResolver) (access.LiveSession, error) {
	if f.establishErr != nil {
		return access.LiveSession{}, f.establishErr
	}
	f.established = append(f.established, s.ID)
	f.watermarks = append(f.watermarks, s.WatermarkOr())
	return access.LiveSession{SessionID: s.ID, ProxyPath: "/p/" + s.ID.String(), ProxyToken: "tok"}, nil
}

func (f *fakeGateway) End(_ context.Context, id uuid.UUID) error {
	f.ended = append(f.ended, id)
	return nil
}

// fakeAudit captures recorded events for assertion.
type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, e audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, e)
	return nil
}

// find returns the first event with the given action.
func (f *fakeAudit) find(action string) *audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.events {
		if f.events[i].Action == action {
			return &f.events[i]
		}
	}
	return nil
}

// fakeRecordings tracks recording lifecycle calls.
type fakeRecordings struct {
	mu        sync.Mutex
	started   []uuid.UUID
	finalized []uuid.UUID
	artifacts map[string]access.Artifact
	// rec, when set, is what GetBySession/ListArtifacts answer with.
	rec     *access.Recording
	list    []access.Artifact
	deleted []uuid.UUID
	delErr  error
}

func newFakeRecordings() *fakeRecordings {
	return &fakeRecordings{artifacts: map[string]access.Artifact{}}
}

func (f *fakeRecordings) Start(_ context.Context, _ access.Scope, sessionID uuid.UUID, _ time.Duration) (*access.Recording, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.started = append(f.started, sessionID)
	return &access.Recording{ID: uuid.New(), SessionID: sessionID, Status: "recording"}, nil
}
func (f *fakeRecordings) Finalize(_ context.Context, sessionID uuid.UUID, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalized = append(f.finalized, sessionID)
	return nil
}
func (f *fakeRecordings) GetBySession(context.Context, access.Scope, uuid.UUID) (*access.Recording, error) {
	if f.rec != nil {
		return f.rec, nil
	}
	return nil, access.ErrNotFound
}
func (f *fakeRecordings) ListArtifacts(context.Context, access.Scope, uuid.UUID) ([]access.Artifact, error) {
	return f.list, nil
}
func (f *fakeRecordings) Delete(_ context.Context, _ access.Scope, sessionID uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.delErr != nil {
		return f.delErr
	}
	f.deleted = append(f.deleted, sessionID)
	return nil
}
func (f *fakeRecordings) FindBySessionSystem(context.Context, uuid.UUID) (*access.Recording, error) {
	return nil, access.ErrNotFound
}
func (f *fakeRecordings) AddArtifact(_ context.Context, recordingID uuid.UUID, a access.Artifact) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.artifacts[recordingID.String()+"/"+a.Kind] = a
	return nil
}
func (f *fakeRecordings) GetArtifact(context.Context, access.Scope, uuid.UUID, string) (*access.Artifact, error) {
	return nil, access.ErrNotFound
}

// fakeRegistry records live-registry traffic.
type fakeRegistry struct {
	added      []uuid.UUID
	removed    []uuid.UUID
	terminated []uuid.UUID
}

func (f *fakeRegistry) Add(_ context.Context, _, sessionID uuid.UUID, _ time.Duration) error {
	f.added = append(f.added, sessionID)
	return nil
}
func (f *fakeRegistry) Remove(_ context.Context, _, sessionID uuid.UUID) error {
	f.removed = append(f.removed, sessionID)
	return nil
}
func (f *fakeRegistry) ListActive(context.Context, uuid.UUID) ([]uuid.UUID, error) { return nil, nil }
func (f *fakeRegistry) SignalTerminate(_ context.Context, sessionID uuid.UUID) error {
	f.terminated = append(f.terminated, sessionID)
	return nil
}

var errBoom = errors.New("boom")

// harness bundles a Service with the fakes behind it so a test can assert on
// what the broker did, not just what it returned.
type harness struct {
	svc        *Service
	sessions   *fakeSessions
	authorizer *fakeAuthorizer
	// gateway is the reverse proxy: the default delivery mode.
	gateway *fakeGateway
	// isolated is the browser-isolation gateway, wired in unless opts.noIsolation
	// models a host with no Chromium — so tests can assert both what an isolated
	// device gets and what happens when the host cannot provide it.
	isolated   *fakeGateway
	audit      *fakeAudit
	recordings *fakeRecordings
	registry   *fakeRegistry
}

type opts struct {
	entitled       bool
	authorizerErr  error
	hasCredential  bool
	allowUnmanaged bool
	noAuthorizer   bool
	establishErr   error
	// noRecording models a device whose owner switched recording off.
	noRecording bool
	// isolate models a device delivered through browser isolation. A recorded
	// device implies it — recording only exists under isolation — so this is
	// only worth setting for the isolated-but-not-recorded device, which is what
	// an appliance SPA needs.
	isolate bool
	// noIsolation models a host with no usable Chromium. Isolation is on in the
	// default deployment (the compose image ships one), so the interesting case
	// to opt into is its absence.
	noIsolation bool
	// protocol overrides the device's protocol. Defaults to https, the only one
	// the fake gateways serve, so setting it to anything else models a device
	// whose protocol has no gateway registered.
	protocol access.Protocol
}

func newHarness(o opts) *harness {
	if o.protocol == "" {
		o.protocol = access.ProtocolHTTPS
	}
	sessions := newFakeSessions()
	authz := &fakeAuthorizer{allow: o.entitled, err: o.authorizerErr}
	gw := &fakeGateway{proto: access.ProtocolHTTPS, establishErr: o.establishErr}
	iso := &fakeGateway{proto: access.ProtocolHTTPS, establishErr: o.establishErr, records: true}
	aud := &fakeAudit{}
	rec := newFakeRecordings()
	reg := &fakeRegistry{}

	deps := Deps{
		Sessions:   sessions,
		Gateways:   []access.Gateway{gw},
		Registry:   reg,
		Recordings: rec,
		Devices: fakeDevices{ep: access.Endpoint{
			Protocol: o.protocol, BaseURL: "https://10.0.0.1", Host: "10.0.0.1", Port: 443,
			AllowUnmanaged: o.allowUnmanaged, RecordSessions: !o.noRecording,
			// This mirrors what adapters.go derives from the device row: recording
			// forces isolated delivery, and isolated delivery is also selectable on
			// its own.
			Isolate: !o.noRecording || o.isolate,
		}},
		Creds:  fakeCreds{has: o.hasCredential},
		Audit:  aud,
		Clock:  fixedClock{t: time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)},
		Node:   "test-node",
		Config: DefaultConfig(),
	}
	if !o.noAuthorizer {
		deps.Authorizer = authz
	}
	if !o.noIsolation {
		deps.IsolatedGateways = []access.Gateway{iso}
	}
	return &harness{
		svc: NewService(deps), sessions: sessions, authorizer: authz,
		gateway: gw, isolated: iso, audit: aud, recordings: rec, registry: reg,
	}
}

func actorClaims() iam.Claims {
	return iam.Claims{
		UserID:         uuid.New(),
		OrganizationID: uuid.New(),
		Email:          "operator@example.com",
	}
}

func superClaims() iam.Claims {
	c := actorClaims()
	c.IsSuperAdmin = true
	return c
}

func (f *fakeSessions) touchedIDs() []uuid.UUID {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]uuid.UUID(nil), f.touched...)
}

// fakeBlobs records what was stored and freed.
type fakeBlobs struct {
	mu      sync.Mutex
	objects map[string][]byte
	deleted []string
	delErr  map[string]error
}

func newFakeBlobs() *fakeBlobs {
	return &fakeBlobs{objects: map[string][]byte{}, delErr: map[string]error{}}
}

func (f *fakeBlobs) Put(_ context.Context, key string, data []byte, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = data
	return nil
}
func (f *fakeBlobs) Get(_ context.Context, key string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.objects[key]
	if !ok {
		return nil, access.ErrNotFound
	}
	return b, nil
}
func (f *fakeBlobs) Delete(_ context.Context, key string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.delErr[key]; err != nil {
		return err
	}
	delete(f.objects, key)
	f.deleted = append(f.deleted, key)
	return nil
}
