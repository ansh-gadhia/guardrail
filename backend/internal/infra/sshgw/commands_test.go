package sshgw

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// fakeEvents collects the session timeline.
type fakeEvents struct {
	mu  sync.Mutex
	evs []access.Event
}

func (f *fakeEvents) RecordEvent(_ context.Context, _ uuid.UUID, kind string, data map[string]any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.evs = append(f.evs, access.Event{Kind: kind, Data: data, Timestamp: time.Now()})
	return nil
}
func (f *fakeEvents) ListEvents(context.Context, access.Scope, uuid.UUID, int) ([]access.Event, error) {
	return nil, nil
}
func (f *fakeEvents) commands() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.evs {
		if e.Kind == "command" {
			out = append(out, e.Data["prompt"].(string)+" "+e.Data["command"].(string))
		}
	}
	return out
}

// fakeMirrors hands out mirrors and counts the ones still open.
type fakeMirrors struct {
	mu   sync.Mutex
	open int
}

func (f *fakeMirrors) OpenMirror(context.Context, *access.Recording, uuid.UUID, access.MirrorOptions) (access.TerminalMirror, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.open++
	return &fakeMirror{f: f}, nil
}
func (f *fakeMirrors) stillOpen() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.open
}

type fakeMirror struct {
	f      *fakeMirrors
	closed bool
}

func (m *fakeMirror) Write([]byte)    {}
func (m *fakeMirror) Resize(int, int) {}
func (m *fakeMirror) Close(context.Context) error {
	m.f.mu.Lock()
	defer m.f.mu.Unlock()
	if !m.closed {
		m.closed = true
		m.f.open--
	}
	return nil
}

func commandGateway(t *testing.T, record bool) (*Gateway, *access.Session, *fakeEvents, *httptest.Server, string) {
	t.Helper()
	srv := newTestSSHServer(t, "pw", "Welcome\r\n")
	srv.prompt = "core-sw1# "
	host, port := srv.addr()
	ev := &fakeEvents{}
	g := NewGateway(DefaultConfig(), Deps{
		Devices: stubLookup{ep: access.Endpoint{
			Protocol: access.ProtocolSSH, Host: host, Port: port, RecordSessions: record,
		}},
		HostKeys:   InsecureIgnoreHostKey{},
		Recordings: newFakeRecordings(),
		Blobs:      newFakeBlobs(),
		Events:     ev,
	})
	s := &access.Session{
		ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(),
		Protocol: access.ProtocolSSH,
	}
	live, err := g.Establish(context.Background(), s,
		stubCreds{cred: access.Credential{Username: "u", Secret: "pw", Injection: InjectSSHPassword}})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.Stream(w, r, s.ID, live.ProxyToken)
	}))
	t.Cleanup(ts.Close)
	return g, s, ev, ts, live.ProxyToken
}

// Commands typed in a recorded session reach its timeline, with the prompt
// they were typed at — through the real gateway, a real SSH channel and the
// operator's WebSocket.
func TestCommandsReachTheTimeline(t *testing.T) {
	g, s, ev, ts, _ := commandGateway(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	readUntil(t, ctx, c, "core-sw1# ")
	for _, k := range []string{"s", "h", "o", "w", " ", "v", "e", "r", "s", "i", "o", "n", "\r"} {
		typeInto(t, ctx, c, k)
	}
	readUntil(t, ctx, c, "show version\r\ncore-sw1# ")
	typeInto(t, ctx, c, "reload\r")
	readUntil(t, ctx, c, "reload\r\ncore-sw1# ")

	if err := g.End(context.Background(), s.ID); err != nil {
		t.Fatal(err)
	}
	got := ev.commands()
	want := []string{"core-sw1# show version", "core-sw1# reload"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("timeline commands %q, want %q", got, want)
	}
}

// A device with recording switched off keeps no command log either.
func TestNoCommandLogWithoutRecording(t *testing.T) {
	g, s, ev, ts, _ := commandGateway(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	readUntil(t, ctx, c, "core-sw1# ")
	typeInto(t, ctx, c, "show version\r")
	readUntil(t, ctx, c, "show version\r\ncore-sw1# ")
	_ = g.End(context.Background(), s.ID)
	if got := ev.commands(); len(got) != 0 {
		t.Errorf("an unrecorded session logged commands: %q", got)
	}
}

// A failed connection to a filmed device must not leave its browser tab open.
func TestFailedConnectClosesTheMirror(t *testing.T) {
	srv := newTestSSHServer(t, "right", "")
	host, port := srv.addr()
	mirrors := &fakeMirrors{}
	g := NewGateway(DefaultConfig(), Deps{
		Devices: stubLookup{ep: access.Endpoint{
			Protocol: access.ProtocolSSH, Host: host, Port: port, RecordSessions: true,
			RecordingKinds: []string{access.ArtifactTranscript, access.ArtifactVideo},
		}},
		HostKeys:   InsecureIgnoreHostKey{},
		Recordings: newFakeRecordings(),
		Blobs:      newFakeBlobs(),
		Mirrors:    mirrors,
		Events:     &fakeEvents{},
	})
	s := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), DeviceID: uuid.New(), Protocol: access.ProtocolSSH}
	_, err := g.Establish(context.Background(), s,
		stubCreds{cred: access.Credential{Username: "u", Secret: "wrong", Injection: InjectSSHPassword}})
	if err == nil {
		t.Fatal("a wrong password connected")
	}
	if n := mirrors.stillOpen(); n != 0 {
		t.Errorf("%d mirror(s) left open after a failed connect", n)
	}
}
