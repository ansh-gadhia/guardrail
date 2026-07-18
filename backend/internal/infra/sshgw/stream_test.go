package sshgw

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/infra/term"
)

// fakeBlobs captures what was persisted.
type fakeBlobs struct {
	mu   sync.Mutex
	objs map[string][]byte
}

func newFakeBlobs() *fakeBlobs { return &fakeBlobs{objs: map[string][]byte{}} }

func (f *fakeBlobs) Put(_ context.Context, key string, data []byte, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objs[key] = append([]byte(nil), data...)
	return nil
}
func (f *fakeBlobs) Get(_ context.Context, key string) ([]byte, error) { return f.objs[key], nil }
func (f *fakeBlobs) Delete(context.Context, string) error              { return nil }

func (f *fakeBlobs) find(suffix string) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	for k, v := range f.objs {
		if strings.HasSuffix(k, suffix) {
			return v
		}
	}
	return nil
}

// fakeRecordings is a minimal RecordingStore.
type fakeRecordings struct {
	mu         sync.Mutex
	artifacts  map[string]access.Artifact
	byID       map[uuid.UUID]struct{}
	finalized  []uuid.UUID
	startCalls int
	// row is the recording the broker opened, which the gateway must find.
	row *access.Recording
}

func newFakeRecordings() *fakeRecordings {
	return &fakeRecordings{
		artifacts: map[string]access.Artifact{},
		byID:      map[uuid.UUID]struct{}{},
		row:       &access.Recording{ID: uuid.New(), Status: "recording"},
	}
}

// Start must never be called by the gateway: the broker owns the recording
// lifecycle. A gateway that starts its own leaves two rows for one session.
func (f *fakeRecordings) Start(_ context.Context, _ access.Scope, sid uuid.UUID, _ time.Duration) (*access.Recording, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls++
	return &access.Recording{ID: uuid.New(), SessionID: sid, Status: "recording"}, nil
}
func (f *fakeRecordings) Finalize(_ context.Context, sid uuid.UUID, _ time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finalized = append(f.finalized, sid)
	return nil
}
func (f *fakeRecordings) GetBySession(context.Context, access.Scope, uuid.UUID) (*access.Recording, error) {
	return nil, access.ErrNotFound
}

// FindBySessionSystem models the row the broker opened at Connect.
func (f *fakeRecordings) FindBySessionSystem(_ context.Context, sid uuid.UUID) (*access.Recording, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.row == nil {
		return nil, access.ErrNotFound
	}
	f.row.SessionID = sid
	return f.row, nil
}

// AddArtifact mirrors the real repository, which INSERTs the id explicitly
// instead of relying on the column default. The earlier fake accepted anything
// and so happily stored a zero id — while live Postgres rejected the second
// artifact on a primary-key collision. A fake looser than the thing it stands in
// for does not test, it reassures.
func (f *fakeRecordings) AddArtifact(_ context.Context, recID uuid.UUID, a access.Artifact) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a.ID == uuid.Nil {
		return errors.New("artifact id is zero: would collide on the primary key")
	}
	if _, dup := f.byID[a.ID]; dup {
		return errors.New("duplicate artifact id")
	}
	if a.RecordingID != recID {
		return errors.New("artifact RecordingID does not match the recording")
	}
	f.byID[a.ID] = struct{}{}
	f.artifacts[a.Kind] = a
	return nil
}
func (f *fakeRecordings) GetArtifact(context.Context, access.Scope, uuid.UUID, string) (*access.Artifact, error) {
	return nil, access.ErrNotFound
}

func (f *fakeRecordings) ListArtifacts(context.Context, access.Scope, uuid.UUID) ([]access.Artifact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]access.Artifact, 0, len(f.artifacts))
	for _, a := range f.artifacts {
		out = append(out, a)
	}
	return out, nil
}

// Delete drops the recording and its artifacts for real, so a later
// FindBySessionSystem misses the way live Postgres would. A fake that kept
// serving deleted rows would let a use-after-delete pass here and fail there.
func (f *fakeRecordings) Delete(_ context.Context, _ access.Scope, sid uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.row == nil || f.row.SessionID != sid {
		return access.ErrNotFound
	}
	f.row = nil
	f.artifacts = map[string]access.Artifact{}
	f.byID = map[uuid.UUID]struct{}{}
	return nil
}

// recordingTouches counts idle-timeout activity.
type countingActivity struct {
	mu sync.Mutex
	n  int
}

func (c *countingActivity) Touch(uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
}
func (c *countingActivity) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// liveHarness wires a gateway to a real SSH server behind a real HTTP server, so
// the test drives the same path a browser does.
type liveHarness struct {
	g    *Gateway
	sess *access.Session
	srv  *testSSHServer
	ts   *httptest.Server
	tok  string
	act  *countingActivity
	rec  *fakeRecordings
	blob *fakeBlobs
}

func newLiveHarness(t *testing.T, record bool) *liveHarness {
	t.Helper()
	srv := newTestSSHServer(t, "pw", "banner-line\n")
	host, port := srv.addr()

	act := &countingActivity{}
	rec := newFakeRecordings()
	blob := newFakeBlobs()

	g := NewGateway(DefaultConfig(), Deps{
		Devices: stubLookup{ep: access.Endpoint{
			Protocol: access.ProtocolSSH, Host: host, Port: port, RecordSessions: record,
		}},
		HostKeys:   InsecureIgnoreHostKey{},
		Activity:   act,
		Recordings: rec,
		Blobs:      blob,
	})
	s := &access.Session{
		ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(),
		Protocol: access.ProtocolSSH, Watermark: "operator@example.com",
	}
	live, err := g.Establish(context.Background(), s,
		stubCreds{cred: access.Credential{Username: "u", Secret: "pw", Injection: InjectSSHPassword}})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}

	// Mirror the delivery layer: /<sid>/ is the console, /<sid>/__ws__ the socket.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/__ws__") {
			g.Stream(w, r, s.ID, live.ProxyToken)
			return
		}
		g.Console(w, r, s.ID, live.ProxyToken, "")
	}))
	t.Cleanup(ts.Close)

	return &liveHarness{g: g, sess: s, srv: srv, ts: ts, tok: live.ProxyToken, act: act, rec: rec, blob: blob}
}

func (h *liveHarness) dial(t *testing.T, ctx context.Context) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.ts.URL, "http")+"/__ws__", nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	return c
}

// The end-to-end path: a keystroke sent over the WebSocket reaches the device's
// PTY, and the device's output comes back.
func TestStreamCarriesInputAndOutput(t *testing.T) {
	h := newLiveHarness(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := h.dial(t, ctx)
	defer c.CloseNow()

	// The shell banner should arrive unprompted.
	_, data, err := c.Read(ctx)
	if err != nil {
		t.Fatalf("read banner: %v", err)
	}
	if !strings.Contains(string(data), "banner-line") {
		t.Errorf("first frame = %q, want the shell banner", data)
	}

	// A keystroke must reach the device.
	msg, _ := json.Marshal(term.ClientMsg{T: "i", D: "whoami\n"})
	if err := c.Write(ctx, websocket.MessageText, msg); err != nil {
		t.Fatalf("write input: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(h.srv.got(), "whoami") {
		if time.Now().After(deadline) {
			t.Fatalf("device never received the keystroke; got %q", h.srv.got())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Typing is what proves someone is still there, so it must reset the idle clock.
func TestStreamTouchesActivityOnInputOnly(t *testing.T) {
	h := newLiveHarness(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := h.dial(t, ctx)
	defer c.CloseNow()
	_, _, _ = c.Read(ctx) // banner

	// A resize must NOT count: a window manager can emit one with nobody at the
	// keyboard, which would keep an abandoned session alive past its timeout.
	rs, _ := json.Marshal(term.ClientMsg{T: "r", Cols: 100, Rows: 40})
	if err := c.Write(ctx, websocket.MessageText, rs); err != nil {
		t.Fatalf("write resize: %v", err)
	}
	time.Sleep(150 * time.Millisecond)
	if n := h.act.count(); n != 0 {
		t.Errorf("resize touched activity %d times; an idle session would never expire", n)
	}

	in, _ := json.Marshal(term.ClientMsg{T: "i", D: "x"})
	if err := c.Write(ctx, websocket.MessageText, in); err != nil {
		t.Fatalf("write input: %v", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for h.act.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("input never touched activity; the session would be reaped while in use")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// A recorded SSH session must produce a searchable transcript of what the device
// printed — this is the evidence the whole native-SSH decision is built on.
func TestRecordedSessionWritesSearchableTranscript(t *testing.T) {
	h := newLiveHarness(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := h.dial(t, ctx)
	_, _, _ = c.Read(ctx) // banner

	msg, _ := json.Marshal(term.ClientMsg{T: "i", D: "cat /etc/shadow\n"})
	if err := c.Write(ctx, websocket.MessageText, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Wait for the echo to come back, so it is in the transcript before teardown.
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(h.srv.got(), "cat /etc/shadow") {
		if time.Now().After(deadline) {
			t.Fatal("device never saw the command")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	c.CloseNow()

	if err := h.g.End(context.Background(), h.sess.ID); err != nil {
		t.Fatalf("End: %v", err)
	}

	transcript := h.blob.find("/transcript")
	if transcript == nil {
		t.Fatal("no transcript artifact was written for a recorded session")
	}
	// The decisive property: it is text, and it is greppable years later.
	if !strings.Contains(string(transcript), "cat /etc/shadow") {
		t.Errorf("transcript does not contain the command; got %q", transcript)
	}
	if !strings.Contains(string(transcript), "banner-line") {
		t.Errorf("transcript missing device output; got %q", transcript)
	}

	// The manifest must index it, or a player cannot replay the timing.
	mb := h.blob.find("/manifest.json")
	if mb == nil {
		t.Fatal("no manifest written")
	}
	var m term.Manifest
	if err := json.Unmarshal(mb, &m); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	if len(m.Chunks) == 0 {
		t.Error("manifest indexes no chunks; playback would show nothing")
	}
	total := 0
	for _, ch := range m.Chunks {
		total += ch.Len
	}
	if total != len(transcript) {
		t.Errorf("manifest chunk lengths sum to %d but the transcript is %d bytes", total, len(transcript))
	}

	h.rec.mu.Lock()
	_, hasTranscript := h.rec.artifacts[ArtifactTranscript]
	_, hasManifest := h.rec.artifacts[access.ArtifactManifest]
	nFinal := len(h.rec.finalized)
	starts := h.rec.startCalls
	h.rec.mu.Unlock()
	// The broker opens the recording at Connect; a gateway that starts its own
	// leaves two rows for one session — one with the artifacts and one forever
	// empty, which is indistinguishable from evidence having been removed.
	if starts != 0 {
		t.Errorf("gateway called Recordings.Start %d times; the broker owns that lifecycle", starts)
	}
	if !hasTranscript {
		t.Error("transcript artifact was not registered against the recording")
	}
	if !hasManifest {
		t.Error("manifest artifact was not registered; playback timing would be lost")
	}
	if nFinal != 1 {
		t.Errorf("recording finalized %d times, want 1", nFinal)
	}
}

// A device with recording off must produce no transcript. The policy is the
// device owner's, and capturing anyway would be a quiet betrayal of it.
func TestUnrecordedSessionWritesNothing(t *testing.T) {
	h := newLiveHarness(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := h.dial(t, ctx)
	_, _, _ = c.Read(ctx)
	msg, _ := json.Marshal(term.ClientMsg{T: "i", D: "secret-command\n"})
	_ = c.Write(ctx, websocket.MessageText, msg)
	time.Sleep(200 * time.Millisecond)
	c.CloseNow()

	if err := h.g.End(context.Background(), h.sess.ID); err != nil {
		t.Fatalf("End: %v", err)
	}
	if b := h.blob.find("/transcript"); b != nil {
		t.Errorf("unrecorded session wrote a transcript: %q", b)
	}
}

// One terminal per session: a second socket must be refused, or two people's
// keystrokes interleave into one transcript attributed to one operator.
func TestSecondAttachIsRefused(t *testing.T) {
	h := newLiveHarness(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c1 := h.dial(t, ctx)
	defer c1.CloseNow()
	_, _, _ = c1.Read(ctx) // ensure attached

	if _, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.ts.URL, "http")+"/__ws__", nil); err == nil {
		t.Fatal("a second terminal attached to the same session")
	}
}

// The console must serve the terminal page, with the watermark text present.
func TestConsoleServesTerminal(t *testing.T) {
	h := newLiveHarness(t, false)

	resp, err := http.Get(h.ts.URL + "/")
	if err != nil {
		t.Fatalf("get console: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("console status = %d, want 200", resp.StatusCode)
	}
	buf := make([]byte, 400<<10)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])
	if !strings.Contains(body, "operator@example.com") {
		t.Error("console page does not carry the watermark attribution")
	}
}
