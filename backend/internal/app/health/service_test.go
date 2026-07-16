package health

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/assets"
)

// fakeHealthRepo serves a fixed target list and captures what the poller wrote.
type fakeHealthRepo struct {
	mu      sync.Mutex
	targets []assets.ProbeTarget
	written map[uuid.UUID]assets.Health
	listErr error
}

func newFakeRepo(targets ...assets.ProbeTarget) *fakeHealthRepo {
	return &fakeHealthRepo{targets: targets, written: map[uuid.UUID]assets.Health{}}
}

func (f *fakeHealthRepo) ListProbeTargets(context.Context) ([]assets.ProbeTarget, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.targets, nil
}

func (f *fakeHealthRepo) Upsert(_ context.Context, id uuid.UUID, h assets.Health) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written[id] = h
	return nil
}

func (f *fakeHealthRepo) get(id uuid.UUID) (assets.Health, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	h, ok := f.written[id]
	return h, ok
}

// targetFor turns a test server URL into a probe target.
func targetFor(t *testing.T, rawURL string, failures int) assets.ProbeTarget {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	port := 80
	if u.Port() != "" {
		if port, err = strconv.Atoi(u.Port()); err != nil {
			t.Fatalf("parse port %q: %v", u.Port(), err)
		}
	}
	return assets.ProbeTarget{
		DeviceID: uuid.New(), Host: u.Hostname(), Port: port, Scheme: u.Scheme,
		VerifyTLS: false, ConsecutiveFailures: failures,
	}
}

var errListFailed = errors.New("health: list failed")

func newTestService(repo assets.HealthRepository) *Service {
	return NewService(repo, zap.NewNop(), Config{Interval: time.Hour, Timeout: 2 * time.Second, Concurrency: 4})
}

func TestSweep_ReachableDevice_IsOnline(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv.URL, 0)
	repo := newFakeRepo(tgt)
	newTestService(repo).SweepOnce(context.Background())

	h, ok := repo.get(tgt.DeviceID)
	if !ok {
		t.Fatal("no health recorded for the probed device")
	}
	if h.Status != assets.HealthOnline {
		t.Errorf("status = %q, want %q", h.Status, assets.HealthOnline)
	}
	if h.LatencyMS == nil {
		t.Error("online device recorded no latency")
	}
	if h.CheckedAt == nil {
		t.Error("no checked_at stamped")
	}
	if h.ConsecutiveFailures != 0 {
		t.Errorf("failures = %d, want 0 after a success", h.ConsecutiveFailures)
	}
}

func TestSweep_UnauthenticatedChallenge_IsStillOnline(t *testing.T) {
	// A management UI that challenges an anonymous probe is a healthy one. Reading
	// 401 as "offline" would show every properly-secured device as down.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	tgt := targetFor(t, srv.URL, 0)
	repo := newFakeRepo(tgt)
	newTestService(repo).SweepOnce(context.Background())

	h, _ := repo.get(tgt.DeviceID)
	if h.Status != assets.HealthOnline {
		t.Errorf("status = %q for a 401, want %q — the device answered, so it is up", h.Status, assets.HealthOnline)
	}
}

func TestSweep_UnreachableDevice_IsOfflineAndCountsUp(t *testing.T) {
	// A closed port: start a server and immediately stop it so nothing listens.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close()

	tgt := targetFor(t, dead, 2)
	repo := newFakeRepo(tgt)
	newTestService(repo).SweepOnce(context.Background())

	h, ok := repo.get(tgt.DeviceID)
	if !ok {
		t.Fatal("no health recorded for the unreachable device")
	}
	if h.Status != assets.HealthOffline {
		t.Errorf("status = %q, want %q", h.Status, assets.HealthOffline)
	}
	if h.ConsecutiveFailures != 3 {
		t.Errorf("failures = %d, want 3 (the streak of 2 plus this one)", h.ConsecutiveFailures)
	}
	if h.LastError == "" {
		t.Error("offline device recorded no error; an operator needs to know why")
	}
}

func TestSweep_BlockedByEgressPolicy_IsUnknownNotOffline(t *testing.T) {
	// The metadata endpoint is refused by policy. That is not evidence the device
	// is down, so it must not be reported as offline.
	tgt := assets.ProbeTarget{DeviceID: uuid.New(), Host: "169.254.169.254", Port: 80, Scheme: "http"}
	repo := newFakeRepo(tgt)
	newTestService(repo).SweepOnce(context.Background())

	h, ok := repo.get(tgt.DeviceID)
	if !ok {
		t.Fatal("no health recorded for the blocked target")
	}
	if h.Status != assets.HealthUnknown {
		t.Errorf("status = %q, want %q — a policy refusal is not a liveness signal", h.Status, assets.HealthUnknown)
	}
}

func TestSweep_ProbesEveryDevice(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	targets := []assets.ProbeTarget{
		targetFor(t, srv.URL, 0), targetFor(t, srv.URL, 0), targetFor(t, srv.URL, 0),
		targetFor(t, srv.URL, 0), targetFor(t, srv.URL, 0),
	}
	repo := newFakeRepo(targets...)
	newTestService(repo).SweepOnce(context.Background())

	for i, tgt := range targets {
		if _, ok := repo.get(tgt.DeviceID); !ok {
			t.Errorf("device %d was never probed", i)
		}
	}
}

func TestSweep_ListFailure_DoesNotPanic(t *testing.T) {
	repo := newFakeRepo()
	repo.listErr = errListFailed
	newTestService(repo).SweepOnce(context.Background())
	if len(repo.written) != 0 {
		t.Errorf("wrote %d results despite failing to list, want 0", len(repo.written))
	}
}

// --- Non-web devices ---
//
// The poller probed every device with an HTTP client, so an SSH device produced
//
//	Head "ssh://10.0.0.9:22": unsupported protocol scheme "ssh"
//
// and was written as OFFLINE. Every terminal and desktop device in an estate read
// as down while being perfectly reachable, which inverts the one signal that
// distinguishes "the box is gone" from "my credential is wrong".

func TestSweep_ReachableSSHDevice_IsOnline(t *testing.T) {
	// Something listening on a TCP port, speaking nothing in particular — which is
	// all a liveness check is entitled to assume about SSH.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	target := assets.ProbeTarget{DeviceID: uuid.New(), Host: "127.0.0.1", Port: port, Scheme: "ssh"}
	repo := newFakeRepo(target)
	newTestService(repo).SweepOnce(context.Background())

	got, ok := repo.get(target.DeviceID)
	if !ok {
		t.Fatal("no health was written for the SSH device")
	}
	if got.Status != assets.HealthOnline {
		t.Errorf("status = %q (error: %s), want online — a listening SSH port is a live device",
			got.Status, got.LastError)
	}
	if got.ConsecutiveFailures != 0 {
		t.Errorf("failures = %d, want 0", got.ConsecutiveFailures)
	}
}

func TestSweep_UnreachableSSHDevice_IsOffline(t *testing.T) {
	// Port 1 on loopback: nothing listens there.
	target := assets.ProbeTarget{DeviceID: uuid.New(), Host: "127.0.0.1", Port: 1, Scheme: "ssh", ConsecutiveFailures: 2}
	repo := newFakeRepo(target)
	newTestService(repo).SweepOnce(context.Background())

	got, _ := repo.get(target.DeviceID)
	if got.Status != assets.HealthOffline {
		t.Errorf("status = %q, want offline", got.Status)
	}
	if got.ConsecutiveFailures != 3 {
		t.Errorf("failures = %d, want the streak continued to 3", got.ConsecutiveFailures)
	}
}

// RDP and VNC take the same path, and a desktop device must never be probed with
// an HTTP request.
func TestSweep_DesktopDevices_AreProbedByTCPNotHTTP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	// Accept and immediately close, saying nothing: an RDP server does not answer
	// an HTTP HEAD, and the probe must not need it to.
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	for _, scheme := range []string{"rdp", "vnc"} {
		t.Run(scheme, func(t *testing.T) {
			target := assets.ProbeTarget{DeviceID: uuid.New(), Host: "127.0.0.1", Port: port, Scheme: scheme}
			repo := newFakeRepo(target)
			newTestService(repo).SweepOnce(context.Background())

			got, _ := repo.get(target.DeviceID)
			if got.Status != assets.HealthOnline {
				t.Errorf("%s: status = %q (error: %s), want online", scheme, got.Status, got.LastError)
			}
			// The old failure named the HTTP verb; make sure it cannot come back.
			if strings.Contains(got.LastError, "unsupported protocol scheme") {
				t.Errorf("%s: still being probed over HTTP: %s", scheme, got.LastError)
			}
		})
	}
}
