package telnetgw

import (
	"context"
	"encoding/json"
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

// echoDevice is a telnet device that prompts and echoes what is typed. It
// counts connections, so a test can tell a reattach from a new login. It echoes
// printable text only: echoing the client's option negotiation back would read
// as the device negotiating, and the two would answer each other for ever.
type echoDevice struct {
	mu    sync.Mutex
	conns int
}

func (d *echoDevice) count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.conns
}

func startEchoDevice(t *testing.T) (*echoDevice, string) {
	t.Helper()
	ln, addr := listenLocal(t)
	d := &echoDevice{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			d.mu.Lock()
			d.conns++
			d.mu.Unlock()
			go func() {
				defer func() { _ = c.Close() }()
				_, _ = c.Write([]byte("router> "))
				buf := make([]byte, 512)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					var out []byte
					for _, b := range buf[:n] {
						if b >= 32 && b < 127 || b == '\r' || b == '\n' {
							out = append(out, b)
						}
					}
					if len(out) > 0 {
						_, _ = c.Write(out)
					}
				}
			}()
		}
	}()
	return d, addr
}

func readUntil(t *testing.T, ctx context.Context, c *websocket.Conn, want string) string {
	t.Helper()
	var got strings.Builder
	for !strings.Contains(got.String(), want) {
		_, data, err := c.Read(ctx)
		if err != nil {
			t.Fatalf("waiting for %q, got %q: %v", want, got.String(), err)
		}
		got.Write(data)
	}
	return got.String()
}

// Leaving the session page and coming back must find the same device
// connection and the screen as it was — not a fresh login on an empty terminal.
func TestReattachKeepsTheDeviceConnection(t *testing.T) {
	dev, addr := startEchoDevice(t)
	g := NewGateway(Config{}, Deps{Devices: fakeDevices{ep: endpointFor(t, addr, true)}})
	sess := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), DeviceID: uuid.New()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	live, err := g.Establish(ctx, sess, fakeResolver{err: access.ErrNoCredential})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = g.End(context.Background(), sess.ID) }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.Stream(w, r, sess.ID, live.ProxyToken)
	}))
	defer ts.Close()
	dial := func() *websocket.Conn {
		c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), nil)
		if err != nil {
			t.Fatalf("ws dial: %v", err)
		}
		return c
	}

	c1 := dial()
	readUntil(t, ctx, c1, "router>")
	msg, _ := json.Marshal(term.ClientMsg{T: "i", D: "show version\r"})
	if err := c1.Write(ctx, websocket.MessageText, msg); err != nil {
		t.Fatal(err)
	}
	readUntil(t, ctx, c1, "show version")
	_ = c1.Close(websocket.StatusGoingAway, "") // the page is left

	time.Sleep(100 * time.Millisecond)
	c2 := dial()
	defer func() { _ = c2.CloseNow() }()
	screen := readUntil(t, ctx, c2, "show version")
	if !strings.Contains(screen, "router>") {
		t.Errorf("the screen came back without its start: %q", screen)
	}
	if n := dev.count(); n != 1 {
		t.Fatalf("%d connections to the device, want 1: coming back must not log in again", n)
	}
}

// One keyboard per session, as in sshgw: a newer window takes it, and the one
// it replaced is closed with CloseTakenOver — told why, not cut off.
func TestNewerWindowTakesTheKeyboard(t *testing.T) {
	dev, addr := startEchoDevice(t)
	g := NewGateway(Config{}, Deps{Devices: fakeDevices{ep: endpointFor(t, addr, true)}})
	sess := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), DeviceID: uuid.New()}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	live, err := g.Establish(ctx, sess, fakeResolver{err: access.ErrNoCredential})
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = g.End(context.Background(), sess.ID) }()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.Stream(w, r, sess.ID, live.ProxyToken)
	}))
	defer ts.Close()
	dial := func() *websocket.Conn {
		c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(ts.URL, "http"), nil)
		if err != nil {
			t.Fatalf("ws dial: %v", err)
		}
		return c
	}

	c1 := dial()
	defer func() { _ = c1.CloseNow() }()
	readUntil(t, ctx, c1, "router>")
	c2 := dial()
	defer func() { _ = c2.CloseNow() }()
	readUntil(t, ctx, c2, "router>") // the screen, from the scrollback

	for {
		if _, _, err := c1.Read(ctx); err != nil {
			if got := websocket.CloseStatus(err); got != term.CloseTakenOver {
				t.Fatalf("older window closed with %d, want %d (taken over)", got, term.CloseTakenOver)
			}
			break
		}
	}
	msg, _ := json.Marshal(term.ClientMsg{T: "i", D: "from-the-new-window\r"})
	if err := c2.Write(ctx, websocket.MessageText, msg); err != nil {
		t.Fatal(err)
	}
	readUntil(t, ctx, c2, "from-the-new-window")
	if n := dev.count(); n != 1 {
		t.Fatalf("%d connections to the device, want 1", n)
	}
}
