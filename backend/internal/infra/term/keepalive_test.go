package term

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// keepAliveServer accepts one socket, pings it every `every`, and reads it until
// it closes — the shape of every session handler. It reports when it is done.
func keepAliveServer(t *testing.T, every time.Duration) (string, <-chan struct{}) {
	t.Helper()
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		go KeepAlive(ctx, c, every)
		for {
			if _, _, err := c.Read(ctx); err != nil {
				close(done)
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return "ws" + strings.TrimPrefix(srv.URL, "http"), done
}

func TestKeepAlive_KeepsAnAnsweringViewerConnected(t *testing.T) {
	url, done := keepAliveServer(t, 30*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()
	// A reading client answers pings, as a browser does.
	rctx := c.CloseRead(ctx)

	select {
	case <-done:
		t.Fatal("an answering viewer was disconnected")
	case <-rctx.Done():
		t.Fatal("the server closed a connection that was answering its pings")
	case <-time.After(400 * time.Millisecond): // a dozen pings
	}
}

func TestKeepAlive_ClosesAViewerThatStopsAnswering(t *testing.T) {
	url, done := keepAliveServer(t, 30*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Never reading, so never answering: a half-open connection, as far as the
	// server can tell.
	c, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.CloseNow() }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("a viewer that never answered a ping was never closed")
	}
}
