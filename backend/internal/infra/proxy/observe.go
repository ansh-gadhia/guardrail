package proxy

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/infra/term"
)

// watch broadcasts one request line to anyone observing this session.
//
// The QUERY STRING IS NOT INCLUDED. A legacy appliance that authenticates with
// GET /login?user=…&pass=… would otherwise put the device credential on a
// supervisor's screen — the same disclosure that was removed from the recorded
// timeline, and it must not come back through a live view of the same data.
func (sc *sessionCtx) watch(method, path string) {
	if sc == nil || sc.obs == nil {
		return
	}
	if i := strings.IndexByte(path, '?'); i >= 0 {
		path = path[:i]
	}
	if path == "" {
		path = "/"
	}
	line := time.Now().UTC().Format("15:04:05") + "  " + method + " " + path + "\r\n"
	sc.obs.Broadcast([]byte(line))
}

// Observe streams a reverse-proxied session's activity to a supervisor.
//
// # WHAT WATCHING MEANS FOR THIS TRANSPORT
//
// The other gateways have a stream to mirror: a terminal's bytes, a desktop's
// drawing instructions, an isolated browser's frames. A reverse-proxied session
// has none. It is discrete HTTP requests between the operator's own browser and
// the device, and the response bodies never pass through anything that could
// render them for somebody else — they go straight to the operator.
//
// So this shows what CAN be known live: what the operator is reaching, as they
// reach it. That is the same material the playback timeline holds, delivered as
// it happens instead of afterwards. Saying "this session cannot be watched"
// would have been easier and would have left a supervisor with nothing during
// exactly the session where they most wanted to look.
func (g *HTTPGateway) Observe(w http.ResponseWriter, r *http.Request, sid, orgID uuid.UUID) bool {
	sc := g.observable(sid, orgID)
	if sc == nil {
		return false
	}

	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return true
	}
	defer func() { _ = c.CloseNow() }()

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	ob, backlog := sc.obs.Attach()
	defer sc.obs.Detach(ob)

	header := "\x1b[38;5;245mWatching a proxied session. These are the requests the operator is making;\r\n" +
		"the pages themselves go straight to their browser and are not relayed here.\x1b[0m\r\n\r\n"
	if len(backlog) == 0 {
		header += "\x1b[38;5;245m(nothing yet — the next request will appear here)\x1b[0m\r\n"
	}
	wctx, wcancel := context.WithTimeout(ctx, 15*time.Second)
	err = c.Write(wctx, websocket.MessageBinary, append([]byte(header), backlog...))
	wcancel()
	if err != nil {
		return true
	}

	go func() {
		for {
			if _, _, rerr := c.Read(ctx); rerr != nil {
				cancel()
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = c.Close(websocket.StatusNormalClosure, "")
			return true
		case b, open := <-ob.C:
			if !open {
				_ = c.Close(term.CloseDeviceGone, "session ended or viewer fell behind")
				return true
			}
			wc, wcan := context.WithTimeout(ctx, 10*time.Second)
			werr := c.Write(wc, websocket.MessageBinary, b)
			wcan()
			if werr != nil {
				return true
			}
		}
	}
}

// ObserveConsole serves the page a supervisor watches proxied activity in.
//
// The terminal viewer, read-only: the activity feed is lines of text, and
// reusing the console that already renders lines of text beats a third bespoke
// page that would have to re-learn scrollback, resizing and reconnection.
func (g *HTTPGateway) ObserveConsole(w http.ResponseWriter, _ *http.Request, sid, orgID uuid.UUID) bool {
	sc := g.observable(sid, orgID)
	if sc == nil {
		return false
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(term.Page(term.Options{
		SessionID: sid.String(),
		Device:    sc.target.Host,
		Protocol:  "Web",
		ReadOnly:  true,
	})))
	return true
}

// observable finds a live proxied session by id within one organisation.
func (g *HTTPGateway) observable(sessionID, orgID uuid.UUID) *sessionCtx {
	g.mu.RLock()
	sc, ok := g.sessions[sessionID]
	g.mu.RUnlock()
	if !ok || sc.orgID != orgID || sc.obs == nil || time.Now().After(sc.expiresAt) {
		return nil
	}
	return sc
}

// WatcherCount reports how many people are watching a proxied session's activity.
func (g *HTTPGateway) WatcherCount(sid uuid.UUID) (int, bool) {
	g.mu.RLock()
	sc, ok := g.sessions[sid]
	g.mu.RUnlock()
	if !ok || sc.obs == nil {
		return 0, false
	}
	return sc.obs.Count(), true
}
