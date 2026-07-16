// Package browser implements a browser-isolation access Gateway. Instead of
// reverse-proxying (and rewriting) a device's HTML — which is fragile for modern
// SPAs that force HTTPS and hard-navigate to the origin root — it renders the
// device UI in a real headless Chromium on the server and streams the resulting
// pixels to the user over a WebSocket, forwarding mouse/keyboard back. The device
// credential is typed into the real browser server-side and never reaches the
// user, exactly like a clientless PAM. This is the same model CyberPAM/Guacamole
// use; here it is implemented directly with the Chrome DevTools Protocol.
package browser

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/security"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/infra/watermark"
	"github.com/guardrail/guardrail/internal/platform/hostmem"
)

// Config configures the browser gateway.
type Config struct {
	ChromePath string        // path to the Chromium/Chrome binary ("" lets chromedp autodetect)
	Node       string        // gateway node id, surfaced on the session
	IdleTTL    time.Duration // safety cap on a tab's lifetime if the broker never ends it
	Width      int64
	Height     int64
	Quality    int64 // JPEG quality 1..100 for the screencast
	// MaxRecordingBytes caps the frames one session may buffer in memory before
	// they are flushed at teardown. A long, busy session would otherwise grow
	// without bound.
	MaxRecordingBytes int
	// SessionMemoryEstimate is what one isolated session is assumed to cost:
	// a browser instance plus its renderer, plus the frames buffered between
	// flushes. Admission subtracts it from real measured headroom rather than
	// counting sessions, so the platform runs to whatever the machine can
	// actually hold instead of to a number somebody guessed at deploy time.
	SessionMemoryEstimate uint64
	// HostReserve is memory that must remain free after admitting a session. It
	// is the API process's own working set and the room the kernel needs; without
	// it, admission would keep saying yes right up to the OOM killer.
	HostReserve uint64
	// DialogTimeout is how long a device's alert/confirm/prompt waits for the
	// operator before it is dismissed. It exists so a closed viewer cannot leave
	// a page blocked forever; it is long enough that someone reading the message
	// is not rushed.
	DialogTimeout time.Duration
}

func (c *Config) defaults() {
	if c.Width == 0 {
		c.Width = 1280
	}
	if c.Height == 0 {
		c.Height = 800
	}
	if c.Quality == 0 {
		c.Quality = 60
	}
	if c.IdleTTL == 0 {
		c.IdleTTL = 2 * time.Hour
	}
	if c.MaxRecordingBytes == 0 {
		c.MaxRecordingBytes = 512 << 20 // 512 MiB
	}
	if c.SessionMemoryEstimate == 0 {
		// Observed: a headless Chromium serving one 1280x800 screencast settles
		// around 200-300 MiB across its process group. 400 MiB leaves room for a
		// heavy management SPA without being so conservative that a modest host
		// refuses work it could have done.
		c.SessionMemoryEstimate = 400 << 20
	}
	if c.HostReserve == 0 {
		c.HostReserve = 512 << 20
	}
	if c.DialogTimeout == 0 {
		c.DialogTimeout = 90 * time.Second
	}
}

// dlgReply is a viewer's answer to a device dialog.
type dlgReply struct {
	accept bool
	text   string
}

// bSession is the live per-session browser state (in-memory only).
type bSession struct {
	tabCtx  context.Context
	cancel  context.CancelFunc
	token   string
	frames  chan []byte // decoded JPEG frames from the screencast (live viewer)
	notes   chan []byte // outbound JSON notifications (device dialogs)
	replies chan dlgReply
	w, h    int64
	expires time.Time
	orgID   uuid.UUID
	// rec captures frames for playback. Nil when recording is not configured.
	rec *recorder
	// recording is the DB row the captured artifacts belong to.
	recording *access.Recording
}

// Gateway is an access.Gateway backed by headless Chromium.
type Gateway struct {
	cfg        Config
	devices    access.DeviceLookup
	events     access.EventRecorder
	recordings access.RecordingStore
	blobs      access.BlobStore
	activity   access.ActivitySink
	log        *zap.Logger

	// availMem reports free memory for admission. A field so tests can drive
	// admission against a known number instead of the machine they happen to run
	// on; nil means the real host.
	availMem func() (uint64, error)
	// memWarn keeps the "cannot measure memory" warning to one line per process
	// instead of one per connect.
	memWarn sync.Once

	allocOnce   sync.Once
	allocCtx    context.Context
	allocCancel context.CancelFunc
	allocErr    error

	mu       sync.RWMutex
	sessions map[uuid.UUID]*bSession
}

// Deps bundles the gateway's collaborators. Recordings and Blobs are optional:
// with either absent the gateway still serves sessions, it just doesn't capture
// them.
type Deps struct {
	Devices    access.DeviceLookup
	Events     access.EventRecorder
	Recordings access.RecordingStore
	Blobs      access.BlobStore
	// Activity marks the session as in use. Optional; without it an isolated
	// session is never seen as busy and idle expiry would close it out from under
	// a working operator.
	Activity access.ActivitySink
	Log      *zap.Logger
}

// NewGateway constructs the browser gateway. Chromium is launched lazily on the
// first Establish so the process starts even when no sessions are active.
func NewGateway(cfg Config, d Deps) *Gateway {
	cfg.defaults()
	return &Gateway{
		cfg: cfg, devices: d.Devices, events: d.Events, recordings: d.Recordings,
		blobs: d.Blobs, activity: d.Activity, log: d.Log, sessions: map[uuid.UUID]*bSession{},
	}
}

// Protocol reports the modality this gateway serves.
func (g *Gateway) Protocol() access.Protocol { return access.ProtocolHTTPS }

// CanRecord reports that isolated sessions are captured. The device is rendered
// by a browser on this server, so its frames pass through here — which is the
// whole reason a recorded web device has to be delivered this way.
func (g *Gateway) CanRecord() bool { return true }

// admit decides whether the host can afford one more isolated session, from
// memory it actually measures rather than a configured session count.
//
// The check is deliberately about the marginal session only. Sessions already
// running are never touched: an operator halfway through a change on a firewall
// is not the right thing to sacrifice to admit somebody else's new session, and
// an OOM would take them all anyway.
//
// When memory cannot be measured at all, it admits. That restores the behaviour
// this check replaced (which was unbounded), and it is the safer failure: a
// host whose /proc is unreadable is unusual, and wedging every recorded session
// shut on such a host would be a worse bug than the one being prevented. It
// says so once, loudly, rather than silently.
func (g *Gateway) admit() error {
	read := g.availMem
	if read == nil {
		read = hostmem.Available
	}
	avail, err := read()
	if err != nil {
		g.memWarn.Do(func() {
			g.log.Warn("cannot measure host memory; isolated sessions are admitted without a capacity check",
				zap.Error(err))
		})
		return nil
	}
	need := g.cfg.SessionMemoryEstimate + g.cfg.HostReserve
	if avail < need {
		g.mu.RLock()
		live := len(g.sessions)
		g.mu.RUnlock()
		g.log.Warn("refusing isolated session: host is out of memory headroom",
			zap.Uint64("available_mib", avail>>20),
			zap.Uint64("needed_mib", need>>20),
			zap.Int("live_isolated_sessions", live))
		return access.ErrCapacity
	}
	return nil
}

// onDialog handles a device's alert/confirm/prompt.
//
// This is not optional bookkeeping: enabling the Page domain (which the timeline
// needs for navigation events) makes CDP hand dialog control to us, and Chromium
// then blocks the renderer until someone answers. Nothing did, so a device that
// reports a bad password with alert() — which is most consumer network gear —
// froze the session outright. The screencast stops because the page has stopped,
// and it looks like GuardRail hung.
//
// The dialog is forwarded to the viewer rather than auto-accepted. Auto-accept
// is the tempting one-liner and it is wrong: confirm("Erase configuration?") is
// the same API as a failed-login alert, and answering yes on the operator's
// behalf is not something a PAM gets to do.
func (g *Gateway) onDialog(bs *bSession, sessionID uuid.UUID, e *page.EventJavascriptDialogOpening) {
	// The device is telling the operator something ("password is wrong"). That is
	// session history, so it belongs on the timeline next to the navigations.
	if g.events != nil {
		go func() {
			ectx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = g.events.RecordEvent(ectx, sessionID, "dialog", map[string]any{
				"kind": string(e.Type), "message": e.Message,
			})
		}()
	}

	msg, err := json.Marshal(map[string]any{
		"t": "dialog", "kind": string(e.Type), "message": e.Message, "default": e.DefaultPrompt,
	})
	if err != nil {
		msg = []byte(`{"t":"dialog","kind":"alert","message":"The device is asking for a response."}`)
	}
	// Clear any stale answer from a previous dialog before asking for this one.
	select {
	case <-bs.replies:
	default:
	}
	select {
	case bs.notes <- msg:
	default: // viewer is gone or wedged; the timeout below still unblocks the page
	}

	go func() {
		var reply dlgReply
		select {
		case reply = <-bs.replies:
		case <-time.After(g.cfg.DialogTimeout):
			// Nobody answered — the viewer may be closed. Dismiss so the page runs
			// again: a session frozen behind an invisible dialog is worse than one
			// whose dialog was declined, and declining is the safe direction.
			g.log.Info("dismissing unanswered device dialog",
				zap.String("session_id", sessionID.String()), zap.String("kind", string(e.Type)))
		case <-bs.tabCtx.Done():
			return
		}
		h := page.HandleJavaScriptDialog(reply.accept)
		if reply.accept && reply.text != "" {
			h = h.WithPromptText(reply.text)
		}
		if err := chromedp.Run(bs.tabCtx, h); err != nil && bs.tabCtx.Err() == nil {
			g.log.Warn("could not answer device dialog", zap.Error(err))
		}
	}()
}

// ensureAlloc lazily launches the shared Chromium allocator.
func (g *Gateway) ensureAlloc() error {
	g.allocOnce.Do(func() {
		opts := append([]chromedp.ExecAllocatorOption{}, chromedp.DefaultExecAllocatorOptions[:]...)
		if g.cfg.ChromePath != "" {
			opts = append(opts, chromedp.ExecPath(g.cfg.ChromePath))
		}
		opts = append(opts,
			chromedp.Flag("headless", "new"),
			chromedp.Flag("no-sandbox", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-gpu", true),
			chromedp.WindowSize(int(g.cfg.Width), int(g.cfg.Height)),
		)
		g.allocCtx, g.allocCancel = chromedp.NewExecAllocator(context.Background(), opts...)
	})
	return g.allocErr
}

// Establish opens a tab, navigates to the device, injects the credential
// server-side, and starts a screencast whose frames feed ServeWS.
func (g *Gateway) Establish(ctx context.Context, s *access.Session, r access.CredentialResolver) (access.LiveSession, error) {
	if err := g.admit(); err != nil {
		return access.LiveSession{}, err
	}
	if err := g.ensureAlloc(); err != nil {
		return access.LiveSession{}, err
	}
	ep, err := g.devices.Endpoint(ctx, access.Scope{OrganizationID: s.OrganizationID}, s.DeviceID)
	if err != nil {
		return access.LiveSession{}, err
	}
	if _, err := url.Parse(ep.BaseURL); err != nil {
		return access.LiveSession{}, fmt.Errorf("browser: bad device url: %w", err)
	}
	// Credential is optional: if none is bound, open the session anyway and let the
	// device present its own (blank) login page — just with no server-side inject.
	cred, err := r.Resolve(ctx, s)
	if err != nil {
		if !errors.Is(err, access.ErrNoCredential) {
			return access.LiveSession{}, err
		}
		cred = access.Credential{Injection: "none"}
	}

	tabCtx, cancel := chromedp.NewContext(g.allocCtx)
	until := time.Now().Add(g.cfg.IdleTTL)
	if s.GrantedUntil != nil && s.GrantedUntil.Before(until) {
		until = *s.GrantedUntil
	}
	bs := &bSession{
		tabCtx: tabCtx, cancel: cancel, token: randomToken(),
		frames: make(chan []byte, 6),
		// notes is small but never dropped-on-full the way frames are: a missed
		// frame is invisible, a missed dialog leaves the operator staring at a
		// frozen screen. replies holds one answer so a viewer that responds before
		// the waiter is ready does not block.
		notes: make(chan []byte, 4), replies: make(chan dlgReply, 1),
		w: g.cfg.Width, h: g.cfg.Height, expires: until,
		orgID: s.OrganizationID,
	}

	// Attach the recorder here, not when a viewer connects: a session must be
	// recorded whether or not anyone is watching it live.
	if g.recordings != nil && g.blobs != nil {
		if rec, rerr := g.recordings.FindBySessionSystem(ctx, s.ID); rerr == nil && rec != nil {
			bs.recording = rec
			bs.rec = newRecorder(time.Now(), g.cfg.MaxRecordingBytes)
		} else if rerr != nil {
			// A session that can't be recorded still beats no session; the operator
			// sees the gap in the recording list.
			g.log.Warn("browser: no recording row for session; not capturing",
				zap.String("session_id", s.ID.String()), zap.Error(rerr))
		}
	}

	// Frame pump: on each screencast frame, ack it (so Chrome keeps sending), tee
	// it to the recorder, and hand it to the WebSocket writer. The same listener
	// records navigations, so the playback timeline is populated in browser mode
	// exactly as it is behind the reverse proxy.
	sessionID := s.ID
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		switch e := ev.(type) {
		case *page.EventScreencastFrame:
			go func() { _ = chromedp.Run(tabCtx, page.ScreencastFrameAck(e.SessionID)) }()
			data, derr := base64.StdEncoding.DecodeString(e.Data)
			if derr != nil {
				return
			}
			// The recorder takes every frame. The live viewer is allowed to miss
			// some (latest-wins keeps interaction responsive); the recording is not.
			if bs.rec != nil {
				bs.rec.add(time.Now(), data)
			}
			select {
			case bs.frames <- data:
			default: // client behind — drop this frame, latest wins
			}

		case *page.EventJavascriptDialogOpening:
			g.onDialog(bs, sessionID, e)

		case *page.EventFrameNavigated:
			// Main frame only: sub-frame loads are page furniture, not somewhere
			// the operator chose to go.
			if g.events == nil || e.Frame == nil || e.Frame.ParentID != "" {
				return
			}
			path := e.Frame.URL
			if u, uerr := url.Parse(e.Frame.URL); uerr == nil && u.Path != "" {
				path = u.Path
				if u.RawQuery != "" {
					path += "?" + u.RawQuery
				}
			}
			// Best-effort, and off the event goroutine: a slow audit write must not
			// stall the frame pump.
			go func() {
				ectx, ecancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer ecancel()
				_ = g.events.RecordEvent(ectx, sessionID, "url_change",
					map[string]any{"path": path, "method": "GET"})
			}()
		}
	})

	// Bring the tab up: network on, credential injection, viewport, navigate,
	// then start the screencast.
	// page.Enable is what makes FrameNavigated events arrive, which is how the
	// playback timeline gets populated in browser mode.
	actions := []chromedp.Action{network.Enable(), page.Enable()}
	// Stamp the attribution watermark into the page itself, before any device
	// document runs. AddScriptToEvaluateOnNewDocument re-applies it on every
	// navigation, so it cannot be shed by clicking through the device's UI.
	//
	// This is the mode where the watermark is a real control rather than a
	// courtesy: the user is sent pixels, so there is no client-side DOM for them
	// to edit, and the screencast frames the recorder captures are taken from
	// this same page — the mark is in the evidence, not just on the screen.
	actions = append(actions, chromedp.ActionFunc(func(ctx context.Context) error {
		_, err := page.AddScriptToEvaluateOnNewDocument(watermark.JS(s.WatermarkOr())).Do(ctx)
		return err
	}))
	// Management UIs almost always present a self-signed cert; honor the device's
	// verify_tls policy by telling the headless browser to ignore cert errors.
	if !ep.VerifyTLS {
		actions = append(actions, security.SetIgnoreCertificateErrors(true))
	}
	if h := injectionHeaders(cred); len(h) > 0 {
		actions = append(actions, network.SetExtraHTTPHeaders(h))
	}
	actions = append(actions,
		emulation.SetDeviceMetricsOverride(g.cfg.Width, g.cfg.Height, 1, false),
		chromedp.Navigate(ep.BaseURL),
	)
	if err := chromedp.Run(tabCtx, actions...); err != nil {
		cancel()
		g.log.Warn("browser establish failed", zap.String("device_url", ep.BaseURL), zap.Error(err))
		return access.LiveSession{}, fmt.Errorf("browser: establish: %w", err)
	}
	// Best-effort form-fill for devices that use a login form (fire-and-forget so
	// a missing form never blocks the session).
	if cred.Injection == "form" && cred.Secret != "" {
		go g.fillLoginForm(tabCtx, cred)
	}
	sc := page.StartScreencast()
	sc.Format = page.ScreencastFormatJpeg
	sc.Quality = g.cfg.Quality
	sc.MaxWidth = g.cfg.Width
	sc.MaxHeight = g.cfg.Height
	if err := chromedp.Run(tabCtx, sc); err != nil {
		cancel()
		return access.LiveSession{}, fmt.Errorf("browser: screencast: %w", err)
	}

	g.mu.Lock()
	g.sessions[s.ID] = bs
	g.mu.Unlock()

	return access.LiveSession{
		SessionID: s.ID, GatewayNode: g.cfg.Node,
		ProxyPath: "/proxy/" + s.ID.String() + "/", ProxyToken: bs.token,
	}, nil
}

// End flushes the recording, then tears down the tab and its in-memory state.
//
// Order matters: bs.cancel() kills the tab context, and the frames live only in
// memory until they are written, so flushing after cancelling would lose the
// recording. The flush deliberately uses its own context rather than the tab's
// or the caller's — teardown is often triggered by a request that is itself
// about to end.
func (g *Gateway) End(_ context.Context, sessionID uuid.UUID) error {
	g.mu.Lock()
	bs := g.sessions[sessionID]
	delete(g.sessions, sessionID)
	g.mu.Unlock()
	if bs == nil {
		return nil
	}
	if bs.rec != nil && bs.recording != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		n, err := bs.rec.flush(ctx, g.blobs, g.recordings, bs.recording, bs.orgID, bs.w, bs.h)
		cancel()
		if err != nil {
			g.log.Warn("browser: could not store recording",
				zap.String("session_id", sessionID.String()), zap.Error(err))
		} else if n > 0 {
			g.log.Info("browser: recording stored",
				zap.String("session_id", sessionID.String()), zap.Int("frames", n))
		}
	}
	bs.cancel()
	return nil
}

func (g *Gateway) lookup(sessionID uuid.UUID, token string) *bSession {
	g.mu.RLock()
	bs := g.sessions[sessionID]
	g.mu.RUnlock()
	if bs == nil || time.Now().After(bs.expires) {
		return nil
	}
	if subtleConstantEqual(token, bs.token) {
		return bs
	}
	return nil
}
