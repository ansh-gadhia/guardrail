// Package telnetgw brokers telnet sessions natively.
//
// It exists because telnet is a terminal, and terminals should be carried as
// text. Telnet was originally routed through guacd alongside RDP and VNC, which
// works — guacd speaks telnet — but it means a remote desktop daemon rasterises
// a Cisco console into a canvas and streams it back as drawing instructions. The
// operator then feels every keystroke go out as input and come back as pixels,
// which is exactly as slow as it sounds, and the "recording" of a router session
// is megabytes of images that no one can grep.
//
// So this gateway is the SSH gateway's twin, and deliberately so: dial, hand the
// byte stream to the shared xterm console, capture the text. What differs is
// only how the stream is obtained. SSH has a handshake; telnet has none — it is
// cleartext, with no authentication of its own, so the credential is typed at
// the device's own prompt (see login.go), and that is the whole of its security
// story. Nothing here changes that. Brokering telnet means the password lives in
// the vault instead of a spreadsheet and the session is recorded; the bytes on
// the wire are still readable by anything on the path, and the device should be
// moved to SSH.
//
// The operator never learns the credential: it is resolved just-in-time from the
// vault, typed at the prompt, and never travels to the browser.
package telnetgw

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/infra/proxy"
	"github.com/guardrail/guardrail/internal/infra/term"
)

// Config tunes the gateway.
type Config struct {
	// DialTimeout bounds reaching the device. A firewall that blackholes port 23
	// must not hold a Connect request open indefinitely.
	DialTimeout time.Duration
	// LoginTimeout bounds typing the credential at the device's prompt.
	LoginTimeout time.Duration
	// SessionTTL is how long the session handle stays valid.
	SessionTTL time.Duration
	// MaxRecordingBytes caps a single session's captured text.
	MaxRecordingBytes int64
	// MaxBannerBytes caps the login output replayed to a viewer that attaches or
	// reattaches.
	MaxBannerBytes int
}

// DefaultConfig returns workable defaults.
func DefaultConfig() Config {
	return Config{
		DialTimeout: 10 * time.Second,
		// Generous on purpose: console servers and terminal servers can take
		// several seconds to wake a line, and a premature failure here reads to
		// the operator as "wrong password" when nothing was wrong.
		LoginTimeout:      20 * time.Second,
		SessionTTL:        12 * time.Hour,
		MaxRecordingBytes: 16 << 20,
		MaxBannerBytes:    16 << 10,
	}
}

// Deps are the collaborators the gateway needs. They mirror sshgw's, minus host
// keys: telnet has no host identity to pin, which is one more reason not to use it.
type Deps struct {
	Devices    access.DeviceLookup
	Recordings access.RecordingStore
	Blobs      access.BlobStore
	Activity   access.ActivitySink
	Events     access.EventRecorder
	Log        *zap.Logger
}

// Gateway is the telnet access.Gateway and v1.SessionServer.
type Gateway struct {
	cfg  Config
	deps Deps

	mu       sync.RWMutex
	sessions map[uuid.UUID]*telnetSession
}

// NewGateway constructs the telnet gateway.
func NewGateway(cfg Config, deps Deps) *Gateway {
	d := DefaultConfig()
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = d.DialTimeout
	}
	if cfg.LoginTimeout <= 0 {
		cfg.LoginTimeout = d.LoginTimeout
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = d.SessionTTL
	}
	if cfg.MaxRecordingBytes <= 0 {
		cfg.MaxRecordingBytes = d.MaxRecordingBytes
	}
	if cfg.MaxBannerBytes <= 0 {
		cfg.MaxBannerBytes = d.MaxBannerBytes
	}
	return &Gateway{cfg: cfg, deps: deps, sessions: map[uuid.UUID]*telnetSession{}}
}

// Protocol reports which devices this gateway serves.
func (g *Gateway) Protocol() access.Protocol { return access.ProtocolTelnet }

// CanRecord reports that telnet sessions are captured, as text, by this process.
// Like SSH and unlike a desktop, this needs no sidecar and no Chromium, so it
// holds on any host.
func (g *Gateway) CanRecord() bool { return true }

// telnetSession is one brokered telnet connection.
type telnetSession struct {
	id      uuid.UUID
	orgID   uuid.UUID
	token   string
	expires time.Time

	watermark   string
	deviceLabel string
	addr        string

	// What a redial needs. The credential is deliberately absent: it is
	// re-resolved from the vault on every dial, so a long-lived session never
	// holds a plaintext secret in memory waiting to be read out of a core dump.
	sess  *access.Session
	creds access.CredentialResolver
	// allowUnmanaged is the device's break-glass policy, captured at Establish so
	// a redial applies the same rule the first connect did.
	allowUnmanaged bool

	// rec accumulates the transcript. nil when the device is not recorded. It
	// spans the whole session, so a reconnect continues one transcript rather
	// than starting a second.
	rec       *term.Recorder
	recording *access.Recording

	mu   sync.Mutex
	conn *conn
	// banner is the login output, replayed to whoever attaches so the operator
	// sees how they got in rather than an empty black rectangle.
	banner   []byte
	attached bool
	closed   bool
}

// Establish dials the device and logs in.
//
// Done here rather than lazily on the WebSocket so that an unreachable host or a
// credential the device rejects fails the Connect request itself, where the
// operator sees a real error, instead of surfacing as a terminal that opens and
// immediately dies.
func (g *Gateway) Establish(ctx context.Context, s *access.Session, r access.CredentialResolver) (access.LiveSession, error) {
	ep, err := g.deps.Devices.Endpoint(ctx, access.Scope{OrganizationID: s.OrganizationID}, s.DeviceID)
	if err != nil {
		return access.LiveSession{}, err
	}
	if ep.Protocol != access.ProtocolTelnet {
		// The broker routes by protocol, so reaching here means a wiring mistake
		// rather than bad input — but it would mean typing a credential at the
		// wrong transport, so refuse loudly instead of trying anyway.
		return access.LiveSession{}, fmt.Errorf("telnetgw: refusing protocol %q", ep.Protocol)
	}
	if err := proxy.GuardSSRF(ep.Host); err != nil {
		return access.LiveSession{}, err
	}

	port := ep.Port
	if port == 0 {
		port, _ = access.DefaultPort(access.ProtocolTelnet)
	}
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(port))

	sess := &telnetSession{
		id: s.ID, orgID: s.OrganizationID,
		token:          randomToken(),
		expires:        time.Now().Add(g.cfg.SessionTTL),
		watermark:      s.WatermarkOr(),
		deviceLabel:    ep.Host,
		addr:           addr,
		sess:           s,
		creds:          r,
		allowUnmanaged: ep.AllowUnmanaged,
	}

	// Attach to the recording the broker already opened; do not start one. The
	// broker owns that lifecycle, and starting a second here would leave two rows
	// for one session — one holding the artifacts and one permanently empty,
	// which reads exactly like a recording that was tampered with.
	if ep.RecordSessions && g.deps.Recordings != nil && g.deps.Blobs != nil {
		rec, rerr := g.deps.Recordings.FindBySessionSystem(ctx, s.ID)
		if rerr == nil && rec != nil {
			sess.recording = rec
			sess.rec = term.NewRecorder(g.cfg.MaxRecordingBytes)
		}
	}

	if err := g.dial(ctx, sess); err != nil {
		return access.LiveSession{}, err
	}

	g.mu.Lock()
	g.sessions[s.ID] = sess
	g.mu.Unlock()

	return access.LiveSession{
		SessionID:  s.ID,
		ProxyPath:  "/proxy/" + s.ID.String() + "/",
		ProxyToken: sess.token,
	}, nil
}

// dial opens the device connection and logs in, storing the result on the
// session. It is used both for the first connection and for a reconnect, so
// there is exactly one path that knows how to get into a device — a reconnect
// that authenticated differently from a connect would be a hole.
func (g *Gateway) dial(ctx context.Context, s *telnetSession) error {
	cred, err := s.creds.Resolve(ctx, s.sess)
	if err != nil && !errors.Is(err, access.ErrNoCredential) {
		return err
	}
	// Break-glass. This is the one place telnet must NOT copy the SSH gateway.
	//
	// sshgw refuses to connect without a credential, and is right to: SSH
	// authenticates in its handshake, so with nothing to offer there is no
	// session and no page to render — nothing for a human to do. Telnet is the
	// opposite. Its login is just text the device prints and waits on, so a
	// credential-less session lands the operator at the device's own prompt,
	// exactly as a web device shows its own login form. That is precisely what
	// break-glass means everywhere else in this platform, and refusing it here
	// would break the commonest way a lab router is reached.
	//
	// A device that has NOT opted in still fails closed.
	unmanaged := errors.Is(err, access.ErrNoCredential)
	if unmanaged && !s.allowUnmanaged {
		return access.ErrNoCredential
	}

	d := net.Dialer{Timeout: g.cfg.DialTimeout}
	raw, err := d.DialContext(ctx, "tcp", s.addr)
	if err != nil {
		return fmt.Errorf("telnetgw: dial %s: %w", s.addr, err)
	}
	// Keepalives so a device that vanishes without a FIN — a reload, a pulled
	// cable — surfaces as a dead socket in minutes instead of hanging a terminal
	// that looks live and answers nothing.
	if tcp, ok := raw.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}

	c := newConn(raw)
	if err := c.hello(); err != nil {
		_ = c.Close()
		return fmt.Errorf("telnetgw: negotiate %s: %w", s.addr, err)
	}

	if unmanaged {
		// Nothing to type. Hand the raw stream over and let the device's own
		// prompt reach the operator: no pre-read, so the banner simply arrives
		// live once the terminal attaches, and TCP holds it until then.
		//
		// Their keystrokes are not recorded — only device output is — so a
		// password typed at the prompt does not land in the transcript, the same
		// guarantee an injected credential gets.
		s.mu.Lock()
		s.conn = c
		s.banner = nil
		s.mu.Unlock()
		return nil
	}

	banner, err := g.login(c, cred, time.Now().Add(g.cfg.LoginTimeout))
	if err != nil {
		_ = c.Close()
		return err
	}
	// Clear the login deadline or the established session would die on it.
	_ = raw.SetReadDeadline(time.Time{})

	banner = redact(banner, cred.Secret)

	s.mu.Lock()
	s.conn = c
	s.banner = trimBanner(banner, g.cfg.MaxBannerBytes)
	s.mu.Unlock()

	// The login output is the start of the session and belongs in the transcript.
	if s.rec != nil {
		s.rec.Write(banner)
	}
	return nil
}

// End tears the session down and flushes its transcript.
func (g *Gateway) End(_ context.Context, sessionID uuid.UUID) error {
	g.mu.Lock()
	s := g.sessions[sessionID]
	delete(g.sessions, sessionID)
	g.mu.Unlock()
	if s == nil {
		return nil
	}
	return g.teardown(s)
}

// teardown closes the device connection and persists whatever was captured.
func (g *Gateway) teardown(s *telnetSession) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	c := s.conn
	s.conn = nil
	s.mu.Unlock()

	if c != nil {
		_ = c.Close()
	}
	if s.rec == nil || s.recording == nil {
		return nil
	}
	// Flush on a fresh context: teardown often runs because the caller's context
	// was cancelled, and the transcript is the audit evidence — losing it because
	// the operator closed the tab would be the worst possible time to lose it.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := s.rec.Flush(ctx, g.deps.Blobs, g.deps.Recordings, s.recording, s.orgID)
	if err != nil && g.deps.Log != nil {
		g.deps.Log.Error("telnetgw: session transcript was not persisted; the recording has no evidence",
			zap.String("session_id", s.id.String()), zap.Error(err))
	}
	return err
}

// lookup resolves a session by id, enforcing the per-session token.
func (g *Gateway) lookup(sessionID uuid.UUID, token string) *telnetSession {
	g.mu.RLock()
	s := g.sessions[sessionID]
	g.mu.RUnlock()
	if s == nil || time.Now().After(s.expires) {
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1 {
		return s
	}
	return nil
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
