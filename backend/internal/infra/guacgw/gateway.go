package guacgw

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"path"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/infra/proxy"
)

// Config tunes the gateway. The zero value is usable: DefaultConfig fills it.
type Config struct {
	// Addr is guacd's address, host:port.
	Addr string
	// HandshakeTimeout bounds select→ready. A wedged guacd must fail the Connect
	// request, not hang it.
	HandshakeTimeout time.Duration
	// SessionTTL is how long a live session handle stays valid.
	SessionTTL time.Duration
	// Width/Height/DPI are the desktop geometry requested of the device. The
	// browser re-sends its real size once connected.
	Width, Height, DPI int
	// RecordingDir is where guacd writes session recordings. It must be a path
	// guacd can write to — under compose that means a volume shared with it, which
	// is why this is configured rather than derived.
	RecordingDir string
}

func (c Config) withDefaults() Config {
	if c.Addr == "" {
		c.Addr = "127.0.0.1:4822"
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 20 * time.Second
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = 8 * time.Hour
	}
	if c.Width == 0 {
		c.Width = 1280
	}
	if c.Height == 0 {
		c.Height = 800
	}
	if c.DPI == 0 {
		c.DPI = 96
	}
	return c
}

// Deps are the collaborators the gateway needs.
type Deps struct {
	// Devices resolves the session's target. The gateway looks the endpoint up
	// itself rather than trusting the caller, exactly as the other gateways do.
	Devices access.DeviceLookup
	// Recordings registers the recording guacd writes, and Blobs stores its bytes.
	// Both may be nil, in which case nothing is recorded.
	Recordings access.RecordingStore
	Blobs      access.BlobStore
	// Activity marks a session as in use so the idle reaper leaves it alone.
	Activity access.ActivitySink
	// Events records the session timeline.
	Events access.EventRecorder
	// Log surfaces failures nothing else would report.
	Log *zap.Logger
}

// Gateway brokers one desktop protocol (RDP or VNC) through guacd.
//
// One gateway serves one protocol because the broker routes by protocol and
// access.Gateway reports exactly one. The two are otherwise identical: guacd
// abstracts the difference, which is the entire reason for the sidecar.
type Gateway struct {
	proto access.Protocol
	cfg   Config
	deps  Deps

	mu       sync.RWMutex
	sessions map[uuid.UUID]*guacSession
}

type guacSession struct {
	id      uuid.UUID
	orgID   uuid.UUID
	token   string
	expires time.Time
	// watermark is drawn by the operator's browser over the desktop. Like the SSH
	// console's, it is a deterrent and not a control — guacd composites nothing,
	// so anyone with devtools can remove it. The accountability for a desktop
	// session rests on the recording, which guacd writes server-side.
	watermark   string
	deviceLabel string

	conn *guacConn
	// recordingName is the file guacd is writing, relative to RecordingDir.
	recordingName string
	recording     *access.Recording

	mu       sync.Mutex
	attached bool
	closed   bool
}

// NewGateway constructs a gateway for one desktop protocol.
func NewGateway(proto access.Protocol, cfg Config, deps Deps) *Gateway {
	return &Gateway{
		proto:    proto,
		cfg:      cfg.withDefaults(),
		deps:     deps,
		sessions: map[uuid.UUID]*guacSession{},
	}
}

// Protocol reports which devices this gateway serves.
func (g *Gateway) Protocol() access.Protocol { return g.proto }

// CanRecord reports that desktop sessions are captured. guacd writes the
// recording itself, from the same instruction stream it sends the browser, so
// this needs no Chromium and holds on any host — the recording is produced where
// the pixels are, which is exactly why the reverse proxy could never do it.
func (g *Gateway) CanRecord() bool {
	return g.deps.Recordings != nil && g.deps.Blobs != nil && g.cfg.RecordingDir != ""
}

// Establish opens the guacd connection and returns the client-facing handle.
//
// Note what this does NOT prove. guacd answers `ready` once it has accepted the
// request and created its client — before it has reached the device. A wrong
// password or an unreachable host is reported later, asynchronously, as an
// `error` instruction in the session stream (measured: ~15s for a host that does
// not answer). So a Connect to a misconfigured desktop returns 200 and the
// failure surfaces in the viewer, carrying guacd's own message.
//
// That is guacd's model, not a shortcut: there is no reply that means "connected"
// to wait for, and blocking Connect until drawing instructions appeared would
// hold the request open for the length of an RDP handshake and still guess. The
// error reaches the operator either way; it arrives in the viewer rather than on
// the button they pressed.
func (g *Gateway) Establish(ctx context.Context, s *access.Session, r access.CredentialResolver) (access.LiveSession, error) {
	ep, err := g.deps.Devices.Endpoint(ctx, access.Scope{OrganizationID: s.OrganizationID}, s.DeviceID)
	if err != nil {
		return access.LiveSession{}, err
	}
	if ep.Protocol != g.proto {
		// The broker routes by protocol, so reaching here is a wiring mistake — but
		// it would mean handing a credential to the wrong transport, so refuse
		// loudly rather than try anyway.
		return access.LiveSession{}, fmt.Errorf("guac: %s gateway refusing protocol %q", g.proto, ep.Protocol)
	}
	// The device host is operator-supplied and we are about to dial it from
	// inside the network. Same guard the other gateways use.
	if err := proxy.GuardSSRF(ep.Host); err != nil {
		return access.LiveSession{}, err
	}

	cred, err := r.Resolve(ctx, s)
	if err != nil && !errors.Is(err, access.ErrNoCredential) {
		return access.LiveSession{}, err
	}
	// Break-glass. This used to refuse unconditionally, reasoning that "a desktop
	// has no useful show-me-the-login-page state". That is not true of the
	// protocols guacd brokers: connect an RDP or VNC session with no credential
	// and the device presents its own login, exactly as a web device does — which
	// is the whole of what break-glass means everywhere else.
	//
	// The refusal also contradicted the error it produced. ErrNoCredential is
	// rendered to the operator as "bind one, or enable break-glass unmanaged
	// access on the device", so a device with AllowUnmanaged already set was told
	// to turn on the setting it had on. The remedy the error names has to exist.
	//
	// A device that has NOT opted in still fails closed here, and not only in the
	// broker's pre-flight: this is the gateway that would put the operator in
	// front of the device, and it must not depend on a check somewhere else
	// having run.
	unmanaged := errors.Is(err, access.ErrNoCredential)
	if unmanaged && !ep.AllowUnmanaged {
		return access.LiveSession{}, access.ErrNoCredential
	}
	if !unmanaged {
		if err := checkCredential(cred, g.proto); err != nil {
			return access.LiveSession{}, err
		}
	}

	port := ep.Port
	if port == 0 {
		port, _ = access.DefaultPort(g.proto)
	}

	sess := &guacSession{
		id: s.ID, orgID: s.OrganizationID,
		token:       randomToken(),
		expires:     time.Now().Add(g.cfg.SessionTTL),
		watermark:   s.WatermarkOr(),
		deviceLabel: ep.Host,
	}

	// Attach to the recording the broker already opened for this session; do not
	// start one. The broker owns that lifecycle, and starting a second here would
	// leave two rows for one session — one holding the artifact and one
	// permanently empty, which reads exactly like a recording that was tampered
	// with.
	if ep.RecordSessions && g.CanRecord() {
		rec, rerr := g.deps.Recordings.FindBySessionSystem(ctx, s.ID)
		switch {
		case rerr == nil && rec != nil:
			sess.recording = rec
			sess.recordingName = s.ID.String() + ".guac"
		default:
			// The device is set to be recorded and we are about to open it anyway,
			// unrecorded. That is a decision, not a detail: without the row there is
			// nothing to hang the artifact on, so refusing the session here would
			// deny access over a bookkeeping failure the operator cannot see or fix.
			// But it must never be silent — this is the one path where the console
			// says "recorded" and the truth is "not".
			if g.deps.Log != nil {
				g.deps.Log.Error("guac: device is set to record, but its recording row was not found; "+
					"the session will open UNRECORDED",
					zap.String("session_id", s.ID.String()),
					zap.Error(rerr))
			}
		}
	}

	cfg := connConfig{
		Protocol: string(g.proto),
		Width:    g.cfg.Width, Height: g.cfg.Height, DPI: g.cfg.DPI,
		Params: g.params(ep, cred, port, sess.recordingName),
	}
	conn, err := dialGuacd(ctx, g.cfg.Addr, cfg, g.cfg.HandshakeTimeout)
	if err != nil {
		return access.LiveSession{}, err
	}
	sess.conn = conn

	g.mu.Lock()
	g.sessions[s.ID] = sess
	g.mu.Unlock()

	if g.deps.Log != nil {
		g.deps.Log.Info("guac: desktop session established",
			zap.String("session_id", s.ID.String()),
			zap.String("protocol", string(g.proto)),
			// guacd's own id, so its logs can be joined to this session.
			zap.String("guacd_connection", conn.ID),
			zap.Bool("recorded", sess.recording != nil),
			// Which account the device was asked to log in as. Not a secret — the
			// audit trail already names the credential — and it is the only way to
			// tell "GuardRail logged in as the wrong user" from "the device ignored
			// the credential we sent" without guessing. Empty means break-glass.
			zap.String("device_username", cred.Username),
			zap.Bool("unmanaged", unmanaged))
	}

	return access.LiveSession{
		SessionID:  s.ID,
		ProxyPath:  "/proxy/" + s.ID.String() + "/",
		ProxyToken: sess.token,
	}, nil
}

// InjectPassword is the only injection method a desktop can authenticate with.
// It mirrors the vault's stored value; the gateway keeps its own copy rather than
// importing the vault, exactly as sshgw does, so infra does not depend on infra.
const InjectPassword = "password"

// checkCredential refuses a credential the desktop protocols cannot use.
//
// RDP and VNC authenticate with a username and password in guacd's connect
// handshake, and that is the only shape they have. A 'basic' or 'form'
// credential reaching here means somebody bound a web credential to a desktop
// device; guacd would take its secret as the password and the device would
// simply refuse it, presenting as "wrong password" for a credential that is not
// wrong — it is the wrong kind. Say which, and say it before the secret is put
// on the wire.
//
// The API validates this at write time, so this is the second line: it also
// covers devices whose protocol was changed after the credential was bound, and
// rows written before that validation existed.
// It serves RDP and VNC only. Telnet was once brokered here too — guacd does
// speak it — but that meant rasterising a text console into a canvas, which is
// why it now has a native gateway of its own (internal/infra/telnetgw).
func checkCredential(c access.Credential, proto access.Protocol) error {
	if proto == access.ProtocolTelnet {
		// Unreachable via main.go, which no longer builds a telnet guacd gateway.
		// Stated anyway: this is the mistake that would silently undo the fix, and
		// a wrong-but-working telnet session looks identical to a right one until
		// somebody notices the console feels like screen sharing again.
		return fmt.Errorf("guacgw: refusing to broker telnet through guacd; telnet is served natively by telnetgw")
	}
	if c.Injection != InjectPassword {
		return fmt.Errorf("%w: this device speaks %s, but its credential is set to %q. Re-save the credential using %q",
			access.ErrCredentialUnusable, proto, c.Injection, InjectPassword)
	}
	// A bound credential with no username is not a credential this protocol can
	// authenticate with, and the failure it produces is the worst kind: guacd
	// sends an empty username, RDP has nobody to log in as, and Windows falls back
	// to painting its own login screen — pre-filled with the last account that
	// used the machine. The operator signs in there as whoever they happen to
	// know, and the session is uninjected and attributed to the wrong person while
	// GuardRail's own records say a credential was resolved and used.
	//
	// Nothing upstream prevents this: the vault stores a username only if one was
	// typed, and it is genuinely optional for VNC, whose authentication is a
	// password and nothing else. So the check belongs here, where the protocol is
	// known, and it must not ask VNC for a username it has no field for.
	if c.Username == "" && proto != access.ProtocolVNC {
		return fmt.Errorf("%w: this device's credential has no username, and %s cannot authenticate without one. "+
			"Re-save the credential with the username to log in as",
			access.ErrCredentialUnusable, proto)
	}
	return nil
}

// params builds guacd's connection parameters for this device.
//
// This is where the vaulted credential enters the session, and it never leaves
// the server: guacd authenticates to the device itself, and the browser receives
// only drawing instructions. Nothing here is ever sent to the client.
func (g *Gateway) params(ep access.Endpoint, cred access.Credential, port int, recordingName string) map[string]string {
	p := map[string]string{
		"hostname": ep.Host,
		"port":     strconv.Itoa(port),
	}
	// Omitted rather than sent empty under break-glass, so the device presents its
	// own login instead of being handed a blank username to fail against. Set
	// individually because VNC authenticates with a password and no username, and
	// an empty "username" param is not the same thing to guacd as no param.
	if cred.Username != "" {
		p["username"] = cred.Username
	}
	if cred.Secret != "" {
		p["password"] = cred.Secret
	}

	if g.proto == access.ProtocolRDP {
		// "any" lets guacd negotiate rather than pinning a security mode that half
		// the estate will not speak. Getting this wrong presents as a connection
		// that fails identically for every reason — including break-glass.
		//
		// An earlier version forced security=rdp for break-glass, reasoning that
		// legacy RDP security is the only mode that shows a login screen without a
		// credential. That was worse: a current Windows negotiates TLS or NLA and
		// simply refuses plain RDP, which surfaces as "Server refused connection
		// (wrong security type?)" — the exact failure it was meant to avoid. "any"
		// negotiates instead, so a host that permits an interactive (non-NLA) login
		// is reached and paints its logon screen, and only a host that REQUIRES NLA
		// refuses — because NLA authenticates before the desktop is drawn, so there
		// is genuinely no screen to reach without a credential. That last case is
		// the target's own policy, not something a security param can talk it out
		// of: break-glass to it needs "Require NLA" turned off on the Windows box.
		p["security"] = "any"
		// The device's own TLS setting decides this, rather than a hardcoded
		// "true". An operator who ticked "verify TLS" on a device meant it, and a
		// gateway that ignored it would quietly downgrade the check they asked for.
		//
		// Break-glass forces it off regardless: reaching a login screen means not
		// having authenticated yet, and a host offering an interactive login
		// commonly presents a self-signed cert that a strict check would reject
		// before the operator ever sees the prompt.
		if cred.Username == "" && cred.Secret == "" {
			p["ignore-cert"] = "true"
		} else {
			p["ignore-cert"] = boolStr(!ep.VerifyTLS)
		}
		// Let the desktop follow the browser window instead of scaling a fixed
		// canvas: a 1280x800 desktop stretched over a 4K screen is unreadable, and
		// unreadable evidence is not evidence.
		p["resize-method"] = "display-update"
	}

	if recordingName != "" {
		p["recording-path"] = g.cfg.RecordingDir
		p["recording-name"] = recordingName
		p["create-recording-path"] = "true"
		// Keystrokes are deliberately NOT recorded, matching the SSH transcript's
		// reasoning: a keystroke log of a desktop session contains every password
		// typed into a login box and every secret pasted into a config. The screen
		// already shows what was done. Recording keys would make the recording
		// itself a credential store, which is the thing this product exists to
		// avoid.
		p["recording-include-keys"] = "false"
	}
	return p
}

// End tears the session down and registers whatever guacd recorded.
func (g *Gateway) End(ctx context.Context, sessionID uuid.UUID) error {
	g.mu.Lock()
	s := g.sessions[sessionID]
	delete(g.sessions, sessionID)
	g.mu.Unlock()
	if s == nil {
		return nil
	}
	return g.teardown(ctx, s)
}

// teardown closes the guacd connection and stores the recording it wrote.
func (g *Gateway) teardown(ctx context.Context, s *guacSession) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	if s.conn != nil {
		// Ask guacd to end the connection cleanly before dropping the socket, so it
		// finishes flushing the recording it is writing. A killed connection can
		// leave the last instructions unwritten, and the tail of a session is
		// usually the part someone is looking for.
		_ = write(s.conn.Conn, Instruction{Opcode: "disconnect"})
		_ = s.conn.Close()
	}
	if s.recording == nil {
		return nil
	}
	// Register on a fresh context: teardown often runs because the caller's
	// context was cancelled, and the recording is the audit evidence — losing it
	// because the operator closed the tab would be the worst possible time.
	regCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := g.storeRecording(regCtx, s); err != nil {
		if g.deps.Log != nil {
			g.deps.Log.Error("guac: session recording was not registered; the recording has no evidence",
				zap.String("session_id", s.id.String()), zap.Error(err))
		}
		return err
	}
	return nil
}

// lookup resolves a session by id, enforcing the per-session token.
func (g *Gateway) lookup(sessionID uuid.UUID, token string) *guacSession {
	g.mu.RLock()
	s := g.sessions[sessionID]
	g.mu.RUnlock()
	if s == nil || time.Now().After(s.expires) {
		return nil
	}
	// Constant time: the token is a session bearer secret, and comparing it with
	// == leaks its prefix through timing.
	if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) == 1 {
		return s
	}
	return nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// recordingFile is the absolute path guacd writes for this session.
func (g *Gateway) recordingFile(name string) string { return path.Join(g.cfg.RecordingDir, name) }
