// Package sshgw brokers SSH sessions.
//
// It is the terminal counterpart to the two web gateways. The shape is
// deliberately the same as browser isolation — the operator's browser talks only
// to GuardRail over the session WebSocket, and GuardRail alone holds the device
// connection — but the resemblance stops at the transport. There is no browser
// and no screencast here: an SSH session is a byte stream, so it is carried as
// bytes and recorded as text.
//
// That is the whole reason SSH is native rather than routed through a remote
// desktop daemon. A recorded terminal session is a few kilobytes of exactly what
// was typed and printed, greppable years later during an investigation. The same
// session rendered to pixels is megabytes that no one can search. For SSH the
// text IS the better evidence, and it is cheaper.
//
// The operator never learns the device credential: the password or private key
// is resolved just-in-time from the vault, used for the handshake, and never
// travels to the browser.
package sshgw

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
	"golang.org/x/crypto/ssh"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/infra/proxy"
	"github.com/guardrail/guardrail/internal/infra/term"
)

// ArtifactTranscript is re-exported so callers that reason about SSH evidence
// need not know the transcript is written by the shared terminal package.
const ArtifactTranscript = term.ArtifactTranscript

// Injection methods this gateway understands. They mirror the vault's stored
// values; the HTTP-shaped methods (form/basic/header) are meaningless for a
// transport handshake and are rejected rather than reinterpreted.
const (
	InjectSSHPassword = "ssh-password"
	InjectSSHKey      = "ssh-key"
)

// Config tunes the gateway.
type Config struct {
	// DialTimeout bounds reaching the device. A firewall that blackholes port 22
	// must not hold a Connect request open indefinitely.
	DialTimeout time.Duration
	// HandshakeTimeout bounds authentication once connected.
	HandshakeTimeout time.Duration
	// SessionTTL is how long the session handle stays valid.
	SessionTTL time.Duration
	// MaxRecordingBytes caps a single session's captured text. A runaway `yes` or
	// a cat of a huge binary must not exhaust the disk.
	MaxRecordingBytes int64
}

// DefaultConfig returns workable defaults.
func DefaultConfig() Config {
	return Config{
		DialTimeout:       10 * time.Second,
		HandshakeTimeout:  15 * time.Second,
		SessionTTL:        12 * time.Hour,
		MaxRecordingBytes: 16 << 20, // 16 MiB of text is an enormous session
	}
}

// Deps are the collaborators the gateway needs.
type Deps struct {
	// Devices resolves the session's target. The gateway looks the endpoint up
	// itself rather than trusting the caller, exactly as the web gateways do.
	Devices access.DeviceLookup
	// Recordings/Blobs persist the session transcript. Both may be nil, in which
	// case nothing is recorded.
	Recordings access.RecordingStore
	Blobs      access.BlobStore
	// Activity marks a session as in use so the idle reaper leaves it alone.
	Activity access.ActivitySink
	// Events records the session timeline alongside the transcript.
	Events access.EventRecorder
	// HostKeys decides whether to trust a device's host key.
	HostKeys HostKeyPolicy
	// Log surfaces failures that nothing else would report. The broker discards
	// End's error (it tears down every gateway and cannot act on one failing), so
	// without this a transcript that fails to persist disappears silently — the
	// recording still finalizes and the evidence is simply gone.
	Log *zap.Logger
}

// Gateway is the SSH access.Gateway and v1.SessionServer.
type Gateway struct {
	cfg  Config
	deps Deps

	mu       sync.RWMutex
	sessions map[uuid.UUID]*sshSession
}

// NewGateway constructs the SSH gateway.
func NewGateway(cfg Config, deps Deps) *Gateway {
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = DefaultConfig().DialTimeout
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = DefaultConfig().HandshakeTimeout
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = DefaultConfig().SessionTTL
	}
	if cfg.MaxRecordingBytes <= 0 {
		cfg.MaxRecordingBytes = DefaultConfig().MaxRecordingBytes
	}
	return &Gateway{cfg: cfg, deps: deps, sessions: map[uuid.UUID]*sshSession{}}
}

// Protocol reports which devices this gateway serves.
func (g *Gateway) Protocol() access.Protocol { return access.ProtocolSSH }

// CanRecord reports that SSH sessions are captured. A terminal session is
// recorded by keeping its transcript, so this needs no browser and holds on any
// host — unlike an HTTPS device, which can only be recorded under isolation.
func (g *Gateway) CanRecord() bool { return true }

// sshSession is one live brokered SSH connection.
type sshSession struct {
	id      uuid.UUID
	orgID   uuid.UUID
	token   string
	expires time.Time

	// watermark is the attribution shown over the terminal.
	watermark string
	// deviceLabel is what the operator is connected to, for the console header.
	deviceLabel string

	// What a reconnect needs. The credential is deliberately absent: it is
	// re-resolved from the vault on every dial, so a session that lives for hours
	// never holds a plaintext secret in memory waiting to be read out of a core
	// dump.
	sess  *access.Session
	creds access.CredentialResolver
	ep    access.Endpoint
	addr  string

	client *ssh.Client

	// rec accumulates the transcript. nil when the device is not recorded.
	rec       *term.Recorder
	recording *access.Recording

	// attached guards the socket: one terminal per session. A second viewer would
	// share the PTY and interleave keystrokes, and the transcript would attribute
	// both to one operator.
	mu       sync.Mutex
	attached bool
	closed   bool
}

// Establish opens the SSH connection and returns the client-facing handle.
//
// The connection is made here rather than lazily on the WebSocket so that a bad
// credential or an unreachable host fails the Connect request itself, where the
// operator sees a real error, instead of surfacing as a terminal that opens and
// immediately dies.
func (g *Gateway) Establish(ctx context.Context, s *access.Session, r access.CredentialResolver) (access.LiveSession, error) {
	ep, err := g.deps.Devices.Endpoint(ctx, access.Scope{OrganizationID: s.OrganizationID}, s.DeviceID)
	if err != nil {
		return access.LiveSession{}, err
	}
	if ep.Protocol != access.ProtocolSSH {
		// The broker routes by protocol, so reaching here means a wiring mistake
		// rather than bad input — but it would mean handing a credential to the
		// wrong transport, so refuse loudly instead of trying anyway.
		return access.LiveSession{}, fmt.Errorf("sshgw: refusing protocol %q", ep.Protocol)
	}
	if err := proxy.GuardSSRF(ep.Host); err != nil {
		return access.LiveSession{}, err
	}

	port := ep.Port
	if port == 0 {
		port, _ = access.DefaultPort(access.ProtocolSSH)
	}
	addr := net.JoinHostPort(ep.Host, strconv.Itoa(port))

	sess := &sshSession{
		id: s.ID, orgID: s.OrganizationID,
		token:       randomToken(),
		expires:     time.Now().Add(g.cfg.SessionTTL),
		watermark:   s.WatermarkOr(),
		deviceLabel: ep.Host,
		sess:        s,
		creds:       r,
		ep:          ep,
		addr:        addr,
	}

	// Attach to the recording the broker already opened for this session; do not
	// start one. The broker owns that lifecycle (it applies the retention policy
	// and it is what the recordings list reads), and starting a second here left
	// two rows for one session — one holding the artifacts and one permanently
	// empty, which reads exactly like a recording that was tampered with.
	//
	// Attached at Establish, not when the terminal connects: a session is recorded
	// whether or not anyone is watching it live.
	if ep.RecordSessions && g.deps.Recordings != nil && g.deps.Blobs != nil {
		rec, rerr := g.deps.Recordings.FindBySessionSystem(ctx, s.ID)
		if rerr == nil && rec != nil {
			sess.recording = rec
			sess.rec = term.NewRecorder(g.cfg.MaxRecordingBytes)
		}
	}

	if err := g.connect(ctx, sess); err != nil {
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

// connect opens the device connection and authenticates, storing the client on
// the session.
//
// Used both for the first connection and for a reconnect, so there is exactly
// one path that knows how to get into a device — a reconnect that authenticated
// differently from a connect would be a hole, and the credential is re-resolved
// from the vault each time rather than cached for the life of the session.
func (g *Gateway) connect(ctx context.Context, s *sshSession) error {
	cred, err := s.creds.Resolve(ctx, s.sess)
	if err != nil && !errors.Is(err, access.ErrNoCredential) {
		return err
	}
	// Unlike a web UI, there is no useful "show me the device's own login page"
	// state for SSH: without a credential there is nothing to authenticate with
	// and no page to render. Break-glass therefore cannot mean "connect anyway".
	if errors.Is(err, access.ErrNoCredential) {
		return access.ErrNoCredential
	}

	auth, err := authMethod(cred)
	if err != nil {
		return err
	}
	hk, err := g.hostKeyCallback(ctx, s.sess, s.ep)
	if err != nil {
		return err
	}
	client, err := dial(ctx, s.addr, &ssh.ClientConfig{
		User:            cred.Username,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: hk,
		Timeout:         g.cfg.DialTimeout,
	}, g.cfg.HandshakeTimeout)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.client = client
	s.mu.Unlock()
	return nil
}

// deviceSession opens a shell channel, redialling the device if the client is
// dead.
//
// A reconnect is the point: the operator's authorisation is still good and the
// session is still live, so a device that dropped us (rebooted, reset the TCP
// connection) should be dialled again rather than leaving a Reconnect button
// that can never work. The new shell is genuinely new — cwd, environment and any
// running program are gone — because that is what reconnecting to SSH means.
func (g *Gateway) deviceSession(ctx context.Context, s *sshSession) (*ssh.Session, error) {
	s.mu.Lock()
	client := s.client
	s.mu.Unlock()

	if client != nil {
		if sess, err := client.NewSession(); err == nil {
			return sess, nil
		}
		// The client is unusable. Close it before replacing it or its socket and
		// goroutines leak for as long as the session lives.
		_ = client.Close()
		s.mu.Lock()
		s.client = nil
		s.mu.Unlock()
	}

	if err := g.connect(ctx, s); err != nil {
		return nil, err
	}
	s.mu.Lock()
	client = s.client
	s.mu.Unlock()
	if client == nil {
		return nil, fmt.Errorf("sshgw: no device connection after redial")
	}
	return client.NewSession()
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
func (g *Gateway) teardown(s *sshSession) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	s.mu.Unlock()

	if s.client != nil {
		_ = s.client.Close()
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
		g.deps.Log.Error("sshgw: session transcript was not persisted; the recording has no evidence",
			zap.String("session_id", s.id.String()), zap.Error(err))
	}
	return err
}

// lookup resolves a session by id, enforcing the per-session token.
func (g *Gateway) lookup(sessionID uuid.UUID, token string) *sshSession {
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

// authMethod turns a vaulted credential into an SSH auth method.
//
// The HTTP injection methods are rejected rather than coerced. 'basic' on an SSH
// device means somebody bound a web credential to a terminal device, and quietly
// treating its secret as a password would be a guess about intent that happens
// to send a secret to a host.
func authMethod(c access.Credential) (ssh.AuthMethod, error) {
	switch c.Injection {
	case InjectSSHPassword:
		return ssh.Password(c.Secret), nil
	case InjectSSHKey:
		signer, err := ssh.ParsePrivateKey([]byte(c.Secret))
		if err != nil {
			// Deliberately vague: the error must not echo key material, and a
			// passphrase-protected key reaches here as a parse failure too.
			return nil, fmt.Errorf("sshgw: private key is unusable (encrypted keys are not supported)")
		}
		return ssh.PublicKeys(signer), nil
	default:
		// Wrapped in the domain error so the API answers 422 with this sentence,
		// rather than a 500 that tells the operator nothing. The bare error this
		// replaced surfaced as "unexpected error" for the commonest first-time
		// mistake there is: binding a web credential to an SSH device.
		return nil, fmt.Errorf("%w: this device speaks SSH, but its credential is set to %q. Re-save the credential using %q or %q",
			access.ErrCredentialUnusable, c.Injection, InjectSSHPassword, InjectSSHKey)
	}
}

// dial connects with the context honoured, since ssh.Dial alone ignores it.
func dial(ctx context.Context, addr string, conf *ssh.ClientConfig, handshake time.Duration) (*ssh.Client, error) {
	d := net.Dialer{Timeout: conf.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("sshgw: dial %s: %w", addr, err)
	}
	// The handshake is a separate budget from the TCP connect: a host that accepts
	// the connection then stalls must not hold the session open forever.
	_ = conn.SetDeadline(time.Now().Add(handshake))
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, conf)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("sshgw: %w", err)
	}
	// Clear the handshake deadline or the established session would die on it.
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(c, chans, reqs), nil
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
