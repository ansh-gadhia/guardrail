// Package access is the access-broker bounded context. It brokers an audited,
// time-boxed session between a user and a target device, and defines the Gateway
// plugin contract that lets new protocols (SSH, RDP, VNC, K8s, DB) be added
// without changing the broker, authorization, audit, or recording code.
package access

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Errors surfaced by the broker.
var (
	ErrNotFound  = errors.New("access: session not found")
	ErrNotActive = errors.New("access: session not active")
	ErrExpired   = errors.New("access: session window expired")
	ErrForbidden = errors.New("access: forbidden")
	ErrNoGateway = errors.New("access: no gateway for protocol")
	// ErrInvalid marks a value the broker refuses rather than interprets — an
	// unknown protocol, for instance, which must never be guessed at.
	ErrInvalid = errors.New("access: invalid")
	// ErrNoCredential means the device has no bound credential. GuardRail brokers
	// access so a vaulted secret is injected server-side; with none bound there is
	// nothing to inject, so Connect FAILS CLOSED by default. A device may opt into
	// break-glass unmanaged access (Endpoint.AllowUnmanaged), in which case the
	// gateway establishes the session and renders the device's own login page.
	ErrNoCredential = errors.New("access: no credential bound")
	// ErrCapacity means the host has too little memory left to start another
	// isolated session safely. An isolated session runs a real browser, so
	// admitting one the host cannot hold does not degrade the new session — it
	// OOM-kills the process and takes every session already running with it.
	// Refusing to start the marginal session is what keeps the existing ones up.
	ErrCapacity = errors.New("access: isolation capacity reached")
	// ErrRecordingUnavailable means the device is set to be recorded but this host
	// cannot record: recording captures frames from a server-side browser, and
	// there is no usable browser here.
	//
	// The alternative is what used to happen — fall back to the reverse proxy and
	// serve the session unrecorded. That is the worst outcome available: the
	// operator gets their session, the device's policy still reads "recording on",
	// and the evidence that policy promises does not exist. Nobody finds out until
	// somebody goes looking for a recording of an incident. Refusing is loud, and
	// loud is recoverable.
	//
	// Delivery has no such problem: a device that merely prefers isolation is
	// still reachable through the proxy, so that fallback stays.
	ErrRecordingUnavailable = errors.New("access: session recording unavailable on this host")
	// ErrInjectionUnsupported means the device's credential cannot be injected by
	// the gateway that would serve it.
	//
	// Specifically: login-form fill needs something that can type into the page.
	// Browser isolation has that — a real browser, server-side, where the secret
	// is entered into the device's own form and never leaves the host. The reverse
	// proxy does not: it only rewrites HTTP, so the only way it could fill a form
	// is to hand the secret to the operator's browser, which is precisely the
	// thing GuardRail exists to prevent.
	//
	// So it is refused, loudly. The alternative — the one this replaced — was to
	// ignore the credential and proxy the request unauthenticated, which left the
	// operator staring at the device's login page with a vaulted password they
	// were never meant to know, and nothing anywhere saying why.
	ErrInjectionUnsupported = errors.New("access: credential injection not supported by this gateway")
	// ErrCredentialUnusable means the bound credential's injection method cannot
	// authenticate this device's protocol at all — an HTTP Basic credential on an
	// SSH box, say, or a login-form credential on a Windows desktop.
	//
	// Distinct from ErrInjectionUnsupported, which means "this gateway cannot
	// inject an otherwise-valid method": that one is answerable by switching
	// delivery mode, and its message says so. This one is not — no delivery mode
	// makes an Authorization header log into a terminal. The only fix is to rebind
	// the credential, so it says which methods would work.
	//
	// It exists because the alternative was a bare error from the gateway, which
	// no handler recognised and every operator therefore saw as "unexpected error"
	// — a 500 for a misconfiguration they could have fixed in ten seconds had
	// anything told them what it was.
	ErrCredentialUnusable = errors.New("credential cannot authenticate this device")
	// ErrHostKeyMismatch means a device presented a different host key than the
	// one pinned when it was first trusted.
	//
	// It is deliberately its own error rather than one more way for a connection
	// to fail. Every other establish failure is an inconvenience — a wrong
	// password, a firewall, a host that is down. This one means the machine
	// answering for the device is not the machine that answered last time, which
	// is either a rebuilt host or someone sitting in the middle of the
	// connection. GuardRail cannot tell those apart, so it refuses and says so
	// precisely; folding it into a generic failure would hide the only warning an
	// operator gets before a credential is handed to an impostor.
	ErrHostKeyMismatch = errors.New("access: device host key changed")
)

// Protocol identifies the access modality a device is brokered over.
type Protocol string

const (
	ProtocolHTTPS Protocol = "https"
	ProtocolHTTP  Protocol = "http"
	ProtocolSSH   Protocol = "ssh"
	ProtocolRDP   Protocol = "rdp"
	ProtocolVNC   Protocol = "vnc"
	// ProtocolTelnet is the CLI on network gear too old to speak SSH — Cisco IOS
	// and its imitators. It is brokered through guacd, which speaks telnet, so a
	// telnet session records and replays exactly like a desktop.
	//
	// Telnet is cleartext, and no amount of brokering changes that: the device
	// credential crosses the wire to the device in the clear. What GuardRail buys
	// here is that the operator never learns it, and that the session is recorded —
	// which is the whole reason to reach for this instead of handing out the
	// enable password. Prefer SSH on any device that offers it.
	ProtocolTelnet Protocol = "telnet"
)

// protocols is the closed set of protocols the platform understands, with the
// port each one answers on by convention.
//
// This is the single source of truth: the device form offers these, the API
// validates against them, and ParseProtocol below refuses everything else. A
// protocol listed here still needs a Gateway registered before a session can be
// opened — the broker reports "unsupported protocol" if one is missing, which is
// the honest failure. Adding an entry here without a gateway would let an
// operator register a device they can never connect to.
var protocols = map[Protocol]int{
	ProtocolHTTPS:  443,
	ProtocolHTTP:   80,
	ProtocolSSH:    22,
	ProtocolRDP:    3389,
	ProtocolVNC:    5900,
	ProtocolTelnet: 23,
}

// ParseProtocol validates an incoming protocol string.
//
// It fails closed, and that is the entire point. This replaced a derivation that
// defaulted to HTTPS for any unrecognised value, which meant an "ssh" device
// would have been handed to the HTTP reverse proxy — and the proxy injects the
// device credential as an Authorization header, so the password would have been
// written to port 22 in the clear. Guessing a protocol is never safe here;
// refusing is.
func ParseProtocol(s string) (Protocol, error) {
	p := Protocol(s)
	if _, ok := protocols[p]; !ok {
		return "", fmt.Errorf("%w: unknown protocol %q", ErrInvalid, s)
	}
	return p, nil
}

// DefaultPort returns the conventional port for a protocol, and whether it is
// one the platform knows.
func DefaultPort(p Protocol) (int, bool) {
	port, ok := protocols[p]
	return port, ok
}

// Protocols lists every known protocol. The order is fixed so the console's
// dropdown does not reshuffle between requests.
func Protocols() []Protocol {
	return []Protocol{ProtocolHTTPS, ProtocolHTTP, ProtocolSSH, ProtocolRDP, ProtocolVNC, ProtocolTelnet}
}

// IsWeb reports whether a protocol is delivered as a web UI (reverse proxy or
// browser isolation) rather than a terminal or desktop stream.
func (p Protocol) IsWeb() bool { return p == ProtocolHTTPS || p == ProtocolHTTP }

// Status is the lifecycle state of an access session.
type Status string

const (
	StatusActive  Status = "active" // live
	StatusEnded   Status = "ended"
	StatusExpired Status = "expired"
)

// Scope is the tenant scope for access operations.
type Scope struct {
	OrganizationID uuid.UUID
	IsSuperAdmin   bool
}

// Session is a brokered access session.
type Session struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	UserID         uuid.UUID
	DeviceID       uuid.UUID
	Protocol       Protocol
	Status         Status
	GrantedFrom    *time.Time
	GrantedUntil   *time.Time
	ClientIP       string
	UserAgent      string
	GatewayNode    string
	StartedAt      *time.Time
	EndedAt        *time.Time
	EndReason      string
	CreatedAt      time.Time
	// Watermark is the attribution text a gateway stamps over the device UI: who
	// is in the session and which session it is. The broker fills it in from the
	// acting principal at Connect time and it is stored with the session, so a
	// Session read back from the repository carries the same text the operator
	// saw.
	//
	// It was once presentation state only, and the difference was not academic:
	// the console reads the string it draws over a desktop from GET /sessions/:id,
	// which is a re-read, so desktops were watermarked "session <uuid>" while
	// every other protocol — stamped at Establish time from the in-memory Session
	// — named the operator. It is persisted because it is a record of what was
	// displayed, not a value to be recomputed from whatever the user row says
	// today.
	//
	// Empty means a session older than the column. Gateways must treat that as
	// "derive a fallback", never as "no watermark" — an accountability control
	// that silently switches itself off on a path nobody thought about is worse
	// than not having one.
	Watermark string
}

// WatermarkOr returns the session's attribution text, falling back to the
// session id for a session stored before the watermark was persisted. This is
// what keeps the overlay present on every path that reaches a gateway.
func (s *Session) WatermarkOr() string {
	if s.Watermark != "" {
		return s.Watermark
	}
	return "session " + s.ID.String()
}

// IsLive reports whether the session may currently proxy traffic.
func (s *Session) IsLive(now time.Time) bool {
	if s.Status != StatusActive {
		return false
	}
	if s.GrantedUntil != nil && now.After(*s.GrantedUntil) {
		return false
	}
	return true
}

// LiveSession is a handle to an established gateway session.
type LiveSession struct {
	SessionID   uuid.UUID
	GatewayNode string
	// ProxyPath is the path the client uses to reach the proxied device UI.
	ProxyPath string
	// ProxyToken binds the user's browser to this session (set as an HttpOnly
	// cookie by the delivery layer); it is not a device credential.
	ProxyToken string
}

// CredentialResolver returns, just-in-time and one-shot, the plaintext
// credential to inject for a session. The broker passes this to a gateway so the
// gateway never receives credentials it didn't explicitly request, and the
// resolution is audited as credential use.
type CredentialResolver interface {
	Resolve(ctx context.Context, s *Session) (Credential, error)
	// HasCredential reports whether a device has at least one bound credential,
	// without decrypting or auditing. The broker uses it as a fail-closed
	// pre-flight so no session is created for a device that could never have a
	// credential injected.
	HasCredential(ctx context.Context, s Scope, deviceID uuid.UUID) (bool, error)
}

// Credential is the plaintext material injected by a gateway. It exists only in
// memory for the duration of a request and is never persisted or logged.
type Credential struct {
	Username  string
	Secret    string
	Injection string // form | basic | header | none
}

// Gateway establishes and serves a brokered session for one protocol. This is
// the extension point of the platform.
type Gateway interface {
	Protocol() Protocol
	// Establish prepares a live session (e.g. launches/attaches a browser) and
	// returns the client-facing handle.
	Establish(ctx context.Context, s *Session, r CredentialResolver) (LiveSession, error)
	// End tears down gateway resources for a session.
	End(ctx context.Context, sessionID uuid.UUID) error
}

// RecordingGateway is a Gateway that captures what happens in a session. A
// gateway that does not implement it cannot produce evidence, and the broker
// refuses to open a recorded device through one rather than serve a session that
// captures nothing while the device's policy still reads "recording on".
//
// This is asked of the gateway rather than derived from the protocol because the
// answer is not a property of the protocol: HTTPS records under isolation and
// cannot under the reverse proxy — same protocol, same device, different gateway.
// SSH records with no browser at all, by keeping the transcript.
type RecordingGateway interface {
	Gateway
	// CanRecord reports whether a session this gateway establishes will actually
	// be captured when the device asks for it.
	CanRecord() bool
}
