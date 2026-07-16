package sshgw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// An in-process SSH server. Unit tests with a fake transport would not prove the
// thing that actually matters here — that a real handshake authenticates with the
// vaulted secret and that a real channel carries bytes both ways.
type testSSHServer struct {
	ln       net.Listener
	hostKey  ssh.Signer
	password string
	// echo is what the fake shell prints once a session opens.
	banner string

	mu       sync.Mutex
	received []byte
	// auths counts authentication attempts the server saw. It exists so a test can
	// prove a credential was never offered — "the handshake failed" alone does not
	// distinguish refusing before auth from sending the password and then failing.
	auths int
	wg    sync.WaitGroup
}

func newTestSSHServer(t *testing.T, password, banner string) *testSSHServer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("hostkey: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &testSSHServer{ln: ln, hostKey: signer, password: password, banner: banner}
	s.wg.Add(1)
	go s.serve()
	t.Cleanup(func() { _ = ln.Close(); s.wg.Wait() })
	return s
}

func (s *testSSHServer) addr() (string, int) {
	a := s.ln.Addr().(*net.TCPAddr)
	return a.IP.String(), a.Port
}

func (s *testSSHServer) serve() {
	defer s.wg.Done()
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(c)
	}
}

func (s *testSSHServer) handle(c net.Conn) {
	conf := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			s.mu.Lock()
			s.auths++
			s.mu.Unlock()
			if string(pass) == s.password {
				return nil, nil
			}
			return nil, fmt.Errorf("denied")
		},
	}
	conf.AddHostKey(s.hostKey)

	conn, chans, reqs, err := ssh.NewServerConn(c, conf)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	go ssh.DiscardRequests(reqs)

	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "no")
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range chReqs {
				// Accept pty-req/shell/window-change so the gateway's real
				// sequence succeeds.
				if r.WantReply {
					_ = r.Reply(true, nil)
				}
				if r.Type == "shell" {
					_, _ = ch.Write([]byte(s.banner))
				}
			}
		}()
		go func() {
			defer func() { _ = ch.Close() }()
			buf := make([]byte, 1024)
			for {
				n, err := ch.Read(buf)
				if n > 0 {
					s.mu.Lock()
					s.received = append(s.received, buf[:n]...)
					s.mu.Unlock()
					// Echo back so the transcript has device output to capture.
					_, _ = ch.Write(buf[:n])
				}
				if err != nil {
					return
				}
			}
		}()
	}
}

func (s *testSSHServer) got() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return string(s.received)
}

// authAttempts reports how many times a credential was offered to this server.
func (s *testSSHServer) authAttempts() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.auths
}

// stubLookup returns a canned endpoint.
type stubLookup struct{ ep access.Endpoint }

func (s stubLookup) Endpoint(context.Context, access.Scope, uuid.UUID) (access.Endpoint, error) {
	return s.ep, nil
}

// stubCreds hands back a canned credential.
type stubCreds struct {
	cred access.Credential
	err  error
}

func (s stubCreds) Resolve(context.Context, *access.Session) (access.Credential, error) {
	if s.err != nil {
		return access.Credential{}, s.err
	}
	return s.cred, nil
}
func (s stubCreds) HasCredential(context.Context, access.Scope, uuid.UUID) (bool, error) {
	return s.err == nil, nil
}

func newLiveGateway(t *testing.T, srv *testSSHServer, cred access.Credential, record bool) (*Gateway, *access.Session) {
	t.Helper()
	host, port := srv.addr()
	g := NewGateway(DefaultConfig(), Deps{
		Devices: stubLookup{ep: access.Endpoint{
			Protocol: access.ProtocolSSH, Host: host, Port: port, RecordSessions: record,
		}},
		HostKeys: InsecureIgnoreHostKey{},
	})
	s := &access.Session{
		ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(),
		Protocol: access.ProtocolSSH, Watermark: "operator@example.com",
	}
	_ = cred
	return g, s
}

// The whole point of the gateway: a real SSH handshake authenticated with the
// vaulted secret, against a real server.
func TestLiveEstablishAuthenticatesWithVaultedPassword(t *testing.T) {
	srv := newTestSSHServer(t, "correct-horse", "welcome\n")
	g, s := newLiveGateway(t, srv, access.Credential{}, false)

	creds := stubCreds{cred: access.Credential{
		Username: "root", Secret: "correct-horse", Injection: InjectSSHPassword,
	}}

	live, err := g.Establish(context.Background(), s, creds)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if live.ProxyToken == "" {
		t.Error("no session token issued; the console would be unauthenticated")
	}
	if !strings.Contains(live.ProxyPath, s.ID.String()) {
		t.Errorf("ProxyPath = %q, want it to carry the session id", live.ProxyPath)
	}
	if err := g.End(context.Background(), s.ID); err != nil {
		t.Errorf("End: %v", err)
	}
}

// A device whose host key changed must fail with the TYPED error, through a real
// handshake.
//
// The type is the whole mechanism: the API maps ErrHostKeyMismatch to an alarm
// that names the fingerprint and the remedy, and everything unmapped collapses
// into 500 "unexpected error". x/crypto/ssh carries the callback's error up
// through its own layers, so this asserts against the real library rather than
// against the policy in isolation — if some version flattened it to a string,
// errors.Is would quietly stop matching, the mapping would never fire, and a
// possible interception would look exactly like a server glitch. That failure
// would be invisible in a test that only called TOFU.Check directly.
func TestLiveEstablishSurfacesHostKeyMismatchAsTypedError(t *testing.T) {
	srv := newTestSSHServer(t, "correct-horse", "welcome\n")
	host, port := srv.addr()

	s := &access.Session{
		ID: uuid.New(), OrganizationID: uuid.New(), UserID: uuid.New(), DeviceID: uuid.New(),
		Protocol: access.ProtocolSSH,
	}
	// A key pinned earlier that is not the one this server presents: the device's
	// identity changed under us.
	store := &fakeKnownHosts{keys: map[string]string{
		s.DeviceID.String(): "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPinnedEarlier pinned@earlier\n",
	}}
	g := NewGateway(DefaultConfig(), Deps{
		Devices:  stubLookup{ep: access.Endpoint{Protocol: access.ProtocolSSH, Host: host, Port: port}},
		HostKeys: TOFU{Store: store},
	})
	creds := stubCreds{cred: access.Credential{
		Username: "root", Secret: "correct-horse", Injection: InjectSSHPassword,
	}}

	_, err := g.Establish(context.Background(), s, creds)
	if err == nil {
		t.Fatal("Establish accepted a device whose host key changed")
	}
	if !errors.Is(err, access.ErrHostKeyMismatch) {
		t.Fatalf("error = %v; want it to wrap access.ErrHostKeyMismatch so the API raises the alarm "+
			"instead of the generic 500 that hides an interception", err)
	}
	// The decisive one: the password is correct, so if the host key were checked
	// after authentication this server would have received it. Refusing must
	// happen before the credential is offered to whatever answered.
	if n := srv.authAttempts(); n != 0 {
		t.Errorf("credential was offered %d time(s) to a host whose key did not match; "+
			"the vaulted password reached a possible impostor", n)
	}
	// The pin must survive: silently re-pinning the new key would turn TOFU into
	// trust-on-every-use and erase the evidence that anything changed.
	if store.keys[s.DeviceID.String()] != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPinnedEarlier pinned@earlier\n" {
		t.Error("the pinned host key was overwritten by the key presented; a changed device would be trusted next time")
	}
}

// A wrong password must fail the Connect request itself, not open a terminal that
// dies a moment later. This is the bug the operator hit on the web side.
func TestLiveEstablishFailsOnBadPassword(t *testing.T) {
	srv := newTestSSHServer(t, "correct-horse", "welcome\n")
	g, s := newLiveGateway(t, srv, access.Credential{}, false)

	creds := stubCreds{cred: access.Credential{
		Username: "root", Secret: "wrong-password", Injection: InjectSSHPassword,
	}}

	if _, err := g.Establish(context.Background(), s, creds); err == nil {
		t.Fatal("Establish succeeded with a wrong password")
	}
}

// A device with no bound credential cannot be brokered over SSH: there is no
// login page to fall back to, so break-glass must not mean "connect anyway".
func TestLiveEstablishRefusesWithoutCredential(t *testing.T) {
	srv := newTestSSHServer(t, "pw", "hi\n")
	g, s := newLiveGateway(t, srv, access.Credential{}, false)

	_, err := g.Establish(context.Background(), s, stubCreds{err: access.ErrNoCredential})
	if err != access.ErrNoCredential {
		t.Fatalf("Establish error = %v, want ErrNoCredential", err)
	}
}

// The session token must actually gate the console: a wrong token is not this
// gateway's session as far as the mux is concerned.
func TestLookupRejectsWrongToken(t *testing.T) {
	srv := newTestSSHServer(t, "pw", "hi\n")
	g, s := newLiveGateway(t, srv, access.Credential{}, false)
	creds := stubCreds{cred: access.Credential{Username: "u", Secret: "pw", Injection: InjectSSHPassword}}

	live, err := g.Establish(context.Background(), s, creds)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	defer func() { _ = g.End(context.Background(), s.ID) }()

	if g.lookup(s.ID, "not-the-token") != nil {
		t.Error("lookup accepted a forged token")
	}
	if g.lookup(uuid.New(), live.ProxyToken) != nil {
		t.Error("lookup matched an unknown session id")
	}
	if g.lookup(s.ID, live.ProxyToken) == nil {
		t.Error("lookup rejected the real token")
	}
}

// End must close the device connection, not just forget the session — a leaked
// SSH connection holds a credential-authenticated channel open indefinitely.
func TestEndClosesDeviceConnection(t *testing.T) {
	srv := newTestSSHServer(t, "pw", "hi\n")
	g, s := newLiveGateway(t, srv, access.Credential{}, false)
	creds := stubCreds{cred: access.Credential{Username: "u", Secret: "pw", Injection: InjectSSHPassword}}

	if _, err := g.Establish(context.Background(), s, creds); err != nil {
		t.Fatalf("Establish: %v", err)
	}
	g.mu.RLock()
	sess := g.sessions[s.ID]
	g.mu.RUnlock()
	if sess == nil {
		t.Fatal("session not registered")
	}

	if err := g.End(context.Background(), s.ID); err != nil {
		t.Fatalf("End: %v", err)
	}
	// The client is closed, so opening a new channel on it must fail.
	if _, err := sess.client.NewSession(); err == nil {
		t.Error("device connection still usable after End; the SSH connection leaked")
	}
	g.mu.RLock()
	_, still := g.sessions[s.ID]
	g.mu.RUnlock()
	if still {
		t.Error("session still in the map after End")
	}
}

// Timeouts must be honoured against a host that accepts TCP then says nothing —
// a blackholed port must not hold a Connect request open.
func TestEstablishHonoursHandshakeTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// Accept and stall: never speak the SSH version string.
		defer func() { _ = c.Close() }()
		io.Copy(io.Discard, c) //nolint:errcheck
	}()

	a := ln.Addr().(*net.TCPAddr)
	g := NewGateway(Config{DialTimeout: time.Second, HandshakeTimeout: 300 * time.Millisecond},
		Deps{
			Devices:  stubLookup{ep: access.Endpoint{Protocol: access.ProtocolSSH, Host: a.IP.String(), Port: a.Port}},
			HostKeys: InsecureIgnoreHostKey{},
		})
	s := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), DeviceID: uuid.New()}
	creds := stubCreds{cred: access.Credential{Username: "u", Secret: "p", Injection: InjectSSHPassword}}

	start := time.Now()
	if _, err := g.Establish(context.Background(), s, creds); err == nil {
		t.Fatal("Establish succeeded against a stalled host")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Establish took %v; the handshake timeout did not apply", elapsed)
	}
}
