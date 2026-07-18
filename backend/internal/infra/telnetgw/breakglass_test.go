package telnetgw

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// fakeDevices serves one endpoint.
type fakeDevices struct{ ep access.Endpoint }

func (f fakeDevices) Endpoint(context.Context, access.Scope, uuid.UUID) (access.Endpoint, error) {
	return f.ep, nil
}

// fakeResolver answers with a credential, or with the "none bound" error.
type fakeResolver struct {
	cred access.Credential
	err  error
}

func (f fakeResolver) Resolve(context.Context, *access.Session) (access.Credential, error) {
	return f.cred, f.err
}
func (f fakeResolver) HasCredential(context.Context, access.Scope, uuid.UUID) (bool, error) {
	return f.err == nil, nil
}

// listenLocal stands in for a device that accepts TCP.
func listenLocal(t *testing.T) (net.Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return ln, ln.Addr().String()
}

func endpointFor(t *testing.T, addr string, allowUnmanaged bool) access.Endpoint {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split %q: %v", addr, err)
	}
	port := 0
	for _, r := range portStr {
		port = port*10 + int(r-'0')
	}
	return access.Endpoint{
		Protocol:       access.ProtocolTelnet,
		Host:           host,
		Port:           port,
		AllowUnmanaged: allowUnmanaged,
	}
}

// TestBreakGlassConnectsWithoutACredential is the regression guard for a bug I
// shipped into this package: telnetgw copied sshgw's "break-glass cannot mean
// connect anyway" rule, which is right for SSH and wrong here.
//
// SSH authenticates in its handshake, so with no credential there is nothing to
// do. A telnet login is just text the device prints and waits on, so a
// credential-less session lands the operator at the device's own prompt — the
// same thing break-glass means for a web device. The lab Cisco router is exactly
// this: no stored credential, allow_unmanaged on, operator types at the prompt.
// Refusing it would have broken a device that already worked.
func TestBreakGlassConnectsWithoutACredential(t *testing.T) {
	ln, addr := listenLocal(t)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		// The device's own login prompt, which is the whole point: the operator
		// will answer it themselves.
		_, _ = c.Write([]byte("\r\nUser Access Verification\r\n\r\nUsername: "))
	}()

	g := NewGateway(Config{}, Deps{
		Devices: fakeDevices{ep: endpointFor(t, addr, true)},
	})
	sess := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), DeviceID: uuid.New()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	live, err := g.Establish(ctx, sess, fakeResolver{err: access.ErrNoCredential})
	if err != nil {
		t.Fatalf("break-glass telnet was refused: %v\n"+
			"a device with allow_unmanaged set must reach its own login prompt", err)
	}
	if live.SessionID != sess.ID {
		t.Errorf("SessionID = %v, want %v", live.SessionID, sess.ID)
	}
	_ = g.End(context.Background(), sess.ID)
}

// TestNoCredentialFailsClosedWithoutBreakGlass is the other half: a device that
// has not opted in gets nothing. Break-glass is a setting, not a fallback.
func TestNoCredentialFailsClosedWithoutBreakGlass(t *testing.T) {
	ln, addr := listenLocal(t)
	go func() {
		if c, err := ln.Accept(); err == nil {
			_, _ = c.Write([]byte("Username: "))
		}
	}()

	g := NewGateway(Config{}, Deps{
		Devices: fakeDevices{ep: endpointFor(t, addr, false)},
	})
	sess := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), DeviceID: uuid.New()}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := g.Establish(ctx, sess, fakeResolver{err: access.ErrNoCredential})
	if !errors.Is(err, access.ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential; a device without break-glass must fail closed", err)
	}
}

// TestWrongProtocolIsRefused: the broker routes by protocol, so arriving here
// with anything else is a wiring mistake — and it would mean typing a credential
// at the wrong transport.
func TestWrongProtocolIsRefused(t *testing.T) {
	g := NewGateway(Config{}, Deps{
		Devices: fakeDevices{ep: access.Endpoint{Protocol: access.ProtocolSSH, Host: "127.0.0.1", Port: 22}},
	})
	sess := &access.Session{ID: uuid.New(), OrganizationID: uuid.New(), DeviceID: uuid.New()}

	_, err := g.Establish(context.Background(), sess, fakeResolver{cred: pwCred("u", "p")})
	if err == nil {
		t.Fatal("an SSH endpoint was accepted by the telnet gateway")
	}
}
