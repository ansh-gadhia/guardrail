package sshgw

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// An HTTP-shaped credential must never be coerced into an SSH auth method.
// 'basic' on an SSH device means someone bound a web credential to a terminal
// device; treating its secret as a password would be a guess about intent whose
// side effect is mailing that secret to a host.
func TestAuthMethodRejectsHTTPInjection(t *testing.T) {
	for _, inj := range []string{"basic", "header", "form", "none", "", "bogus"} {
		_, err := authMethod(access.Credential{Username: "root", Secret: "hunter2", Injection: inj})
		if err == nil {
			t.Errorf("authMethod(%q) succeeded; HTTP credentials must not authenticate SSH", inj)
		}
	}
}

func TestAuthMethodAcceptsPassword(t *testing.T) {
	m, err := authMethod(access.Credential{Username: "root", Secret: "s3cret", Injection: InjectSSHPassword})
	if err != nil {
		t.Fatalf("authMethod(ssh-password): %v", err)
	}
	if m == nil {
		t.Fatal("authMethod(ssh-password) returned a nil method")
	}
}

// A malformed or passphrase-protected key must fail without echoing key material
// into an error that lands in a log.
func TestAuthMethodKeyErrorHidesMaterial(t *testing.T) {
	secret := "-----BEGIN OPENSSH PRIVATE KEY-----\nSUPERSECRETKEYBYTES\n-----END OPENSSH PRIVATE KEY-----"
	_, err := authMethod(access.Credential{Username: "root", Secret: secret, Injection: InjectSSHKey})
	if err == nil {
		t.Fatal("authMethod accepted a malformed private key")
	}
	if strings.Contains(err.Error(), "SUPERSECRETKEYBYTES") {
		t.Errorf("error echoes key material: %v", err)
	}
}

// fakeKnownHosts is an in-memory KnownHostStore.
type fakeKnownHosts struct {
	keys   map[string]string
	getErr error
}

func (f *fakeKnownHosts) Get(_ context.Context, id string) (string, error) {
	if f.getErr != nil {
		return "", f.getErr
	}
	return f.keys[id], nil
}
func (f *fakeKnownHosts) Pin(_ context.Context, id, key string) error {
	f.keys[id] = key
	return nil
}

// testSigner generates a real key per run. Generating beats embedding a literal:
// an embedded key that fails to parse turns every host-key test into a silent
// skip, which is how a security control ends up untested while the suite is green.
func testSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	return signer
}

func testPubKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	return testSigner(t).PublicKey()
}

// A real PEM private key must produce a working publickey auth method.
func TestAuthMethodAcceptsPrivateKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(blk)

	m, err := authMethod(access.Credential{Username: "root", Secret: string(pemBytes), Injection: InjectSSHKey})
	if err != nil {
		t.Fatalf("authMethod(ssh-key) with a valid PEM key: %v", err)
	}
	if m == nil {
		t.Fatal("authMethod(ssh-key) returned a nil method")
	}
}

var testAddr = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 22}

// First contact pins the key; the same key later is accepted.
func TestTOFUPinsThenAccepts(t *testing.T) {
	store := &fakeKnownHosts{keys: map[string]string{}}
	p := TOFU{Store: store}
	key := testPubKey(t)

	if err := p.Check(context.Background(), "dev-1", testAddr, key); err != nil {
		t.Fatalf("first contact should pin, got: %v", err)
	}
	if store.keys["dev-1"] == "" {
		t.Fatal("first contact did not pin the key")
	}
	if err := p.Check(context.Background(), "dev-1", testAddr, key); err != nil {
		t.Fatalf("same key should be accepted, got: %v", err)
	}
}

// A changed host key is either a rebuilt host or an interception, and we cannot
// tell which — so the credential must not be sent.
func TestTOFURefusesChangedKey(t *testing.T) {
	store := &fakeKnownHosts{keys: map[string]string{"dev-1": "ssh-ed25519 AAAAsomethingelse different@host\n"}}
	p := TOFU{Store: store}

	err := p.Check(context.Background(), "dev-1", testAddr, testPubKey(t))
	if err == nil {
		t.Fatal("changed host key was accepted; the session could be intercepted")
	}
	if !strings.Contains(err.Error(), "changed") {
		t.Errorf("error should name the cause, got: %v", err)
	}
}

// If the pin cannot be read we cannot distinguish a first meeting from a
// substituted host. Guessing sends a credential, so it must fail closed.
func TestTOFUFailsClosedWhenStoreErrors(t *testing.T) {
	store := &fakeKnownHosts{keys: map[string]string{}, getErr: context.DeadlineExceeded}
	p := TOFU{Store: store}

	if err := p.Check(context.Background(), "dev-1", testAddr, testPubKey(t)); err == nil {
		t.Fatal("store error was treated as 'not seen before' and the key was trusted")
	}
}

// With no policy wired, the gateway must refuse rather than accept any host key.
// An SSH gateway that trusts whatever answers on port 22 looks like a PAM while
// removing the guarantee a PAM exists to provide.
func TestNoHostKeyPolicyRefuses(t *testing.T) {
	g := NewGateway(DefaultConfig(), Deps{})
	_, err := g.hostKeyCallback(context.Background(), &access.Session{}, access.Endpoint{Host: "10.0.0.1"})
	if err == nil {
		t.Fatal("gateway with no host-key policy accepted a connection")
	}
}

func TestGatewayServesSSHOnly(t *testing.T) {
	if got := NewGateway(DefaultConfig(), Deps{}).Protocol(); got != access.ProtocolSSH {
		t.Errorf("Protocol() = %q, want ssh", got)
	}
}
