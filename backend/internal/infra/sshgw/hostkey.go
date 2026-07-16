package sshgw

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// HostKeyPolicy decides whether a device's SSH host key is trusted.
//
// This is the SSH analogue of VerifyTLS on a web device, and it carries the same
// weight: without it, a machine-in-the-middle between GuardRail and the device
// can present its own key, and GuardRail will hand it the vaulted credential and
// faithfully record the attacker's session as though it were the device.
//
// Trust-on-first-use is the pragmatic model for infrastructure that predates the
// PAM: the first key seen for a device is pinned, and any later change is
// refused until an admin clears it. That distinguishes "we have not met this
// device yet" from "this device's identity changed", which is the alarm worth
// raising.
type HostKeyPolicy interface {
	// Check is called with the key the device presented. Returning an error
	// aborts the handshake before any credential is sent.
	Check(ctx context.Context, deviceID string, remote net.Addr, key ssh.PublicKey) error
}

// hostKeyCallback adapts the configured policy to x/crypto/ssh.
//
// With no policy configured this refuses every connection rather than accepting
// any key. An SSH gateway that silently trusts whatever answers on port 22 is
// worse than one that does not work: it would look like a PAM while removing the
// guarantee a PAM exists to provide. Wiring a policy is therefore mandatory.
func (g *Gateway) hostKeyCallback(ctx context.Context, s *access.Session, ep access.Endpoint) (ssh.HostKeyCallback, error) {
	if g.deps.HostKeys == nil {
		return nil, fmt.Errorf("sshgw: no host-key policy configured; refusing to connect to %s", ep.Host)
	}
	deviceID := s.DeviceID.String()
	return func(_ string, remote net.Addr, key ssh.PublicKey) error {
		err := g.deps.HostKeys.Check(ctx, deviceID, remote, key)
		if err != nil && g.deps.Log != nil {
			// Logged here rather than in the policy so it covers every policy, and
			// because this is the last point that still knows which device and key
			// were involved — x/crypto/ssh wraps the error on its way out. The
			// broker's audit event is the durable record; this is the ops signal
			// that something is wrong right now.
			g.deps.Log.Warn("sshgw: refused device host key",
				zap.String("device_id", deviceID),
				zap.String("remote", remote.String()),
				zap.String("presented_fingerprint", ssh.FingerprintSHA256(key)),
				zap.Error(err))
		}
		return err
	}, nil
}

// InsecureIgnoreHostKey accepts any host key.
//
// It exists so a lab or a first-run demo can work before a real policy is
// wired, and it is named to be uncomfortable to type. It must never be the
// default: every session it allows could be talking to an impostor, and the
// recording would prove nothing about which host was actually touched.
type InsecureIgnoreHostKey struct{}

// Check accepts unconditionally.
func (InsecureIgnoreHostKey) Check(context.Context, string, net.Addr, ssh.PublicKey) error {
	return nil
}

// KnownHostStore persists the key pinned to a device.
type KnownHostStore interface {
	// Get returns the pinned key for a device, or ("", nil) when none is pinned.
	Get(ctx context.Context, deviceID string) (string, error)
	// Pin records the key for a device seen for the first time.
	Pin(ctx context.Context, deviceID, key string) error
}

// TOFU pins the first host key seen for a device and refuses any later change.
type TOFU struct{ Store KnownHostStore }

// Check implements HostKeyPolicy.
func (t TOFU) Check(ctx context.Context, deviceID string, remote net.Addr, key ssh.PublicKey) error {
	presented := string(ssh.MarshalAuthorizedKey(key))

	pinned, err := t.Store.Get(ctx, deviceID)
	if err != nil {
		// Fail closed: if the pin cannot be read we cannot tell a first meeting
		// from a substituted host, and guessing sends a credential.
		return fmt.Errorf("sshgw: cannot read pinned host key: %w", err)
	}
	if pinned == "" {
		if err := t.Store.Pin(ctx, deviceID, presented); err != nil {
			return fmt.Errorf("sshgw: cannot pin host key: %w", err)
		}
		return nil
	}
	if pinned != presented {
		// Deliberately blunt. This is either a rebuilt host or an interception,
		// and the operator cannot tell which — so neither should we.
		//
		// Wrapped in the typed error so the API answers with an alarm carrying
		// this text, rather than the 500 "unexpected error" that every unmapped
		// failure collapses into.
		return fmt.Errorf("%w: %s presented host key %s, which is not the one pinned "+
			"when this device was first trusted. If the device was legitimately rebuilt, "+
			"clear its pinned host key; otherwise this connection is being intercepted",
			access.ErrHostKeyMismatch, remote, ssh.FingerprintSHA256(key))
	}
	return nil
}
