package access

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/assets"
)

// A device whose protocol has no gateway must be refused, not quietly handed to
// whichever gateway happens to be registered. The reverse proxy injects the
// vaulted credential as an Authorization header, so misrouting an SSH device to
// it would write the device password to port 22 in the clear. ErrNoGateway is
// the only acceptable outcome.
func TestConnectRefusesProtocolWithNoGateway(t *testing.T) {
	for _, proto := range []access.Protocol{access.ProtocolSSH, access.ProtocolRDP, access.ProtocolVNC} {
		t.Run(string(proto), func(t *testing.T) {
			// Only the https fake gateway is registered in the harness.
			h := newHarness(opts{entitled: true, hasCredential: true, protocol: proto})

			_, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{})
			if !errors.Is(err, access.ErrNoGateway) {
				t.Fatalf("Connect(%s) error = %v, want ErrNoGateway", proto, err)
			}
			// The decisive assertion: nothing was established, so no credential was
			// injected anywhere.
			if len(h.gateway.established) != 0 {
				t.Errorf("%s session was established on the HTTP gateway: %v", proto, h.gateway.established)
			}
			if len(h.gateway.watermarks) != 0 {
				t.Errorf("%s session reached the HTTP gateway's credential path", proto)
			}
		})
	}
}

// The web protocols still route, so the fail-closed guard did not break the case
// that already worked.
func TestConnectStillRoutesWebProtocols(t *testing.T) {
	for _, proto := range []access.Protocol{access.ProtocolHTTPS, access.ProtocolHTTP} {
		t.Run(string(proto), func(t *testing.T) {
			h := newHarness(opts{entitled: true, hasCredential: true, protocol: proto, noRecording: true})
			if _, err := h.svc.Connect(context.Background(), actorClaims(), uuid.New(), ReqMeta{}); err != nil {
				t.Fatalf("Connect(%s): %v", proto, err)
			}
			if len(h.gateway.established) != 1 {
				t.Errorf("%s: established %d sessions, want 1", proto, len(h.gateway.established))
			}
		})
	}
}

// The adapter is where a stored device becomes a routable endpoint. It must
// refuse a protocol it does not know rather than inventing one — the storage
// CHECK makes such a row hard to create, but a constraint dropped in a future
// migration must not silently become a credential leak.
func TestEndpointRejectsUnknownScheme(t *testing.T) {
	dev := &assets.Device{
		ID: uuid.New(), Name: "weird", Host: "10.0.0.9", Port: 21, Scheme: "ftp",
	}
	a := NewDeviceLookup(stubDeviceRepo{dev: dev})

	_, err := a.Endpoint(context.Background(), access.Scope{OrganizationID: uuid.New()}, dev.ID)
	if !errors.Is(err, access.ErrInvalid) {
		t.Fatalf("Endpoint(scheme=ftp) error = %v, want ErrInvalid", err)
	}
}

// A known protocol resolves, carrying the host/port a terminal gateway dials.
func TestEndpointCarriesHostPortForSSH(t *testing.T) {
	dev := &assets.Device{
		ID: uuid.New(), Name: "jump", Host: "10.0.0.5", Port: 2222, Scheme: "ssh",
		IdleTimeoutMinutes: 30,
	}
	a := NewDeviceLookup(stubDeviceRepo{dev: dev})

	ep, err := a.Endpoint(context.Background(), access.Scope{OrganizationID: uuid.New()}, dev.ID)
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	if ep.Protocol != access.ProtocolSSH {
		t.Errorf("Protocol = %q, want ssh", ep.Protocol)
	}
	// BaseURL is meaningless for SSH; Host:Port is what the gateway dials, so a
	// non-default port must survive.
	if ep.Host != "10.0.0.5" || ep.Port != 2222 {
		t.Errorf("Host:Port = %s:%d, want 10.0.0.5:2222", ep.Host, ep.Port)
	}
}

// stubDeviceRepo returns one canned device.
type stubDeviceRepo struct{ dev *assets.Device }

func (s stubDeviceRepo) GetByID(context.Context, assets.Scope, uuid.UUID) (*assets.Device, error) {
	return s.dev, nil
}
func (s stubDeviceRepo) Create(context.Context, assets.Scope, *assets.Device) error { return nil }
func (s stubDeviceRepo) Update(context.Context, assets.Scope, *assets.Device) error { return nil }
func (s stubDeviceRepo) SoftDelete(context.Context, assets.Scope, uuid.UUID) error  { return nil }
func (s stubDeviceRepo) Count(context.Context, assets.Scope) (int, error)           { return 0, nil }
func (s stubDeviceRepo) List(context.Context, assets.Scope, assets.Filter) ([]assets.Device, error) {
	return nil, nil
}
