package telnetgw

import (
	"testing"

	"github.com/guardrail/guardrail/internal/domain/access"
)

func TestGatewayServesTelnet(t *testing.T) {
	g := NewGateway(Config{}, Deps{})
	if got := g.Protocol(); got != access.ProtocolTelnet {
		t.Errorf("Protocol() = %q, want %q", got, access.ProtocolTelnet)
	}
}

func TestGatewayRecordsWithoutASidecar(t *testing.T) {
	// A telnet session is captured as text by this process. Unlike a desktop it
	// needs no guacd and no Chromium, so this must not be conditional on anything
	// — the broker asks before it will open a recorded device, and answering
	// "no" here would refuse a router the platform can perfectly well record.
	if !NewGateway(Config{}, Deps{}).CanRecord() {
		t.Error("CanRecord() = false; recorded telnet devices would be refused")
	}
}

func TestZeroConfigGetsWorkableDefaults(t *testing.T) {
	// main.go constructs this with Config{}. A zero LoginTimeout would make every
	// login deadline already expired, so every telnet connect would fail with
	// "no login prompt" and nothing would ever work.
	g := NewGateway(Config{}, Deps{})
	d := DefaultConfig()
	if g.cfg.LoginTimeout != d.LoginTimeout {
		t.Errorf("LoginTimeout = %v, want the default %v", g.cfg.LoginTimeout, d.LoginTimeout)
	}
	if g.cfg.DialTimeout != d.DialTimeout {
		t.Errorf("DialTimeout = %v, want the default %v", g.cfg.DialTimeout, d.DialTimeout)
	}
	if g.cfg.MaxRecordingBytes != d.MaxRecordingBytes {
		t.Errorf("MaxRecordingBytes = %v, want the default %v", g.cfg.MaxRecordingBytes, d.MaxRecordingBytes)
	}
	if g.cfg.MaxBannerBytes != d.MaxBannerBytes {
		t.Errorf("MaxBannerBytes = %v, want the default %v", g.cfg.MaxBannerBytes, d.MaxBannerBytes)
	}
}

func TestTrimBannerCutsFromTheEnd(t *testing.T) {
	// The tail is the part that matters: the prompt the operator is looking at.
	// Trimming from the front would replay a wall of MOTD and hide it.
	in := []byte("line one\nline two\nRouter>")
	got := trimBanner(in, 12)
	if len(got) > 12 {
		t.Errorf("trimBanner returned %d bytes, want <= 12", len(got))
	}
	if want := "Router>"; string(got[len(got)-len(want):]) != want {
		t.Errorf("trimBanner = %q, want it to end at the prompt", got)
	}
}

func TestTrimBannerLeavesAShortBannerAlone(t *testing.T) {
	in := []byte("Router>")
	if got := trimBanner(in, 1024); string(got) != string(in) {
		t.Errorf("trimBanner = %q, want %q unchanged", got, in)
	}
}
