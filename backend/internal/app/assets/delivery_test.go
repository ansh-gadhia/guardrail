package assets

import (
	"errors"
	"strings"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/assets"
)

// Delivery mode and recording are two settings with one dependency between them:
// recording a WEB device captures frames from a server-side browser, so for the
// web it exists only under isolation. These tests pin that dependency — and its
// limits — at the only place a device can be born or changed, because everything
// downstream trusts it. A device that got in with "recorded" plus "proxied" would
// broker sessions that capture nothing while its policy says otherwise; a rule
// drawn too widely would refuse a recorded SSH device, which needs no browser at
// all.

func strp(s string) *string { return &s }

func TestDeliveryDefaultsToProxyWhenUnrecorded(t *testing.T) {
	got, err := deliveryOrDefault("https", nil, "", false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != assets.DeliveryProxy {
		t.Errorf("delivery = %q, want %q — isolation costs a browser process and must be asked for",
			got, assets.DeliveryProxy)
	}
}

// Asking for recording is asking for isolation, whether or not the registrant
// used that word. Defaulting to the proxy here would refuse the device outright
// (recorded + proxied is impossible) for saying nothing about a mode it had
// already implied.
func TestDeliveryDefaultsToIsolatedWhenRecorded(t *testing.T) {
	got, err := deliveryOrDefault("https", nil, "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != assets.DeliveryIsolated {
		t.Errorf("delivery = %q, want %q — recording only exists under isolation",
			got, assets.DeliveryIsolated)
	}
}

func TestDeliveryHonoursExplicitMode(t *testing.T) {
	for _, mode := range assets.DeliveryModes() {
		got, err := deliveryOrDefault("https", strp(mode), "", false)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", mode, err)
		}
		if got != mode {
			t.Errorf("delivery = %q, want %q", got, mode)
		}
	}
}

// An isolated device that is not recorded is the whole point of the split: an
// appliance SPA cannot be re-served under a path prefix, so it needs isolation
// for delivery alone, with no obligation to keep evidence.
func TestDeliveryAllowsIsolatedWithoutRecording(t *testing.T) {
	got, err := deliveryOrDefault("https", strp(assets.DeliveryIsolated), "", false)
	if err != nil {
		t.Fatalf("isolated delivery must not require recording: %v", err)
	}
	if got != assets.DeliveryIsolated {
		t.Errorf("delivery = %q, want %q", got, assets.DeliveryIsolated)
	}
}

// Stating both, incompatibly, is refused rather than resolved. Silently picking
// one would mean guessing which of the two things the caller asked for they
// actually meant — a coin flip over an audit control.
func TestDeliveryRefusesRecordedProxy(t *testing.T) {
	_, err := deliveryOrDefault("https", strp(assets.DeliveryProxy), "", true)
	if !errors.Is(err, assets.ErrInvalid) {
		t.Fatalf("error = %v, want assets.ErrInvalid", err)
	}
	// The message is the whole remedy: an operator has to learn which of the two
	// settings to change, and "invalid input" does not tell them.
	if !strings.Contains(err.Error(), "isolated") {
		t.Errorf("error %q must name isolated delivery as the fix", err)
	}
}

func TestDeliveryRefusesUnknownMode(t *testing.T) {
	_, err := deliveryOrDefault("https", strp("vnc-ish"), "", false)
	if !errors.Is(err, assets.ErrInvalid) {
		t.Fatalf("error = %v, want assets.ErrInvalid", err)
	}
	// Naming the offending value and the allowed set is the reason this refuses
	// rather than substituting a default.
	if !strings.Contains(err.Error(), "vnc-ish") {
		t.Errorf("error %q must quote the rejected value", err)
	}
	for _, mode := range assets.DeliveryModes() {
		if !strings.Contains(err.Error(), mode) {
			t.Errorf("error %q must list the allowed mode %q", err, mode)
		}
	}
}

func TestRecordingImpossible(t *testing.T) {
	cases := []struct {
		scheme    string
		mode      string
		record    bool
		forbidden bool
	}{
		{"https", assets.DeliveryIsolated, true, false},  // recorded, and able to record
		{"https", assets.DeliveryIsolated, false, false}, // isolated for delivery alone
		{"https", assets.DeliveryProxy, false, false},    // the plain case
		{"https", assets.DeliveryProxy, true, true},      // the impossible one
		{"http", assets.DeliveryProxy, true, true},       // http is a web scheme too
		// A recorded SSH device is achievable on any host: the SSH gateway keeps the
		// transcript itself, with no browser anywhere. Refusing it would be applying
		// a rule about browsers to a protocol that has none.
		{"ssh", assets.DeliveryProxy, true, false},
	}
	for _, c := range cases {
		if got := assets.RecordingImpossible(c.scheme, c.mode, c.record); got != c.forbidden {
			t.Errorf("RecordingImpossible(%q, %q, %v) = %v, want %v",
				c.scheme, c.mode, c.record, got, c.forbidden)
		}
	}
}

// Delivery mode is a web-only choice, and the non-web cases are where the rule
// used to be wrong: a blanket "recording implies isolation" refused a recorded SSH
// device, and marked the ones it accepted as delivered by a browser they never
// touched.

func TestDeliveryDefaultsToProxyForRecordedNonWebDevice(t *testing.T) {
	got, err := deliveryOrDefault("ssh", nil, "", true)
	if err != nil {
		t.Fatalf("a recorded SSH device must be allowed — its gateway records itself: %v", err)
	}
	if got != assets.DeliveryProxy {
		t.Errorf("delivery = %q, want %q: an SSH device is never rendered in a browser",
			got, assets.DeliveryProxy)
	}
}

func TestDeliveryRefusesIsolationForNonWebDevice(t *testing.T) {
	for _, scheme := range []string{"ssh", "rdp", "vnc"} {
		_, err := deliveryOrDefault(scheme, strp(assets.DeliveryIsolated), "", false)
		if !errors.Is(err, assets.ErrInvalid) {
			t.Errorf("%s: error = %v, want assets.ErrInvalid — isolation is a web-only mode", scheme, err)
			continue
		}
		if !strings.Contains(err.Error(), scheme) {
			t.Errorf("%s: error %q must name the scheme it is refusing", scheme, err)
		}
	}
}

func TestIsWebScheme(t *testing.T) {
	for _, s := range []string{"http", "https"} {
		if !assets.IsWebScheme(s) {
			t.Errorf("IsWebScheme(%q) = false", s)
		}
	}
	for _, s := range []string{"ssh", "rdp", "vnc", "", "HTTPS"} {
		if assets.IsWebScheme(s) {
			t.Errorf("IsWebScheme(%q) = true", s)
		}
	}
}

// Saying nothing on an update means "leave it", not "re-default it". Re-defaulting
// would flip an isolated-for-delivery device back to the proxy the first time
// someone edited its name.
func TestDeliveryKeepsCurrentModeWhenUnstated(t *testing.T) {
	got, err := deliveryOrDefault("https", nil, assets.DeliveryIsolated, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != assets.DeliveryIsolated {
		t.Errorf("delivery = %q, want the stored %q left alone", got, assets.DeliveryIsolated)
	}
}

// The pair is judged after both fields settle. Turning recording on while saying
// nothing about a device stored as proxied must be refused, not accepted because
// the impossible half was the one left unstated.
func TestDeliveryRefusesRecordingTurnedOnOverStoredProxy(t *testing.T) {
	_, err := deliveryOrDefault("https", nil, assets.DeliveryProxy, true)
	if !errors.Is(err, assets.ErrInvalid) {
		t.Fatalf("error = %v, want assets.ErrInvalid", err)
	}
}

// A device switched to ssh in the same call that leaves delivery alone is judged
// as the ssh device it is about to become, not the https device it was.
func TestDeliveryJudgedAgainstTheSettledScheme(t *testing.T) {
	_, err := deliveryOrDefault("ssh", nil, assets.DeliveryIsolated, false)
	if !errors.Is(err, assets.ErrInvalid) {
		t.Fatalf("error = %v, want assets.ErrInvalid: an ssh device cannot stay isolated", err)
	}
}

func TestValidDeliveryIsAClosedSet(t *testing.T) {
	for _, mode := range assets.DeliveryModes() {
		if !assets.ValidDelivery(mode) {
			t.Errorf("ValidDelivery(%q) = false for a mode DeliveryModes lists", mode)
		}
	}
	for _, bad := range []string{"", "PROXY", "isolated ", "browser", "rdp"} {
		if assets.ValidDelivery(bad) {
			t.Errorf("ValidDelivery(%q) = true; the set must stay closed", bad)
		}
	}
}

// DeliveryModes hands out a copy. A caller that sorts or appends to the returned
// slice must not be able to reach into the package's own list.
func TestDeliveryModesIsNotAliased(t *testing.T) {
	got := assets.DeliveryModes()
	got[0] = "clobbered"
	if assets.DeliveryModes()[0] == "clobbered" {
		t.Error("DeliveryModes returns the package's slice; a caller can rewrite the closed set")
	}
}
