package access

import (
	"testing"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/assets"
)

// The protocol vocabulary is duplicated on purpose: assets owns what a device may
// be registered as, access owns what the broker can route, and the two bounded
// contexts do not import one another. Duplication is only safe while something
// checks it, and this is that check — the app/access package is one of the few
// that legitimately sees both.
//
// Drift is not cosmetic. A protocol in assets but not access is a device you can
// register and never connect to. One in access but not assets is a gateway that
// can never receive a session. Either way the failure appears far from the edit
// that caused it.
func TestProtocolVocabulariesAgree(t *testing.T) {
	inAccess := map[string]bool{}
	for _, p := range access.Protocols() {
		inAccess[string(p)] = true
	}
	inAssets := map[string]bool{}
	for _, s := range assets.Schemes() {
		inAssets[s] = true
	}

	for s := range inAssets {
		if !inAccess[s] {
			t.Errorf("assets allows registering %q but access cannot route it: "+
				"the device would be unconnectable", s)
		}
	}
	for p := range inAccess {
		if !inAssets[p] {
			t.Errorf("access routes %q but assets refuses to register it: "+
				"no device can ever use that gateway", p)
		}
	}
}

// Both sides must agree on the port too, or the console prefills one number while
// the server stores another.
func TestDefaultPortsAgree(t *testing.T) {
	for _, p := range access.Protocols() {
		want, ok := access.DefaultPort(p)
		if !ok {
			t.Errorf("access.DefaultPort(%q) unknown", p)
			continue
		}
		got, ok := assets.DefaultPortFor(string(p))
		if !ok {
			t.Errorf("assets.DefaultPortFor(%q) unknown", p)
			continue
		}
		if got != want {
			t.Errorf("default port for %q: assets says %d, access says %d", p, got, want)
		}
	}
}
