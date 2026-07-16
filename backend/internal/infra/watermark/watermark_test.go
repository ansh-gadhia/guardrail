package watermark

import (
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestJSEmbedsText(t *testing.T) {
	js := JS("alice@example.com · sess 1a2b3c4d")
	if !strings.Contains(js, `"alice@example.com · sess 1a2b3c4d"`) {
		t.Fatalf("attribution text not embedded as a literal:\n%s", js)
	}
	if !strings.Contains(js, elementID) {
		t.Error("overlay element id not embedded")
	}
}

// The whole point of jsString is that hostile attribution text cannot break out
// of the literal and into the surrounding <script> element. This is the test
// that has to hold, not the doc comment claiming json.Marshal does it.
func TestHTMLCannotBreakOutOfScript(t *testing.T) {
	for _, text := range []string{
		`</script><script>alert(1)</script>`,
		`"; alert(1); var x="`,
		`<!--`,
		"line\nbreak",
	} {
		out := HTML(text)
		body := strings.TrimSuffix(strings.TrimPrefix(out, "<script>"), "</script>")
		if strings.Contains(strings.ToLower(body), "</script") {
			t.Errorf("raw closing script tag survived for %q:\n%s", text, out)
		}
		if strings.Contains(body, "<!--") {
			t.Errorf("comment opener survived for %q:\n%s", text, out)
		}
		// Exactly one wrapper open/close, i.e. the payload did not add elements.
		if n := strings.Count(out, "<script>"); n != 1 {
			t.Errorf("expected 1 script open for %q, got %d", text, n)
		}
	}
}

func TestHTMLWraps(t *testing.T) {
	out := HTML("x")
	if !strings.HasPrefix(out, "<script>") || !strings.HasSuffix(out, "</script>") {
		t.Errorf("HTML() must wrap the script; got %q", out)
	}
}

// The overlay must never intercept input meant for the device, and must sit
// above the device's own stacking contexts.
func TestOverlayIsInertAndOnTop(t *testing.T) {
	js := JS("x")
	for _, want := range []string{"pointer-events:none", "z-index:2147483647", "position:fixed"} {
		if !strings.Contains(js, want) {
			t.Errorf("overlay style missing %q", want)
		}
	}
}

// A single-page UI can swap the whole body out from under us; the overlay has to
// come back rather than silently leaving the rest of the session unmarked.
func TestOverlayReasserts(t *testing.T) {
	js := JS("x")
	if !strings.Contains(js, "setInterval(ensure") {
		t.Error("overlay is not re-asserted after load")
	}
	if !strings.Contains(js, "getElementById(ID)") {
		t.Error("re-assert must be idempotent (no duplicate overlays)")
	}
}

// The overlay's legibility is the control. Pin the opacity so a future edit to
// the SVG string cannot quietly fade the attribution back out.
func TestOverlayOpacity(t *testing.T) {
	js := JS("x")
	if !strings.Contains(js, `fill-opacity="'+"0.24"+'"`) {
		t.Errorf("watermark opacity not applied as expected:\n%s", js)
	}
}

// A pattern tile clips at its edges, so the rotated string must fit inside it
// for every attribution the broker can produce — not just a short one. This is
// the failure that looks fine: the email renders, the session id is cropped off
// every tile, and the watermark stops identifying the session.
func TestRotatedTextFitsInsideTileForAnyLength(t *testing.T) {
	for _, text := range []string{
		"a@b.co · 1a2b3c4d",
		"admin@guardrail.local · 1a2b3c4d",
		"very.long.operator.name@subdomain.example.com · 1a2b3c4d",
		strings.Repeat("x", 120) + " · 1a2b3c4d",
		"session 00000000-0000-0000-0000-000000000000", // the no-email fallback
	} {
		tl := tileFor(text)
		rad := angleDeg * math.Pi / 180
		w := float64(len([]rune(text))) * monoAdvance
		baseX := float64(tilePad / 2)
		endX := baseX + w*math.Cos(rad)
		topY := float64(tl.BaseY) - w*math.Sin(rad)

		if endX > float64(tl.W) {
			t.Errorf("%q: runs off the tile: ends x=%.0f, tile w=%d", text, endX, tl.W)
		}
		if topY < 0 {
			t.Errorf("%q: clipped at top: reaches y=%.0f", text, topY)
		}
		if tl.BaseY > tl.H {
			t.Errorf("%q: baseline %d below tile height %d", text, tl.BaseY, tl.H)
		}
	}
}

// The geometry reasoned about above must be the geometry actually emitted, or
// the test is checking numbers nobody renders.
func TestTileGeometryMatchesEmitted(t *testing.T) {
	text := "admin@guardrail.local · 1a2b3c4d"
	tl := tileFor(text)
	js := JS(text)
	for _, want := range []string{
		fmt.Sprintf(`width="%d" height="%d"`, tl.W, tl.H),
		fmt.Sprintf(`x="%d" y="%d"`, tilePad/2, tl.BaseY),
		fmt.Sprintf(`rotate(-28 %d %d)`, tilePad/2, tl.BaseY),
	} {
		if !strings.Contains(js, want) {
			t.Errorf("emitted SVG missing %q:\n%s", want, js)
		}
	}
}

// A longer name must produce a bigger tile; a fixed tile is the bug this
// replaced.
func TestTileScalesWithText(t *testing.T) {
	short := tileFor("a@b.co · 1a2b3c4d")
	long := tileFor("very.long.operator.name@subdomain.example.com · 1a2b3c4d")
	if long.W <= short.W || long.H <= short.H {
		t.Errorf("tile must grow with text: short=%+v long=%+v", short, long)
	}
}
