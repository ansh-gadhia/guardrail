package browser

import (
	"strings"
	"testing"

	"github.com/guardrail/guardrail/internal/infra/term"
)

// A mirror is drawn as large as the recorder's frame limit allows, stepping down
// for wide terminals rather than clipping them.
func TestMirrorGeometry(t *testing.T) {
	cases := []struct {
		name       string
		cols, rows int
		w, h       int64
		scale      float64
	}{
		{"an ordinary terminal is drawn at twice the size", 80, 24, 1312, 848, 2},
		{"a wide one steps down rather than being clipped", 200, 50, 2424, 1299, 1.5},
		{"a very wide one is drawn at the console's own size", 300, 60, 2416, 1036, 1},
		{"beyond even that, the frame limit holds", 400, 100, mirrorMaxW, mirrorMaxH, 1},
		{"a tiny one is padded up to the minimum", 10, 3, mirrorMinW, mirrorMinH, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, h, s := mirrorGeometry(c.cols, c.rows)
			if w != c.w || h != c.h || s != c.scale {
				t.Errorf("mirrorGeometry(%d,%d) = %dx%d at %gx, want %dx%d at %gx", c.cols, c.rows, w, h, s, c.w, c.h, c.scale)
			}
		})
	}
}

// The page is drawn at the scale it is given, and a resize carries the scale
// with it.
func TestMirrorPageScale(t *testing.T) {
	html := term.MirrorPage(term.Options{}, 1.5)
	for _, want := range []string{"fontSize: 13 * 1.5", "setScale(1.5)"} {
		if !strings.Contains(html, want) {
			t.Errorf("mirror page does not contain %q", want)
		}
	}
	if got := resizeJS(120, 40, 2); got != "window.__grResize(120,40,2)" {
		t.Errorf("resizeJS = %q", got)
	}
}
