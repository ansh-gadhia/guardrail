// Package watermark renders the session attribution overlay that both delivery
// modes stamp over a brokered device UI.
//
// Why this lives server-side rather than in the console page: an overlay drawn
// by GuardRail's own React shell only exists in that shell. It vanishes the
// moment the session URL is opened directly, and it is never present in a
// recording, because the recorder captures frames from the server-side browser
// which never sees the shell. A watermark that disappears exactly when someone
// is trying to work around it is not an attribution control.
//
// The strength of the guarantee still differs by mode, and the difference is
// inherent rather than an implementation gap:
//
//   - Browser isolation: the user receives pixels, never a DOM. The overlay is
//     inside the page being rendered, so it is burned into what they see and
//     into every recorded frame, and there is no client-side DOM to edit.
//   - Reverse proxy: the device's own DOM runs in the user's browser. Injecting
//     here means the watermark survives direct URL access, but a determined user
//     with devtools can delete the node. That is a property of handing someone
//     the real DOM, and no amount of injection changes it.
package watermark

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
)

// elementID is the overlay node's id. It is also how the keep-alive check finds
// out whether the overlay is still there.
const elementID = "__guardrail_watermark__"

// opacity is how strongly the tiled attribution reads over the device UI.
//
// It is a balance rather than a preference: too faint and it does not survive a
// screenshot re-encode or a photo of the screen, which is the whole point; too
// strong and it competes with the device's own interface and operators start
// asking to turn it off. Mid-grey at this alpha stays legible on both light and
// dark device pages without obscuring the work underneath.
const opacity = "0.24"

// JS returns a self-contained script (no <script> wrapper) that tiles text
// faintly across the viewport. It is safe to evaluate more than once and on any
// document: it no-ops when the overlay is already present.
//
// The script re-asserts the overlay on an interval rather than only at load. A
// single-page management UI can replace the whole body on navigation, which
// would otherwise take the watermark with it and leave the rest of the session
// unmarked.
func JS(text string) string {
	t := tileFor(text)
	return strings.NewReplacer(
		"__TEXT__", jsString(text),
		"__ID__", jsString(elementID),
		"OPACITY", jsString(opacity),
		"__TW__", strconv.Itoa(t.W),
		"__TH__", strconv.Itoa(t.H),
		"__BX__", strconv.Itoa(tilePad/2),
		"__BY__", strconv.Itoa(t.BaseY),
	).Replace(overlayJS)
}

// Geometry of one pattern tile.
const (
	// fontSize and letterSpacing must match what overlayJS renders with.
	fontSize      = 14.0
	letterSpacing = 1.0
	// monoAdvance is the horizontal advance of one character: monospace faces are
	// ~0.6em wide, plus the tracking.
	monoAdvance = fontSize*0.6 + letterSpacing
	// angleDeg is the tilt. Diagonal text is harder to crop out of a screenshot
	// than horizontal text, and reads across both dense tables and empty space.
	angleDeg = 28.0
	// tilePad is the margin around the rotated string, which doubles as the gap
	// between neighbouring tiles.
	tilePad = 40
)

type tile struct{ W, H, BaseY int }

// tileFor sizes a pattern tile so the whole rotated string fits inside it.
//
// This is computed rather than hard-coded because an SVG pattern clips at the
// tile edge and the string's length is not known until a session exists: a short
// admin address and a 50-character corporate one need very different tiles. A
// fixed tile that happens to suit the developer's own email crops the session id
// off everyone else's watermark, and still looks like it works.
func tileFor(text string) tile {
	rad := angleDeg * math.Pi / 180
	w := float64(len([]rune(text))) * monoAdvance
	dx := math.Ceil(w * math.Cos(rad)) // horizontal extent of the rotated string
	dy := math.Ceil(w * math.Sin(rad)) // vertical rise (rotation is negative)
	// Anchor the baseline pad/2 above the tile's bottom edge: the string then
	// rises to exactly pad/2 below the top, and runs from pad/2 to pad/2 short of
	// the right edge. Every edge keeps half the padding as margin.
	return tile{
		W:     int(dx) + tilePad,
		H:     int(dy) + tilePad,
		BaseY: int(dy) + tilePad/2,
	}
}

// HTML returns the same overlay wrapped in a <script> tag, for injection into a
// proxied HTML document.
func HTML(text string) string {
	return "<script>" + JS(text) + "</script>"
}

// jsString renders a Go string as a JavaScript literal. json.Marshal escapes
// quotes, backslashes and control characters, and — relevant here — HTML-escapes
// the angle brackets and ampersand to their \u00xx forms unless explicitly told
// not to. That is what stops attribution text containing a closing script tag
// from ending the element early once this literal is embedded in a proxied HTML
// document.
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// overlayJS tiles the attribution text as a repeating SVG background on a fixed,
// non-interactive layer. An SVG data URI is used rather than many DOM nodes so
// the overlay is one element the page cannot trip over, and pointer-events:none
// keeps it from ever swallowing a click meant for the device.
//
// The tile geometry is load-bearing, not styling. A pattern tile clips whatever
// crosses its edge, and rotating ~270px of attribution by -28 degrees lifts the
// tail of the string about 126px above its baseline. Anchoring the baseline low
// in a tile this tall keeps the whole string — crucially the session id, which
// is what joins a leaked screenshot back to the audit trail — inside the tile.
// Anchor it at the middle and the id is silently cropped off every tile, which
// still looks like a working watermark.
const overlayJS = `(function(){
var T=__TEXT__,ID=__ID__;
function svg(){
 var t=T.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
 return 'data:image/svg+xml;charset=utf-8,'+encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" width="__TW__" height="__TH__">'+
  '<text x="__BX__" y="__BY__" transform="rotate(-28 __BX__ __BY__)" '+
  'fill="#64748b" fill-opacity="'+OPACITY+'" '+
  'font-size="14" font-family="ui-monospace,SFMono-Regular,Menlo,monospace" '+
  'letter-spacing="1">'+t+'</text></svg>');
}
var url=svg();
function ensure(){
 if(!document.body||document.getElementById(ID))return;
 var d=document.createElement('div');
 d.id=ID;
 d.setAttribute('aria-hidden','true');
 d.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;z-index:2147483647;'+
  'pointer-events:none;user-select:none;background-repeat:repeat;background-image:url("'+url+'")';
 document.body.appendChild(d);
}
if(document.readyState==='loading'){
 document.addEventListener('DOMContentLoaded',ensure);
}else{ensure();}
setInterval(ensure,1000);
})();`
