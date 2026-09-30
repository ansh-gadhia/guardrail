package term

import (
	"strconv"
	"strings"
)

// MirrorPage is the terminal as rendered for RECORDING rather than for a person.
//
// It is the same xterm.js the operator sees, with the interactive half removed:
// no WebSocket, no keyboard, no reconnect. Output arrives by function call
// (window.__grWrite) because the only thing that will ever drive this page is a
// headless browser under CDP control, and giving it a socket would mean giving
// it a credential to hold and a reconnect story to get right — for a page whose
// entire job is to be photographed.
//
// Why render a terminal in a browser at all, when the transcript already has
// every byte: a transcript is evidence of what the device printed, and video is
// evidence of what the operator saw. They differ whenever those diverge — a
// full-screen curses UI, a progress bar redrawing in place, a screen cleared
// before the reviewer's eyes. A reviewer asking "what did they actually see"
// is not served by a byte log, and this is the cheapest honest way to answer,
// because the frames it produces flow into the recorder the isolated web
// gateway already uses.
//
// The operator's own session never touches this page. They stay on the native
// socket, so nothing here can slow down their typing.
//
// scale is how much larger than the operator's own terminal it is drawn: the
// recording is captured at the page's CSS size, pixel for pixel, and played back
// stretched to fill the player — so a mirror drawn at the console's 13px came out
// soft, and JPEG made the soft edges blocky. Drawing the text itself larger is what
// puts more pixels into the frame; a device scale factor does not reach the
// screencast. The watermark scales with it so its density does not change.
func MirrorPage(o Options, scale float64) string {
	if scale <= 0 {
		scale = 1
	}
	return strings.NewReplacer(
		"__XTERM_CSS__", xtermCSS,
		"__XTERM_JS__", xtermJS,
		"__WATERMARK__", jsString(o.Watermark),
		"__SCALE__", strconv.FormatFloat(scale, 'f', -1, 64),
	).Replace(mirrorTmpl)
}

// mirrorTmpl is deliberately close to consoleTmpl in appearance and deliberately
// unlike it in wiring. Appearance matters because the recording has to look like
// the session; wiring differs because there is nobody at this keyboard.
const mirrorTmpl = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>session mirror</title>
<style>__XTERM_CSS__</style>
<style>
  html,body{margin:0;padding:0;background:#0b0e14;height:100%;overflow:hidden}
  #t{position:absolute;inset:0}
  /* The watermark is composited by the browser here, exactly as it is for an
     isolated web session, so it is burnt into the captured frames rather than
     drawn by a client that could remove it. That is the whole difference
     between the overlay on the operator's console (a deterrent) and this one
     (a control). */
  /* Font size and gap are set from the scale, below. Larger than the page on
     every side: the layer is rotated, and a page-sized one left the corners
     bare — the top left, where a terminal's output starts, among them. */
  #wm{position:absolute;inset:-50%;pointer-events:none;z-index:10;opacity:.10;
      font-family:ui-monospace,SFMono-Regular,Menlo,monospace;line-height:1.6;color:#fff;
      white-space:pre;transform:rotate(-24deg);transform-origin:center;
      display:flex;flex-wrap:wrap;align-content:center;justify-content:center}
</style>
</head>
<body>
<div id="t"></div>
<div id="wm"></div>
<script>__XTERM_JS__</script>
<script>
(function(){
  var wm = __WATERMARK__;
  if (wm) {
    var host = document.getElementById('wm'), frag = document.createDocumentFragment();
    // Enough to fill the overscanned layer at the largest frame.
    for (var i = 0; i < 400; i++) {
      var s = document.createElement('span');
      // textContent, never innerHTML: the watermark carries an operator email,
      // and this page also renders device output. Neither gets to be markup.
      s.textContent = wm;
      frag.appendChild(s);
    }
    host.appendChild(frag);
  }

  var term = new Terminal({
    convertEol: false,
    cursorBlink: false,          // a blinking cursor is pure frame churn here
    disableStdin: true,          // nobody types into a mirror
    scrollback: 0,               // the recording IS the scrollback
    fontFamily: 'ui-monospace,SFMono-Regular,Menlo,monospace',
    fontSize: 13 * __SCALE__,
    theme: { background: '#0b0e14' }
  });
  term.open(document.getElementById('t'));

  // The console's own sizes (13px text, a 12px watermark) times the scale.
  function setScale(s){
    if (!(s > 0)) return;
    if (term.options.fontSize !== 13 * s) term.options.fontSize = 13 * s;
    var w = document.getElementById('wm').style;
    w.fontSize = (12 * s) + 'px';
    w.gap = (38 * s) + 'px ' + (64 * s) + 'px';
  }
  setScale(__SCALE__);

  // Driven from Go over CDP. Base64 in, because the payload is raw terminal
  // bytes — escape sequences, partial UTF-8 runes at chunk boundaries, 0x00 —
  // none of which survives a trip through a JS string literal intact.
  window.__grWrite = function(b64){
    var bin = atob(b64), len = bin.length, buf = new Uint8Array(len);
    for (var i = 0; i < len; i++) buf[i] = bin.charCodeAt(i);
    term.write(buf);
  };

  // The scale travels with the geometry: a terminal made much wider is drawn at
  // a smaller scale, so the frame stays within the recorder's size.
  window.__grResize = function(cols, rows, scale){
    if (scale) setScale(scale);
    if (cols > 0 && rows > 0) term.resize(cols, rows);
  };

  // Lets the driver wait for xterm to be live before writing, instead of
  // sleeping and hoping.
  window.__grReady = true;
})();
</script>
</body>
</html>`
