package term

import "strings"

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
func MirrorPage(o Options) string {
	return strings.NewReplacer(
		"__XTERM_CSS__", xtermCSS,
		"__XTERM_JS__", xtermJS,
		"__WATERMARK__", jsString(o.Watermark),
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
  #wm{position:absolute;inset:0;pointer-events:none;z-index:10;opacity:.10;
      font:12px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace;color:#fff;
      white-space:pre;transform:rotate(-24deg);transform-origin:center;
      display:flex;flex-wrap:wrap;align-content:center;justify-content:center;gap:38px 64px}
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
    for (var i = 0; i < 60; i++) {
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
    fontSize: 13,
    theme: { background: '#0b0e14' }
  });
  term.open(document.getElementById('t'));

  // Driven from Go over CDP. Base64 in, because the payload is raw terminal
  // bytes — escape sequences, partial UTF-8 runes at chunk boundaries, 0x00 —
  // none of which survives a trip through a JS string literal intact.
  window.__grWrite = function(b64){
    var bin = atob(b64), len = bin.length, buf = new Uint8Array(len);
    for (var i = 0; i < len; i++) buf[i] = bin.charCodeAt(i);
    term.write(buf);
  };

  window.__grResize = function(cols, rows){
    if (cols > 0 && rows > 0) term.resize(cols, rows);
  };

  // Lets the driver wait for xterm to be live before writing, instead of
  // sleeping and hoping.
  window.__grReady = true;
})();
</script>
</body>
</html>`
