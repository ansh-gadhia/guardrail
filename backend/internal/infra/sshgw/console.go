package sshgw

import (
	_ "embed"
	"encoding/json"
	"strings"
)

// xterm.js, vendored rather than fetched from a CDN.
//
// The console must work on an air-gapped management network, and a PAM that
// pulls its terminal emulator from a third-party host at session time would let
// that host run code in an operator's authenticated session. Serving it from our
// own origin also keeps the frontend's dependency list honest: this is Go-served
// like the canvas viewer, so the React app gains nothing to build.
//
// Upstream: https://github.com/xtermjs/xterm.js (MIT) — see web/xterm.LICENSE.
//
//go:embed web/xterm.js
var xtermJS string

//go:embed web/xterm.css
var xtermCSS string

// consolePage returns the self-contained terminal served at a session root.
//
// It opens the session WebSocket, feeds device bytes into xterm, and sends
// keystrokes and resizes back as JSON. Nothing from the device is ever
// interpreted as markup — xterm renders it as terminal output — so a hostile
// device cannot inject script into this page.
func consolePage(sid, device, watermark string) string {
	return strings.NewReplacer(
		"__XTERM_CSS__", xtermCSS,
		"__XTERM_JS__", xtermJS,
		"__SID__", jsString(sid),
		"__DEVICE__", jsString(device),
		"__WATERMARK__", jsString(watermark),
	).Replace(consoleTmpl)
}

// jsString renders a Go string as a JS literal. json.Marshal escapes the
// characters that would otherwise let device- or user-controlled text break out
// of the literal and into the surrounding script.
func jsString(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// The watermark here is an honest deterrent, not the control it is in browser
// isolation.
//
// For an isolated web session the watermark is composited by the headless
// browser and captured in the recording, so it cannot be removed. A terminal has
// no pixels to burn into: this overlay is drawn by the operator's own browser and
// anyone with devtools can delete it. It still does the job it is here for —
// discouraging a photo of the screen — but the accountability for an SSH session
// rests on the transcript, which is captured server-side and never passes through
// the client.
const consoleTmpl = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GuardRail SSH Session</title>
<style>__XTERM_CSS__</style>
<style>
 html,body{margin:0;height:100%;background:#0b1220;overflow:hidden}
 #term{position:fixed;inset:0;padding:6px 8px 8px}
 #status{position:fixed;top:8px;left:50%;transform:translateX(-50%);color:#9fb0c8;
   font:13px system-ui;background:rgba(15,23,42,.92);padding:6px 12px;border-radius:6px;z-index:5}
 #status[hidden]{display:none}
 /* pointer-events:none so the overlay never eats a click meant for the terminal */
 #wm{position:fixed;inset:0;z-index:4;pointer-events:none;opacity:.24}
</style></head><body>
<div id="term"></div>
<div id="wm"></div>
<div id="status">connecting…</div>
<script>__XTERM_JS__</script>
<script>
(function(){
  var SID = __SID__, DEVICE = __DEVICE__, WM = __WATERMARK__;
  var statusEl = document.getElementById('status');
  function status(t){ if(t){statusEl.textContent=t; statusEl.hidden=false;} else {statusEl.hidden=true;} }

  // Tiled diagonal attribution. Deterrent only — see the note in console.go.
  if (WM) {
    var c = document.createElement('canvas'), g = c.getContext('2d');
    g.font = '14px ui-monospace, monospace';
    var w = Math.ceil(g.measureText(WM).width) + 60;
    c.width = w; c.height = 90;
    g = c.getContext('2d');
    g.font = '14px ui-monospace, monospace';
    g.fillStyle = '#94a3b8';
    g.translate(0, 70); g.rotate(-28 * Math.PI / 180);
    g.fillText(WM, 10, 0);
    document.getElementById('wm').style.background = "url(" + c.toDataURL() + ") repeat";
  }

  var term = new Terminal({
    cursorBlink: true, fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
    fontSize: 13, theme: { background: '#0b1220' }, scrollback: 5000
  });
  term.open(document.getElementById('term'));
  term.focus();

  // xterm's fit addon is a separate package; the geometry is simple enough to do
  // here and keeps the vendored surface to one file.
  function fit(){
    var dims = term._core._renderService.dimensions.css.cell;
    if (!dims || !dims.width || !dims.height) return;
    var el = document.getElementById('term');
    var cols = Math.max(20, Math.floor((el.clientWidth - 16) / dims.width));
    var rows = Math.max(5, Math.floor((el.clientHeight - 14) / dims.height));
    if (cols !== term.cols || rows !== term.rows) term.resize(cols, rows);
    return { cols: cols, rows: rows };
  }

  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  var base = location.pathname.replace(/\/$/, '');
  var ws = new WebSocket(proto + '//' + location.host + base + '/__ws__');
  ws.binaryType = 'arraybuffer';
  var dec = new TextDecoder();

  ws.onopen = function(){
    status(null);
    var g = fit();
    if (g) ws.send(JSON.stringify({ t:'r', cols:g.cols, rows:g.rows }));
  };
  ws.onmessage = function(ev){
    // Device output arrives as raw bytes and is written straight to the emulator.
    term.write(typeof ev.data === 'string' ? ev.data : new Uint8Array(ev.data));
  };
  ws.onclose = function(){ status('session ended — ' + DEVICE); term.options.cursorBlink = false; };
  ws.onerror = function(){ status('connection error'); };

  term.onData(function(d){
    if (ws.readyState === 1) ws.send(JSON.stringify({ t:'i', d:d }));
  });

  var rt;
  window.addEventListener('resize', function(){
    clearTimeout(rt);
    rt = setTimeout(function(){
      var g = fit();
      if (g && ws.readyState === 1) ws.send(JSON.stringify({ t:'r', cols:g.cols, rows:g.rows }));
    }, 120);
  });
})();
</script></body></html>`
