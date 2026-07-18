// Package term holds what every terminal gateway needs: the operator-facing
// console page and the transcript recorder.
//
// It exists because SSH and telnet differ only in how the byte stream to the
// device is obtained. Once there is a stream, the console that renders it and
// the transcript that records it are identical — and the console carries a
// 289KB vendored xterm.js, so a second copy would be a second copy of that too.
// Keeping them here also means a fix to the console (reconnect, say) lands for
// every terminal protocol at once instead of being ported by hand.
package term

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

// CloseDeviceGone is the WebSocket close code for "the device connection ended,
// but the access session is still live".
//
// It exists to separate the two ways a terminal can go quiet, because the
// console must react to them differently and cannot tell them apart on its own.
// A normal closure means the session itself is over (terminated, expired) and
// there is nothing to reconnect to. This code means the far end hung up while
// the operator's authorisation is still good, so reconnecting is meaningful —
// the gateway will dial the device again and re-authenticate from the vault.
//
// 4002 is in the 4000-4999 range the WebSocket RFC reserves for applications.
const CloseDeviceGone = 4002

// Options parameterise the console page.
type Options struct {
	// SessionID is the access session being rendered.
	SessionID string
	// Device is what the operator is connected to, shown when the socket drops.
	Device string
	// Watermark is the attribution tiled over the terminal.
	Watermark string
	// Protocol names the transport in the page title and reconnect copy, e.g.
	// "SSH" or "Telnet".
	Protocol string
}

// Page returns the self-contained terminal served at a session root.
//
// It opens the session WebSocket, feeds device bytes into xterm, and sends
// keystrokes and resizes back as JSON. Nothing from the device is ever
// interpreted as markup — xterm renders it as terminal output — so a hostile
// device cannot inject script into this page.
func Page(o Options) string {
	proto := o.Protocol
	if proto == "" {
		proto = "Terminal"
	}
	return strings.NewReplacer(
		"__XTERM_CSS__", xtermCSS,
		"__XTERM_JS__", xtermJS,
		"__SID__", jsString(o.SessionID),
		"__DEVICE__", jsString(o.Device),
		"__WATERMARK__", jsString(o.Watermark),
		"__PROTO__", jsString(proto),
		"__PROTO_TEXT__", htmlEscape(proto),
		"__CLOSE_DEVICE_GONE__", itoa(CloseDeviceGone),
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

// htmlEscape guards the one place a value lands in markup rather than script.
func htmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// The watermark here is an honest deterrent, not the control it is in browser
// isolation.
//
// For an isolated web session the watermark is composited by the headless
// browser and captured in the recording, so it cannot be removed. A terminal has
// no pixels to burn into: this overlay is drawn by the operator's own browser and
// anyone with devtools can delete it. It still does the job it is here for —
// discouraging a photo of the screen — but the accountability for a terminal
// session rests on the transcript, which is captured server-side and never
// passes through the client.
const consoleTmpl = `<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GuardRail __PROTO_TEXT__ Session</title>
<style>__XTERM_CSS__</style>
<style>
 html,body{margin:0;height:100%;background:#0b1220;overflow:hidden}
 #term{position:fixed;inset:0;padding:6px 8px 8px}
 #status{position:fixed;top:8px;left:50%;transform:translateX(-50%);color:#9fb0c8;
   font:13px system-ui;background:rgba(15,23,42,.92);padding:6px 12px;border-radius:6px;z-index:5;
   display:flex;align-items:center;gap:10px;box-shadow:0 1px 12px rgba(0,0,0,.4)}
 #status[hidden]{display:none}
 #msg{white-space:nowrap}
 #again{font:600 12px system-ui;color:#0b1220;background:#7dd3fc;border:0;border-radius:5px;
   padding:4px 10px;cursor:pointer}
 #again:hover{background:#a5e4fd}
 #again[hidden]{display:none}
 /* pointer-events:none so the overlay never eats a click meant for the terminal */
 #wm{position:fixed;inset:0;z-index:4;pointer-events:none;opacity:.24}
</style></head><body>
<div id="term"></div>
<div id="wm"></div>
<div id="status"><span id="msg">connecting…</span><button id="again" hidden>Reconnect</button></div>
<script>__XTERM_JS__</script>
<script>
(function(){
  var SID = __SID__, DEVICE = __DEVICE__, WM = __WATERMARK__, PROTO = __PROTO__;
  var DEVICE_GONE = __CLOSE_DEVICE_GONE__;
  var statusEl = document.getElementById('status');
  var msgEl = document.getElementById('msg');
  var againEl = document.getElementById('again');

  // showRetry decides whether the button is offered, so no caller can leave the
  // operator staring at a dead terminal with no way to act.
  function status(t, retry){
    if (t) { msgEl.textContent = t; statusEl.hidden = false; }
    else { statusEl.hidden = true; }
    againEl.hidden = !retry;
  }

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

  // notice writes a line the DEVICE did not send. It is deliberately client-side
  // only and never travels to the recorder: the transcript is evidence of what
  // the device printed, and editing our own commentary into it would make it
  // evidence of nothing.
  function notice(text){ term.write('\r\n\x1b[38;5;245m*** ' + text + ' ***\x1b[0m\r\n'); }

  var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  var base = location.pathname.replace(/\/$/, '');
  var url = proto + '//' + location.host + base + '/__ws__';
  var dec = new TextDecoder();

  var ws = null;
  var attempts = 0;        // consecutive failed transport attempts
  var everOpened = false;  // distinguishes "reconnected" from "connected"
  var ended = false;       // the access session itself is over: stop trying
  var timer = null;
  var MAX_AUTO = 6;        // ~30s of backoff before we stop and ask

  function send(o){ if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); }
  function sendFit(){ var g = fit(); if (g) send({ t:'r', cols:g.cols, rows:g.rows }); }

  function connect(){
    clearTimeout(timer);
    if (ended) return;
    status(everOpened ? 'reconnecting…' : 'connecting…', false);
    try { ws = new WebSocket(url); }
    catch (e) { retry(); return; }
    ws.binaryType = 'arraybuffer';

    ws.onopen = function(){
      attempts = 0;
      if (everOpened) notice('reconnected to ' + DEVICE);
      everOpened = true;
      status(null, false);
      term.options.cursorBlink = true;
      sendFit();
      term.focus();
    };
    ws.onmessage = function(ev){
      // Device output arrives as raw bytes and is written straight to the emulator.
      term.write(typeof ev.data === 'string' ? ev.data : new Uint8Array(ev.data));
    };
    ws.onclose = function(ev){
      term.options.cursorBlink = false;
      if (ended) return;
      if (ev.code === 1000) {
        // The session is over — terminated, expired, or the shell exited. There
        // is nothing on the other side to reconnect to, so do not pretend.
        ended = true;
        status('session ended — ' + DEVICE, false);
        return;
      }
      if (ev.code === DEVICE_GONE) {
        // The device hung up while the operator is still authorised. This is
        // NOT auto-retried: a clean hangup is what both an idle timeout and a
        // deliberate "exit" look like on the wire, and silently dialling back
        // into a router nobody is sitting at is the wrong default for a PAM.
        // One click re-dials and re-authenticates from the vault.
        status('disconnected by ' + DEVICE + '. ' + PROTO + ' can reconnect.', true);
        return;
      }
      retry();
    };
    // onerror is always followed by onclose; retrying here too would double the
    // backoff schedule.
    ws.onerror = function(){};
  }

  function retry(){
    // A dropped socket is not a dropped session: GuardRail still holds the
    // device connection, so re-attaching is lossless and safe to do unasked.
    attempts++;
    if (attempts > MAX_AUTO) {
      status('connection lost — ' + DEVICE, true);
      return;
    }
    var delay = Math.min(15000, 500 * Math.pow(2, attempts - 1));
    status('connection lost — retrying in ' + Math.ceil(delay / 1000) + 's…', true);
    timer = setTimeout(connect, delay);
  }

  againEl.addEventListener('click', function(){
    attempts = 0;
    ended = false;
    connect();
  });

  term.onData(function(d){
    if (ws && ws.readyState === 1) ws.send(JSON.stringify({ t:'i', d:d }));
  });

  var rt;
  window.addEventListener('resize', function(){
    clearTimeout(rt);
    rt = setTimeout(sendFit, 120);
  });

  connect();
})();
</script></body></html>`
