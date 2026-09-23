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
	// ReadOnly renders the session for somebody WATCHING it rather than driving
	// it: keystrokes are not sent, resizes are not sent, and the page says so.
	//
	// Not sending is the whole point. A supervisor's terminal that quietly
	// transmitted would put a second keyboard on one PTY, interleaving two
	// people's input into a transcript that attributes all of it to whoever
	// opened the session. The gateway discards observer input as well — this is
	// the near side of the same rule, so a viewer never sees their own typing
	// echo locally and think it landed.
	ReadOnly bool
	// WatchedUser is who is being watched, named in the read-only banner. A
	// supervisor should not have to cross-reference an id to know whose keyboard
	// they are looking at.
	WatchedUser string
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
		"__READONLY__", boolJS(o.ReadOnly),
		"__WATCHED_USER__", jsString(o.WatchedUser),
	).Replace(consoleTmpl)
}

// boolJS renders a Go bool as a JS literal.
func boolJS(b bool) string {
	if b {
		return "true"
	}
	return "false"
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
 /* The read-only banner is pinned and unmissable on purpose. Somebody watching a
    colleague should never be in doubt about which of the two they are doing, and
    a supervisor who believes they are driving will try to type into a terminal
    that is deliberately ignoring them. */
 /* :not([hidden]) is load-bearing — see the note in the canvas viewer. An
    author display rule beats [hidden], so this banner appeared on the
    operator's own terminal too. */
 #ro:not([hidden]){position:fixed;top:0;left:0;right:0;z-index:30;display:flex;align-items:center;
     gap:8px;padding:5px 10px;background:#1e293b;border-bottom:1px solid #334155;
     color:#cbd5e1;font:12px/1.4 ui-sans-serif,system-ui,sans-serif}
 #ro #rodot{width:7px;height:7px;border-radius:50%;background:#38bdf8;flex:none;
            box-shadow:0 0 0 3px rgba(56,189,248,.18)}
 body.ro #term{top:27px;padding-top:4px}
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
<div id="ro" hidden><span id="rodot"></span><span id="rotext"></span></div>
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
    // The tile must fit the text's *rotated* bounding box, not the text's own.
    // A fixed-height tile silently clips a long watermark: rotated up and to the
    // right, the tail of the string climbs past the top edge and the end of it
    // simply vanishes (e.g. "admin@guardrail.local · a1b2c3d4" showing as
    // "admin@guardrail.l"). Sizing to the rotated extent keeps every glyph.
    var FONT = '14px ui-monospace, monospace';
    var ANGLE = -28 * Math.PI / 180;
    var PAD = 22;
    var c = document.createElement('canvas'), g = c.getContext('2d');
    g.font = FONT;
    var m = g.measureText(WM);
    var tw = m.width;
    var asc = m.actualBoundingBoxAscent || 11, desc = m.actualBoundingBoxDescent || 3;
    var th = asc + desc;
    var sin = Math.abs(Math.sin(ANGLE)), cos = Math.abs(Math.cos(ANGLE));
    c.width = Math.ceil(tw * cos + th * sin) + PAD * 2;
    c.height = Math.ceil(tw * sin + th * cos) + PAD * 2;
    // Assigning width/height resets the context, so re-establish font and fill.
    g = c.getContext('2d');
    g.font = FONT;
    g.fillStyle = '#94a3b8';
    // Anchor the baseline so the run's top-left corner sits at (PAD, PAD): its
    // highest point is the right end climbing up by sin*tw, plus the ascender.
    g.translate(PAD + sin * asc, PAD + sin * tw + cos * asc);
    g.rotate(ANGLE);
    g.fillText(WM, 0, 0);
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

  var READONLY = __READONLY__;
  var WATCHED_USER = __WATCHED_USER__;

  if (READONLY) {
    document.body.classList.add('ro');
    document.getElementById('rotext').textContent =
      WATCHED_USER ? ('Watching ' + WATCHED_USER + ' \u2014 read-only. Your keystrokes are not sent.')
                   : 'Watching a live session \u2014 read-only. Your keystrokes are not sent.';
    document.getElementById('ro').hidden = false;
    document.title = 'Watching \u2014 GuardRail __PROTO_TEXT__ Session';
  }

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
  // fit() ALWAYS runs; only the send is withheld.
  //
  // They are two different things and conflating them is what made a watched
  // terminal a small box in the corner of a large frame: fit() resizes the
  // LOCAL xterm to its container, and send() tells the DEVICE to change its
  // geometry. A watcher must not do the second — the person working owns the
  // grid — but skipping the first left their terminal at the default 80x24
  // regardless of how much room it had, which looks exactly like a feature that
  // does not fill the screen, because it is one.
  function sendFit(){ var g = fit(); if (g && !READONLY) send({ t:'r', cols:g.cols, rows:g.rows }); }

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
    // A watcher sends nothing. The gateway discards observer input too; this is
    // the near side of the same rule, so keystrokes do not echo locally and read
    // as though they reached the device.
    if (READONLY) return;
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
