package browser

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/chromedp/cdproto/input"
	"github.com/chromedp/chromedp"
	"github.com/coder/websocket"
	"github.com/google/uuid"
)

// Console serves the browser-facing entry for a session. For the browser gateway
// this is a self-contained canvas page that opens the streaming WebSocket; the
// device pixels arrive over that socket, so the device HTML/JS never reaches the
// user. Returns false if the session is unknown/expired or the token is wrong.
func (g *Gateway) Console(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token, path string) bool {
	bs := g.lookup(sid, token)
	if bs == nil {
		return false
	}
	// Anything other than the session root here is a stray asset request from a
	// prior reverse-proxy attempt; the canvas page needs nothing but itself.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(consolePage(sid.String())))
	return true
}

// Stream upgrades to a WebSocket, pushes screencast frames to the client, and
// dispatches the client's input events into the headless browser.
func (g *Gateway) Stream(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool {
	bs := g.lookup(sid, token)
	if bs == nil {
		return false
	}
	// Same-origin is enforced by the session cookie/token, so accept any origin.
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return true // handshake already responded
	}
	defer c.CloseNow()

	// Tie the socket lifetime to the tab and a generous read budget.
	ctx, cancel := context.WithCancel(bs.tabCtx)
	defer cancel()

	// Writer: frames go out as binary, notifications as text. The viewer tells
	// them apart by message type, so a dialog can never be mistaken for a frame.
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case frame := <-bs.frames:
				if !write(ctx, c, websocket.MessageBinary, frame) {
					cancel()
					return
				}
			case note := <-bs.notes:
				if !write(ctx, c, websocket.MessageText, note) {
					cancel()
					return
				}
			}
		}
	}()

	// Reader: input events (JSON). Blocks until the client disconnects.
	for {
		typ, data, err := c.Read(ctx)
		if err != nil {
			return true
		}
		if typ != websocket.MessageText {
			continue
		}
		g.dispatchInput(sid, bs, data)
	}
}

// write sends one message, bounded so a stalled viewer cannot pin the writer.
func write(ctx context.Context, c *websocket.Conn, typ websocket.MessageType, b []byte) bool {
	wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return c.Write(wctx, typ, b) == nil
}

type inputMsg struct {
	T    string  `json:"t"`    // "m" mouse | "k" key | "r" resize | "d" dialog answer | "p" paste
	E    string  `json:"e"`    // event: move|down|up|wheel ; down|up
	X    float64 `json:"x"`    // mouse coords (CSS px)
	Y    float64 `json:"y"`    //
	B    int     `json:"b"`    // button: 0 left, 1 middle, 2 right
	DX   float64 `json:"dx"`   // wheel delta
	DY   float64 `json:"dy"`   //
	Mod  int64   `json:"mod"`  // modifier bitfield (Alt1 Ctrl2 Meta4 Shift8)
	Key  string  `json:"key"`  // key event
	Code string  `json:"code"` //
	KC   int64   `json:"kc"`   // keyCode
	Text string  `json:"text"` //
	W    int64   `json:"w"`    // resize
	H    int64   `json:"h"`    //
	OK   bool    `json:"ok"`   // dialog: accepted?
}

func (g *Gateway) dispatchInput(sid uuid.UUID, bs *bSession, data []byte) {
	var m inputMsg
	if json.Unmarshal(data, &m) != nil {
		return
	}
	// Every one of these is the operator doing something, which is the only
	// evidence this mode produces: an isolated session is a single long-lived
	// socket, so no HTTP request ever says "still here". A resize is excluded —
	// browsers fire it on their own (window snapping, a device rotating), and a
	// session that keeps itself alive without a human is exactly what the idle
	// timeout is for.
	if g.activity != nil && (m.T == "m" || m.T == "k" || m.T == "d" || m.T == "p") {
		g.activity.Touch(sid)
	}

	switch m.T {
	case "m":
		g.dispatchMouse(bs, m)
	case "k":
		g.dispatchKey(bs, m)
	case "r":
		g.resize(bs, m.W, m.H)
	case "d":
		// The operator's answer to a device dialog. Non-blocking: an answer with
		// no dialog waiting for it is a stray click, not a reason to stall the
		// reader that carries every other input.
		select {
		case bs.replies <- dlgReply{accept: m.OK, text: m.Text}:
		default:
		}
	case "p":
		g.paste(bs, m.Text)
	}
}

// paste inserts the operator's clipboard text into the focused element of the
// server-side page.
//
// It exists because isolation streams pixels: the operator's own Ctrl+V pastes
// into their browser, which is not where the device's form is. Nothing would
// happen, and a PAM that cannot paste a 40-character generated password pushes
// people back to typing secrets by hand.
//
// Input.insertText rather than synthesized keystrokes: it puts the whole string
// in at once, so it handles characters that have no key code, and does not
// depend on the device's keydown handlers.
func (g *Gateway) paste(bs *bSession, text string) {
	if text == "" {
		return
	}
	if len(text) > maxPasteBytes {
		text = text[:maxPasteBytes]
	}
	_ = chromedp.Run(bs.tabCtx, input.InsertText(text))
}

// maxPasteBytes bounds one paste. A clipboard can hold a whole file, and there
// is no reason for a device form to receive megabytes through this path.
const maxPasteBytes = 64 << 10

func (g *Gateway) dispatchMouse(bs *bSession, m inputMsg) {
	p := &input.DispatchMouseEventParams{X: m.X, Y: m.Y, Modifiers: input.Modifier(m.Mod)}
	switch m.B {
	case 1:
		p.Button = input.Middle
	case 2:
		p.Button = input.Right
	default:
		p.Button = input.Left
	}
	switch m.E {
	case "move":
		p.Type = input.MouseMoved
		p.Button = input.None
	case "down":
		p.Type = input.MousePressed
		p.ClickCount = 1
	case "up":
		p.Type = input.MouseReleased
		p.ClickCount = 1
	case "wheel":
		p.Type = input.MouseWheel
		p.Button = input.None
		p.DeltaX = m.DX
		p.DeltaY = m.DY
	default:
		return
	}
	_ = chromedp.Run(bs.tabCtx, p)
}

func (g *Gateway) dispatchKey(bs *bSession, m inputMsg) {
	p := &input.DispatchKeyEventParams{
		Modifiers: input.Modifier(m.Mod), Key: m.Key, Code: m.Code, WindowsVirtualKeyCode: m.KC,
	}
	if m.E == "up" {
		p.Type = input.KeyUp
	} else if len(m.Text) > 0 {
		// Printable key: keyDown with text inserts the character.
		p.Type = input.KeyDown
		p.Text = m.Text
		p.UnmodifiedText = m.Text
	} else {
		// Non-printable (Enter, Backspace, arrows, …).
		p.Type = input.KeyRawDown
	}
	_ = chromedp.Run(bs.tabCtx, p)
}

func (g *Gateway) resize(bs *bSession, w, h int64) {
	if w < 320 || h < 240 || w > 4096 || h > 4096 {
		return
	}
	_ = chromedp.Run(bs.tabCtx, emulationResize(w, h))
	bs.w, bs.h = w, h
}

// IsWSPath reports whether the proxied path targets the streaming socket.
func IsWSPath(path string) bool {
	return strings.TrimPrefix(path, "/") == wsSentinel
}

const wsSentinel = "__ws__"
