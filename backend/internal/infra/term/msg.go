package term

import "encoding/json"

// MaxInputBytes bounds a single client message. Terminal input is keystrokes and
// the occasional paste; anything larger is not a person typing.
const MaxInputBytes = 1 << 20

// ClientMsg is one message from the console.
//
// It lives here, next to the JavaScript that sends it, so the two halves of the
// wire format cannot drift apart unnoticed.
type ClientMsg struct {
	// T is the type: "i" input, "r" resize.
	T string `json:"t"`
	// D is input data (for "i").
	D string `json:"d,omitempty"`
	// Cols/Rows are the new geometry (for "r").
	Cols int `json:"cols,omitempty"`
	Rows int `json:"rows,omitempty"`
}

// Message types.
const (
	MsgInput  = "i"
	MsgResize = "r"
)

// ParseClientMsg decodes one console frame. A malformed frame yields ok=false
// and is meant to be ignored: a viewer sending junk should not kill a live
// device session.
func ParseClientMsg(b []byte) (ClientMsg, bool) {
	var m ClientMsg
	if err := json.Unmarshal(b, &m); err != nil {
		return ClientMsg{}, false
	}
	return m, true
}
