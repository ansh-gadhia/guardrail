package guacgw

import (
	"strings"
	"testing"
)

func frame(ins ...Instruction) []byte {
	var b strings.Builder
	for _, in := range ins {
		b.WriteString(in.String())
	}
	return []byte(b.String())
}

// A watcher must keep answering guacd, or guacd drops them as "not responding"
// after about fifteen seconds — which is exactly how the first version failed.
func TestWatcherKeepsTheProtocolAlive(t *testing.T) {
	fwd, _, err := splitWatcherMessage(frame(
		Instruction{Opcode: "sync", Args: []string{"1234567"}},
		Instruction{Opcode: "ack", Args: []string{"1", "OK", "0"}},
		Instruction{Opcode: "nop"},
	))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"4.sync", "3.ack", "3.nop"} {
		if !strings.Contains(string(fwd), want) {
			t.Errorf("%s was not forwarded; guacd needs it to keep the watcher attached", want)
		}
	}
}

// And must never put their hands on the desktop.
func TestWatcherInputNeverReachesGuacd(t *testing.T) {
	fwd, _, err := splitWatcherMessage(frame(
		Instruction{Opcode: "mouse", Args: []string{"100", "200", "1"}},
		Instruction{Opcode: "key", Args: []string{"65", "1"}},
		Instruction{Opcode: "clipboard", Args: []string{"2", "text/plain"}},
		// size on a shared connection resizes the OPERATOR's desktop to the
		// watcher's window.
		Instruction{Opcode: "size", Args: []string{"800", "600"}},
		Instruction{Opcode: "disconnect"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(fwd) != 0 {
		t.Fatalf("watcher input was forwarded to guacd: %q", fwd)
	}
}

// The tunnel's own keepalive is answered locally, never forwarded.
func TestWatcherTunnelPingIsAnswered(t *testing.T) {
	fwd, replies, err := splitWatcherMessage(frame(
		Instruction{Opcode: internalOpcode, Args: []string{"ping", "42"}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if len(fwd) != 0 {
		t.Errorf("a tunnel ping was forwarded to guacd: %q", fwd)
	}
	if !strings.Contains(string(replies), "4.ping") {
		t.Errorf("the tunnel ping was not answered; the client closes after 15s without it: %q", replies)
	}
}

// Mixed traffic: bookkeeping survives, input is stripped out of the same message.
func TestWatcherMixedMessageKeepsOnlyBookkeeping(t *testing.T) {
	fwd, _, err := splitWatcherMessage(frame(
		Instruction{Opcode: "sync", Args: []string{"9"}},
		Instruction{Opcode: "key", Args: []string{"65", "1"}},
		Instruction{Opcode: "sync", Args: []string{"10"}},
	))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(fwd), "3.key") {
		t.Fatalf("a key event survived inside a mixed message: %q", fwd)
	}
	if strings.Count(string(fwd), "4.sync") != 2 {
		t.Fatalf("both syncs should survive: %q", fwd)
	}
}
