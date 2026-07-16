package guacgw

import (
	"context"
	"net"
	"os"
	"testing"
	"time"
)

// These run against a REAL guacd, because the fake in client_test.go can only
// prove that the client is self-consistent. It cannot prove that guacd accepts
// this handshake — and the handshake is where a protocol misunderstanding hides:
// a wrong opcode order or a miscounted length shows up as a daemon that quietly
// waits forever, which no unit test would catch.
//
// Skipped unless GUACD_ADDR names one, so `go test ./...` stays hermetic:
//
//	docker run -d --name guacd -p 127.0.0.1:4822:4822 guacamole/guacd:1.5.5
//	GUACD_ADDR=127.0.0.1:4822 go test ./internal/infra/guacgw/ -run Live

func liveGuacd(t *testing.T) string {
	t.Helper()
	addr := os.Getenv("GUACD_ADDR")
	if addr == "" {
		t.Skip("set GUACD_ADDR to run against a real guacd")
	}
	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Skipf("no guacd at %s: %v", addr, err)
	}
	_ = c.Close()
	return addr
}

// The real daemon must accept our handshake and open a connection.
//
// This is the test that earns its keep. The fake happily accepted a `connect`
// that was one value short, because it was written to the same misreading as the
// client: that the leading VERSION_x_y_z in guacd's `args` is a header rather
// than a parameter slot. Real guacd answered `ready` and then dropped the
// connection with "Client did not return the expected number of arguments" —
// a session that opens and dies a moment later, which is the worst shape a bug
// can take.
func TestLiveHandshakeIsAcceptedByRealGuacd(t *testing.T) {
	addr := liveGuacd(t)

	for _, proto := range []string{"vnc", "rdp"} {
		t.Run(proto, func(t *testing.T) {
			conn, err := dialGuacd(context.Background(), addr, connConfig{
				Protocol: proto,
				Width:    1024, Height: 768, DPI: 96,
				Params: map[string]string{
					// 203.0.113.0/24 is TEST-NET-3: reserved for documentation, so
					// nothing answers and no real host is touched.
					"hostname": "203.0.113.1",
					"port":     "5900",
					"username": "operator",
					"password": "unused",
					"security": "any", "ignore-cert": "true",
				},
			}, 25*time.Second)
			if err != nil {
				t.Fatalf("real guacd rejected the handshake: %v", err)
			}
			defer conn.Close()
			if conn.ID == "" {
				t.Error("guacd reported no connection id; its logs cannot be joined to this session")
			}
			// If the arg count were wrong, guacd would drop the connection right
			// after `ready`. Reading one instruction proves it is still talking to us.
			_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			if _, err := conn.r.ReadInstruction(); err != nil {
				t.Fatalf("guacd hung up right after ready — the handshake was not really accepted: %v", err)
			}
		})
	}
}

// `ready` does not mean "connected to the device": guacd sends it once it has
// accepted the request, and reports an unreachable host asynchronously in the
// stream. The viewer depends on that error arriving, so it is pinned here.
func TestLiveDeviceFailureArrivesInTheStreamNotTheHandshake(t *testing.T) {
	addr := liveGuacd(t)

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "vnc", Width: 1024, Height: 768, DPI: 96,
		Params: map[string]string{"hostname": "203.0.113.1", "port": "5900", "password": "unused"},
	}, 25*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	// guacd sends nop keepalives while it tries, then the failure.
	_ = conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	for i := 0; i < 32; i++ {
		in, err := conn.r.ReadInstruction()
		if err != nil {
			t.Fatalf("stream ended without an error instruction: %v", err)
		}
		if in.Opcode == "error" {
			t.Logf("guacd reported the failure in-stream: %v", in.Args)
			return
		}
	}
	t.Fatal("no error instruction arrived; the viewer would show a blank desktop forever")
}

// A protocol guacd does not implement gets no reply at all — it does not refuse,
// it simply never sends `args`. Only the handshake timeout ends it, which is
// exactly why there is one: without it a typo in a protocol name would hang the
// operator's Connect request indefinitely.
func TestLiveUnknownProtocolHitsTheTimeout(t *testing.T) {
	addr := liveGuacd(t)

	start := time.Now()
	_, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "telnet-ish", Params: map[string]string{"hostname": "203.0.113.1"},
	}, 2*time.Second)
	if err == nil {
		t.Fatal("guacd accepted a protocol it does not implement")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("took %v to give up; the handshake timeout is not bounding this", elapsed)
	}
	t.Logf("gave up after %v: %v", time.Since(start).Round(time.Millisecond), err)
}
