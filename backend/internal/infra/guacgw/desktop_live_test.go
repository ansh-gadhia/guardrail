package guacgw

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The end-to-end proof: this client, real guacd, and a real VNC desktop. Every
// other test stops short of the thing the product actually does — put a desktop
// in front of an operator without handing them the password.
//
// Skipped unless a target is configured:
//
//	docker network create guactest
//	docker run -d --name vnc-target --network guactest -e VNC_PASSWORD=testpass123 theasp/novnc
//	docker run -d --name guacd --network guactest -p 127.0.0.1:4822:4822 guacamole/guacd:1.5.5
//	GUACD_ADDR=127.0.0.1:4822 VNC_TARGET=vnc-target:5900 VNC_PASSWORD=testpass123 \
//	  go test ./internal/infra/guacgw/ -run LiveDesktop -v

// recordingDir is the path guacd writes recordings to, as guacd sees it. Set
// GUACD_REC_DIR to guacd's own path and GUACD_REC_DIR_HOST to where the same
// directory is visible from these tests.
func recordingDirs(t *testing.T) (guacdPath, hostPath string) {
	t.Helper()
	guacdPath, hostPath = os.Getenv("GUACD_REC_DIR"), os.Getenv("GUACD_REC_DIR_HOST")
	if guacdPath == "" || hostPath == "" {
		t.Skip("set GUACD_REC_DIR and GUACD_REC_DIR_HOST to test recording")
	}
	return guacdPath, hostPath
}

func liveDesktop(t *testing.T) (addr, host, port, password string) {
	t.Helper()
	addr = os.Getenv("GUACD_ADDR")
	target := os.Getenv("VNC_TARGET")
	if addr == "" || target == "" {
		t.Skip("set GUACD_ADDR and VNC_TARGET to run against a real desktop")
	}
	h, p, ok := strings.Cut(target, ":")
	if !ok {
		t.Fatalf("VNC_TARGET %q must be host:port", target)
	}
	return addr, h, p, os.Getenv("VNC_PASSWORD")
}

// The signal that actually distinguishes an authenticated desktop from a refused
// one — and it is NOT drawing.
//
// guacd renders its own connection-status screen before it has spoken to the
// device, so an authentication failure and a successful login begin with an
// identical run of instructions. Against a real Windows box the first ten were
// byte-for-byte the same:
//
//	wrong:   mouse size img blob end cursor set size img blob end  error(...|769) disconnect
//	correct: mouse size img blob end cursor set size img blob end  sync sync sync ...
//
// Both painted. Only one logged in. A test that treats `img` as proof of a
// desktop therefore passes against a device that refused the credential — which
// is exactly what this test did until the guacd logs were read.
//
// So: `error` means refused, and sustained `sync` (guacd completing frames from
// the device) means connected. Nothing else is evidence.
type outcome struct {
	failure *Instruction // the `error` guacd reported, if it refused
	syncs   int          // frames completed, i.e. a live desktop
}

func awaitOutcome(t *testing.T, conn *guacConn, wantSyncs int, limit time.Duration) outcome {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(limit))
	var o outcome
	for i := 0; i < 500; i++ {
		in, err := conn.r.ReadInstruction()
		if err != nil {
			return o // the stream ended; report what was seen
		}
		switch in.Opcode {
		case "error":
			cp := in
			o.failure = &cp
			return o
		case "sync":
			o.syncs++
			if o.syncs >= wantSyncs {
				return o
			}
		}
	}
	return o
}

// A real desktop must actually stream frames: handshake accepted, credential
// accepted by the device, pixels flowing back.
func TestLiveDesktopConnectsAndStreamsFrames(t *testing.T) {
	addr, host, port, password := liveDesktop(t)

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "vnc",
		Width:    1024, Height: 768, DPI: 96,
		Params: map[string]string{"hostname": host, "port": port, "password": password},
	}, 25*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	o := awaitOutcome(t, conn, 3, 30*time.Second)
	if o.failure != nil {
		t.Fatalf("guacd could not open the desktop: %v", o.failure.Args)
	}
	if o.syncs < 3 {
		t.Errorf("only %d frames completed; the operator would see guacd's status screen, not the desktop", o.syncs)
	}
}

// The credential must actually be used. Without this, every other desktop test
// here would pass against a device with no authentication at all — which is what
// happened the first time this ran: the VNC target ignored its password, the
// wrong-password case connected happily, and nothing proved the vault was in the
// loop.
func TestLiveDesktopRefusesAWrongCredential(t *testing.T) {
	addr, host, port, password := liveDesktop(t)
	if password == "" {
		t.Skip("VNC_PASSWORD is empty; the target has no authentication to fail")
	}

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "vnc",
		Width:    1024, Height: 768, DPI: 96,
		// PREPENDED, not appended. The VNC authentication scheme keys DES with at
		// most 8 bytes, so the password is truncated to 8 characters: appending to a
		// password of 8+ characters produces the SAME secret, and this test passed
		// against a deliberately wrong password until that showed up here.
		Params: map[string]string{"hostname": host, "port": port, "password": "wrong-" + password},
	}, 25*time.Second)
	if err != nil {
		return // refused during the handshake is a refusal too
	}
	defer conn.Close()

	o := awaitOutcome(t, conn, 1, 25*time.Second)
	if o.failure != nil {
		return // what we expect: the device rejected the credential
	}
	if o.syncs > 0 {
		t.Fatal("a desktop streamed frames with the wrong password; the credential is not being honoured")
	}
	// No error and no desktop: guacd hung up without saying why, so nothing here
	// proves the credential was checked. Not a pass.
	t.Fatal("neither a refusal nor a desktop; the target's authentication state is unknown")
}

// The security property, stated as a test: the operator's stream must never carry
// the device password. It went into the connect handshake, server-side, and what
// comes back is pixels.
//
// This is worth pinning because it is exactly the kind of guarantee that erodes
// quietly — a future parameter echoed back in an instruction, or a debug opcode
// that reflects the connect args, would not fail any other test here.
func TestLiveDesktopStreamNeverCarriesTheCredential(t *testing.T) {
	addr, host, port, password := liveDesktop(t)
	if password == "" {
		t.Skip("VNC_PASSWORD is empty; there is no secret to look for")
	}

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "vnc",
		Width:    1024, Height: 768, DPI: 96,
		Params: map[string]string{"hostname": host, "port": port, "password": password},
	}, 25*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	for i := 0; i < 300; i++ {
		in, err := conn.r.ReadInstruction()
		if err != nil {
			break // the stream ended; everything read so far was clean
		}
		for _, a := range in.Args {
			if strings.Contains(a, password) {
				t.Fatalf("the device password appeared in a %q instruction sent to the browser", in.Opcode)
			}
		}
	}
}

// Recording is guacd's own feature, and the gateway depends on two things it does
// not control: that guacd writes the file where it was told, and that the file is
// a Guacamole protocol dump the console's player can read. Both are pinned here,
// because a recording that is silently never written is the failure this product
// exists to prevent.
func TestLiveDesktopWritesARecordingGuacdCanBeReadBack(t *testing.T) {
	addr, host, port, password := liveDesktop(t)
	guacdDir, hostDir := recordingDirs(t)

	name := "live-test-session.guac"
	_ = os.Remove(filepath.Join(hostDir, name))

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "vnc",
		Width:    1024, Height: 768, DPI: 96,
		Params: map[string]string{
			"hostname": host, "port": port, "password": password,
			"recording-path": guacdDir, "recording-name": name,
			"create-recording-path": "true",
			// Keystrokes are deliberately excluded: a desktop recording that logged
			// keys would capture every password typed into a login box, turning the
			// evidence store into a credential store.
			"recording-include-keys": "false",
		},
	}, 25*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}

	// Let the desktop paint, so there is something to record.
	_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	for i := 0; i < 60; i++ {
		in, err := conn.r.ReadInstruction()
		if err != nil {
			break
		}
		if in.Opcode == "error" {
			t.Fatalf("guacd could not open the desktop: %v", in.Args)
		}
	}
	_ = write(conn.Conn, Instruction{Opcode: "disconnect"})
	_ = conn.Close()

	// The same wait the gateway uses on teardown: guacd finishes writing
	// asynchronously, so the file can still be growing.
	path := filepath.Join(hostDir, name)
	size, err := waitForStableFile(context.Background(), path, 300*time.Millisecond, 15*time.Second)
	if err != nil {
		t.Fatalf("waiting for the recording: %v", err)
	}
	if size == 0 {
		t.Fatal("guacd wrote no recording; a recorded session would have no evidence")
	}

	// It must be a protocol dump the player can parse, not opaque bytes.
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("opening the recording: %v", err)
	}
	defer f.Close()
	first, err := newReader(f).ReadInstruction()
	if err != nil {
		t.Fatalf("the recording is not a readable instruction stream: %v", err)
	}
	t.Logf("recording is %d bytes, opening with a %q instruction", size, first.Opcode)
}

// A real Windows desktop over RDP. VNC and RDP share this client but not much
// else: RDP negotiates security, presents a certificate, and authenticates
// before it paints, so a VNC-only proof would leave the protocol most operators
// actually use untested.
//
//	RDP_TARGET=10.200.11.111:3389 RDP_USER=... RDP_PASSWORD=... \
//	  GUACD_ADDR=127.0.0.1:4822 go test ./internal/infra/guacgw/ -run LiveRDP -v
func liveRDP(t *testing.T) (addr, host, port, user, password string) {
	t.Helper()
	addr = os.Getenv("GUACD_ADDR")
	target := os.Getenv("RDP_TARGET")
	if addr == "" || target == "" {
		t.Skip("set GUACD_ADDR and RDP_TARGET to run against a real Windows desktop")
	}
	h, p, ok := strings.Cut(target, ":")
	if !ok {
		t.Fatalf("RDP_TARGET %q must be host:port", target)
	}
	return addr, h, p, os.Getenv("RDP_USER"), os.Getenv("RDP_PASSWORD")
}

// The same proof as the VNC case: the credential is accepted and frames arrive.
// `security=any` and `ignore-cert` mirror what the gateway sends for a device
// with VerifyTLS off, so this exercises the real parameter set rather than a
// hand-tuned one.
func TestLiveRDPConnectsAndStreamsFrames(t *testing.T) {
	addr, host, port, user, password := liveRDP(t)

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "rdp",
		Width:    1024, Height: 768, DPI: 96,
		Params: map[string]string{
			"hostname": host, "port": port,
			"username": user, "password": password,
			"security": "any", "ignore-cert": "true",
			"resize-method": "display-update",
		},
	}, 30*time.Second)
	if err != nil {
		t.Fatalf("handshake: %v", err)
	}
	defer conn.Close()

	o := awaitOutcome(t, conn, 3, 40*time.Second)
	if o.failure != nil {
		t.Fatalf("Windows refused the connection: %v", o.failure.Args)
	}
	if o.syncs < 3 {
		t.Errorf("only %d frames completed; the operator would see guacd's status screen, not the desktop", o.syncs)
	}
}

// RDP must honour the password too. Unlike VNC there is no 8-character
// truncation here — RDP passwords are sent whole — so appending is a genuinely
// different secret.
func TestLiveRDPRefusesAWrongCredential(t *testing.T) {
	addr, host, port, user, password := liveRDP(t)
	if password == "" {
		t.Skip("RDP_PASSWORD is empty; there is no credential to get wrong")
	}

	conn, err := dialGuacd(context.Background(), addr, connConfig{
		Protocol: "rdp",
		Width:    1024, Height: 768, DPI: 96,
		Params: map[string]string{
			"hostname": host, "port": port,
			"username": user, "password": password + "-wrong",
			"security": "any", "ignore-cert": "true",
		},
	}, 30*time.Second)
	if err != nil {
		return // refused during the handshake is a refusal too
	}
	defer conn.Close()

	o := awaitOutcome(t, conn, 1, 30*time.Second)
	if o.failure != nil {
		// Windows reports this as guac status 769 (CLIENT_UNAUTHORIZED), which is
		// the gateway's cue that the CREDENTIAL was wrong rather than the host being
		// unreachable. Pinned because the two are told apart nowhere else.
		if code := o.failure.Arg(1); code != "769" {
			t.Errorf("refused with status %q, want 769 (unauthorized); a bad credential is being reported as something else", code)
		}
		return
	}
	if o.syncs > 0 {
		t.Fatal("a desktop streamed frames with the wrong password; the credential is not being honoured")
	}
	t.Fatal("neither a refusal nor a desktop; the target's authentication state is unknown")
}
