package guacgw

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Protocol version negotiation. guacd advertises the version it speaks as the
// first parameter slot, and the client answers with the version it wants to use —
// which must not exceed guacd's.
const versionPrefix = "VERSION_"

// clientVersion is the newest protocol version this gateway speaks. It is pinned
// to guacamole-common-js in the console, because that is what actually decodes
// the stream: claiming a version the client cannot read would let guacd send
// instructions the browser silently ignores.
const clientVersion = "VERSION_1_5_0"

// knownVersions are the protocol versions this gateway understands, oldest first.
var knownVersions = []string{"VERSION_1_0_0", "VERSION_1_1_0", "VERSION_1_3_0", "VERSION_1_5_0"}

// negotiateVersion answers guacd's offer with the highest version both sides
// speak. An offer newer than anything known gets ours, which guacd accepts by
// speaking down to it; an older guacd gets its own version back.
func negotiateVersion(offered string) string {
	oi := slices.Index(knownVersions, offered)
	ci := slices.Index(knownVersions, clientVersion)
	if oi < 0 || oi > ci {
		return clientVersion
	}
	return offered
}

// The client half of the guacd handshake:
//
//	-> select,<protocol>
//	<- args,<version>,<name>,<name>,...
//	-> size,<w>,<h>,<dpi>
//	-> audio / video / image        (codecs we accept; empty = none)
//	-> connect,<value>,<value>,...
//	<- ready,<connection id>
//
// The one thing that matters here: the values in `connect` are positional, and
// their order is whatever guacd just listed in `args`. That list is not stable —
// it differs between rdp (82 parameters) and vnc (45), and it changes between
// guacd releases. So the values are assembled by looking each name up in a map
// rather than by counting: a hardcoded position silently sends the password into
// whatever field moved into that slot, which is the worst possible way to be
// wrong. Unknown names get "", which guacd reads as "use the default".

// connConfig is one device connection's parameters.
type connConfig struct {
	// Protocol is the guacd protocol name: "rdp" or "vnc".
	Protocol string
	// Params are guacd connection parameters by name (hostname, port, username,
	// password, …). Only names guacd asked for are sent.
	Params map[string]string
	Width  int
	Height int
	DPI    int
}

// guacConn is a live, handshaken connection to guacd.
type guacConn struct {
	net.Conn
	r *reader
	// ID is guacd's connection id, echoed in its `ready` reply. Logged as the
	// join between a GuardRail session and guacd's own logs.
	ID string
}

// dialGuacd opens a connection to guacd and completes the handshake, leaving the
// connection ready to relay.
func dialGuacd(ctx context.Context, addr string, cfg connConfig, timeout time.Duration) (*guacConn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("guac: dial guacd at %s: %w", addr, err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = c.Close()
		}
	}()
	// The whole handshake is bounded. Without this a guacd that accepts the TCP
	// connection and then says nothing — which is what a wedged daemon looks like
	// — would hang the operator's Connect request until it timed out somewhere
	// far less informative.
	if err := c.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	r := newReader(c)
	if err := write(c, Instruction{Opcode: "select", Args: []string{cfg.Protocol}}); err != nil {
		return nil, err
	}

	args, err := r.ReadInstruction()
	if err != nil {
		return nil, fmt.Errorf("guac: reading the parameter list: %w", err)
	}
	if args.Opcode != "args" {
		// guacd reports a refused protocol as an `error` instruction rather than
		// by closing, so say what it said instead of a generic failure.
		return nil, fmt.Errorf("guac: expected the parameter list, got %q %v", args.Opcode, args.Args)
	}

	if err := write(c, Instruction{Opcode: "size", Args: []string{
		strconv.Itoa(cfg.Width), strconv.Itoa(cfg.Height), strconv.Itoa(cfg.DPI),
	}}); err != nil {
		return nil, err
	}
	// No audio, video or image codecs are declared. Audio would stream a device's
	// sound to the operator, and neither the recording nor the watermark covers
	// it; the display is negotiated as PNG/JPEG by guacd's own defaults, which is
	// what the browser client decodes.
	for _, op := range []string{"audio", "video", "image"} {
		if err := write(c, Instruction{Opcode: op}); err != nil {
			return nil, err
		}
	}

	// Every element of `args` is a slot `connect` must fill — including the
	// version, which guacd lists as a parameter named VERSION_x_y_z rather than as
	// a header. Sending one value short is not a near miss: guacd answers `ready`
	// anyway and then drops the connection with "Client did not return the expected
	// number of arguments", so the session appears to open and dies a moment later.
	//
	// Matched by name, never by position, for the same reason the values are.
	values := make([]string, 0, len(args.Args))
	for _, name := range args.Args {
		if strings.HasPrefix(name, versionPrefix) {
			values = append(values, negotiateVersion(name))
			continue
		}
		values = append(values, cfg.Params[name])
	}
	if err := write(c, Instruction{Opcode: "connect", Args: values}); err != nil {
		return nil, err
	}

	ready, err := r.ReadInstruction()
	if err != nil {
		return nil, fmt.Errorf("guac: waiting for the connection to open: %w", err)
	}
	if ready.Opcode != "ready" {
		// This is where a wrong password, an unreachable host or a rejected
		// certificate lands, as `error,<message>,<status code>`. The message is the
		// operator's only clue, so it is passed through — guacd's errors describe
		// the connection, never the credential.
		if ready.Opcode == "error" {
			return nil, fmt.Errorf("guac: %s refused the connection: %s", cfg.Protocol, ready.Arg(0))
		}
		return nil, fmt.Errorf("guac: expected ready, got %q %v", ready.Opcode, ready.Args)
	}

	// Relaying has no deadline: a desktop session is idle for long stretches, and
	// the idle policy is the broker's job, not the socket's.
	if err := c.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	ok = true
	return &guacConn{Conn: c, r: r, ID: ready.Arg(0)}, nil
}

func write(c net.Conn, in Instruction) error {
	if _, err := c.Write([]byte(in.String())); err != nil {
		return fmt.Errorf("guac: writing %s: %w", in.Opcode, err)
	}
	return nil
}
