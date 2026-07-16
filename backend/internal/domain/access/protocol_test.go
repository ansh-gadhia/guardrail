package access

import (
	"errors"
	"testing"
)

// ParseProtocol is the guard that replaced a derivation reading "anything that
// isn't http is https". Under that rule an ssh device resolved to ProtocolHTTPS
// and was handed to the reverse-proxy gateway, which injects the vaulted
// credential as an Authorization header — writing the device password to port 22
// in the clear. Every unknown value must therefore be refused, never defaulted.
func TestParseProtocolRejectsUnknown(t *testing.T) {
	// The empty string matters on its own: a device row predating the column, or
	// a zero-valued struct, must not resolve to a working protocol.
	// "telnet" is deliberately absent: it is brokered now. The list is unknown
	// protocols, and a value moving off it is what adding one looks like.
	for _, in := range []string{"", "ftp", "HTTPS", "ssh ", "TELNET", "gopher", "https://", "sftp"} {
		got, err := ParseProtocol(in)
		if err == nil {
			t.Errorf("ParseProtocol(%q) = %q, want an error — unknown protocols must fail closed", in, got)
			continue
		}
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("ParseProtocol(%q) error = %v, want it to wrap ErrInvalid so callers can map it to 400", in, err)
		}
	}
}

func TestParseProtocolAcceptsKnown(t *testing.T) {
	for _, want := range Protocols() {
		got, err := ParseProtocol(string(want))
		if err != nil {
			t.Errorf("ParseProtocol(%q) unexpected error: %v", want, err)
			continue
		}
		if got != want {
			t.Errorf("ParseProtocol(%q) = %q, want %q", want, got, want)
		}
	}
}

// Every protocol the console can offer needs a port to prefill, or the form
// would present a protocol it cannot complete.
func TestEveryProtocolHasADefaultPort(t *testing.T) {
	for _, p := range Protocols() {
		port, ok := DefaultPort(p)
		if !ok {
			t.Errorf("DefaultPort(%q): not known, but Protocols() lists it", p)
			continue
		}
		if port < 1 || port > 65535 {
			t.Errorf("DefaultPort(%q) = %d, outside the valid port range", p, port)
		}
	}
	if _, ok := DefaultPort(Protocol("ftp")); ok {
		t.Error("DefaultPort(ftp) reported known; nothing brokers FTP")
	}
}

// Protocols() and the internal table must not drift: a protocol in the map but
// missing from the list would be storable yet never offered, and the reverse
// would prefill no port.
func TestProtocolsMatchesTable(t *testing.T) {
	if len(Protocols()) != len(protocols) {
		t.Fatalf("Protocols() has %d entries, table has %d", len(Protocols()), len(protocols))
	}
	for _, p := range Protocols() {
		if _, ok := protocols[p]; !ok {
			t.Errorf("Protocols() lists %q, which is absent from the table", p)
		}
	}
}

func TestIsWeb(t *testing.T) {
	for p, want := range map[Protocol]bool{
		ProtocolHTTPS: true, ProtocolHTTP: true,
		ProtocolSSH: false, ProtocolRDP: false, ProtocolVNC: false,
	} {
		if got := p.IsWeb(); got != want {
			t.Errorf("%q.IsWeb() = %v, want %v", p, got, want)
		}
	}
}
