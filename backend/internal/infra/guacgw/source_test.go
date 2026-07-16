package guacgw

import "os"

// readSource reads a file from this package. Used by tests that pin a detail no
// runtime assertion in this package can reach — the WebSocket handshake needs a
// real browser to observe, and a browser is exactly what CI does not have.
func readSource(name string) (string, error) {
	b, err := os.ReadFile(name)
	return string(b), err
}
