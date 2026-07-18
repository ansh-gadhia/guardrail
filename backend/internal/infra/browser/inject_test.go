package browser

import (
	"strings"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/access"
)

func TestInjectionHeaders(t *testing.T) {
	basic := injectionHeaders(access.Credential{Username: "admin", Secret: "pw", Injection: "basic"})
	if got := basic["Authorization"]; got != "Basic YWRtaW46cHc=" {
		t.Errorf("basic header = %q", got)
	}
	hdr := injectionHeaders(access.Credential{Secret: "Bearer xyz", Injection: "header"})
	if got := hdr["Authorization"]; got != "Bearer xyz" {
		t.Errorf("header = %q", got)
	}
	if injectionHeaders(access.Credential{Injection: "form", Secret: "x"}) != nil {
		t.Error("form injection must not set headers (filled in-page)")
	}
	if injectionHeaders(access.Credential{Injection: "none"}) != nil {
		t.Error("none injection must set no headers")
	}
}

func TestJSStrEscapes(t *testing.T) {
	got := jsStr(`a"b\c</script>`)
	// A "</script>" in the value must be neutralized so it can't break out of an
	// inline script context; the '<' is escaped to \x3c.
	if strings.Contains(got, "</script>") {
		t.Errorf("jsStr did not neutralize </script>: %s", got)
	}
	for _, want := range []string{`\"`, `\\`, `\x3c/script>`} {
		if !strings.Contains(got, want) {
			t.Errorf("jsStr missing escaped form %q: %s", want, got)
		}
	}
	if !strings.HasPrefix(got, `"`) || !strings.HasSuffix(got, `"`) {
		t.Errorf("jsStr not quoted: %s", got)
	}
}

func TestConsolePageEmbedsSession(t *testing.T) {
	p := consolePage("sess-123", 1120, 700)
	if !strings.Contains(p, "__ws__") || !strings.Contains(p, "createImageBitmap") {
		t.Error("console page missing ws/render wiring")
	}
	// The canvas backing store and the input-coordinate mapping both key off these
	// dimensions; if the placeholder ever stops being substituted the page would
	// paint and map clicks at the wrong scale.
	if !strings.Contains(p, "DEV_W=1120") || !strings.Contains(p, "DEV_H=700") {
		t.Error("console page did not template render dimensions")
	}
	if strings.Contains(p, "__DEV_W__") || strings.Contains(p, "__DEV_H__") {
		t.Error("console page left a dimension placeholder unsubstituted")
	}
}

func TestIsWSPath(t *testing.T) {
	if !IsWSPath("/__ws__") || !IsWSPath("__ws__") {
		t.Error("expected ws path match")
	}
	if IsWSPath("/index.html") {
		t.Error("unexpected ws path match")
	}
}
