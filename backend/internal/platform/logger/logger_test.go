package logger

import "testing"

func TestNew_ValidConfigs(t *testing.T) {
	for _, tc := range []struct{ level, format string }{
		{"info", "json"},
		{"debug", "console"},
		{"error", "json"},
	} {
		log, err := New(tc.level, tc.format)
		if err != nil {
			t.Fatalf("New(%q,%q) error: %v", tc.level, tc.format, err)
		}
		if log == nil {
			t.Fatalf("New(%q,%q) returned nil logger", tc.level, tc.format)
		}
		_ = log.Sync()
	}
}

func TestNew_InvalidLevel(t *testing.T) {
	if _, err := New("not-a-level", "json"); err == nil {
		t.Fatal("expected error for invalid log level")
	}
}
