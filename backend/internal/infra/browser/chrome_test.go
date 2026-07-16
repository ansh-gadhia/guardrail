package browser

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// An explicit path that works is used verbatim.
func TestResolveChromePathUsesConfigured(t *testing.T) {
	bin := fakeChrome(t, "chrome", 0o755)

	got, err := ResolveChromePath(bin)
	if err != nil {
		t.Fatalf("ResolveChromePath(%q): %v", bin, err)
	}
	if got != bin {
		t.Errorf("got %q, want the configured path %q", got, bin)
	}
}

// A configured path that cannot run is a configuration error, not a cue to go
// find some other browser. Silently launching a different binary than the one
// pinned in config is the kind of surprise a PAM must not spring — and it would
// hide the operator's typo behind a browser that happened to work.
func TestResolveChromePathDoesNotFallBackFromBadConfigured(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"missing":        filepath.Join(dir, "nope"),
		"not executable": fakeChrome(t, "noexec", 0o644),
		"a directory":    dir,
	}
	for name, p := range cases {
		got, err := ResolveChromePath(p)
		if err == nil {
			t.Errorf("%s: ResolveChromePath(%q) = %q with no error; a bad configured path must be refused", name, p, got)
			continue
		}
		if !errors.Is(err, ErrNoChrome) {
			t.Errorf("%s: error = %v, want it to wrap ErrNoChrome", name, err)
		}
		// The message has to name the setting, or the operator is left guessing
		// which of Chromium or config is wrong.
		if !contains(err.Error(), "GUARDRAIL_CHROME_PATH") {
			t.Errorf("%s: error %q does not name the setting that fixes it", name, err)
		}
	}
}

// isolate points $PATH and $HOME at empty temp dirs, so a test decides what
// exists rather than inheriting it from the machine. Without the $HOME half these
// tests pass or fail on whether the developer happens to have a Playwright cache:
// the "no browser installed" case found the real one and reported success for a
// host where resolution would have failed.
func isolate(t *testing.T) {
	t.Helper()
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
}

// With nothing configured, a browser on $PATH is found.
func TestResolveChromePathAutodetectsFromPath(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	writeExec(t, filepath.Join(dir, "chromium"))
	t.Setenv("PATH", dir)

	got, err := ResolveChromePath("")
	if err != nil {
		t.Fatalf("ResolveChromePath(\"\"): %v", err)
	}
	if got != filepath.Join(dir, "chromium") {
		t.Errorf("got %q, want the chromium on PATH", got)
	}
}

// "chromium" is the name a Linux server actually installs. chromedp's built-in
// default is "google-chrome" alone, which is why a host with Chromium installed
// still failed to launch anything.
func TestResolveChromePathFindsChromiumNotOnlyGoogleChrome(t *testing.T) {
	isolate(t)
	dir := t.TempDir()
	writeExec(t, filepath.Join(dir, "chromium-browser"))
	t.Setenv("PATH", dir)

	if _, err := ResolveChromePath(""); err != nil {
		t.Errorf("chromium-browser on PATH was not found: %v", err)
	}
}

// No browser anywhere must be an error, not an empty string that chromedp would
// turn into an exec of "google-chrome" at Connect time — a 500 for the operator,
// long after the console promised recording worked.
func TestResolveChromePathFailsWhenNoBrowserExists(t *testing.T) {
	isolate(t)

	got, err := ResolveChromePath("")
	if err == nil {
		t.Fatalf("ResolveChromePath(\"\") = %q with no browser installed; want an error", got)
	}
	if !errors.Is(err, ErrNoChrome) {
		t.Errorf("error = %v, want it to wrap ErrNoChrome", err)
	}
	if !contains(err.Error(), "GUARDRAIL_CHROME_PATH") {
		t.Errorf("error %q does not say how to fix it", err)
	}
}

// The cache fallback is what keeps .env portable between servers: a host
// provisioned for testing often has a Playwright or Puppeteer browser and no
// system Chromium at all, and pinning an absolute path in .env works exactly once
// — on the machine it was written for.
func TestResolveChromePathFindsCachedBrowserWhenPathHasNone(t *testing.T) {
	isolate(t)
	home := os.Getenv("HOME")
	bin := filepath.Join(home, ".cache", "ms-playwright", "chromium-1200", "chrome-linux", "chrome")
	if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExec(t, bin)

	got, err := ResolveChromePath("")
	if err != nil {
		t.Fatalf("a cached browser must be found when $PATH has none: %v", err)
	}
	if got != bin {
		t.Errorf("got %q, want the cached browser %q", got, bin)
	}
}

// A host with several cached versions gets the newest, so an upgrade is picked up
// without anyone editing config.
func TestResolveChromePathPrefersNewestCachedBrowser(t *testing.T) {
	isolate(t)
	home := os.Getenv("HOME")
	var newest string
	for _, v := range []string{"chromium-1100", "chromium-1228", "chromium-1200"} {
		bin := filepath.Join(home, ".cache", "ms-playwright", v, "chrome-linux", "chrome")
		if err := os.MkdirAll(filepath.Dir(bin), 0o755); err != nil {
			t.Fatal(err)
		}
		writeExec(t, bin)
		if v == "chromium-1228" {
			newest = bin
		}
	}
	got, err := ResolveChromePath("")
	if err != nil {
		t.Fatalf("ResolveChromePath: %v", err)
	}
	if got != newest {
		t.Errorf("got %q, want the newest cached build %q", got, newest)
	}
}

// $PATH wins over the cache: a browser the administrator installed system-wide is
// the deliberate one, and a stale test cache must not shadow it.
func TestResolveChromePathPrefersPathOverCache(t *testing.T) {
	isolate(t)
	home := os.Getenv("HOME")
	cached := filepath.Join(home, ".cache", "puppeteer", "chrome", "linux-120", "chrome-linux64", "chrome")
	if err := os.MkdirAll(filepath.Dir(cached), 0o755); err != nil {
		t.Fatal(err)
	}
	writeExec(t, cached)

	dir := t.TempDir()
	onPath := filepath.Join(dir, "chromium")
	writeExec(t, onPath)
	t.Setenv("PATH", dir)

	got, err := ResolveChromePath("")
	if err != nil {
		t.Fatalf("ResolveChromePath: %v", err)
	}
	if got != onPath {
		t.Errorf("got %q, want the browser on $PATH %q", got, onPath)
	}
}

func fakeChrome(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeExec(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
