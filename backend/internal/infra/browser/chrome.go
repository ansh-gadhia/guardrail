package browser

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
)

// ErrNoChrome means no usable Chromium/Chrome binary could be found.
var ErrNoChrome = errors.New("browser: no chromium binary")

// chromeCandidates are the names a system-installed browser goes by, in the
// order they are tried. chromedp's own default is "google-chrome" alone, which
// is the least likely of these to exist on a Linux server.
var chromeCandidates = []string{
	"chromium",
	"chromium-browser",
	"google-chrome",
	"google-chrome-stable",
	"chrome",
}

// ResolveChromePath returns the browser binary to launch, or an error explaining
// why isolation cannot run here.
//
// It exists because "no browser" used to be discovered at the worst possible
// moment. The gateway was registered on a config flag alone, the server logged
// "browser isolation available", the console advertised session recording, and an
// operator marked a device recorded on that promise. Only when someone pressed
// Connect did chromedp try to exec its built-in default, "google-chrome", fail to
// find it on $PATH, and return an error that surfaced as HTTP 500 "unexpected
// error" — naming neither Chromium nor the setting that fixes it.
//
// Resolving up front turns that into one honest line at startup, and lets
// IsolationAvailable tell the truth.
func ResolveChromePath(configured string) (string, error) {
	if configured != "" {
		// An explicit path that does not work is a configuration error, never a
		// reason to go looking for some other browser: the operator named this one
		// deliberately, and quietly running a different binary than the one pinned
		// in config is exactly the kind of surprise a PAM must not spring.
		if err := executable(configured); err != nil {
			return "", fmt.Errorf("%w: GUARDRAIL_CHROME_PATH=%q is not usable: %w", ErrNoChrome, configured, err)
		}
		return configured, nil
	}
	for _, name := range chromeCandidates {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	// Nothing on $PATH. Before giving up, look where the browsers that install
	// themselves into a per-user cache put things: Playwright and Puppeteer both
	// do this, and a host provisioned for testing often has one of those and no
	// system Chromium at all.
	//
	// This is what keeps the configuration portable. Pinning an absolute path in
	// .env works exactly once — on the machine it was written for — and moving that
	// file to another server points GUARDRAIL_CHROME_PATH at nothing.
	if p := findCachedChrome(); p != "" {
		return p, nil
	}
	return "", fmt.Errorf("%w: none of %v are on $PATH and no cached browser was found; "+
		"install Chromium (apt install chromium) or set GUARDRAIL_CHROME_PATH to its binary",
		ErrNoChrome, chromeCandidates)
}

// findCachedChrome looks for a browser in the per-user caches Playwright and
// Puppeteer install into, newest version first. Returns "" when there is none.
func findCachedChrome() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	var found []string
	for _, pat := range []string{
		filepath.Join(home, ".cache", "ms-playwright", "chromium-*", "chrome-linux*", "chrome"),
		filepath.Join(home, ".cache", "puppeteer", "chrome", "*", "chrome-linux*", "chrome"),
		filepath.Join(home, ".cache", "ms-playwright", "chromium_headless_shell-*", "chrome-linux*", "headless_shell"),
	} {
		m, err := filepath.Glob(pat)
		if err != nil {
			continue
		}
		found = append(found, m...)
	}
	// Descending, so a host with several installed versions gets the newest. The
	// version sits in the directory name, so this is a string sort over
	// "chromium-1228" style names — good enough to prefer the later build, and it
	// is a fallback either way.
	sort.Sort(sort.Reverse(sort.StringSlice(found)))
	for _, p := range found {
		if executable(p) == nil {
			return p
		}
	}
	return ""
}

// executable reports whether path is a file this process can run.
func executable(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	if fi.IsDir() {
		return fmt.Errorf("is a directory")
	}
	if fi.Mode()&0o111 == 0 {
		return fmt.Errorf("is not executable")
	}
	return nil
}
