// Whole-host tunnel delivery for the HTTP gateway.
//
// Path-prefix delivery (/proxy/<sid>/, see rewrite.go) re-serves a device UI that
// was written for an origin root underneath a prefix, which forces us to rewrite
// every root-absolute reference the page emits. That rewriting has a hard limit
// that no amount of care removes: window.location is a [LegacyUnforgeable]
// platform object, so it is non-configurable and cannot be shadowed. A shim can
// patch fetch, XMLHttpRequest and history, but it can NEVER intercept
// `location.href = "/ng/dashboard"` or a read of location.pathname. An appliance
// SPA that hard-navigates therefore escapes the prefix and lands on the GuardRail
// console — the blank-page class of bug.
//
// This file deletes the prefix rather than fighting it. Each session is given its
// own hostname, <sid>.<tunnel-domain>, so the device UI is served at the root of
// its own origin: /ng/dashboard IS the device's /ng/dashboard. There is no prefix
// to escape, so there is nothing to rewrite — no <base>, no shim, no HTML body
// rewriting anywhere in this file.
//
// What survives is only what genuinely follows from swapping the hostname: the
// device is told the request came from itself (request side), and its cookies,
// redirects and HSTS are re-pointed at the tunnel host (response side).
package proxy

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// tunnelDirector rewrites the outbound request to the device and injects the
// credential server-side, exactly as director does — except that the path and
// query pass through VERBATIM. That is the whole point of this mode: the browser
// asked for the device's own URL, so there is no prefix to strip.
func (g *HTTPGateway) tunnelDirector(target *url.URL, headers map[string]string, cred access.Credential, tunnelHost string) func(*http.Request) {
	return func(req *http.Request) {
		req.URL.Scheme = target.Scheme
		req.URL.Host = target.Host
		req.Host = target.Host
		// A device registered at a sub-path (https://host/base) still has that base
		// joined on; the browser's path is relative to the device root, not the host.
		if target.Path != "" && target.Path != "/" {
			req.URL.Path = singleJoin(target.Path, req.URL.Path)
		}
		rebaseTunnelOrigin(req, target, tunnelHost)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		switch cred.Injection {
		case "basic":
			req.SetBasicAuth(cred.Username, cred.Secret)
		case "header":
			// Secret carries the full header value, e.g. "Bearer <token>".
			req.Header.Set("Authorization", cred.Secret)
		}
		// Strip forwarded identity that could confuse the device.
		req.Header.Del("X-Forwarded-For")
		// Accept-Encoding is deliberately NOT stripped here, unlike the path-mode
		// director. That header is dropped there so ModifyResponse can rewrite HTML
		// bodies without a gzip/br decode step. This mode never touches a body, so
		// the device's compression is passed straight through to the browser.
	}
}

// rebaseTunnelOrigin rewrites Referer/Origin from the tunnel host to the device's
// own origin, as the device UI would have sent them if it were served directly.
//
// The browser computes these against the address it is actually talking to, which
// is <sid>.<tunnel-domain>. Forwarding that verbatim tells the device the broker's
// hostname and the session id, and breaks any appliance that CSRF-checks
// Referer/Origin against itself — a login POST is exactly where such a check
// lives.
//
// A referrer naming anything other than this session's tunnel host is dropped
// rather than translated: it cannot be expressed in the device's terms, and
// guessing would mean inventing a provenance for the request.
func rebaseTunnelOrigin(req *http.Request, target *url.URL, tunnelHost string) {
	origin := target.Scheme + "://" + target.Host
	if req.Header.Get("Origin") != "" {
		req.Header.Set("Origin", origin)
	}
	ref := req.Header.Get("Referer")
	if ref == "" {
		return
	}
	u, err := url.Parse(ref)
	if err != nil || !strings.EqualFold(u.Host, tunnelHost) {
		req.Header.Del("Referer")
		return
	}
	u.Scheme, u.Host = target.Scheme, target.Host
	req.Header.Set("Referer", u.String())
}

// modifyTunnelResponse is the only response rewriting this mode performs, and it
// is confined to headers. Compare rewrite.go, which has to parse and rewrite HTML.
//
// Three things, each a direct consequence of the host swap:
//
//   - Set-Cookie Domain= is stripped so device cookies bind to the tunnel host.
//     A device that sets Domain=appliance.corp would otherwise emit a cookie the
//     browser rejects outright, silently logging the operator out.
//   - An absolute Location naming the device origin is re-pointed at the tunnel
//     host, so a redirect does not bounce the browser to the device's own IP
//     (where it has no credential and no route from the operator's network).
//   - Strict-Transport-Security is dropped so a device's HSTS policy cannot be
//     applied to the tunnel domain, where it would outlive the session and pin
//     every future subdomain.
func modifyTunnelResponse(target *url.URL, tunnelHost string) func(*http.Response) error {
	deviceOrigin := target.Scheme + "://" + target.Host
	tunnelOrigin := "https://" + tunnelHost
	return func(resp *http.Response) error {
		stripCookieDomain(resp.Header)
		if loc := resp.Header.Get("Location"); strings.HasPrefix(loc, deviceOrigin) {
			resp.Header.Set("Location", tunnelOrigin+strings.TrimPrefix(loc, deviceOrigin))
		}
		resp.Header.Del("Strict-Transport-Security")
		return nil
	}
}

// stripCookieDomain removes the Domain attribute from every Set-Cookie, making
// each cookie host-only on the tunnel host. Every other attribute (Path, Secure,
// HttpOnly, SameSite, Max-Age) is preserved verbatim — the device's own session
// semantics are none of our business.
func stripCookieDomain(h http.Header) {
	cs := h["Set-Cookie"]
	for i, c := range cs {
		parts := strings.Split(c, ";")
		kept := parts[:0]
		for _, p := range parts {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(p)), "domain=") {
				continue
			}
			kept = append(kept, p)
		}
		cs[i] = strings.Join(kept, ";")
	}
}
