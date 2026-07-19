// Rewriting for the HTTP gateway. A management UI served from its own web root
// (e.g. a FortiGate/Angular SPA) assumes it lives at the origin root "/". When we
// re-serve it under "/proxy/<sid>/", every root-absolute URL it emits — asset
// links, redirects, cookies, and especially the XHR/fetch calls the SPA makes to
// its own API — would otherwise escape the session prefix and hit GuardRail
// itself. This file rebases those references back under the session prefix:
//
//   - HTML responses get a <base href="/proxy/<sid>/"> (so relative assets load)
//     plus a small injected shim that patches fetch/XMLHttpRequest/WebSocket to
//     prefix root-absolute URLs at runtime (so the SPA's API calls stay bound).
//   - Location redirect headers are rebased.
//   - Set-Cookie Path attributes are rebased so the device's cookies scope to the
//     session, not to all of GuardRail.
//
// It deliberately does NOT rewrite arbitrary JavaScript bodies (too fragile); the
// runtime shim covers the dynamic calls that static rewriting would miss.
package proxy

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strings"
)

// modifyResponse returns an httputil.ReverseProxy ModifyResponse hook that
// rebases device responses under prefix (which has form "/proxy/<sid>/").
//
// It deliberately does NOT stamp a watermark. This path serves the device's own
// HTML to the operator's browser, so a watermark here is only a deterrent a
// determined user removes with devtools, is never captured (the proxy records no
// pixels), and — injected as a node into the live DOM — is a real page-breaker on
// strict-CSP appliances and body-owning SPAs. Accountability for a proxied
// session rests on the audit trail; the burned-into-pixels watermark that is an
// actual control lives in browser isolation, which is where recorded devices go.
func modifyResponse(prefix string) func(*http.Response) error {
	return func(resp *http.Response) error {
		rebaseLocation(resp, prefix)
		rebaseCookies(resp, prefix)

		// Only a response the browser will RENDER gets rewritten. Content-Type is
		// not enough to decide that: appliances answer XHR with text/html and mean
		// "data", not "page".
		if !rendersAsDocument(resp) {
			return nil
		}

		// A device that declares a non-HTML type is taken at its word: there is
		// nothing to rewrite in a stylesheet or a PNG, and reading their bodies
		// here would buffer every asset in memory for no reason.
		ct := resp.Header.Get("Content-Type")
		if ct != "" && !isHTML(ct) {
			return nil
		}

		// Either it says HTML, or it says nothing at all — and "nothing" has to be
		// looked at rather than skipped. Embedded servers (micro_httpd on consumer
		// routers, for one) routinely omit Content-Type entirely. Skipping those
		// silently disabled the <base> tag and the URL shim on exactly the devices
		// this platform exists to broker, and it hid itself:
		// net/http sniffs the body when it writes the response, so the browser
		// still received "text/html" and the page still rendered. The only symptom
		// was the injected markup quietly not being there.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()

		if ct == "" && !isHTML(http.DetectContentType(body)) {
			// Sniffed to something else; hand the bytes back untouched.
			restoreBody(resp, body)
			return nil
		}
		return rewriteHTML(resp, prefix, body)
	}
}

// rendersAsDocument reports whether the browser will render this response as a
// page, and so whether injecting <base> and the shim into it is meaningful
// rather than destructive.
//
// Content-Type alone cannot answer this. A FortiGate's login POST replies with
// ONE byte — "0" — under Content-Type: text/html. It is not a page; it is a
// status code, and the first character IS the protocol: login.js reads
// retval.charAt(0) to branch and eval()s the remainder. Injecting a <base> tag
// and the shim ahead of it made that first character "<", which matches no
// status, so a correct password silently read as rejected. One byte in, 2.6KB
// out.
//
// Sec-Fetch-Dest is the browser telling us what it is going to do with the
// response, which is exactly the question. "document"/"iframe"/"frame" are
// rendered; "empty" (fetch/XHR), "script", "style" and the rest are data the page
// consumes, and must arrive byte-for-byte as the device sent them.
//
// When the header is absent — a non-browser client, or one too old to send it —
// fall through to the Content-Type checks and behave as before. Nothing is
// rendering it, so the injection cannot break a page, and the old behaviour keeps
// existing callers (and tests) working.
func rendersAsDocument(resp *http.Response) bool {
	if resp.Request == nil {
		return true
	}
	switch resp.Request.Header.Get("Sec-Fetch-Dest") {
	case "document", "iframe", "frame", "embed", "object":
		return true
	case "":
		return true // not stated; let Content-Type decide, as before
	default:
		return false // empty/script/style/image/font/audio/…: data, never a page
	}
}

// restoreBody puts an already-read body back on the response unchanged.
func restoreBody(resp *http.Response, body []byte) {
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", itoa(len(body)))
}

func isHTML(ct string) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "text/html")
}

// rebaseLocation rewrites a root-absolute redirect target under prefix so a
// login redirect to "/ng" lands at "/proxy/<sid>/ng" rather than escaping.
func rebaseLocation(resp *http.Response, prefix string) {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return
	}
	if r := rebaseRootAbsolute(loc, prefix); r != loc {
		resp.Header.Set("Location", r)
	}
}

// rebaseCookies rewrites the Path attribute of every Set-Cookie so device
// cookies are scoped to the session prefix.
func rebaseCookies(resp *http.Response, prefix string) {
	cookies := resp.Header["Set-Cookie"]
	if len(cookies) == 0 {
		return
	}
	trimmed := strings.TrimSuffix(prefix, "/")
	out := make([]string, 0, len(cookies))
	for _, c := range cookies {
		out = append(out, cookiePathRe.ReplaceAllStringFunc(c, func(m string) string {
			// m is like "Path=/foo"; rebase the path portion.
			p := strings.TrimSpace(m[len("path="):])
			if strings.HasPrefix(p, prefix) {
				return m
			}
			return "Path=" + trimmed + p
		}))
	}
	resp.Header["Set-Cookie"] = out
}

var cookiePathRe = regexp.MustCompile(`(?i)path=/[^;,\s]*`)

// rebaseRootAbsolute prefixes a single root-absolute URL ("/x") with prefix,
// leaving protocol-relative ("//host"), absolute ("https://"), already-prefixed,
// and document-relative URLs untouched.
func rebaseRootAbsolute(u, prefix string) string {
	if u == "" || u[0] != '/' {
		return u // relative or scheme-qualified — <base>/shim handles it
	}
	if strings.HasPrefix(u, "//") {
		return u // protocol-relative → different origin
	}
	if strings.HasPrefix(u, prefix) {
		return u
	}
	return strings.TrimSuffix(prefix, "/") + u
}

// rewriteHTML injects a <base> tag and the runtime URL-rewriting shim into an
// HTML document, then fixes Content-Length. The upstream is asked (in the
// director) not to compress, so the body is plain text here.
//
// No watermark is injected: on this path the device's real DOM is handed to the
// operator's browser, where an overlay is a removable, unrecorded deterrent that
// also breaks strict-CSP appliances and body-owning SPAs. The <base>+shim, by
// contrast, are load-bearing — without them the SPA's own URLs escape the session
// prefix — so those stay.
func rewriteHTML(resp *http.Response, prefix string, body []byte) error {
	html := string(body)
	// Drop any existing <base> so ours wins, rebase the device's own markup, then
	// inject <base>+shim. Rebasing runs first so it only ever sees the device's
	// URLs, never the prefix we are about to inject.
	html = baseTagRe.ReplaceAllString(html, "")
	html = rebaseMarkupURLs(html, prefix)
	html = containFrameBusting(html)
	inject := `<base href="` + prefix + `">` + shim(prefix)
	html = injectInto(html, inject)

	// Once rewritten, declare the type instead of leaving it to be sniffed. The
	// injected markup changes the leading bytes, and a device that sent no
	// Content-Type would otherwise have the answer decided by whatever our own
	// injection happens to look like.
	if resp.Header.Get("Content-Type") == "" {
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	}

	nb := []byte(html)
	resp.Body = io.NopCloser(bytes.NewReader(nb))
	resp.ContentLength = int64(len(nb))
	resp.Header.Set("Content-Length", itoa(len(nb)))
	// A rewritten body invalidates any upstream validators.
	resp.Header.Del("Content-MD5")
	resp.Header.Del("ETag")
	return nil
}

// injectInto places our markup as early in the document as it can.
//
// The <head> case is the easy one. The fallbacks matter because embedded device
// UIs are rarely well-formed: this platform's own test router serves
// "<html>\n<script>..." with no <head> at all. Injecting after <html> keeps the
// <base> ahead of the device's first script, which is what it has to be —
// relative URLs in that script are resolved against it.
func injectInto(html, inject string) string {
	// After the character encoding declaration, when there is one.
	//
	// A browser decides the encoding by pre-scanning only the FIRST 1024 BYTES of
	// the document. Injecting ahead of <meta charset> pushed it well past that —
	// the URL-rewriting shim is kilobytes — so the declaration was never seen and
	// the encoding fell back to a guess. The device compounds it by
	// sending "Content-Type: text/html" with no charset of its own, leaving nothing
	// authoritative anywhere.
	//
	// Injecting after it keeps it inside the window and changes nothing else: the
	// meta declares an encoding, it resolves no URLs, so <base> does not need to
	// precede it.
	if m := charsetMetaRe.FindStringIndex(html); m != nil {
		return html[:m[1]] + inject + html[m[1]:]
	}
	if m := headOpenRe.FindStringIndex(html); m != nil {
		return html[:m[1]] + inject + html[m[1]:]
	}
	if m := htmlOpenRe.FindStringIndex(html); m != nil {
		return html[:m[1]] + inject + html[m[1]:]
	}
	// No <html> either (a fragment, or a body-only response): prepending is the
	// only option left, and the browser will hoist the tags into the head it
	// fabricates.
	return inject + html
}

var (
	baseTagRe  = regexp.MustCompile(`(?i)<base\b[^>]*>`)
	headOpenRe = regexp.MustCompile(`(?i)<head\b[^>]*>`)
	htmlOpenRe = regexp.MustCompile(`(?i)<html\b[^>]*>`)
	// charsetMetaRe matches both spellings of the encoding declaration:
	// <meta charset="utf-8"> and <meta http-equiv="Content-Type" content="...">.
	charsetMetaRe = regexp.MustCompile(`(?i)<meta\b[^>]*charset[^>]*>`)
)

// rebaseMarkupURLs rewrites root-absolute URLs written into HTML attributes so
// they stay under the session prefix.
//
// <base> does NOT cover these. It resolves document-relative URLs ("logo.png"),
// but a root-absolute one ("/static/main.js") resolves against the ORIGIN and
// ignores <base> entirely — so a UI written for its own web root, which is every
// appliance this platform brokers, reaches past the session and asks GuardRail
// for its assets. GuardRail's SPA fallback answers 200 with its own index.html
// as text/html, and because that response also carries nosniff, the browser
// refuses to execute it: the device UI silently never boots. A FortiGate, whose
// index.html is three root-absolute <script> tags and a stylesheet, renders as a
// blank frame.
//
// The runtime shim cannot cover this. It patches fetch/XHR/WebSocket/location,
// but these URLs are resolved by the HTML parser as it reads the tag, before any
// script has run — server-side rewriting is the only point where they can still
// be caught.
//
// Deliberately narrow: only attributes that take a single URL. srcset (a URL
// list) does not match, because "src" there is not followed by "="; leaving it
// alone is worse-looking than parsing it wrong. Anything not starting with a
// single "/" — fragments, queries, "javascript:", "data:", protocol-relative,
// fully-qualified — falls through rebaseRootAbsolute untouched.
func rebaseMarkupURLs(html, prefix string) string {
	return rootAbsAttrRe.ReplaceAllStringFunc(html, func(m string) string {
		g := rootAbsAttrRe.FindStringSubmatch(m)
		if g == nil {
			return m
		}
		return g[1] + g[2] + rebaseRootAbsolute(g[3], prefix) + g[4]
	})
}

// containFrameBusting retargets top/parent window navigation at the frame itself.
//
// Appliance UIs frame-bust. A FortiGate's /logout is, in its entirety:
//
//	<script language="javascript">top.location="/login";</script>
//
// Served inside the console's session frame, "top" is the operator's console tab,
// so that one line steers the whole console to the device's login page and the
// session view — chrome, controls, the whole GuardRail shell — is simply gone. The device page is
// same-origin with the console (everything is re-served under /proxy/), so the
// browser permits it, and no client-side shim can stop it: window.top and
// Location are both unforgeable.
//
// So it is caught here, on the way out. This is containment before it is
// compatibility: a brokered device UI must never be able to navigate the
// operator's browser away from GuardRail. Retargeted to the frame, the navigation
// still does what the device meant — the root-absolute URL then escapes the
// prefix, and the router's Referer-based containment redirects it back into the
// session, which is how the login page arrives in the frame where it belongs.
//
// "window.top.location" becomes "window.window.location", which is the same
// window — harmless.
func containFrameBusting(html string) string {
	return frameBustRe.ReplaceAllString(html, "window.location")
}

// frameBustRe matches top.location / parent.location, however spaced.
var frameBustRe = regexp.MustCompile(`\b(?:top|parent)\s*\.\s*location\b`)

// rootAbsAttrRe matches attr="/path" / attr='/path' for URL-valued attributes.
// The quote is captured and reused so a value containing the other quote mark
// survives intact.
var rootAbsAttrRe = regexp.MustCompile(`(?i)(\s(?:src|href|action|formaction|poster)\s*=\s*)("|')(/[^"'>]*)("|')`)

// shim returns a <script> that patches the browser's URL-taking APIs to keep
// root-absolute requests inside the session prefix. <base> already handles
// document-relative asset URLs; this covers the dynamic calls a SPA makes.
func shim(prefix string) string {
	return `<script>(function(){var P=` + jsString(prefix) + `;` +
		`function rw(u){try{if(u==null)return u;u=String(u);` +
		`if(u.indexOf(P)===0)return u;` +
		`var o=location.origin;` +
		`if(u.indexOf(o+"/")===0){return P+u.slice(o.length+1);}` +
		`if(u.charAt(0)==="/"&&u.charAt(1)!=="/"){return P+u.slice(1);}` +
		`return u;}catch(e){return u;}}` +
		`var f=window.fetch;if(f){window.fetch=function(i,init){` +
		`try{if(typeof i==="string"){i=rw(i);}else if(i&&i.url){i=new Request(rw(i.url),i);}}catch(e){}` +
		`return f.call(this,i,init);};}` +
		`var xo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){` +
		`try{arguments[1]=rw(u);}catch(e){}return xo.apply(this,arguments);};` +
		`var W=window.WebSocket;if(W){var NW=function(u,p){return new W(rw(u),p);};` +
		`NW.prototype=W.prototype;NW.CONNECTING=W.CONNECTING;NW.OPEN=W.OPEN;NW.CLOSING=W.CLOSING;NW.CLOSED=W.CLOSED;` +
		`window.WebSocket=NW;}` +
		`document.addEventListener("submit",function(e){try{var fm=e.target;if(fm&&fm.tagName==="FORM"){` +
		`var a=fm.getAttribute("action");if(a){var r=rw(a);if(r!==a)fm.setAttribute("action",r);}}}catch(x){}},true);` +
		// Anchor clicks with root-absolute hrefs would escape the prefix; rewrite.
		`document.addEventListener("click",function(e){try{var n=e.target;while(n&&n.tagName!=="A")n=n.parentNode;` +
		`if(n&&n.getAttribute){var h=n.getAttribute("href");if(h){var r=rw(h);if(r!==h)n.setAttribute("href",r);}}}catch(x){}},true);` +
		// Wrap programmatic navigations where the API permits reassigning the method.
		`try{var la=location.assign.bind(location);location.assign=function(u){return la(rw(u));};}catch(x){}` +
		`try{var lr=location.replace.bind(location);location.replace=function(u){return lr(rw(u));};}catch(x){}` +
		// Keep History API navigations inside the session.
		//
		// pushState/replaceState change the URL with no network request, so an
		// escape here is completely silent: no failed fetch, no console error, just
		// an address that is no longer under /proxy/<sid>/. Every later relative URL
		// then resolves against the wrong base, and a router that keys off the
		// document's path stops matching its own routes and renders nothing.
		//
		// Frameworks that respect <base href> already prefix correctly, and rw()
		// leaves an already-prefixed URL alone, so this only catches the hand-rolled
		// root-absolute case.
		`try{var hp=history.pushState.bind(history);history.pushState=function(s,t,u){` +
		`return u==null?hp(s,t):hp(s,t,rw(u));};}catch(x){}` +
		`try{var hr=history.replaceState.bind(history);history.replaceState=function(s,t,u){` +
		`return u==null?hr(s,t):hr(s,t,rw(u));};}catch(x){}` +
		// Refuse service-worker registration.
		//
		// A worker cannot be brokered. It runs in its own context, where none of the
		// patching above exists, so every root-absolute URL it fetches escapes the
		// session prefix — and it outlives the session that installed it, sitting in
		// the operator's browser caching one device's responses. A FortiGate
		// registers "/service-worker.js" at root scope; unpatched that escapes to
		// GuardRail, and registration then dies on the containment redirect anyway,
		// because the spec forbids registering a script that was redirected.
		//
		// Rejecting is what a browser already does on http://, in private mode, and
		// where workers are disabled — so applications are built to tolerate it,
		// which is exactly why it is the safe answer here.
		`try{if(navigator.serviceWorker){navigator.serviceWorker.register=function(){` +
		`return Promise.reject(new Error("GuardRail: service workers are not available in a brokered session"));};}}catch(x){}` +
		`})();</script>`
}

// jsString renders s as a safe JS string literal (the prefix is server-built and
// path-only, but quote defensively).
func jsString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '<':
			b.WriteString(`\x3c`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
