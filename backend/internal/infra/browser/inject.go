package browser

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// injectionHeaders builds the extra request headers used for non-form credential
// injection. The credential is applied server-side to every request the headless
// browser makes to the device, so it is never exposed to the user.
func injectionHeaders(cred access.Credential) network.Headers {
	switch cred.Injection {
	case "basic":
		if cred.Username == "" && cred.Secret == "" {
			return nil
		}
		v := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Secret))
		return network.Headers{"Authorization": "Basic " + v}
	case "header":
		if cred.Secret == "" {
			return nil
		}
		return network.Headers{"Authorization": cred.Secret}
	default:
		return nil
	}
}

// fillLoginForm is a best-effort filler for form-login devices: it polls briefly
// for a password field, fills the username/password, and submits. Credentials are
// entered into the real page in the headless browser, never sent to the client.
func (g *Gateway) fillLoginForm(ctx context.Context, cred access.Credential) {
	js := fmt.Sprintf(loginFillJS, jsStr(cred.Username), jsStr(cred.Secret))
	// A few attempts spaced out to let an SPA login screen render.
	for i := 0; i < 8; i++ {
		var done bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(js, &done)); err == nil && done {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(750 * time.Millisecond):
		}
	}
}

// loginFillJS fills the first password field and its associated username field,
// then submits. %s/%s are the JSON-quoted username and secret.
const loginFillJS = `(function(){
  var pw=document.querySelector('input[type=password]');
  if(!pw) return false;
  var user=%s, secret=%s;
  var form=pw.form;
  var uf=null;
  if(form){ uf=form.querySelector('input[type=text],input[type=email],input[name*=user i],input[name*=name i],input:not([type])'); }
  if(!uf){ uf=document.querySelector('input[type=text],input[type=email]'); }
  function set(el,val){ if(!el) return; el.focus();
    var d=Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value');
    d&&d.set?d.set.call(el,val):(el.value=val);
    el.dispatchEvent(new Event('input',{bubbles:true}));
    el.dispatchEvent(new Event('change',{bubbles:true})); }
  set(uf,user); set(pw,secret);
  if(form){ var btn=form.querySelector('button[type=submit],input[type=submit],button'); if(btn){btn.click();} else {form.submit();} }
  return true;
})()`

// jsStr renders s as a JSON/JS string literal.
func jsStr(s string) string {
	var b []byte
	b = append(b, '"')
	for _, r := range s {
		switch r {
		case '"', '\\':
			b = append(b, '\\', byte(r))
		case '\n':
			b = append(b, '\\', 'n')
		case '<':
			b = append(b, '\\', 'x', '3', 'c')
		default:
			b = append(b, string(r)...)
		}
	}
	b = append(b, '"')
	return string(b)
}

func emulationResize(w, h int64) chromedp.Action {
	return emulation.SetDeviceMetricsOverride(w, h, 1, false)
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func subtleConstantEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
