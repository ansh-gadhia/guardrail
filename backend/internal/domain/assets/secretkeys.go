package assets

import (
	"fmt"
	"net/url"
	"strings"
)

// Free-form JSON columns are where secrets end up when nobody is looking.
//
// Three of them exist — devices.custom_headers, credentials.metadata and
// notification_channels.config — and all three are stored in the clear. The
// vault goes to considerable lengths to keep a device password encrypted,
// bound to its own row and never returned by a read API; none of that applies
// to an operator who pastes the same password into a header map beside it
// because that was the field in front of them.
//
// The answer here is refusal at the edge rather than encryption. Encrypting
// these columns would protect the bad habit instead of correcting it, and would
// mean a device's HTTP headers could no longer be read without the master key.
// GuardRail already HAS somewhere for a secret header: a credential with
// injection "header", which is sealed, bound, audited on use, and never shown
// back. So the useful thing to do is refuse the value and say where it goes.

// secretHeaderNames are header names whose value is a credential by definition.
var secretHeaderNames = map[string]bool{
	"authorization":       true,
	"proxy-authorization": true,
	"cookie":              true,
	"x-api-key":           true,
	"x-auth-token":        true,
	"x-access-token":      true,
	"x-session-token":     true,
	"api-key":             true,
	"apikey":              true,
	"auth-token":          true,
	"x-csrf-token":        true,
	"x-vault-token":       true,
}

// secretKeyHints match a key name that is carrying secret material. Substring
// rather than exact, because the shapes vary — "db_password", "apiSecret",
// "private_key_pem" — and the cost of a false positive is one rejected field
// with a message saying where to put it instead.
var secretKeyHints = []string{
	"password", "passwd", "secret", "token", "apikey", "api_key",
	"privatekey", "private_key", "credential", "passphrase",
}

// SecretHeaderError reports a header that must live in the vault instead.
func SecretHeaderError(name string) error {
	return fmt.Errorf("%w: the %q header carries a credential, so it cannot be stored "+
		"on the device in the clear. Bind a credential with injection \"header\" instead — "+
		"it is encrypted, and its use is audited", ErrInvalid, name)
}

// ValidateCustomHeaders refuses headers whose value is a credential.
//
// Only the NAME is inspected. The value is a secret precisely when it is one,
// and a validator that pattern-matched values would be reading the thing it is
// trying to keep out of its hands.
func ValidateCustomHeaders(headers map[string]string) error {
	for name := range headers {
		n := strings.ToLower(strings.TrimSpace(name))
		if secretHeaderNames[n] {
			return SecretHeaderError(name)
		}
		if looksSecret(n) {
			return SecretHeaderError(name)
		}
	}
	return nil
}

// ValidateFreeformKeys refuses a map whose key names announce secret material.
//
// Used for credentials.metadata and notification_channels.config: both are
// documented as non-secret and neither enforced it, so "non-secret" was a
// comment rather than a property.
func ValidateFreeformKeys(what string, m map[string]any) error {
	for k := range m {
		if looksSecret(strings.ToLower(strings.TrimSpace(k))) {
			return fmt.Errorf("%w: %s is stored in the clear, so it cannot hold %q. "+
				"A secret belongs in the credential vault", ErrInvalid, what, k)
		}
	}
	return nil
}

// ValidateChannelConfig refuses a notification target that carries a credential.
//
// A webhook URL is the awkward case: Slack and Teams incoming-webhook URLs ARE
// bearer credentials — the path IS the secret — and refusing those outright
// would remove the feature. So this catches only what is unambiguously wrong:
// embedded userinfo ("https://user:pass@host"), and a token-shaped query
// parameter, both of which have somewhere better to be and neither of which the
// product needs.
func ValidateChannelConfig(cfg map[string]any) error {
	if err := ValidateFreeformKeys("a notification channel's config", cfg); err != nil {
		return err
	}
	raw, _ := cfg["url"].(string)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil // not this validator's job to reject an unparseable url
	}
	if u.User != nil {
		return fmt.Errorf("%w: the webhook URL embeds a username and password, which would be "+
			"stored in the clear. Use a URL without credentials in it", ErrInvalid)
	}
	for key := range u.Query() {
		if looksSecret(strings.ToLower(key)) {
			return fmt.Errorf("%w: the webhook URL carries %q in its query string, which would be "+
				"stored in the clear and written to every proxy log between here and the target",
				ErrInvalid, key)
		}
	}
	return nil
}

// looksSecret reports whether a lowercased key name announces secret material.
func looksSecret(k string) bool {
	for _, hint := range secretKeyHints {
		if strings.Contains(k, hint) {
			return true
		}
	}
	return false
}
