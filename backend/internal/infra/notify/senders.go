// Package notify implements notification senders (webhook, Slack, email) and the
// dispatcher that drains the outbox. Senders are selected per channel type.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"sort"
	"time"

	"github.com/guardrail/guardrail/internal/domain/notify"

	"go.uber.org/zap"
)

// Router dispatches to a concrete sender based on channel type. It implements
// notify.Sender.
type Router struct {
	senders map[notify.ChannelType]notify.Sender
	// log is optional. Set it with WithLogger; nil is a working Router that
	// simply says nothing when it withholds a field.
	log *zap.Logger
}

// WithLogger attaches a logger and returns the Router, so wiring stays a
// one-liner. Additive on purpose: NewRouter's signature is used from main and
// from tests, and a field nobody has to pass is cheaper than changing both.
func (r *Router) WithLogger(l *zap.Logger) *Router {
	r.log = l
	return r
}

// NewRouter builds a Router with the default senders (webhook, Slack, and, when
// configured, email).
func NewRouter(httpClient *http.Client, email *EmailSender) *Router {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	m := map[notify.ChannelType]notify.Sender{
		notify.ChannelWebhook: &WebhookSender{client: httpClient},
		notify.ChannelSlack:   &SlackSender{client: httpClient},
	}
	if email != nil {
		m[notify.ChannelEmail] = email
	}
	return &Router{senders: m}
}

// payloadAllowlist is every field a notification may carry off this platform.
//
// A notification leaves the trust boundary: to a Slack workspace, an arbitrary
// webhook URL an operator typed in, or an SMTP relay that STARTTLS-upgrades only
// if it feels like it. Until now the payload map was marshalled whole and
// shipped, which meant the set of things that could leave was whatever the
// newest caller happened to put in a map — decided at the call site, reviewed by
// nobody, and impossible to audit from here.
//
// This list is the current payload keys exactly, so nothing about today's
// notifications changes. What changes is the direction of the default: adding a
// field to a Notify call no longer sends it anywhere until it is named here,
// which is the point at which somebody has to decide it is safe to publish.
var payloadAllowlist = map[string]struct{}{
	"request_id": {}, "requester": {}, "device": {}, "device_id": {},
	"reason": {}, "minutes": {}, "level": {}, "status": {},
}

// filterPayload drops anything not on the allowlist.
//
// Dropped rather than masked: a key nobody has vetted should not advertise its
// own existence to a Slack channel. The count is reported so a maintainer who
// adds a field and cannot find it has something to search for.
func filterPayload(payload map[string]any) (map[string]any, []string) {
	if len(payload) == 0 {
		return payload, nil
	}
	out := make(map[string]any, len(payload))
	var dropped []string
	for k, v := range payload {
		if _, ok := payloadAllowlist[k]; ok {
			out[k] = v
			continue
		}
		dropped = append(dropped, k)
	}
	sort.Strings(dropped)
	return out, dropped
}

// Send routes to the sender for the channel's type.
func (r *Router) Send(ctx context.Context, ch notify.Channel, event string, payload map[string]any) error {
	s, ok := r.senders[ch.Type]
	if !ok {
		return fmt.Errorf("notify: no sender for channel type %q", ch.Type)
	}
	// Filtered here, once, rather than in each sender: every sender marshals the
	// payload whole, so this is the single place all three share.
	filtered, dropped := filterPayload(payload)
	if len(dropped) > 0 && r.log != nil {
		r.log.Warn("notification fields withheld: not on the payload allowlist",
			zap.String("event", event), zap.Strings("fields", dropped))
	}
	return s.Send(ctx, ch, event, filtered)
}

// WebhookSender POSTs a JSON envelope to a configured URL.
type WebhookSender struct{ client *http.Client }

// Send delivers the event as JSON to the channel's webhook URL.
func (s *WebhookSender) Send(ctx context.Context, ch notify.Channel, event string, payload map[string]any) error {
	url, _ := ch.Config["url"].(string)
	if url == "" {
		return fmt.Errorf("notify: webhook channel missing url")
	}
	body, _ := json.Marshal(map[string]any{"event": event, "payload": payload, "channel": ch.Name})
	return post(ctx, s.client, url, body)
}

// SlackSender POSTs a Slack-formatted message to an incoming-webhook URL.
type SlackSender struct{ client *http.Client }

// Send delivers a human-readable message to Slack.
func (s *SlackSender) Send(ctx context.Context, ch notify.Channel, event string, payload map[string]any) error {
	url, _ := ch.Config["url"].(string)
	if url == "" {
		return fmt.Errorf("notify: slack channel missing url")
	}
	text := fmt.Sprintf(":lock: *GuardRail* — `%s`\n```%s```", event, jsonPretty(payload))
	body, _ := json.Marshal(map[string]any{"text": text})
	return post(ctx, s.client, url, body)
}

// EmailSender delivers via SMTP. It is constructed only when SMTP is configured.
type EmailSender struct {
	Host string
	Port int
	From string
	Auth smtp.Auth
}

// Send emails the event to the channel's address.
func (s *EmailSender) Send(_ context.Context, ch notify.Channel, event string, payload map[string]any) error {
	to, _ := ch.Config["address"].(string)
	if to == "" {
		return fmt.Errorf("notify: email channel missing address")
	}
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: [GuardRail] %s\r\n\r\n%s\r\n",
		s.From, to, event, jsonPretty(payload))
	addr := net.JoinHostPort(s.Host, fmt.Sprintf("%d", s.Port))
	return smtp.SendMail(addr, s.Auth, s.From, []string{to}, []byte(msg))
}

func post(ctx context.Context, client *http.Client, url string, body []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("notify: delivery returned status %d", resp.StatusCode)
	}
	return nil
}

func jsonPretty(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}
