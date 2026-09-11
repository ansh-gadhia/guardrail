package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/guardrail/guardrail/internal/domain/notify"
)

func TestWebhookSender_PostsJSONEnvelope(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	router := NewRouter(srv.Client(), nil)
	ch := notify.Channel{Name: "ops", Type: notify.ChannelWebhook, Config: map[string]any{"url": srv.URL}}
	err := router.Send(context.Background(), ch, "approval.requested", map[string]any{"device_id": "d1"})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if got["event"] != "approval.requested" {
		t.Fatalf("event = %v, want approval.requested", got["event"])
	}
	payload, _ := got["payload"].(map[string]any)
	if payload["device_id"] != "d1" {
		t.Fatalf("payload not delivered: %v", got["payload"])
	}
}

func TestWebhookSender_ErrorsOnBadStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	router := NewRouter(srv.Client(), nil)
	ch := notify.Channel{Type: notify.ChannelWebhook, Config: map[string]any{"url": srv.URL}}
	if err := router.Send(context.Background(), ch, "e", nil); err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestRouter_UnknownTypeErrors(t *testing.T) {
	router := NewRouter(nil, nil)
	ch := notify.Channel{Type: notify.ChannelEmail} // email sender not configured
	if err := router.Send(context.Background(), ch, "e", nil); err == nil {
		t.Fatal("expected error for unconfigured channel type")
	}
}

func TestChannel_Wants(t *testing.T) {
	all := notify.Channel{Enabled: true, Events: []string{"*"}}
	specific := notify.Channel{Enabled: true, Events: []string{"approval.requested"}}
	disabled := notify.Channel{Enabled: false, Events: []string{"*"}}

	if !all.Wants("anything") {
		t.Error("wildcard channel should want any event")
	}
	if !specific.Wants("approval.requested") || specific.Wants("session.start") {
		t.Error("specific channel subscription mismatch")
	}
	if disabled.Wants("x") {
		t.Error("disabled channel should want nothing")
	}
}

// A notification leaves the trust boundary — to Slack, an operator-supplied
// webhook, or an SMTP relay. The payload used to be marshalled whole, so what
// could leave was whatever the newest caller put in a map. The allowlist makes
// that a decision instead of an accident.
func TestFilterPayloadDropsUnknownFields(t *testing.T) {
	in := map[string]any{
		"request_id": "r-1",
		"requester":  "op@corp",
		"device":     "core-sw-1",
		// Not on the list: exactly the shape of a field somebody adds later
		// without thinking about where notifications go.
		"credential": "hunter2",
		"secret":     "hunter2",
	}
	out, dropped := filterPayload(in)

	for _, k := range []string{"credential", "secret"} {
		if _, present := out[k]; present {
			t.Errorf("%q was forwarded off-platform", k)
		}
	}
	for _, k := range []string{"request_id", "requester", "device"} {
		if _, present := out[k]; !present {
			t.Errorf("%q was dropped but is on the allowlist", k)
		}
	}
	if len(dropped) != 2 || dropped[0] != "credential" || dropped[1] != "secret" {
		t.Errorf("dropped = %v, want [credential secret]", dropped)
	}
}

// Today's notifications must be byte-identical: the allowlist was built from
// the payload keys actually in use, so nothing an operator currently receives
// changes.
func TestFilterPayloadPassesEveryKeyInUse(t *testing.T) {
	// Every key across both notifier.Notify call sites.
	inUse := map[string]any{
		"request_id": "r", "requester": "e", "device": "d", "device_id": "i",
		"reason": "why", "minutes": 30, "level": 2, "status": "approved",
	}
	out, dropped := filterPayload(inUse)
	if len(dropped) != 0 {
		t.Fatalf("a key in current use was dropped: %v", dropped)
	}
	if len(out) != len(inUse) {
		t.Fatalf("payload changed size: got %d, want %d", len(out), len(inUse))
	}
}

func TestFilterPayloadHandlesEmpty(t *testing.T) {
	if out, dropped := filterPayload(nil); out != nil || dropped != nil {
		t.Errorf("nil payload should pass through untouched, got %v / %v", out, dropped)
	}
}
