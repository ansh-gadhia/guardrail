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
