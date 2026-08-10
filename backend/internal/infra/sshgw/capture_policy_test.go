package sshgw

import (
	"context"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// A device set to capture video only must not also accumulate a transcript.
//
// This is the failure mode worth a live test rather than a unit one: the
// transcript is written from deep inside the stream loop, so a policy check that
// is right in Establish and missing at the write site would still produce one.
// An operator who unticked "Transcript" and got a searchable log of everything
// their session printed has been overruled by the software.
func TestVideoOnlyPolicyWritesNoTranscript(t *testing.T) {
	h := newLiveHarnessKinds(t, true, []string{access.ArtifactVideo})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := h.dial(t, ctx)
	if _, _, err := c.Read(ctx); err != nil { // banner
		t.Fatalf("read banner: %v", err)
	}
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"t":"i","d":"secret-command\n"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	// Let the device echo before tearing down, so any transcript that was going
	// to be written has had its chance.
	time.Sleep(200 * time.Millisecond)
	c.CloseNow()
	if err := h.g.End(context.Background(), h.sess.ID); err != nil {
		t.Fatalf("End: %v", err)
	}

	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	if _, ok := h.rec.artifacts[ArtifactTranscript]; ok {
		t.Error("a transcript was stored despite a video-only capture policy")
	}
	if _, ok := h.rec.artifacts[access.ArtifactTranscriptIndex]; ok {
		t.Error("a transcript index was stored despite a video-only capture policy")
	}
}

// The converse, and the default: transcript-only must not try to open a mirror.
// With no mirror factory wired there is nothing to assert but the absence of a
// crash — which is the point, since a deployment without Chromium is the common
// case for terminal-only sites.
func TestTranscriptOnlyPolicyStillRecords(t *testing.T) {
	h := newLiveHarnessKinds(t, true, []string{access.ArtifactTranscript})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c := h.dial(t, ctx)
	if _, _, err := c.Read(ctx); err != nil {
		t.Fatalf("read banner: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	c.CloseNow()
	if err := h.g.End(context.Background(), h.sess.ID); err != nil {
		t.Fatalf("End: %v", err)
	}

	h.rec.mu.Lock()
	defer h.rec.mu.Unlock()
	if _, ok := h.rec.artifacts[ArtifactTranscript]; !ok {
		t.Error("no transcript stored under a transcript-only policy")
	}
}
