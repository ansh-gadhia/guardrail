package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// recorder captures a session's screencast frames and, on teardown, writes them
// as two artifacts: the concatenated JPEG bytes, and a manifest indexing each
// frame's offset and capture time.
//
// Why a manifest of JPEGs rather than a video file: the frames already arrive as
// JPEG from CDP, so this needs no encoder and no ffmpeg dependency, and the
// player can seek by drawing any single frame to a canvas. The cost is size,
// which retention already bounds.
//
// It is deliberately NOT wired to the live viewer's frame channel. That channel
// is lossy by design (it drops frames when the viewer is slow, and has no
// consumer at all when nobody is watching), so a recording taken from it would
// silently depend on whether someone happened to be looking.
type recorder struct {
	mu      sync.Mutex
	frames  []recFrame
	bytes   int
	started time.Time
	closed  bool

	maxBytes int
	dropped  int
}

type recFrame struct {
	at   time.Time
	data []byte
}

// manifest is the JSON index the player reads before fetching frame bytes.
type manifest struct {
	Version    int        `json:"version"`
	Width      int64      `json:"width"`
	Height     int64      `json:"height"`
	StartedAt  time.Time  `json:"started_at"`
	DurationMS int64      `json:"duration_ms"`
	Frames     []manFrame `json:"frames"`
	Truncated  bool       `json:"truncated,omitempty"`
}

// manFrame is one frame's position in the blob and its offset from the start of
// the recording. Field names are short because there is one per frame.
type manFrame struct {
	T int64 `json:"t"` // ms since the recording started
	O int64 `json:"o"` // byte offset into frames.bin
	L int64 `json:"l"` // byte length
}

func newRecorder(started time.Time, maxBytes int) *recorder {
	return &recorder{started: started, maxBytes: maxBytes}
}

// add appends a frame. Frames are held in memory until teardown; maxBytes caps
// that so one very long session cannot exhaust the host. Once the cap is hit the
// recording keeps its beginning and counts what it drops, which the manifest
// reports — a recording that silently stops is worse than one that says where it
// stopped.
func (r *recorder) add(at time.Time, data []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return
	}
	if r.maxBytes > 0 && r.bytes+len(data) > r.maxBytes {
		r.dropped++
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)
	r.frames = append(r.frames, recFrame{at: at, data: cp})
	r.bytes += len(cp)
}

// flush writes the recording's artifacts and returns the number of frames
// stored. It takes its own context: the caller's tab context is cancelled during
// teardown, and a recording that dies with the tab is no recording at all.
func (r *recorder) flush(
	ctx context.Context,
	blobs access.BlobStore,
	store access.RecordingStore,
	rec *access.Recording,
	orgID uuid.UUID,
	w, h int64,
) (int, error) {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return 0, nil
	}
	r.closed = true
	frames := r.frames
	r.frames = nil
	dropped := r.dropped
	r.mu.Unlock()

	if len(frames) == 0 {
		return 0, nil
	}

	man := manifest{
		Version: 1, Width: w, Height: h, StartedAt: r.started.UTC(),
		Frames: make([]manFrame, 0, len(frames)), Truncated: dropped > 0,
	}
	blob := make([]byte, 0, r.bytes)
	for _, f := range frames {
		off := int64(len(blob))
		blob = append(blob, f.data...)
		man.Frames = append(man.Frames, manFrame{
			T: f.at.Sub(r.started).Milliseconds(), O: off, L: int64(len(f.data)),
		})
	}
	man.DurationMS = man.Frames[len(man.Frames)-1].T

	prefix := fmt.Sprintf("%s/%s", orgID.String(), rec.ID.String())
	framesKey := prefix + "/frames.bin"
	manKey := prefix + "/manifest.json"

	if err := blobs.Put(ctx, framesKey, blob, "application/octet-stream"); err != nil {
		return 0, fmt.Errorf("recorder: store frames: %w", err)
	}
	manJSON, err := json.Marshal(man)
	if err != nil {
		return 0, fmt.Errorf("recorder: marshal manifest: %w", err)
	}
	if err := blobs.Put(ctx, manKey, manJSON, "application/json"); err != nil {
		return 0, fmt.Errorf("recorder: store manifest: %w", err)
	}

	if err := store.AddArtifact(ctx, rec.ID, access.Artifact{
		ID: uuid.New(), RecordingID: rec.ID, Kind: access.ArtifactVideo, ObjectKey: framesKey,
		SizeBytes: int64(len(blob)), ContentType: "application/octet-stream", Checksum: sum(blob),
	}); err != nil {
		return 0, fmt.Errorf("recorder: record frames artifact: %w", err)
	}
	if err := store.AddArtifact(ctx, rec.ID, access.Artifact{
		ID: uuid.New(), RecordingID: rec.ID, Kind: access.ArtifactManifest, ObjectKey: manKey,
		SizeBytes: int64(len(manJSON)), ContentType: "application/json", Checksum: sum(manJSON),
	}); err != nil {
		return 0, fmt.Errorf("recorder: record manifest artifact: %w", err)
	}
	return len(man.Frames), nil
}

func sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
