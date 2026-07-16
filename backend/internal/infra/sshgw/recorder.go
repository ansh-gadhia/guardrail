package sshgw

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

// ArtifactTranscript is the terminal transcript: the bytes the device printed.
//
// Aliased from the domain rather than declared here, because the delivery layer
// has to name the same kind to serve it, and it cannot import this package.
const ArtifactTranscript = access.ArtifactTranscript

// chunk is one contiguous piece of terminal output at a point in time.
//
// Only device output is captured, never the operator's keystrokes. That sounds
// backwards for an audit trail until you consider what a keystroke log of an SSH
// session actually contains: every password typed into sudo, every secret pasted
// into a config. The device's echo already shows what was typed at a prompt,
// while a password prompt echoes nothing — so recording output alone reproduces
// the session faithfully and stops short of harvesting secrets the vault
// deliberately never held.
type chunk struct {
	// Offset is milliseconds since the recording started, so a player can replay
	// with the original pauses — the rhythm of a session is itself evidence.
	Offset int64 `json:"offset_ms"`
	// Len is this chunk's byte length in the transcript blob.
	Len int `json:"len"`
}

// manifest indexes the transcript blob.
type manifest struct {
	Version int     `json:"version"`
	Cols    int     `json:"cols"`
	Rows    int     `json:"rows"`
	Chunks  []chunk `json:"chunks"`
	// Truncated marks a transcript that hit the byte cap. A player must say so
	// rather than let a reviewer believe they watched the whole session.
	Truncated bool `json:"truncated"`
}

// recorder accumulates a session transcript in memory and writes it once.
//
// In-memory is affordable here precisely because this is text: the cap is a few
// megabytes for a session that would be gigabytes as video. The browser gateway
// makes the same trade for the same reason.
type recorder struct {
	mu       sync.Mutex
	started  time.Time
	buf      []byte
	chunks   []chunk
	max      int64
	overflow bool
	cols     int
	rows     int
}

func newRecorder(max int64) *recorder {
	return &recorder{started: time.Now(), max: max, cols: 80, rows: 24}
}

// resize records the terminal geometry. The last size wins: a player needs one
// canvas size, and mid-session resizes are cosmetic next to the content.
func (r *recorder) resize(cols, rows int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cols > 0 && rows > 0 {
		r.cols, r.rows = cols, rows
	}
}

// write appends device output.
func (r *recorder) write(b []byte) {
	if len(b) == 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if int64(len(r.buf))+int64(len(b)) > r.max {
		// Stop at the cap but keep the session running. Killing a live session
		// because its transcript got long would turn an audit control into an
		// outage; the manifest records that the tail is missing.
		r.overflow = true
		return
	}
	r.chunks = append(r.chunks, chunk{
		Offset: time.Since(r.started).Milliseconds(),
		Len:    len(b),
	})
	r.buf = append(r.buf, b...)
}

// flush persists the transcript and its index.
func (r *recorder) flush(
	ctx context.Context,
	blobs access.BlobStore,
	store access.RecordingStore,
	rec *access.Recording,
	orgID uuid.UUID,
) error {
	r.mu.Lock()
	buf := r.buf
	m := manifest{Version: 1, Cols: r.cols, Rows: r.rows, Chunks: r.chunks, Truncated: r.overflow}
	r.mu.Unlock()

	// A session where nothing was printed still gets finalized — the absence of
	// output is itself a fact, and a recording row promising a transcript that
	// was never written would look like tampering.
	if len(buf) > 0 {
		prefix := recordingPrefix(orgID, rec.SessionID)
		if err := putArtifact(ctx, blobs, store, rec, ArtifactTranscript,
			prefix+"/transcript", "application/octet-stream", buf); err != nil {
			return err
		}
		mb, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("sshgw: marshal manifest: %w", err)
		}
		if err := putArtifact(ctx, blobs, store, rec, access.ArtifactManifest,
			prefix+"/manifest.json", "application/json", mb); err != nil {
			return err
		}
	}
	return store.Finalize(ctx, rec.SessionID, time.Now())
}

// putArtifact writes one blob and registers it against the recording.
func putArtifact(
	ctx context.Context,
	blobs access.BlobStore,
	store access.RecordingStore,
	rec *access.Recording,
	kind, key, contentType string,
	body []byte,
) error {
	if err := blobs.Put(ctx, key, body, contentType); err != nil {
		return fmt.Errorf("sshgw: put %s: %w", kind, err)
	}
	sum := sha256.Sum256(body)
	return store.AddArtifact(ctx, rec.ID, access.Artifact{
		// The repository inserts this id explicitly rather than letting the column
		// default fire, so leaving it zero makes every artifact collide on the
		// primary key after the first.
		ID:          uuid.New(),
		RecordingID: rec.ID,
		Kind:        kind,
		ObjectKey:   key,
		ContentType: contentType,
		SizeBytes:   int64(len(body)),
		Checksum:    hex.EncodeToString(sum[:]),
	})
}

func recordingPrefix(orgID, sessionID uuid.UUID) string {
	return orgID.String() + "/" + sessionID.String()
}
