package term

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

// Chunk is one contiguous piece of terminal output at a point in time.
//
// Exported because it is a published format, not an internal detail: this is
// what lands in the manifest artifact and what the console's transcript player
// parses back. A reviewer replaying a session years from now is reading this.
//
// Only device output is captured, never the operator's keystrokes. That sounds
// backwards for an audit trail until you consider what a keystroke log of a
// terminal session actually contains: every password typed into sudo or into a
// Cisco enable prompt, every secret pasted into a config. The device's echo
// already shows what was typed at a prompt, while a password prompt echoes
// nothing — so recording output alone reproduces the session faithfully and
// stops short of harvesting secrets the vault deliberately never held.
type Chunk struct {
	// Offset is milliseconds since the recording started, so a player can replay
	// with the original pauses — the rhythm of a session is itself evidence.
	Offset int64 `json:"offset_ms"`
	// Len is this chunk's byte length in the transcript blob.
	Len int `json:"len"`
}

// Manifest indexes the transcript blob. Exported alongside Chunk: it is the
// artifact a player reads, so it is part of the recording format.
type Manifest struct {
	Version int     `json:"version"`
	Cols    int     `json:"cols"`
	Rows    int     `json:"rows"`
	Chunks  []Chunk `json:"chunks"`
	// Truncated marks a transcript that hit the byte cap. A player must say so
	// rather than let a reviewer believe they watched the whole session.
	Truncated bool `json:"truncated"`
}

// Recorder accumulates a session transcript in memory and writes it once.
//
// In-memory is affordable here precisely because this is text: the cap is a few
// megabytes for a session that would be gigabytes as video. The browser gateway
// makes the same trade for the same reason.
//
// One Recorder spans the whole access session, not one device connection. A
// telnet session that drops and is reconnected is still one session and gets one
// continuous transcript; the gap shows up as a pause in the chunk offsets, and
// the reason for it is recorded as a session event rather than written into the
// transcript as text the device never printed.
type Recorder struct {
	mu       sync.Mutex
	started  time.Time
	buf      []byte
	chunks   []Chunk
	max      int64
	overflow bool
	cols     int
	rows     int
}

// NewRecorder starts a transcript capped at max bytes.
func NewRecorder(max int64) *Recorder {
	return &Recorder{started: time.Now(), max: max, cols: 80, rows: 24}
}

// Resize records the terminal geometry. The last size wins: a player needs one
// canvas size, and mid-session resizes are cosmetic next to the content.
func (r *Recorder) Resize(cols, rows int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cols > 0 && rows > 0 {
		r.cols, r.rows = cols, rows
	}
}

// Write appends device output.
func (r *Recorder) Write(b []byte) {
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
	r.chunks = append(r.chunks, Chunk{
		Offset: time.Since(r.started).Milliseconds(),
		Len:    len(b),
	})
	r.buf = append(r.buf, b...)
}

// Flush persists the transcript and its index.
func (r *Recorder) Flush(
	ctx context.Context,
	blobs access.BlobStore,
	store access.RecordingStore,
	rec *access.Recording,
	orgID uuid.UUID,
) error {
	r.mu.Lock()
	buf := r.buf
	m := Manifest{Version: 1, Cols: r.cols, Rows: r.rows, Chunks: r.chunks, Truncated: r.overflow}
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
			return fmt.Errorf("term: marshal manifest: %w", err)
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
		return fmt.Errorf("term: put %s: %w", kind, err)
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
