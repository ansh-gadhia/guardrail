package guacgw

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// Recording a desktop session is guacd's own feature: given recording-path and
// recording-name it writes the session as a Guacamole protocol dump — the same
// instruction stream it sends the browser, with `sync` instructions carrying the
// timing. That is why a desktop session can be recorded on a host with no
// Chromium: the capture happens where the pixels are made.
//
// GuardRail's part is to move that file into the blob store on teardown, so every
// recording lives in one place with one retention policy, whatever produced it.

// storeRecording moves guacd's recording file into the blob store and registers
// it against the session's recording row.
func (g *Gateway) storeRecording(ctx context.Context, s *guacSession) error {
	file := g.recordingFile(s.recordingName)

	// guacd finishes writing asynchronously after the connection ends, so the
	// file can still be growing at this instant. Reading it now would store a
	// truncated session — and the tail is usually the part someone is looking for.
	// There is no completion signal to wait on (the file is guacd's, not ours), so
	// wait for it to stop growing.
	size, err := waitForStableFile(ctx, file, 250*time.Millisecond, 15*time.Second)
	if err != nil {
		return fmt.Errorf("guac: waiting for guacd to finish the recording: %w", err)
	}
	if size == 0 {
		// Nothing on disk. The benign reading is a session that ended before
		// anything was drawn, and that was the only reading this code had — it
		// finalized the row and said nothing.
		//
		// The likelier one, by far, is that guacd could not write. The recording
		// directory is a bind mount and guacd runs as uid 1000, so a directory
		// Docker created (root, 755) gives the daemon EACCES — whereupon guacd logs
		// it and serves the session anyway. Both readings land here as "no file",
		// and only one of them is fine.
		//
		// So say so, loudly, every time. An operator watching a recorded desktop
		// session produce no recording needs to be told where to look, and a silent
		// finalize told them nothing at all. The row is still finalized: the absence
		// of output is a fact, and a row promising evidence that was never written
		// would look like tampering.
		if g.deps.Log != nil {
			g.deps.Log.Error("guac: the session recorded nothing; the recording has no evidence",
				zap.String("session_id", s.recording.SessionID.String()),
				zap.String("expected_file", file),
				// The actual state of the directory, so the cause is not a guess.
				// guacd writes as uid 1000; if this dir is owned by anyone else and
				// is not group-writable by 1000, guacd got EACCES and served the
				// session unrecorded. The API sees the same host path, so it can
				// report what guacd was up against.
				zap.String("recording_dir", dirOwnership(g.cfg.RecordingDir)),
				zap.String("fix_if_permissions", "guacd (uid 1000) must own this dir and be able to write it: "+
					"sudo chown 1000:1000 "+g.cfg.RecordingDir+" && sudo chmod 2770 "+g.cfg.RecordingDir+
					" (then run a NEW session — this one recorded nothing and cannot be recovered). "+
					"If the directory is already 1000:1000, the session simply ended before anything was drawn"))
		}
		return g.deps.Recordings.Finalize(ctx, s.recording.SessionID, time.Now())
	}

	body, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("guac: reading the recording guacd wrote: %w", err)
	}

	key := recordingPrefix(s.orgID, s.recording.SessionID) + "/desktop.guac"
	if err := g.deps.Blobs.Put(ctx, key, body, "application/octet-stream"); err != nil {
		return fmt.Errorf("guac: storing the recording: %w", err)
	}
	sum := sha256.Sum256(body)
	if err := g.deps.Recordings.AddArtifact(ctx, s.recording.ID, access.Artifact{
		// Inserted explicitly rather than letting the column default fire; a zero
		// id collides on the primary key after the first artifact.
		ID:          uuid.New(),
		RecordingID: s.recording.ID,
		Kind:        access.ArtifactDesktop,
		ObjectKey:   key,
		ContentType: "application/octet-stream",
		SizeBytes:   int64(len(body)),
		Checksum:    hex.EncodeToString(sum[:]),
	}); err != nil {
		return fmt.Errorf("guac: registering the recording: %w", err)
	}

	// Only now that the bytes are safely in the blob store. Removing it earlier
	// would trade the evidence for a little disk.
	if err := os.Remove(file); err != nil && g.deps.Log != nil {
		g.deps.Log.Warn("guac: the recording is stored but its scratch file could not be removed",
			zap.String("path", file), zap.Error(err))
	}
	return g.deps.Recordings.Finalize(ctx, s.recording.SessionID, time.Now())
}

// waitForStableFile returns the file's size once it has stopped changing for
// `quiet`, giving up after `limit`. A file that never appears is size 0: guacd
// creates the recording lazily, so a session with no output leaves nothing.
func waitForStableFile(ctx context.Context, path string, quiet, limit time.Duration) (int64, error) {
	deadline := time.Now().Add(limit)
	var last int64 = -1
	var stableSince time.Time

	for {
		var size int64
		if fi, err := os.Stat(path); err == nil {
			size = fi.Size()
		} else if !os.IsNotExist(err) {
			return 0, err
		}

		if size != last {
			last, stableSince = size, time.Now()
		} else if time.Since(stableSince) >= quiet {
			return size, nil
		}
		if time.Now().After(deadline) {
			// Return what is there rather than failing: a partial recording is worth
			// more than none, and the alternative is discarding evidence because a
			// timer expired.
			return last, nil
		}
		select {
		case <-ctx.Done():
			return last, ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// dirOwnership renders a recording directory's owner, group and mode for a log
// line — "uid=65532 gid=65532 mode=2770", or why it could not be read. It turns
// "the recording is empty" from a guess into a diagnosis: an owner that is not
// guacd's uid 1000 (without group-write for it) is the whole reason guacd wrote
// nothing.
func dirOwnership(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return "unreadable: " + err.Error()
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "mode=" + fi.Mode().Perm().String()
	}
	// st.Mode is the raw mode_t: the low 12 bits (07777) are the permission bits
	// plus setuid/setgid/sticky in traditional octal, so a setgid 0750 dir prints
	// as the 2750 an admin would type.
	return fmt.Sprintf("uid=%d gid=%d mode=%04o", st.Uid, st.Gid, st.Mode&0o7777)
}

// recordingPrefix is the blob key namespace for one session's artifacts. Scoped
// by organization so a bucket listing cannot cross tenants.
func recordingPrefix(orgID, sessionID uuid.UUID) string {
	return "recordings/" + orgID.String() + "/" + sessionID.String()
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
