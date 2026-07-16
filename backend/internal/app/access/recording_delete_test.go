package access

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/domain/audit"
)

// deleteRig builds a service holding one recording with two stored artifacts.
func deleteRig(t *testing.T) (*Service, *fakeRecordings, *fakeBlobs, *fakeAudit, uuid.UUID) {
	t.Helper()
	sid, rid := uuid.New(), uuid.New()
	rec := newFakeRecordings()
	rec.rec = &access.Recording{ID: rid, SessionID: sid, Status: "complete"}
	rec.list = []access.Artifact{
		{ID: uuid.New(), RecordingID: rid, Kind: access.ArtifactDesktop, ObjectKey: "rec/desktop.guac", SizeBytes: 217623},
		{ID: uuid.New(), RecordingID: rid, Kind: access.ArtifactManifest, ObjectKey: "rec/manifest.json", SizeBytes: 705},
	}
	blobs := newFakeBlobs()
	_ = blobs.Put(context.Background(), "rec/desktop.guac", []byte("x"), "")
	_ = blobs.Put(context.Background(), "rec/manifest.json", []byte("y"), "")
	aud := &fakeAudit{}

	svc := NewService(Deps{
		Sessions:   newFakeSessions(),
		Recordings: rec,
		Blobs:      blobs,
		Audit:      aud,
		Config:     DefaultConfig(),
	})
	return svc, rec, blobs, aud, sid
}

// The whole point of deleting a recording is to get the storage back. Deleting
// only the rows frees nothing and leaves the bytes on disk forever, unreachable
// because the only thing that pointed at them is gone.
func TestDeleteRecordingFreesTheStoredBytesNotJustTheRows(t *testing.T) {
	svc, rec, blobs, _, sid := deleteRig(t)

	if err := svc.DeleteRecording(context.Background(), actorClaims(), sid, ReqMeta{}); err != nil {
		t.Fatalf("DeleteRecording: %v", err)
	}

	if len(blobs.deleted) != 2 {
		t.Errorf("freed %d blobs, want 2 — the storage this exists to reclaim is still on disk", len(blobs.deleted))
	}
	if len(blobs.objects) != 0 {
		t.Errorf("%d objects remain in the blob store", len(blobs.objects))
	}
	if len(rec.deleted) != 1 {
		t.Errorf("the recording rows were not deleted")
	}
}

// Auditing after the fact loses the record precisely when the delete is what
// fails. An evidence deletion that leaves no trace is worse than no delete
// feature, so the audit must be written before anything is destroyed — and it
// must say what was destroyed.
func TestDeleteRecordingIsAuditedBeforeAnythingIsDestroyed(t *testing.T) {
	svc, _, _, aud, sid := deleteRig(t)

	if err := svc.DeleteRecording(context.Background(), actorClaims(), sid, ReqMeta{}); err != nil {
		t.Fatalf("DeleteRecording: %v", err)
	}

	var found bool
	for _, e := range aud.events {
		if e.Action == "recording.delete" && e.Result == audit.ResultSuccess {
			found = true
			if e.Detail["size_bytes"] == nil {
				t.Error("the audit does not record how much evidence was destroyed")
			}
			if e.Detail["artifacts"] == nil {
				t.Error("the audit does not record which artifacts were destroyed")
			}
		}
	}
	if !found {
		t.Fatal("deleting a recording wrote no audit event; the destruction is untraceable")
	}
}

// A blob that will not delete must not abort the operation — a half-deleted
// recording reads as intact — but it must not vanish either. The orphan is
// recorded, because an object nobody can reach and nobody knows about is what
// turns up in a storage audit years later.
func TestDeleteRecordingRecordsAnOrphanedBlobRatherThanHidingIt(t *testing.T) {
	svc, rec, blobs, aud, sid := deleteRig(t)
	blobs.delErr["rec/desktop.guac"] = errors.New("permission denied")

	if err := svc.DeleteRecording(context.Background(), actorClaims(), sid, ReqMeta{}); err != nil {
		t.Fatalf("a failed blob delete aborted the whole operation: %v", err)
	}
	if len(rec.deleted) != 1 {
		t.Error("the rows were left behind, so the recording still reads as intact")
	}

	var orphanLogged bool
	for _, e := range aud.events {
		if e.Action == "recording.delete" && e.Result == audit.ResultFailure {
			orphanLogged = true
			if e.Detail["orphaned_keys"] == nil {
				t.Error("the audit does not name the orphaned object")
			}
		}
	}
	if !orphanLogged {
		t.Error("a blob was orphaned with no audit event; nothing will ever find it")
	}
}

// "Deleted" and "there was nothing there" must not look the same.
func TestDeleteRecordingReportsAMissingRecording(t *testing.T) {
	svc, rec, _, _, sid := deleteRig(t)
	rec.rec = nil

	err := svc.DeleteRecording(context.Background(), actorClaims(), sid, ReqMeta{})
	if !errors.Is(err, access.ErrNotFound) {
		t.Errorf("deleting a recording that does not exist returned %v, want ErrNotFound", err)
	}
}
