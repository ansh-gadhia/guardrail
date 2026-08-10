package access

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/access"
)

// indexRig builds a service whose recording store serves the given artifacts by
// kind, with each one's bytes in the blob store.
func indexRig(t *testing.T, arts map[string]access.Artifact, blobs map[string][]byte) (*Service, *fakeRecordings) {
	t.Helper()
	rec := newFakeRecordings()
	rec.byKind = arts
	bs := newFakeBlobs()
	for k, v := range blobs {
		_ = bs.Put(context.Background(), k, v, "application/json")
	}
	svc := NewService(Deps{
		Sessions:   newFakeSessions(),
		Recordings: rec,
		Blobs:      bs,
		Audit:      &fakeAudit{},
		Config:     DefaultConfig(),
	})
	return svc, rec
}

// Transcripts recorded before the index got its own artifact kind filed it under
// ArtifactManifest, the kind the screencast now owns. Every deployment that has
// run a terminal session holds real recordings in that shape, and an upgrade
// that made them unplayable would be indistinguishable, to a reviewer, from the
// evidence having been destroyed.
func TestTranscriptIndexFallsBackToLegacyManifestKind(t *testing.T) {
	svc, rec := indexRig(t,
		map[string]access.Artifact{
			access.ArtifactManifest: {Kind: access.ArtifactManifest, ObjectKey: "old/manifest.json", ContentType: "application/json"},
		},
		map[string][]byte{"old/manifest.json": []byte(`{"version":1}`)},
	)

	data, ct, err := svc.RecordingArtifact(context.Background(), actorClaims(), uuid.New(),
		access.ArtifactTranscriptIndex, ReqMeta{})
	if err != nil {
		t.Fatalf("legacy transcript index unreadable after the kind split: %v", err)
	}
	if string(data) != `{"version":1}` {
		t.Errorf("got %q, want the legacy manifest bytes", data)
	}
	if ct != "application/json" {
		t.Errorf("content type = %q, want application/json", ct)
	}
	// The new kind must be tried FIRST. Reaching only for the old one would hand
	// the transcript player the screencast's index on any recording holding both.
	if len(rec.kindsAsked) != 2 ||
		rec.kindsAsked[0] != access.ArtifactTranscriptIndex ||
		rec.kindsAsked[1] != access.ArtifactManifest {
		t.Errorf("lookup order = %v, want [transcript_index metadata]", rec.kindsAsked)
	}
}

// A recording written after the split holds both indexes. The transcript player
// must get the transcript's, never the screencast's — the exact ambiguity the
// separate kind exists to remove.
func TestTranscriptIndexPrefersItsOwnKind(t *testing.T) {
	svc, rec := indexRig(t,
		map[string]access.Artifact{
			access.ArtifactManifest:        {Kind: access.ArtifactManifest, ObjectKey: "video.json", ContentType: "application/json"},
			access.ArtifactTranscriptIndex: {Kind: access.ArtifactTranscriptIndex, ObjectKey: "transcript.json", ContentType: "application/json"},
		},
		map[string][]byte{
			"video.json":      []byte(`{"which":"video"}`),
			"transcript.json": []byte(`{"which":"transcript"}`),
		},
	)

	data, _, err := svc.RecordingArtifact(context.Background(), actorClaims(), uuid.New(),
		access.ArtifactTranscriptIndex, ReqMeta{})
	if err != nil {
		t.Fatalf("RecordingArtifact: %v", err)
	}
	if string(data) != `{"which":"transcript"}` {
		t.Errorf("transcript player was handed %q — the wrong index", data)
	}
	if len(rec.kindsAsked) != 1 {
		t.Errorf("fell back despite its own index existing: %v", rec.kindsAsked)
	}
}

// The video manifest must not fall back to anything: a session with only a
// transcript has no video to replay, and serving the transcript's index to the
// frame player would draw a recording that does not exist.
func TestVideoManifestDoesNotFallBack(t *testing.T) {
	svc, _ := indexRig(t,
		map[string]access.Artifact{
			access.ArtifactTranscriptIndex: {Kind: access.ArtifactTranscriptIndex, ObjectKey: "transcript.json"},
		},
		map[string][]byte{"transcript.json": []byte(`{}`)},
	)

	if _, _, err := svc.RecordingArtifact(context.Background(), actorClaims(), uuid.New(),
		access.ArtifactManifest, ReqMeta{}); err == nil {
		t.Error("video manifest resolved on a transcript-only recording")
	}
}
