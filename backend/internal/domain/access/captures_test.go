package access

import "testing"

// An endpoint that is not recorded captures nothing, whatever kinds it names.
// The kind set says what to capture, never whether to.
func TestCapturesRespectsRecordSessions(t *testing.T) {
	ep := Endpoint{
		Protocol: ProtocolSSH, RecordSessions: false,
		RecordingKinds: []string{ArtifactTranscript, ArtifactVideo},
	}
	for _, k := range []string{ArtifactTranscript, ArtifactVideo, ArtifactDesktop} {
		if ep.Captures(k) {
			t.Errorf("Captures(%q) = true on an unrecorded endpoint", k)
		}
	}
}

// A terminal device set to capture both must answer yes to both — this is the
// case the whole feature exists for.
func TestCapturesBothOnTerminal(t *testing.T) {
	ep := Endpoint{
		Protocol: ProtocolSSH, RecordSessions: true,
		RecordingKinds: []string{ArtifactTranscript, ArtifactVideo},
	}
	if !ep.Captures(ArtifactTranscript) || !ep.Captures(ArtifactVideo) {
		t.Error("a device set to capture both should capture both")
	}
	if ep.Captures(ArtifactDesktop) {
		t.Error("a terminal should not claim a desktop capture")
	}
}

// Video-only is a real choice: the transcript must not be written anyway.
// Storing evidence the operator explicitly unticked is the console lying about
// what it keeps.
func TestCapturesVideoOnlyExcludesTranscript(t *testing.T) {
	ep := Endpoint{
		Protocol: ProtocolSSH, RecordSessions: true,
		RecordingKinds: []string{ArtifactVideo},
	}
	if ep.Captures(ArtifactTranscript) {
		t.Error("transcript captured despite a video-only policy")
	}
	if !ep.Captures(ArtifactVideo) {
		t.Error("video not captured despite a video-only policy")
	}
}

// A recorded endpoint that names no kinds predates the column, or was built by a
// caller that never settled the set. It must fall back to the one capture its
// protocol always produced rather than silently capturing nothing.
func TestCapturesFallsBackWhenNoKindsNamed(t *testing.T) {
	cases := []struct {
		proto Protocol
		want  string
	}{
		{ProtocolSSH, ArtifactTranscript},
		{ProtocolTelnet, ArtifactTranscript},
		{ProtocolRDP, ArtifactDesktop},
		{ProtocolVNC, ArtifactDesktop},
		{ProtocolHTTPS, ArtifactVideo},
		{ProtocolHTTP, ArtifactVideo},
	}
	for _, c := range cases {
		ep := Endpoint{Protocol: c.proto, RecordSessions: true}
		if !ep.Captures(c.want) {
			t.Errorf("%s with no kinds should capture %q", c.proto, c.want)
		}
		for _, other := range []string{ArtifactTranscript, ArtifactVideo, ArtifactDesktop} {
			if other != c.want && ep.Captures(other) {
				t.Errorf("%s with no kinds should not capture %q", c.proto, other)
			}
		}
	}
}

func TestRecordsKind(t *testing.T) {
	kinds := []string{ArtifactTranscript, ArtifactVideo}
	if !RecordsKind(kinds, ArtifactVideo) {
		t.Error("RecordsKind missed a present kind")
	}
	if RecordsKind(kinds, ArtifactDesktop) {
		t.Error("RecordsKind matched an absent kind")
	}
	if RecordsKind(nil, ArtifactVideo) {
		t.Error("RecordsKind matched against an empty set")
	}
}
