package assets

import (
	"reflect"
	"testing"
)

func TestSupportedRecordingKinds(t *testing.T) {
	cases := map[string][]string{
		"ssh":    {RecordTranscript, RecordVideo},
		"telnet": {RecordTranscript, RecordVideo},
		"rdp":    {RecordDesktop},
		"vnc":    {RecordDesktop},
		"https":  {RecordVideo},
		"http":   {RecordVideo},
		"gopher": nil,
	}
	for scheme, want := range cases {
		if got := SupportedRecordingKinds(scheme); !reflect.DeepEqual(got, want) {
			t.Errorf("SupportedRecordingKinds(%q) = %v, want %v", scheme, got, want)
		}
	}
}

// The returned slice must not alias the package table, or a caller appending to
// it would rewrite what every later caller is offered.
func TestSupportedRecordingKindsDoesNotAliasTable(t *testing.T) {
	got := SupportedRecordingKinds("ssh")
	got[0] = "tampered"
	if SupportedRecordingKinds("ssh")[0] != RecordTranscript {
		t.Fatal("caller mutated the package's kind table")
	}
}

func TestNormalizeRecordingKinds(t *testing.T) {
	cases := []struct {
		name   string
		scheme string
		in     []string
		want   []string
	}{
		{"both kinds on a terminal", "ssh", []string{"video", "transcript"},
			[]string{RecordTranscript, RecordVideo}},
		{"canonical order regardless of input order", "ssh", []string{"video", "transcript"},
			[]string{RecordTranscript, RecordVideo}},
		{"duplicates collapse", "ssh", []string{"transcript", "transcript"},
			[]string{RecordTranscript}},
		{"unsupported kind is dropped, not an error", "https", []string{"transcript", "video"},
			[]string{RecordVideo}},
		{"desktop cannot be asked of a terminal", "ssh", []string{"desktop"}, []string{}},
		{"unknown kinds vanish", "ssh", []string{"hologram"}, []string{}},
		{"empty stays empty", "ssh", nil, []string{}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NormalizeRecordingKinds(c.scheme, c.in); !reflect.DeepEqual(got, c.want) {
				t.Errorf("got %v, want %v", got, c.want)
			}
		})
	}
}

// Recording off means nothing is captured, whatever the stored set says. The
// set is what to capture, not whether to.
func TestEffectiveRecordingKindsRespectsMasterSwitch(t *testing.T) {
	d := &Device{Scheme: "ssh", RecordSessions: false, RecordingKinds: []string{RecordTranscript, RecordVideo}}
	if got := d.EffectiveRecordingKinds(); len(got) != 0 {
		t.Errorf("recording off should capture nothing, got %v", got)
	}
	if d.RecordsKind(RecordTranscript) {
		t.Error("RecordsKind true while recording is off")
	}
}

// A device recorded with no stored kinds predates the column. It must keep
// capturing what it captured before, not silently capture nothing — the one
// outcome a migration of an audit control must never produce.
func TestEffectiveRecordingKindsFallsBackToProtocolDefault(t *testing.T) {
	cases := map[string]string{
		"ssh": RecordTranscript, "telnet": RecordTranscript,
		"rdp": RecordDesktop, "vnc": RecordDesktop,
		"https": RecordVideo, "http": RecordVideo,
	}
	for scheme, want := range cases {
		d := &Device{Scheme: scheme, RecordSessions: true}
		got := d.EffectiveRecordingKinds()
		if len(got) != 1 || got[0] != want {
			t.Errorf("scheme %q: got %v, want [%s]", scheme, got, want)
		}
	}
}

// A device whose protocol changed under a stale setting — ssh with 'transcript'
// switched to https — must not resolve to an empty capture while its policy
// still reads "recorded".
func TestEffectiveRecordingKindsRecoversFromStaleSetting(t *testing.T) {
	d := &Device{Scheme: "https", RecordSessions: true, RecordingKinds: []string{RecordTranscript}}
	got := d.EffectiveRecordingKinds()
	if len(got) != 1 || got[0] != RecordVideo {
		t.Errorf("got %v, want [video]", got)
	}
}

func TestRecordsKindBothOnTerminal(t *testing.T) {
	d := &Device{Scheme: "ssh", RecordSessions: true, RecordingKinds: []string{RecordTranscript, RecordVideo}}
	if !d.RecordsKind(RecordTranscript) || !d.RecordsKind(RecordVideo) {
		t.Errorf("terminal device should capture both, got %v", d.EffectiveRecordingKinds())
	}
	if d.RecordsKind(RecordDesktop) {
		t.Error("terminal device should not claim a desktop capture")
	}
}
