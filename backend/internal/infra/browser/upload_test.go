package browser

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func uploadRequest(t *testing.T, name string, size int) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("file", name)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(bytes.Repeat([]byte("x"), size))
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/proxy/sid/__upload__", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

func uploadGateway(t *testing.T, maxBytes int64) (*Gateway, uuid.UUID, *bSession) {
	t.Helper()
	g := NewGateway(Config{MaxUploadBytes: maxBytes}, Deps{})
	sid := uuid.New()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	bs := &bSession{tabCtx: ctx, cancel: cancel, token: "tok", notes: make(chan []byte, 4), tl: nil}
	bs.expires = time.Now().Add(time.Hour)
	g.mu.Lock()
	g.sessions[sid] = bs
	g.mu.Unlock()
	t.Cleanup(func() { g.removeUploads(bs) })
	return g, sid, bs
}

// Files are only taken while the device is asking for one.
func TestUploadRefusedWhenTheDeviceIsNotAsking(t *testing.T) {
	g, sid, _ := uploadGateway(t, 1<<20)
	w := httptest.NewRecorder()
	if !g.Upload(w, uploadRequest(t, "fw.bin", 10), sid, "tok") {
		t.Fatal("the session was not recognised")
	}
	if w.Code != http.StatusConflict {
		t.Errorf("status %d, want 409", w.Code)
	}
}

// Too large is refused with a reason, and the device's picker stays open for a
// retry with a smaller file.
func TestUploadTooLarge(t *testing.T) {
	g, sid, bs := uploadGateway(t, 1024)
	bs.chooser = &fileChooser{node: 7}
	w := httptest.NewRecorder()
	g.Upload(w, uploadRequest(t, "fw.bin", 4096), sid, "tok")
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("status %d, want 413: %s", w.Code, w.Body.String())
	}
	if bs.chooser == nil {
		t.Error("the device's request for a file was dropped by a failed upload")
	}
}

// A device asking for one file gets one.
func TestUploadRespectsSingleFileInputs(t *testing.T) {
	g, sid, bs := uploadGateway(t, 1<<20)
	bs.chooser = &fileChooser{node: 7, multiple: false}
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for _, n := range []string{"a.cfg", "b.cfg"} {
		fw, _ := mw.CreateFormFile("file", n)
		_, _ = fw.Write([]byte("x"))
	}
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	g.Upload(w, r, sid, "tok")
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "fewer files") {
		t.Errorf("status %d %q, want 400 asking for fewer files", w.Code, w.Body.String())
	}
}

func TestSafeFileName(t *testing.T) {
	cases := map[string]string{
		"firmware.bin":                    "firmware.bin",
		"../../etc/passwd":                "passwd",
		`C:\Users\me\config.tgz`:          "config.tgz",
		"name\x00with\ncontrol":           "namewithcontrol",
		"..":                              "upload",
		"":                                "upload",
		strings.Repeat("a", 300) + ".bin": strings.Repeat("a", 196) + ".bin",
	}
	for in, want := range cases {
		if got := safeFileName(in); got != want {
			t.Errorf("safeFileName(%q) = %q, want %q", in, got, want)
		}
	}
	if !IsUploadPath("/__upload__") || IsUploadPath("/__ws__") {
		t.Error("IsUploadPath")
	}
}
