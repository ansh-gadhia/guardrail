package browser

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Uploads in an isolated session.
//
// The device's page runs in a browser on this server, so when it opens a file
// picker — a firmware image, a configuration restore, a certificate — the
// picker opens HERE, where nobody can see it, and the operator had no way to
// give the device a file at all. The picker is intercepted instead: the viewer
// is told the device is asking for a file, shows its own picker, and posts the
// chosen files back; they are staged for the session and handed to the very
// input that asked. Every file is on the session's timeline with its size and
// SHA-256, because a file going INTO a privileged device is exactly what a
// review wants to see.

// uploadSentinel is the sub-path under /proxy/<sid>/ the viewer posts files to.
const uploadSentinel = "__upload__"

// IsUploadPath reports whether the proxied path is the upload endpoint.
func IsUploadPath(path string) bool {
	return strings.TrimPrefix(path, "/") == uploadSentinel
}

// maxUploadFiles bounds one upload. A device input asks for one file, or a few.
const maxUploadFiles = 20

// fileChooser is the picker the device has open and is waiting on.
type fileChooser struct {
	node     cdp.BackendNodeID
	multiple bool
}

// onFileChooser records the device's request for a file and tells the viewer.
func (g *Gateway) onFileChooser(bs *bSession, e *page.EventFileChooserOpened) {
	if e.BackendNodeID == 0 {
		// Opened by script without an <input> to fill (the File System Access
		// API). There is nothing to hand files to.
		return
	}
	multiple := e.Mode == page.FileChooserOpenedModeSelectMultiple
	bs.upMu.Lock()
	bs.chooser = &fileChooser{node: e.BackendNodeID, multiple: multiple}
	bs.upMu.Unlock()

	msg, _ := json.Marshal(map[string]any{"t": "file", "multiple": multiple})
	select {
	case bs.notes <- msg:
	default: // no viewer right now; the device keeps waiting, and asks again on the next click
	}
}

// Upload receives the operator's files for the picker the device has open.
// false => not this gateway's session.
func (g *Gateway) Upload(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool {
	bs := g.lookup(sid, token)
	if bs == nil {
		return false
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "use POST", http.StatusMethodNotAllowed)
		return true
	}
	// Only while the device is asking. A standing endpoint would let anything
	// holding the session cookie stage files on the server at any time.
	bs.upMu.Lock()
	chooser := bs.chooser
	bs.chooser = nil
	bs.upMu.Unlock()
	if chooser == nil {
		http.Error(w, "the device is not asking for a file", http.StatusConflict)
		return true
	}

	// The API reads every other request in seconds; a firmware image over a
	// slow link takes minutes. This one request gets them.
	_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(15 * time.Minute))
	files, err := g.receive(w, r, sid, bs, chooser)
	if err != nil {
		var tooBig *http.MaxBytesError
		switch {
		case errors.As(err, &tooBig):
			http.Error(w, fmt.Sprintf("the upload is larger than %d MB", g.cfg.MaxUploadBytes>>20), http.StatusRequestEntityTooLarge)
		default:
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		// The device is still waiting on its picker; let a retry fill it.
		bs.upMu.Lock()
		if bs.chooser == nil {
			bs.chooser = chooser
		}
		bs.upMu.Unlock()
		return true
	}

	paths := make([]string, len(files))
	for i, f := range files {
		paths[i] = f.path
	}
	ctx, cancel := context.WithTimeout(bs.tabCtx, 15*time.Second)
	defer cancel()
	if err := chromedp.Run(ctx, dom.SetFileInputFiles(paths).WithBackendNodeID(chooser.node)); err != nil {
		http.Error(w, "the device's page no longer has that file input", http.StatusGone)
		return true
	}
	out := make([]map[string]any, len(files))
	for i, f := range files {
		bs.tl.record("upload", map[string]any{"filename": f.name, "size": f.size, "sha256": f.sum})
		out[i] = map[string]any{"name": f.name, "size": f.size}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"files": out})
	return true
}

type stagedFile struct {
	name, path, sum string
	size            int64
}

// receive stages the multipart files in this session's upload directory.
func (g *Gateway) receive(w http.ResponseWriter, r *http.Request, sid uuid.UUID, bs *bSession, chooser *fileChooser) ([]stagedFile, error) {
	r.Body = http.MaxBytesReader(w, r.Body, g.cfg.MaxUploadBytes)
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, errors.New("expected a multipart upload")
	}
	dir, err := bs.stagingDir(sid)
	if err != nil {
		return nil, err
	}
	// Each upload in a directory of its own, so files keep their real names —
	// which the device sees — without colliding with an earlier upload.
	batch, err := os.MkdirTemp(dir, "u-")
	if err != nil {
		return nil, err
	}
	var files []stagedFile
	for {
		part, perr := mr.NextPart()
		if perr == io.EOF {
			break
		}
		if perr != nil {
			return nil, perr
		}
		if part.FileName() == "" {
			_ = part.Close()
			continue
		}
		if len(files) == maxUploadFiles || (!chooser.multiple && len(files) == 1) {
			_ = part.Close()
			return nil, errors.New("the device asked for fewer files")
		}
		name := safeFileName(part.FileName())
		path := filepath.Join(batch, name)
		f, ferr := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 G703 -- a fresh temp dir plus safeFileName's bare base name: no separators, never "." or ".."
		if ferr != nil {
			_ = part.Close()
			return nil, ferr
		}
		h := sha256.New()
		n, cerr := io.Copy(io.MultiWriter(f, h), part)
		_ = part.Close()
		if err := f.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return nil, cerr
		}
		files = append(files, stagedFile{name: name, path: path, size: n, sum: hex.EncodeToString(h.Sum(nil))})
	}
	if len(files) == 0 {
		return nil, errors.New("no file in the upload")
	}
	return files, nil
}

// stagingDir is this session's upload directory, created on first use.
func (bs *bSession) stagingDir(sid uuid.UUID) (string, error) {
	bs.upMu.Lock()
	defer bs.upMu.Unlock()
	if bs.uploadDir != "" {
		return bs.uploadDir, nil
	}
	dir, err := os.MkdirTemp("", "guardrail-upload-"+sid.String()+"-")
	if err != nil {
		return "", err
	}
	bs.uploadDir = dir
	return dir, nil
}

// removeUploads deletes the session's staged files. Called when it ends: the
// device has them by then, and they have no business outliving the session.
func (g *Gateway) removeUploads(bs *bSession) {
	bs.upMu.Lock()
	dir := bs.uploadDir
	bs.uploadDir = ""
	bs.chooser = nil
	bs.upMu.Unlock()
	if dir == "" {
		return
	}
	if err := os.RemoveAll(dir); err != nil && g.log != nil {
		g.log.Warn("browser: could not remove a session's uploaded files", zap.String("dir", dir), zap.Error(err))
	}
}

// safeFileName keeps a client-supplied name to a plain base name: no path, no
// control characters, a sensible length. The device sees this name.
func safeFileName(name string) string {
	name = filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	name = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f || r == '/' {
			return -1
		}
		return r
	}, name)
	if name == "" || name == "." || name == ".." {
		name = "upload"
	}
	if len(name) > 200 {
		ext := filepath.Ext(name)
		if len(ext) > 20 {
			ext = ""
		}
		name = name[:200-len(ext)] + ext
	}
	return name
}
