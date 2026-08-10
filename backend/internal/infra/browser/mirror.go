package browser

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/chromedp/cdproto/emulation"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/guardrail/guardrail/internal/domain/access"
	"github.com/guardrail/guardrail/internal/infra/term"
)

// Terminal mirror geometry. xterm at 13px in this page renders a cell close
// enough to 8x17 that a viewport sized from these numbers fits the grid without
// clipping it or leaving a wide margin. It does not have to be exact: the
// terminal's own cols/rows govern where lines wrap, and this only decides how
// much canvas surrounds them.
const (
	mirrorCellW  = 8
	mirrorCellH  = 17
	mirrorPadPx  = 16
	mirrorMinW   = 480
	mirrorMinH   = 240
	mirrorMaxW   = 2560
	mirrorMaxH   = 1440
	mirrorCols   = 80
	mirrorRows   = 24
	mirrorFlushI = 50 * time.Millisecond
	// mirrorMaxPending caps output buffered between flushes. A device dumping a
	// core file faster than the browser can render is not worth an OOM; the frames
	// already show a screen scrolling too fast to read, which is the truth of what
	// the operator saw, and the transcript holds every byte regardless.
	mirrorMaxPending = 4 << 20
)

// mirror is a headless tab rendering a terminal session for the recorder.
type mirror struct {
	tabCtx context.Context
	cancel context.CancelFunc
	rec    *recorder
	log    *zap.Logger

	recording *access.Recording
	orgID     uuid.UUID
	blobs     access.BlobStore
	store     access.RecordingStore
	w, h      int64

	mu       sync.Mutex
	pending  []byte
	dropped  int
	closed   bool
	flushSig chan struct{}
	done     chan struct{}
}

// OpenMirror starts recording a terminal session as video.
//
// The tab is opened, the mirror page installed and the screencast started before
// this returns, so a caller that gets no error can write immediately and know the
// bytes are being captured. Failure is reported rather than swallowed: a terminal
// gateway that asked for video and silently got none would leave a device whose
// policy promises evidence that does not exist.
func (g *Gateway) OpenMirror(ctx context.Context, rec *access.Recording, orgID uuid.UUID, o access.MirrorOptions) (access.TerminalMirror, error) {
	if rec == nil {
		return nil, fmt.Errorf("browser: mirror needs a recording")
	}
	if g.recordings == nil || g.blobs == nil {
		return nil, fmt.Errorf("browser: mirror needs a recording store and blob store")
	}
	// A mirror is a browser tab and costs what one costs, so it answers to the
	// same admission check as an isolated session rather than sneaking past it.
	if err := g.admit(); err != nil {
		return nil, err
	}
	if err := g.ensureAlloc(); err != nil {
		return nil, err
	}

	cols, rows := o.Cols, o.Rows
	if cols <= 0 {
		cols = mirrorCols
	}
	if rows <= 0 {
		rows = mirrorRows
	}
	w, h := mirrorViewport(cols, rows)

	tabCtx, cancel := chromedp.NewContext(g.allocCtx)
	m := &mirror{
		tabCtx: tabCtx, cancel: cancel, log: g.log,
		rec:       newRecorder(time.Now(), g.cfg.MaxRecordingBytes),
		recording: rec, orgID: orgID, blobs: g.blobs, store: g.recordings,
		w: w, h: h,
		flushSig: make(chan struct{}, 1),
		done:     make(chan struct{}),
	}

	// Frames go straight to the recorder. There is no live viewer for a mirror —
	// the operator is watching their own terminal — so unlike Establish there is
	// no second consumer and no FPS cap to apply.
	chromedp.ListenTarget(tabCtx, func(ev interface{}) {
		e, ok := ev.(*page.EventScreencastFrame)
		if !ok {
			return
		}
		go func() { _ = chromedp.Run(tabCtx, page.ScreencastFrameAck(e.SessionID)) }()
		data, derr := base64.StdEncoding.DecodeString(e.Data)
		if derr != nil {
			return
		}
		m.rec.add(time.Now(), data)
	})

	html := term.MirrorPage(term.Options{Watermark: o.Watermark})
	if err := chromedp.Run(tabCtx,
		emulation.SetDeviceMetricsOverride(w, h, 1, false),
		chromedp.Navigate("about:blank"),
		// setDocumentContent rather than a data: URL — the page carries a 289KB
		// vendored xterm.js, and a data URL that size is at the mercy of Chrome's
		// URL length handling. This hands the same bytes over the debugging
		// protocol, where size is not a question.
		chromedp.ActionFunc(func(ctx context.Context) error {
			tree, err := page.GetFrameTree().Do(ctx)
			if err != nil {
				return err
			}
			return page.SetDocumentContent(tree.Frame.ID, html).Do(ctx)
		}),
		// Wait for xterm to exist rather than sleeping and hoping: writing before
		// it is constructed drops the opening banner, which is the part of a
		// session a reviewer most often wants.
		chromedp.ActionFunc(func(ctx context.Context) error {
			return chromedp.Poll("window.__grReady === true", nil, chromedp.WithPollingTimeout(10*time.Second)).Do(ctx)
		}),
		chromedp.ActionFunc(func(ctx context.Context) error {
			return chromedp.Evaluate(fmt.Sprintf("window.__grResize(%d,%d)", cols, rows), nil).Do(ctx)
		}),
		page.StartScreencast().
			WithFormat("jpeg").
			WithQuality(g.cfg.Quality).
			WithMaxWidth(w).
			WithMaxHeight(h),
	); err != nil {
		cancel()
		return nil, fmt.Errorf("browser: start terminal mirror: %w", err)
	}

	go m.pump()
	return m, nil
}

// mirrorViewport sizes the tab to the terminal grid, clamped so that neither a
// tiny nor an absurd geometry produces an unusable recording.
func mirrorViewport(cols, rows int) (int64, int64) {
	w := int64(cols*mirrorCellW + mirrorPadPx)
	h := int64(rows*mirrorCellH + mirrorPadPx)
	return clamp64(w, mirrorMinW, mirrorMaxW), clamp64(h, mirrorMinH, mirrorMaxH)
}

func clamp64(v, lo, hi int64) int64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// Write buffers device output for the next flush. It never blocks and never
// touches the browser: this is called from the terminal's copy loop, and the
// operator's latency must not depend on how a headless renderer is coping.
func (m *mirror) Write(b []byte) {
	if len(b) == 0 {
		return
	}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if len(m.pending)+len(b) > mirrorMaxPending {
		m.dropped += len(b)
		m.mu.Unlock()
		return
	}
	m.pending = append(m.pending, b...)
	m.mu.Unlock()
	select {
	case m.flushSig <- struct{}{}:
	default: // a flush is already scheduled; this output rides along with it
	}
}

// Resize follows the operator's terminal geometry.
func (m *mirror) Resize(cols, rows int) {
	if cols <= 0 || rows <= 0 {
		return
	}
	w, h := mirrorViewport(cols, rows)
	m.mu.Lock()
	m.w, m.h = w, h
	closed := m.closed
	m.mu.Unlock()
	if closed {
		return
	}
	// Fire and forget. A resize that loses a race with teardown is not worth
	// holding the caller for.
	go func() {
		_ = chromedp.Run(m.tabCtx,
			emulation.SetDeviceMetricsOverride(w, h, 1, false),
			chromedp.ActionFunc(func(ctx context.Context) error {
				return chromedp.Evaluate(fmt.Sprintf("window.__grResize(%d,%d)", cols, rows), nil).Do(ctx)
			}),
		)
	}()
}

// pump coalesces buffered output into one browser call per interval.
//
// Batching is the whole point. A busy terminal produces many small writes, and
// one CDP round trip each would cost more than rendering them; at 50ms the
// browser is asked at most twenty times a second regardless of how chatty the
// device is, and the frames still land close enough to real time that the replay
// keeps the session's rhythm.
func (m *mirror) pump() {
	defer close(m.done)
	tick := time.NewTicker(mirrorFlushI)
	defer tick.Stop()
	for {
		select {
		case <-m.tabCtx.Done():
			return
		case <-tick.C:
			m.flush()
		case <-m.flushSig:
			// Coalesce: the ticker does the work. This only wakes a pump that is
			// otherwise idle so the first byte after a quiet spell is not held for
			// the remainder of the interval.
		}
	}
}

func (m *mirror) flush() {
	m.mu.Lock()
	if len(m.pending) == 0 {
		m.mu.Unlock()
		return
	}
	buf := m.pending
	m.pending = nil
	m.mu.Unlock()

	js := "window.__grWrite(\"" + base64.StdEncoding.EncodeToString(buf) + "\")"
	if err := chromedp.Run(m.tabCtx, chromedp.Evaluate(js, nil)); err != nil {
		// Losing a batch degrades the video; it must not disturb the session or
		// the transcript, so it is logged and dropped.
		m.log.Debug("mirror: write to renderer failed", zap.Error(err))
	}
}

// Close flushes what is pending, stops the screencast and writes the video.
func (m *mirror) Close(ctx context.Context) error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	dropped := m.dropped
	m.mu.Unlock()

	// One last batch, then a moment for the renderer to paint it and for the
	// screencast to deliver the resulting frame. Without the pause the final
	// screen — often the most interesting one — is missing from the recording.
	m.flush()
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
	}

	_ = chromedp.Run(m.tabCtx, page.StopScreencast())

	w, h := m.w, m.h
	frames, err := m.rec.flush(ctx, m.blobs, m.store, m.recording, m.orgID, w, h)

	// The tab is cancelled only after the frames are safely out, because the
	// recorder's buffer lives in this process and cancelling first would race the
	// listener that is still appending to it.
	m.cancel()
	<-m.done

	if err != nil {
		return fmt.Errorf("browser: flush terminal mirror: %w", err)
	}
	if dropped > 0 {
		m.log.Warn("mirror: dropped device output under load; video is incomplete",
			zap.Int("dropped_bytes", dropped), zap.String("session", m.recording.SessionID.String()))
	}
	m.log.Info("mirror: terminal video captured",
		zap.String("session", m.recording.SessionID.String()), zap.Int("frames", frames))
	return nil
}

var _ access.TerminalMirrorFactory = (*Gateway)(nil)
