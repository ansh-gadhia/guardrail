package v1

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	appaccess "github.com/guardrail/guardrail/internal/app/access"
	domaccess "github.com/guardrail/guardrail/internal/domain/access"
)

// SessionServer serves the browser-facing side of a live session. The reverse-
// proxy gateway and the browser-isolation gateway both implement it, so the
// delivery layer is agnostic to which is active.
type SessionServer interface {
	// Console serves the entry response at /proxy/<sid>/<path> (the proxied device
	// response, or the canvas viewer for browser isolation). false => bad session.
	Console(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token, path string) bool
	// Stream upgrades to the interactive streaming WebSocket. Gateways that do not
	// stream (the reverse proxy) return false.
	Stream(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool
}

// SessionMux dispatches a request to whichever gateway is holding the session.
//
// Both delivery modes can be live at once — recorded devices are isolated while
// the rest are proxied — so the delivery layer can no longer be handed a single
// server. It does not need to look the session up to route it: a gateway keys
// its live sessions by id and reports false without touching the
// ResponseWriter when the id is not one of its own, so trying each in turn
// resolves the owner. The alternative, re-reading the device's recording policy
// per request, would route to the wrong gateway the moment an owner flipped that
// policy mid-session.
type SessionMux []SessionServer

// Console serves the session entry from the owning gateway.
func (m SessionMux) Console(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token, path string) bool {
	for _, s := range m {
		if s.Console(w, r, sid, token, path) {
			return true
		}
	}
	return false
}

// Stream upgrades the session's socket on the owning gateway. Only isolated
// sessions stream; the reverse proxy always declines, so an unmatched id here
// simply means "no streaming session by that id".
func (m SessionMux) Stream(w http.ResponseWriter, r *http.Request, sid uuid.UUID, token string) bool {
	for _, s := range m {
		if s.Stream(w, r, sid, token) {
			return true
		}
	}
	return false
}

// wsSentinel is the sub-path under /proxy/<sid>/ that maps to the streaming
// WebSocket (kept under the session prefix so the session cookie is sent).
const wsSentinel = "__ws__"

// AccessHandler exposes the connect/session routes and the proxy endpoint.
type AccessHandler struct {
	svc     *appaccess.Service
	gateway SessionServer
	secure  bool
}

// NewAccessHandler constructs an AccessHandler.
func NewAccessHandler(svc *appaccess.Service, gw SessionServer, secure bool) *AccessHandler {
	return &AccessHandler{svc: svc, gateway: gw, secure: secure}
}

// Register mounts the connect + session API routes (auth + RBAC protected).
func (h *AccessHandler) Register(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	rg.POST("/devices/:id/connect", authMW, middleware.RequirePermission("device:connect"), h.connect)
	// Any authenticated user may read delivery capabilities: it says what the
	// server can do, not anything about a tenant's data.
	rg.GET("/capabilities", authMW, h.capabilities)

	s := rg.Group("/sessions", authMW)
	{
		s.GET("", middleware.RequirePermission("session:read"), h.list)
		s.GET("/active", middleware.RequirePermission("session:read"), h.active)
		s.GET("/:id", middleware.RequirePermission("session:read"), h.get)
		// Session playback timeline is a recording read, not just a session read.
		s.GET("/:id/events", middleware.RequirePermission("recording:read"), h.events)
		// Playback: metadata, the frame index, and the frames themselves.
		s.GET("/:id/recording", middleware.RequirePermission("recording:read"), h.recording)
		s.GET("/:id/recording/manifest", middleware.RequirePermission("recording:read"), h.recordingManifest)
		s.GET("/:id/recording/frames", middleware.RequirePermission("recording:read"), h.recordingFrames)
		s.GET("/:id/recording/transcript", middleware.RequirePermission("recording:read"), h.recordingTranscript)
		s.GET("/:id/recording/desktop", middleware.RequirePermission("recording:read"), h.recordingDesktop)
		s.DELETE("/:id/recording", middleware.RequirePermission("recording:delete"), h.recordingDelete)
		s.POST("/:id/terminate", middleware.RequirePermission("session:terminate"), h.terminate)
	}
}

// capabilities reports what this deployment can actually deliver.
//
// Both keys read the same thing — whether a usable Chromium resolved at startup —
// and they are reported separately because they fail differently, and the console
// has to say which one an operator is about to hit. Without isolation, an isolated
// device silently degrades to a reverse-proxy session (it still connects, and an
// appliance SPA still breaks); a recorded device is refused outright, because a
// session that captures nothing while the policy reads "recording on" is the gap
// nobody finds until they go looking for the evidence.
func (h *AccessHandler) capabilities(c *gin.Context) {
	iso := h.svc.IsolationAvailable()
	c.JSON(http.StatusOK, gin.H{"session_recording": iso, "browser_isolation": iso})
}

// RegisterProxy mounts the browser-facing proxy endpoint on the root engine. It
// is authenticated by the per-session HttpOnly proxy cookie, not the API bearer
// token (browser navigations don't carry bearer headers).
func (h *AccessHandler) RegisterProxy(e *gin.Engine) {
	e.Any("/proxy/:sid/*path", h.proxy)
}

func proxyCookieName(sid string) string { return "guardrail_proxy_" + sid }

func (h *AccessHandler) connect(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	deviceID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid device id")
		return
	}
	res, err := h.svc.Connect(c.Request.Context(), actor, deviceID,
		accessMeta(c))
	if err != nil {
		failAccess(c, err)
		return
	}
	h.writeConnected(c, res)
}

// writeConnected sets the proxy cookie and returns the connected session info.
func (h *AccessHandler) writeConnected(c *gin.Context, res *appaccess.ConnectResult) {
	// Bind the browser to this session with an HttpOnly cookie scoped to the
	// session's proxy path. This is a session handle, never a device credential.
	sid := res.Session.ID.String()
	maxAge := int(time.Until(res.GrantedUntil).Seconds())
	if maxAge < 60 {
		maxAge = 60
	}
	c.SetSameSite(http.SameSiteLaxMode)
	c.SetCookie(proxyCookieName(sid), res.ProxyToken, maxAge, "/proxy/"+sid, "", h.secure, true)
	c.JSON(http.StatusOK, gin.H{
		"session_id":    sid,
		"status":        string(res.Session.Status),
		"proxy_url":     res.ProxyPath,
		"granted_until": res.GrantedUntil.UTC().Format("2006-01-02T15:04:05Z07:00"),
	})
}

func (h *AccessHandler) proxy(c *gin.Context) {
	sidStr := c.Param("sid")
	sid, err := uuid.Parse(sidStr)
	if err != nil {
		problem(c, http.StatusBadRequest, "Bad Request", "invalid session id")
		return
	}
	token, err := c.Cookie(proxyCookieName(sidStr))
	if err != nil || token == "" {
		problem(c, http.StatusUnauthorized, "Unauthorized", "no proxy session")
		return
	}
	rawPath := strings.TrimPrefix(c.Param("path"), "/")
	// The streaming WebSocket lives under the session prefix so the cookie is sent.
	if rawPath == wsSentinel {
		if !h.gateway.Stream(c.Writer, c.Request, sid, token) {
			problem(c, http.StatusGone, "Session Closed", "the access session is no longer active")
		}
		return
	}
	upstream := rawPath
	if raw := c.Request.URL.RawQuery; raw != "" {
		upstream += "?" + raw
	}
	if !h.gateway.Console(c.Writer, c.Request, sid, token, "/"+upstream) {
		problem(c, http.StatusGone, "Session Closed", "the access session is no longer active")
	}
}

func (h *AccessHandler) list(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	f := domaccess.SessionFilter{Status: domaccess.Status(c.Query("status")), Limit: queryLimit(c)}
	if did, err := uuid.Parse(c.Query("device_id")); err == nil {
		f.DeviceID = &did
	}
	sessions, err := h.svc.List(c.Request.Context(), actor, f)
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": sessionsDTO(sessions)})
}

func (h *AccessHandler) active(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	sessions, err := h.svc.ListActive(c.Request.Context(), actor)
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": sessionsDTO(sessions)})
}

func (h *AccessHandler) get(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid session id")
		return
	}
	s, err := h.svc.Get(c.Request.Context(), actor, id)
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, sessionDTO(s))
}

func (h *AccessHandler) events(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid session id")
		return
	}
	evts, err := h.svc.Events(c.Request.Context(), actor, id, queryLimit(c))
	if err != nil {
		failAccess(c, err)
		return
	}
	out := make([]gin.H, 0, len(evts))
	for _, e := range evts {
		out = append(out, gin.H{"ts": e.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z07:00"), "kind": e.Kind, "data": e.Data})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// recording returns playback metadata for a session. A session whose device has
// recording switched off simply has none — a 404 here is a normal answer, not an
// error, and the console renders it as "not recorded".
func (h *AccessHandler) recording(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid session id")
		return
	}
	rec, err := h.svc.Recording(c.Request.Context(), actor, id)
	if err != nil {
		failAccess(c, err)
		return
	}
	out := gin.H{
		"id": rec.ID.String(), "session_id": rec.SessionID.String(), "status": rec.Status,
		"started_at": rfc3339UTC(rec.StartedAt),
	}
	if rec.EndedAt != nil {
		out["ended_at"] = rfc3339UTC(*rec.EndedAt)
	}
	if rec.DurationMS != nil {
		out["duration_ms"] = *rec.DurationMS
	}
	// Whether there is video to play is a separate question from whether a
	// recording row exists: a session still running, or one that produced no
	// frames, has a row but nothing to draw yet. This reads artifact metadata
	// only — fetching the frames to answer a yes/no question would pull hundreds
	// of megabytes and log a view that never happened.
	out["has_video"] = h.svc.RecordingHasVideo(c.Request.Context(), actor, id)
	// Which player to open. A recorded session is either frames or a transcript,
	// never both, and the console cannot tell from the session alone: the device's
	// protocol decides it, and by playback time the device may have been edited or
	// removed. Report what was actually stored.
	out["has_transcript"] = h.svc.RecordingHasTranscript(c.Request.Context(), actor, id)
	// A desktop is the third kind, and it is not video: guacd writes a Guacamole
	// protocol dump the player replays instruction by instruction, not frames. It
	// therefore answers has_video false and would have read as "recorded nothing"
	// to a console that only knew those two questions — which is exactly how a
	// desktop recording that captured perfectly well came to look like a lost one.
	out["has_desktop"] = h.svc.RecordingHasDesktop(c.Request.Context(), actor, id)
	c.JSON(http.StatusOK, out)
}

// recordingManifest returns the frame index the player reads before drawing.
func (h *AccessHandler) recordingManifest(c *gin.Context) {
	h.serveArtifact(c, domaccess.ArtifactManifest)
}

// recordingFrames returns the concatenated JPEG frames. The player slices this
// blob using the manifest's offsets, so it is served as opaque bytes.
func (h *AccessHandler) recordingFrames(c *gin.Context) {
	h.serveArtifact(c, domaccess.ArtifactVideo)
}

// recordingTranscript returns an SSH session's terminal output. Like the frames,
// it is one blob the player slices with the manifest's offsets — so the pauses
// between the device's replies are replayable, not just the text.
func (h *AccessHandler) recordingTranscript(c *gin.Context) {
	h.serveArtifact(c, domaccess.ArtifactTranscript)
}

// recordingDesktop returns an RDP/VNC session as guacd wrote it: one Guacamole
// protocol dump the player replays instruction by instruction. There is no
// manifest to pair it with — the dump carries its own timing, so unlike the
// frames it needs no index to be seekable.
func (h *AccessHandler) recordingDesktop(c *gin.Context) {
	h.serveArtifact(c, domaccess.ArtifactDesktop)
}

func (h *AccessHandler) serveArtifact(c *gin.Context, kind string) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid session id")
		return
	}
	data, contentType, err := h.svc.RecordingArtifact(c.Request.Context(), actor, id, kind, accessMeta(c))
	if err != nil {
		failAccess(c, err)
		return
	}
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	// A recording never changes once written, so it is safe to cache hard. It is
	// private: it is one tenant's session, not a public asset.
	c.Header("Cache-Control", "private, max-age=31536000, immutable")
	c.Data(http.StatusOK, contentType, data)
}

func accessMeta(c *gin.Context) appaccess.ReqMeta {
	return appaccess.ReqMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

type terminateRequest struct {
	Reason string `json:"reason"`
}

func (h *AccessHandler) terminate(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid session id")
		return
	}
	var req terminateRequest
	_ = c.ShouldBindJSON(&req)
	reason := req.Reason
	if reason == "" {
		reason = "admin_terminate"
	}
	if err := h.svc.Terminate(c.Request.Context(), actor, id, reason,
		accessMeta(c)); err != nil {
		failAccess(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func sessionDTO(s *domaccess.Session) gin.H {
	dto := gin.H{
		"id": s.ID.String(), "device_id": s.DeviceID.String(), "user_id": s.UserID.String(),
		"protocol": string(s.Protocol), "status": string(s.Status), "gateway_node": s.GatewayNode,
		"client_ip": s.ClientIP, "user_agent": s.UserAgent,
		"created_at": rfc3339UTC(s.CreatedAt),
		// The console draws this over a desktop session, which is the only surface
		// where nothing else can: the other gateways stamp the attribution into the
		// document they serve, but a desktop is a canvas of drawing instructions and
		// guacd composites nothing. Attribution text is not a secret — it names the
		// operator to themselves, and the reader already has session:read and the
		// user_id above.
		"watermark": s.WatermarkOr(),
	}
	if s.StartedAt != nil {
		dto["started_at"] = rfc3339UTC(*s.StartedAt)
	}
	if s.EndedAt != nil {
		dto["ended_at"] = rfc3339UTC(*s.EndedAt)
	}
	if s.GrantedUntil != nil {
		dto["granted_until"] = rfc3339UTC(*s.GrantedUntil)
	}
	if s.EndReason != "" {
		dto["end_reason"] = s.EndReason
	}
	return dto
}

func sessionsDTO(sessions []domaccess.Session) []gin.H {
	out := make([]gin.H, 0, len(sessions))
	for i := range sessions {
		out = append(out, sessionDTO(&sessions[i]))
	}
	return out
}

// recordingDelete removes a session's recording and frees its stored bytes.
//
// Gated on recording:delete, which nothing else grants — deleting the record of
// what someone did on a privileged device is not an ordinary administrative
// action, and it is audited before it happens.
func (h *AccessHandler) recordingDelete(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		problem(c, http.StatusBadRequest, "Bad Request", "invalid session id")
		return
	}
	if err := h.svc.DeleteRecording(c.Request.Context(), actor, id, accessMeta(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}
