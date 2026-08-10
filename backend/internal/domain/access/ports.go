package access

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// SessionRepository persists access sessions (tenant-scoped).
type SessionRepository interface {
	Create(ctx context.Context, s Scope, sess *Session) error
	GetByID(ctx context.Context, s Scope, id uuid.UUID) (*Session, error)
	List(ctx context.Context, s Scope, filter SessionFilter) ([]Session, error)
	// ListView returns one page of sessions enriched with display names, plus the
	// total number of rows the filter matches. The total comes back with the page
	// because a pager needs both and they must agree: counting separately lets a
	// session end between the two queries and page the reviewer off the end.
	ListView(ctx context.Context, s Scope, filter SessionFilter) ([]SessionView, int, error)
	// Stats returns the live totals across every session in scope.
	Stats(ctx context.Context, s Scope) (SessionStats, error)
	// UpdateStatus transitions a session and stamps timing fields.
	UpdateStatus(ctx context.Context, s Scope, id uuid.UUID, status Status, endReason string, at time.Time) error
	// CountActive returns the number of active sessions in the tenant.
	CountActive(ctx context.Context, s Scope) (int, error)
	// ExpireOverdue marks active sessions past their window as expired
	// (cross-tenant maintenance).
	ExpireOverdue(ctx context.Context, now time.Time) (int, error)
	// ExpireIdle ends active sessions that have gone untouched for longer than
	// their device's idle timeout, returning the ones it ended so the caller can
	// tear their gateways down. Cross-tenant maintenance.
	ExpireIdle(ctx context.Context, now time.Time) ([]ExpiredSession, error)
	// TouchActivity stamps a session as recently used. Callers throttle: this is
	// on the path of every proxied request and every keystroke.
	TouchActivity(ctx context.Context, id uuid.UUID, at time.Time) error
}

// ExpiredSession identifies a session the reaper closed. Protocol comes along
// because tearing the session down means finding the gateway that serves it.
type ExpiredSession struct {
	ID       uuid.UUID
	OrgID    uuid.UUID
	Protocol Protocol
}

// ActivitySink records that a session is being used, so an idle one can be told
// apart from a busy one.
//
// It is a port on the gateways rather than something the delivery layer does,
// because "the operator is still there" is not visible at the HTTP layer in
// every mode: an isolated session holds a single long-lived WebSocket, so an
// operator typing steadily for an hour makes no further HTTP requests at all.
// Watching only requests would reap exactly the session someone is working in.
//
// Implementations must be non-blocking and self-throttling: this is called for
// every proxied asset and every keystroke.
type ActivitySink interface {
	Touch(sessionID uuid.UUID)
}

// SessionFilter narrows a session listing.
//
// Search, Sort and Offset exist so that paging, searching and sorting all happen
// where the rows are. The console used to pull a fixed slab of sessions and do
// all three in the browser, which quietly turned every count into "or the slab
// size, whichever is smaller" and made the search box mean "search the part we
// happened to fetch". For an audit console that is worse than no search at all.
type SessionFilter struct {
	Status   Status
	UserID   *uuid.UUID
	DeviceID *uuid.UUID
	Limit    int
	Offset   int
	// Search matches device name, client IP, protocol and status, and — only when
	// the caller may read users — the operator's email. Case-insensitive substring.
	Search string
	// SearchEmail permits the email predicate. It is a separate flag rather than
	// something derived here because the domain does not know the caller's
	// permissions; the delivery layer sets it from session:read + user:read.
	SearchEmail bool
	// SortBy is a logical column name (see SessionSortColumns). Anything else
	// falls back to newest-first, so an unknown value cannot become raw SQL.
	SortBy   string
	SortDesc bool
}

// SessionSortColumns are the sortable columns a client may name. The repository
// maps these to SQL; a value outside this set is ignored rather than
// interpolated.
var SessionSortColumns = map[string]struct{}{
	"created": {}, "started": {}, "duration": {}, "user": {},
	"device": {}, "protocol": {}, "status": {}, "ip": {},
}

// SessionView is one session enriched with the display names a reviewer needs.
//
// A read model rather than fields on Session: the aggregate is what the broker
// operates on, and it has no business carrying an email that belongs to another
// bounded context. Mirrors iam.AuthSessionView, which exists for the same reason.
type SessionView struct {
	Session
	// UserEmail is empty when the caller may not read users, or when the account
	// has since been deleted. Callers must not treat empty as "no user".
	UserEmail string
	// The device's label is NOT here. It lives on Session, snapshotted at connect,
	// precisely so that deleting the device cannot blank it — a join-supplied name
	// would go empty the moment the device row went away, which is the bug this
	// read model used to have.
}

// SessionStats are the live totals behind the console's counters. They are
// computed over every session in scope, not over the page being displayed.
type SessionStats struct {
	Total   int
	Active  int
	Ended   int
	Devices int
}

// EventRecorder appends timeline events for a session (URL changes, etc.), used
// for playback and audit. Recording of video/screenshots is handled by a
// gateway-specific Recorder introduced with the Chromium gateway.
type EventRecorder interface {
	RecordEvent(ctx context.Context, sessionID uuid.UUID, kind string, data map[string]any) error
	ListEvents(ctx context.Context, s Scope, sessionID uuid.UUID, limit int) ([]Event, error)
}

// Event is one entry in a session's timeline.
type Event struct {
	Timestamp time.Time
	Kind      string
	Data      map[string]any
}

// LiveRegistry tracks active sessions in a fast store (Redis) for real-time
// monitoring and cross-node termination signalling.
type LiveRegistry interface {
	Add(ctx context.Context, orgID, sessionID uuid.UUID, ttl time.Duration) error
	Remove(ctx context.Context, orgID, sessionID uuid.UUID) error
	ListActive(ctx context.Context, orgID uuid.UUID) ([]uuid.UUID, error)
	// SignalTerminate publishes a termination request other nodes observe.
	SignalTerminate(ctx context.Context, sessionID uuid.UUID) error
}

// Recording is the metadata for a session recording (artifacts — video,
// screenshots — are stored in the object store and referenced separately by the
// Chromium gateway).
type Recording struct {
	ID         uuid.UUID
	SessionID  uuid.UUID
	Status     string
	StartedAt  time.Time
	EndedAt    *time.Time
	DurationMS *int64
}

// RecordingStore persists recording metadata and retention.
type RecordingStore interface {
	Start(ctx context.Context, s Scope, sessionID uuid.UUID, retention time.Duration) (*Recording, error)
	Finalize(ctx context.Context, sessionID uuid.UUID, at time.Time) error
	GetBySession(ctx context.Context, s Scope, sessionID uuid.UUID) (*Recording, error)
	// AddArtifact records one stored object belonging to a recording.
	AddArtifact(ctx context.Context, recordingID uuid.UUID, a Artifact) error
	// GetArtifact returns a recording's artifact of the given kind, tenant-scoped
	// through the parent recording.
	GetArtifact(ctx context.Context, s Scope, sessionID uuid.UUID, kind string) (*Artifact, error)
	// ListArtifacts returns every artifact of a recording, tenant-scoped. Deletion
	// needs the object keys: the rows are only pointers, and dropping them without
	// the blobs frees no storage at all — which is the entire reason to delete.
	ListArtifacts(ctx context.Context, s Scope, sessionID uuid.UUID) ([]Artifact, error)
	// Delete removes a recording and its artifact rows, tenant-scoped. The blobs
	// are the caller's to free first: a row deleted before its bytes leaves an
	// object nothing points to, unreachable and unbilled to anyone.
	Delete(ctx context.Context, s Scope, sessionID uuid.UUID) error
	// FindBySessionSystem resolves a recording without a tenant scope, for the
	// gateway — which finalizes recordings from a background teardown with no
	// acting user.
	FindBySessionSystem(ctx context.Context, sessionID uuid.UUID) (*Recording, error)
}

// Artifact kinds. A recording is stored as two objects: the payload, and a
// manifest describing where each piece sits and when it was captured. Keeping
// them separate means the player can read the (small) manifest and then fetch
// only the payload it needs.
//
// The payload's kind is what tells a player which kind of session it is looking
// at. A web session under isolation yields frames; an SSH session yields the
// terminal transcript, which is a fraction of the size and, unlike pixels, can be
// searched. These values are CHECK-constrained in recording_artifacts.kind, so
// they are not free-form.
const (
	ArtifactVideo      = "video"      // concatenated JPEG frames
	ArtifactManifest   = "metadata"   // JSON index over the frames
	ArtifactTranscript = "transcript" // terminal output bytes
	// ArtifactTranscriptIndex is the transcript's chunk index.
	//
	// Distinct from ArtifactManifest because a terminal device can be set to
	// capture a transcript AND video, and one recording would then hold two
	// indexes under one kind — leaving the playback endpoint, which fetches a
	// manifest by kind, to return whichever row came back first. Recordings
	// written before this kind existed keep their index under ArtifactManifest,
	// and the transcript lookup falls back to it.
	ArtifactTranscriptIndex = "transcript_index"
	// ArtifactDesktop is an RDP/VNC session as a Guacamole protocol dump, written
	// by guacd. It carries its own timing, so unlike the frames it needs no
	// separate manifest.
	ArtifactDesktop = "desktop"
)

// TerminalMirror records a terminal session as video, alongside — never instead
// of — whatever else that session captures.
//
// A transcript is evidence of what the device printed; video is evidence of what
// the operator saw. Those diverge exactly where it matters most: a curses UI, a
// progress bar redrawing in place, a screen cleared before the reviewer's eyes.
// A device may be set to capture both, and this is the second one.
//
// Implementations MUST NOT block Write. It sits on the terminal's output path,
// between the device and the operator's screen, and an implementation that waits
// on a browser round trip there would make recording a device slower to type on
// than not recording it — which is a tax on doing the right thing.
type TerminalMirror interface {
	// Write mirrors device output. Non-blocking.
	Write(b []byte)
	// Resize follows the operator's terminal geometry, so the recording wraps
	// lines where the real session wrapped them.
	Resize(cols, rows int)
	// Close flushes what is pending and writes the video artifact. It takes its
	// own context: teardown usually runs because the session's context is already
	// cancelled, and a recording that dies with the session is no recording.
	Close(ctx context.Context) error
}

// RecordsKind reports whether a resolved recording policy asks for a particular
// capture. Kinds arrive from Endpoint.RecordingKinds already settled against the
// device's protocol, so this is a membership test and nothing more.
func RecordsKind(kinds []string, kind string) bool {
	for _, k := range kinds {
		if k == kind {
			return true
		}
	}
	return false
}

// Captures reports whether this endpoint's policy asks for a given capture.
//
// Gateways must ask this rather than testing RecordingKinds directly, because an
// endpoint can be recorded and name no kinds at all: one built before the column
// existed, or by any caller that sets RecordSessions without settling the set.
// A bare membership test answers "capture nothing" there, which turns a device
// whose policy reads "recorded" into one that silently produces no evidence —
// the exact failure this package exists to prevent. An unqualified set falls
// back to the single capture the protocol always produced.
func (e Endpoint) Captures(kind string) bool {
	if !e.RecordSessions {
		return false
	}
	if len(e.RecordingKinds) > 0 {
		return RecordsKind(e.RecordingKinds, kind)
	}
	return kind == defaultCapture(e.Protocol)
}

// defaultCapture is what a protocol captured before the choice existed. It
// mirrors assets.DefaultRecordingKinds; the two contexts keep their own protocol
// vocabularies, and this is the access side of the same rule.
func defaultCapture(p Protocol) string {
	switch p {
	case ProtocolSSH, ProtocolTelnet:
		return ArtifactTranscript
	case ProtocolRDP, ProtocolVNC:
		return ArtifactDesktop
	default:
		return ArtifactVideo
	}
}

// MirrorOptions parameterise a terminal mirror.
type MirrorOptions struct {
	// Cols and Rows are the terminal's geometry at open time. 0 means the
	// conventional 80x24.
	Cols, Rows int
	// Watermark is the attribution composited into the captured frames.
	Watermark string
}

// TerminalMirrorFactory opens mirrors for terminal gateways.
//
// Optional on every gateway that takes one: a deployment with no usable Chromium
// still brokers and transcribes terminal sessions, it just cannot also film them.
type TerminalMirrorFactory interface {
	// OpenMirror starts recording video for a session. The returned mirror is
	// owned by the caller and must be closed.
	OpenMirror(ctx context.Context, rec *Recording, orgID uuid.UUID, o MirrorOptions) (TerminalMirror, error)
}

// Artifact is one stored object belonging to a recording.
type Artifact struct {
	ID          uuid.UUID
	RecordingID uuid.UUID
	Kind        string
	ObjectKey   string
	SizeBytes   int64
	ContentType string
	Checksum    string
	CreatedAt   time.Time
}

// BlobStore stores recording artifacts as opaque bytes under a key. It is the
// seam between the recorder and wherever bytes actually live: the shipped
// implementation writes to a local directory, and an S3/MinIO backend can be
// dropped in without the recorder changing.
type BlobStore interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, error)
	Delete(ctx context.Context, key string) error
}

// DeviceLookup returns the target endpoint details a gateway needs. It decouples
// the access context from the assets context.
type DeviceLookup interface {
	Endpoint(ctx context.Context, s Scope, deviceID uuid.UUID) (Endpoint, error)
}

// Endpoint is the resolved target for a device.
type Endpoint struct {
	Protocol Protocol
	// BaseURL is only meaningful for the web protocols; a terminal or desktop
	// gateway dials Host:Port instead, because there is no URL to fetch.
	BaseURL       string
	Host          string
	Port          int
	VerifyTLS     bool
	CustomHeaders map[string]string
	// Name and DeviceType are the device's labels, carried so the broker can
	// snapshot them onto the session it creates. A session must record what it
	// connected to at the time, or deleting the device rewrites the audit trail.
	Name       string
	DeviceType string
	// AllowUnmanaged permits a brokered session with no bound credential
	// (break-glass). When false (the default), Connect fails closed.
	AllowUnmanaged bool
	// RecordSessions is the device's recording policy. When false the broker
	// creates no recording, and the gateway therefore captures no frames.
	RecordSessions bool
	// RecordingKinds is what a recorded session captures — the assets package's
	// Record* values, already resolved against the protocol, so a gateway can
	// take this at face value rather than re-deriving policy. Empty whenever
	// RecordSessions is false.
	//
	// A terminal gateway reads this to decide whether the session needs a video
	// mirror alongside the transcript; a gateway with only one capture to make
	// can ignore it entirely.
	RecordingKinds []string
	// Isolate selects the isolated gateway (a browser on the server) over the
	// reverse proxy.
	//
	// The broker used to derive this from RecordSessions, which tied a delivery
	// decision to an evidence decision and made "isolated but not recorded"
	// unreachable — the mode an appliance SPA needs, since it cannot be re-served
	// under a path prefix at all. Recording still requires isolation, so Isolate
	// is true whenever RecordSessions is; the reverse does not hold.
	Isolate bool
	// IdleTimeoutMinutes ends the session after this long with no operator
	// activity. 0 disables idle expiry for the device.
	IdleTimeoutMinutes int
}

// Authorizer answers resource-level entitlement questions for the broker:
// whether a user's roles actually reach a specific device. This is distinct from
// the coarse permission check (device:connect) enforced at the delivery layer —
// it scopes access to particular devices by device type and asset-group
// membership. Implementations must be tenant-scoped via the passed Scope.
type Authorizer interface {
	// CanAccessDevice reports whether the user is entitled to broker a session to
	// the given device under any of their roles. A user with a role whose device
	// scope is "all" reaches every device in the org; otherwise access is the
	// union of that role's granted device types and asset groups.
	CanAccessDevice(ctx context.Context, s Scope, userID, deviceID uuid.UUID) (bool, error)
}
