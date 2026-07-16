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
type SessionFilter struct {
	Status   Status
	UserID   *uuid.UUID
	DeviceID *uuid.UUID
	Limit    int
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
	ArtifactManifest   = "metadata"   // JSON index over the payload
	ArtifactTranscript = "transcript" // terminal output bytes
	// ArtifactDesktop is an RDP/VNC session as a Guacamole protocol dump, written
	// by guacd. It carries its own timing, so unlike the frames it needs no
	// separate manifest.
	ArtifactDesktop = "desktop"
)

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
	// AllowUnmanaged permits a brokered session with no bound credential
	// (break-glass). When false (the default), Connect fails closed.
	AllowUnmanaged bool
	// RecordSessions is the device's recording policy. When false the broker
	// creates no recording, and the gateway therefore captures no frames.
	RecordSessions bool
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
