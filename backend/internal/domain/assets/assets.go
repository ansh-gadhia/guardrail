// Package assets is the device-inventory bounded context: target devices and the
// groups that organize them. It is independent of IAM and vault.
package assets

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

// ErrNotFound is returned when a device or group does not exist in scope.
var ErrNotFound = errors.New("assets: not found")

// ErrInvalid marks input the service refuses rather than corrects.
var ErrInvalid = errors.New("assets: invalid")

// schemePorts is the closed set of protocols a device can be reached over, and
// the port each answers on by convention.
//
// The access context has the same vocabulary (access.Protocols) because it
// routes on it; the two are checked against each other in a test rather than
// shared, since the bounded contexts do not import one another. If you add one
// here, add it there — and only once something can actually broker it.
var schemePorts = map[string]int{
	"https":  443,
	"http":   80,
	"ssh":    22,
	"rdp":    3389,
	"vnc":    5900,
	"telnet": 23,
}

// ValidScheme reports whether a protocol is one this platform understands.
func ValidScheme(s string) bool {
	_, ok := schemePorts[s]
	return ok
}

// DefaultPortFor returns the conventional port for a protocol.
func DefaultPortFor(s string) (int, bool) {
	p, ok := schemePorts[s]
	return p, ok
}

// Schemes lists every known protocol, in a stable order.
func Schemes() []string { return []string{"https", "http", "ssh", "rdp", "vnc", "telnet"} }

// IsWebScheme reports whether a device is reached over a web UI, which is the
// only kind with a delivery mode to choose. A terminal or desktop device has one
// gateway and no choice: it stores DeliveryProxy, meaning "not applicable".
func IsWebScheme(s string) bool { return s == "https" || s == "http" }

// Delivery modes: how a brokered session reaches the operator. Web devices only.
const (
	// DeliveryProxy re-serves the device's own HTML under /proxy/<sid>/, with the
	// vaulted credential injected server-side. Cheap, but the device's markup and
	// scripts run in the operator's browser, so every URL the page builds has to
	// be caught by rewriting — and some (a compiled-in router base, for one)
	// cannot be. It is also what a non-web device stores, where it means only
	// "no isolation", because there is nothing else it could mean.
	DeliveryProxy = "proxy"
	// DeliveryIsolated runs the device in a browser on the server; the operator
	// receives pixels and sends input. Costs a browser process per session, and in
	// exchange the device loads at its own origin with nothing rewritten, the
	// watermark cannot be removed from the DOM because the DOM never leaves the
	// host, and frames can be recorded.
	DeliveryIsolated = "isolated"
)

// deliveryModes is the closed set, in a stable order.
var deliveryModes = []string{DeliveryProxy, DeliveryIsolated}

// ValidDelivery reports whether m is a delivery mode this platform serves.
func ValidDelivery(m string) bool {
	for _, d := range deliveryModes {
		if d == m {
			return true
		}
	}
	return false
}

// DeliveryModes lists every delivery mode, in a stable order.
func DeliveryModes() []string { return append([]string(nil), deliveryModes...) }

// RecordingImpossible reports whether this device could not be recorded as
// configured, and so must be refused rather than stored.
//
// A recorded web device has to be isolated: recording captures frames from the
// server-side browser, and the reverse proxy has no browser and never sees
// pixels. A device whose policy reads "recording on" while nothing is captured is
// worse than one with recording off, because then the audit trail claims evidence
// that does not exist.
//
// The rule is "recording needs a gateway that can capture", not "recording needs
// a browser", which is why this is scoped to web schemes. SSH is recorded by its
// own gateway keeping the transcript, with no browser involved, so a recorded SSH
// device is achievable on any host and must not be refused here.
func RecordingImpossible(scheme, mode string, record bool) bool {
	return record && IsWebScheme(scheme) && mode != DeliveryIsolated
}

// ErrForbidden is returned when the actor may edit a device but not make this
// particular change — currently, changing the recording policy of a device they
// did not register.
var ErrForbidden = errors.New("assets: forbidden")

// Scope is the tenant scope for asset operations.
type Scope struct {
	OrganizationID uuid.UUID
	IsSuperAdmin   bool
}

// Device is a target HTTP/HTTPS administrative interface.
type Device struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	Name           string
	Description    string
	Vendor         string
	DeviceType     string
	Host           string
	Port           int
	Scheme         string // http | https
	VerifyTLS      bool
	CustomHeaders  map[string]string
	Tags           []string
	Status         string
	// AllowUnmanaged permits a brokered session with no bound credential
	// (break-glass). Default false makes Connect fail closed when no credential
	// is bound — the platform never dumps a user at a device's own login page.
	AllowUnmanaged bool
	// RecordSessions enables screen recording of sessions brokered to this device.
	// Defaults on: recording is the posture you should get without thinking about
	// it, and turning it off is a deliberate act by the device's owner.
	//
	// Recording only exists under DeliveryIsolated — frames are captured from the
	// server-side browser, and the reverse proxy never sees pixels. ValidDelivery
	// / the storage CHECK refuse the impossible combination rather than letting a
	// device claim to be recorded while nothing is captured.
	RecordSessions bool
	// DeliveryMode is how a session to this device reaches the operator:
	// DeliveryProxy re-serves the device's own HTML under a session prefix, and
	// DeliveryIsolated runs the device in a browser on the server and sends
	// pixels.
	//
	// It is a separate decision from recording. Isolation earns its keep on its
	// own for anything that ships a real single-page app: such a UI resolves its
	// router base and navigates in ways nothing outside the page can intercept, so
	// re-serving it under a path prefix cannot be made to work, while isolation
	// loads it at its own origin where it simply does.
	DeliveryMode string
	// IdleTimeoutMinutes ends a session that has sat unused for this long. It is
	// a different control from the granted window, which caps total lifetime: a
	// session abandoned five minutes into a two-hour grant is an unattended,
	// credential-injected door held open for the remaining hour and fifty-five.
	// 0 opts the device out.
	IdleTimeoutMinutes int
	// CreatedBy is who registered the device. It governs who may change the
	// recording policy; nil when the creator's account has since been removed.
	CreatedBy *uuid.UUID
	CreatedAt time.Time
	UpdatedAt time.Time
	// Health is the device's last observed liveness, maintained by the health
	// poller. Nil when the device has never been probed.
	Health *Health
}

// CanSetRecording reports whether the given user may change this device's
// recording policy. Recording is an accountability control, so the set of people
// who can switch it off is deliberately narrow: the person who registered the
// device, and super admins. A device:write grant is enough to edit a device's
// address — it is not enough to stop it being recorded.
func (d *Device) CanSetRecording(userID uuid.UUID, isSuperAdmin bool) bool {
	if isSuperAdmin {
		return true
	}
	return d.CreatedBy != nil && *d.CreatedBy == userID
}

// HealthStatus is a device's reachability as of the last probe.
type HealthStatus string

const (
	// HealthUnknown means the device has not been probed yet (or the probe could
	// not run). It is deliberately distinct from Offline: "we haven't looked" is
	// not the same claim as "we looked and it's down".
	HealthUnknown HealthStatus = "unknown"
	HealthOnline  HealthStatus = "online"
	HealthOffline HealthStatus = "offline"
)

// Health is the result of probing a device's management endpoint.
type Health struct {
	Status              HealthStatus
	CheckedAt           *time.Time
	LatencyMS           *int
	ConsecutiveFailures int
	LastError           string
}

// BaseURL returns the device's management URL (scheme://host:port).
func (d *Device) BaseURL() string {
	return d.Scheme + "://" + d.hostport()
}

func (d *Device) hostport() string {
	// Elide default ports for cleanliness.
	if (d.Scheme == "https" && d.Port == 443) || (d.Scheme == "http" && d.Port == 80) {
		return d.Host
	}
	return d.Host + ":" + itoa(d.Port)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [6]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// AssetGroup is a folder or dynamic grouping of devices; groups may nest.
type AssetGroup struct {
	ID             uuid.UUID
	OrganizationID uuid.UUID
	ParentID       *uuid.UUID
	Name           string
	Type           string // folder | dynamic
	MatchRules     map[string]any
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// DeviceRepository persists devices (tenant-scoped).
type DeviceRepository interface {
	Create(ctx context.Context, s Scope, d *Device) error
	Update(ctx context.Context, s Scope, d *Device) error
	GetByID(ctx context.Context, s Scope, id uuid.UUID) (*Device, error)
	List(ctx context.Context, s Scope, f Filter) ([]Device, error)
	SoftDelete(ctx context.Context, s Scope, id uuid.UUID) error
	Count(ctx context.Context, s Scope) (int, error)
}

// Filter narrows a device listing.
type Filter struct {
	Vendor string
	Tag    string
	Search string
	Limit  int
}

// HealthRepository persists device liveness. Its methods are system-scoped
// (cross-tenant) because the poller probes every organization's devices from a
// single background loop — there is no acting user to scope to.
type HealthRepository interface {
	// ListProbeTargets returns every active device across all tenants, with just
	// the fields a probe needs.
	ListProbeTargets(ctx context.Context) ([]ProbeTarget, error)
	// Upsert records the outcome of one probe.
	Upsert(ctx context.Context, deviceID uuid.UUID, h Health) error
}

// ProbeTarget is the minimal device projection the health poller needs.
type ProbeTarget struct {
	DeviceID  uuid.UUID
	Host      string
	Port      int
	Scheme    string
	VerifyTLS bool
	// ConsecutiveFailures carries the current failure streak so the poller can
	// increment it without a second round-trip.
	ConsecutiveFailures int
}

// BaseURL returns the probe target's management URL.
func (p ProbeTarget) BaseURL() string {
	d := Device{Host: p.Host, Port: p.Port, Scheme: p.Scheme}
	return d.BaseURL()
}

// AssetGroupRepository persists asset groups and membership.
type AssetGroupRepository interface {
	Create(ctx context.Context, s Scope, g *AssetGroup) error
	List(ctx context.Context, s Scope) ([]AssetGroup, error)
	AddMember(ctx context.Context, s Scope, groupID, deviceID uuid.UUID) error
	RemoveMember(ctx context.Context, s Scope, groupID, deviceID uuid.UUID) error
	// ListDeviceGroups returns the group ids a device belongs to.
	ListDeviceGroups(ctx context.Context, s Scope, deviceID uuid.UUID) ([]uuid.UUID, error)
	// SetDeviceGroups replaces a device's group membership with the given set.
	SetDeviceGroups(ctx context.Context, s Scope, deviceID uuid.UUID, groupIDs []uuid.UUID) error
}
