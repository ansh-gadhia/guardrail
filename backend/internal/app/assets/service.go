// Package assets is the application layer for the device inventory: device CRUD,
// grouping, and the audit that accompanies changes.
package assets

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/domain/assets"
	"github.com/guardrail/guardrail/internal/domain/audit"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// Service implements device and asset-group use cases.
type Service struct {
	devices assets.DeviceRepository
	groups  assets.AssetGroupRepository
	audit   audit.Recorder
}

// NewService constructs the assets service.
func NewService(devices assets.DeviceRepository, groups assets.AssetGroupRepository, rec audit.Recorder) *Service {
	return &Service{devices: devices, groups: groups, audit: rec}
}

// DeviceInput describes a device create/update.
type DeviceInput struct {
	Name           string
	Description    string
	Vendor         string
	DeviceType     string
	Host           string
	Port           int
	Scheme         string
	VerifyTLS      bool
	CustomHeaders  map[string]string
	Tags           []string
	AllowUnmanaged bool
	// RecordSessions is the device's recording policy. A nil pointer leaves it
	// unchanged, which is what lets a caller edit a device without needing rights
	// over recording.
	RecordSessions *bool
	// DeliveryMode is how sessions to this device reach the operator: "proxy" or
	// "isolated". A nil pointer leaves it unchanged.
	//
	// Separate from RecordSessions, because they answer different questions.
	// Recording asks what evidence to keep; delivery asks how the device is put in
	// front of the operator at all — and an appliance whose UI is a real
	// single-page app can only be delivered by isolation, whether or not anyone
	// wants the video.
	DeliveryMode *string
	// IdleTimeoutMinutes ends a session after this long with no operator
	// activity. A nil pointer leaves it unchanged; 0 disables idle expiry for the
	// device.
	IdleTimeoutMinutes *int
	// GroupIDs, when non-nil, replaces the device's asset-group membership. A nil
	// pointer leaves membership untouched (so callers that don't manage groups can
	// omit it); a non-nil empty slice clears all memberships.
	GroupIDs *[]uuid.UUID
	Meta     ReqMeta
}

// defaultIdleTimeout is how long a new device lets a session sit unused. An
// hour is long enough not to interrupt real work and short enough that a walked-
// away-from session is not still open at the end of the day.
const defaultIdleTimeout = 60

// idleOrDefault applies the device default when the caller says nothing.
func idleOrDefault(v *int) int {
	if v == nil {
		return defaultIdleTimeout
	}
	return *v
}

// ReqMeta carries request metadata for auditing.
type ReqMeta struct{ IP, UserAgent string }

func scopeOf(a iam.Claims) assets.Scope {
	return assets.Scope{OrganizationID: a.OrganizationID, IsSuperAdmin: a.IsSuperAdmin}
}

// CreateDevice registers a new device. The registering user becomes its owner
// for the purposes of the recording policy.
func (s *Service) CreateDevice(ctx context.Context, actor iam.Claims, in DeviceInput) (*assets.Device, error) {
	owner := actor.UserID
	scheme, err := schemeOrDefault(in.Scheme)
	if err != nil {
		return nil, err
	}
	record := in.RecordSessions == nil || *in.RecordSessions
	mode, err := deliveryOrDefault(scheme, in.DeliveryMode, "", record)
	if err != nil {
		return nil, err
	}
	d := &assets.Device{
		ID: uuid.New(), OrganizationID: actor.OrganizationID, Name: in.Name, Description: in.Description,
		Vendor: in.Vendor, DeviceType: in.DeviceType, Host: in.Host, Port: portOrDefault(in.Port, scheme),
		Scheme: scheme, VerifyTLS: in.VerifyTLS, CustomHeaders: in.CustomHeaders,
		Tags: in.Tags, Status: "active", AllowUnmanaged: in.AllowUnmanaged,
		// Recording defaults on; an explicit choice at registration wins.
		RecordSessions: record,
		DeliveryMode:   mode,
		// An hour of inactivity ends the session unless the registrant says
		// otherwise. A default of 0 would mean "never", which is not a posture to
		// arrive at by saying nothing.
		IdleTimeoutMinutes: idleOrDefault(in.IdleTimeoutMinutes),
		CreatedBy:          &owner,
	}
	if err := s.devices.Create(ctx, scopeOf(actor), d); err != nil {
		return nil, err
	}
	if in.GroupIDs != nil {
		if err := s.groups.SetDeviceGroups(ctx, scopeOf(actor), d.ID, *in.GroupIDs); err != nil {
			return nil, err
		}
	}
	s.recordDevice(ctx, actor, "device.create", d.ID, in.Meta)
	return d, nil
}

// UpdateDevice mutates an existing device.
func (s *Service) UpdateDevice(ctx context.Context, actor iam.Claims, id uuid.UUID, in DeviceInput) (*assets.Device, error) {
	d, err := s.devices.GetByID(ctx, scopeOf(actor), id)
	if err != nil {
		return nil, err
	}
	// Changing the recording policy is governed separately from editing the
	// device: only the owner or a super admin may switch recording off (or back
	// on). Checked before anything is written, so a refused request changes
	// nothing at all.
	if in.RecordSessions != nil && *in.RecordSessions != d.RecordSessions {
		if !d.CanSetRecording(actor.UserID, actor.IsSuperAdmin) {
			s.recordAsset(ctx, actor, "device.recording_denied", "device", d.ID,
				map[string]any{"requested": *in.RecordSessions})
			return nil, assets.ErrForbidden
		}
		d.RecordSessions = *in.RecordSessions
	}
	if in.IdleTimeoutMinutes != nil {
		d.IdleTimeoutMinutes = *in.IdleTimeoutMinutes
	}
	scheme, err := schemeOrDefault(in.Scheme)
	if err != nil {
		return nil, err
	}
	// Resolved and judged against the values this request settles on, not the
	// stored ones. Two reasons: a device switched from https to ssh in the same
	// call that says nothing about delivery must be judged as the ssh device it is
	// about to become, and turning recording on while switching isolation off has
	// to be refused as a pair rather than a field at a time.
	mode, err := deliveryOrDefault(scheme, in.DeliveryMode, d.DeliveryMode, d.RecordSessions)
	if err != nil {
		return nil, err
	}
	d.DeliveryMode = mode
	d.Name, d.Description, d.Vendor, d.DeviceType = in.Name, in.Description, in.Vendor, in.DeviceType
	d.Host, d.Port, d.Scheme = in.Host, portOrDefault(in.Port, scheme), scheme
	d.VerifyTLS, d.CustomHeaders, d.Tags = in.VerifyTLS, in.CustomHeaders, in.Tags
	d.AllowUnmanaged = in.AllowUnmanaged
	if err := s.devices.Update(ctx, scopeOf(actor), d); err != nil {
		return nil, err
	}
	if in.GroupIDs != nil {
		if err := s.groups.SetDeviceGroups(ctx, scopeOf(actor), d.ID, *in.GroupIDs); err != nil {
			return nil, err
		}
	}
	s.recordDevice(ctx, actor, "device.update", d.ID, in.Meta)
	return d, nil
}

// GetDevice loads a device.
func (s *Service) GetDevice(ctx context.Context, actor iam.Claims, id uuid.UUID) (*assets.Device, error) {
	return s.devices.GetByID(ctx, scopeOf(actor), id)
}

// ListDevices lists devices with an optional filter.
func (s *Service) ListDevices(ctx context.Context, actor iam.Claims, f assets.Filter) ([]assets.Device, error) {
	return s.devices.List(ctx, scopeOf(actor), f)
}

// DeleteDevice soft-deletes a device.
func (s *Service) DeleteDevice(ctx context.Context, actor iam.Claims, id uuid.UUID, meta ReqMeta) error {
	if err := s.devices.SoftDelete(ctx, scopeOf(actor), id); err != nil {
		return err
	}
	s.recordDevice(ctx, actor, "device.delete", id, meta)
	return nil
}

// CountDevices returns the number of active devices in the tenant.
func (s *Service) CountDevices(ctx context.Context, actor iam.Claims) (int, error) {
	return s.devices.Count(ctx, scopeOf(actor))
}

// CreateGroup creates an asset group.
func (s *Service) CreateGroup(ctx context.Context, actor iam.Claims, name, groupType string, parentID *uuid.UUID) (*assets.AssetGroup, error) {
	if groupType == "" {
		groupType = "folder"
	}
	g := &assets.AssetGroup{ID: uuid.New(), OrganizationID: actor.OrganizationID, ParentID: parentID, Name: name, Type: groupType}
	if err := s.groups.Create(ctx, scopeOf(actor), g); err != nil {
		return nil, err
	}
	s.recordAsset(ctx, actor, "group.create", "group", g.ID, map[string]any{"name": name, "type": groupType})
	return g, nil
}

// ListGroups lists asset groups.
func (s *Service) ListGroups(ctx context.Context, actor iam.Claims) ([]assets.AssetGroup, error) {
	return s.groups.List(ctx, scopeOf(actor))
}

// AddDeviceToGroup adds a device to a group.
func (s *Service) AddDeviceToGroup(ctx context.Context, actor iam.Claims, groupID, deviceID uuid.UUID) error {
	if err := s.groups.AddMember(ctx, scopeOf(actor), groupID, deviceID); err != nil {
		return err
	}
	s.recordAsset(ctx, actor, "group.add_member", "group", groupID, map[string]any{"device_id": deviceID.String()})
	return nil
}

// RemoveDeviceFromGroup removes a device from a group.
func (s *Service) RemoveDeviceFromGroup(ctx context.Context, actor iam.Claims, groupID, deviceID uuid.UUID) error {
	if err := s.groups.RemoveMember(ctx, scopeOf(actor), groupID, deviceID); err != nil {
		return err
	}
	s.recordAsset(ctx, actor, "group.remove_member", "group", groupID, map[string]any{"device_id": deviceID.String()})
	return nil
}

// DeviceGroups returns the asset-group ids a device belongs to.
func (s *Service) DeviceGroups(ctx context.Context, actor iam.Claims, deviceID uuid.UUID) ([]uuid.UUID, error) {
	return s.groups.ListDeviceGroups(ctx, scopeOf(actor), deviceID)
}

func (s *Service) recordDevice(ctx context.Context, actor iam.Claims, action string, deviceID uuid.UUID, meta ReqMeta) {
	if s.audit == nil {
		return
	}
	org := actor.OrganizationID
	uid := actor.UserID
	_ = s.audit.Record(ctx, audit.Event{
		ID: uuid.New(), OrganizationID: &org, ActorID: &uid, ActorEmail: actor.Email,
		Action: action, Category: audit.CategoryDevice, TargetType: "device", TargetID: deviceID.String(),
		IP: meta.IP, UserAgent: meta.UserAgent, Result: audit.ResultSuccess,
	})
}

// recordAsset audits an asset-management action (groups and other asset changes
// whose service methods don't carry request metadata). Best-effort like the
// other recorders.
func (s *Service) recordAsset(ctx context.Context, actor iam.Claims, action, targetType string, targetID uuid.UUID, detail map[string]any) {
	if s.audit == nil {
		return
	}
	org := actor.OrganizationID
	uid := actor.UserID
	_ = s.audit.Record(ctx, audit.Event{
		ID: uuid.New(), OrganizationID: &org, ActorID: &uid, ActorEmail: actor.Email,
		Action: action, Category: audit.CategoryDevice, TargetType: targetType, TargetID: targetID.String(),
		Result: audit.ResultSuccess, Detail: detail,
	})
}

// deliveryOrDefault resolves a device's delivery mode from what the caller stated
// (mode), what the device already has (current, empty for a new device), and the
// recording policy the request settles on — then refuses the result if it is
// something this platform cannot actually serve.
//
// Saying nothing leaves an existing device alone and gives a new one "proxy",
// unless it is a recorded web device: recording captures frames from a
// server-side browser, so for the web it only exists under isolation, and a web
// device registered as recorded has already chosen isolation whether or not its
// registrant used that word.
//
// Both callers go through here so the rules cannot drift apart, and because the
// combination has to be judged after every field has settled rather than as each
// one arrives.
func deliveryOrDefault(scheme string, mode *string, current string, record bool) (string, error) {
	settled := current
	switch {
	case mode != nil:
		settled = *mode
	case settled == "":
		if record && assets.IsWebScheme(scheme) {
			settled = assets.DeliveryIsolated
		} else {
			settled = assets.DeliveryProxy
		}
	}
	if !assets.ValidDelivery(settled) {
		return "", fmt.Errorf("%w: unknown delivery mode %q (one of %v)",
			assets.ErrInvalid, settled, assets.DeliveryModes())
	}
	// A non-web device has one gateway and no delivery choice. Storing "proxy"
	// anyway and saying nothing would leave the console showing a mode the device
	// is not in.
	if settled == assets.DeliveryIsolated && !assets.IsWebScheme(scheme) {
		return "", fmt.Errorf("%w: delivery mode %q is for web devices; a %q device is served by its own "+
			"gateway and has no delivery choice", assets.ErrInvalid, assets.DeliveryIsolated, scheme)
	}
	// Recorded and proxied is refused rather than silently resolved: the caller
	// believes one of the two things they asked for, and guessing which would be a
	// coin flip over an audit control.
	if assets.RecordingImpossible(scheme, settled, record) {
		return "", fmt.Errorf("%w: recording a web device needs isolated delivery — the reverse proxy "+
			"never sees pixels, so a recorded proxy session would capture nothing", assets.ErrInvalid)
	}
	return settled, nil
}

// schemeOrDefault validates the requested protocol, defaulting only when none was
// given.
//
// It used to map anything that was not "http" to "https". That silently rewrote
// the caller's intent: a device registered as "ssh" was stored as an HTTPS device
// and then brokered to the reverse proxy, which injects the vaulted credential
// as an Authorization header — sending the device password to port 22 in the
// clear. An unrecognised protocol is a mistake worth reporting, never one to
// paper over.
func schemeOrDefault(s string) (string, error) {
	if s == "" {
		return "https", nil
	}
	if !assets.ValidScheme(s) {
		return "", fmt.Errorf("%w: unknown protocol %q (one of %v)", assets.ErrInvalid, s, assets.Schemes())
	}
	return s, nil
}

// portOrDefault fills in the protocol's conventional port when none was given.
// An explicit port always wins: plenty of SSH lives on 2222.
func portOrDefault(p int, scheme string) int {
	if p > 0 {
		return p
	}
	if port, ok := assets.DefaultPortFor(scheme); ok {
		return port
	}
	return 443
}
