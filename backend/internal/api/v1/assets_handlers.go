package v1

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	appassets "github.com/guardrail/guardrail/internal/app/assets"
	appvault "github.com/guardrail/guardrail/internal/app/vault"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
	"github.com/guardrail/guardrail/internal/domain/iam"
	domvault "github.com/guardrail/guardrail/internal/domain/vault"
)

// AssetsHandler exposes device and asset-group routes. It consults the vault
// service (read-only, no decryption) to annotate devices with whether a
// credential is bound, so the console can surface unmanaged devices.
type AssetsHandler struct {
	svc   *appassets.Service
	vault *appvault.Service
}

// NewAssetsHandler constructs an AssetsHandler.
func NewAssetsHandler(svc *appassets.Service, vault *appvault.Service) *AssetsHandler {
	return &AssetsHandler{svc: svc, vault: vault}
}

// Register mounts device + group routes.
func (h *AssetsHandler) Register(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	d := rg.Group("/devices", authMW)
	{
		d.GET("", middleware.RequirePermission("device:read"), h.list)
		d.POST("", middleware.RequirePermission("device:write"), h.create)
		d.GET("/:id", middleware.RequirePermission("device:read"), h.get)
		d.PATCH("/:id", middleware.RequirePermission("device:write"), h.update)
		d.DELETE("/:id", middleware.RequirePermission("device:write"), h.remove)
		// A device owns its credential: manage it under the device itself rather
		// than a separate vault surface.
		d.PUT("/:id/credential", middleware.RequirePermission("credential:write"), h.setCredential)
		d.DELETE("/:id/credential", middleware.RequirePermission("credential:write"), h.clearCredential)
	}
	g := rg.Group("/asset-groups", authMW)
	{
		g.GET("", middleware.RequirePermission("group:read"), h.listGroups)
		g.POST("", middleware.RequirePermission("group:write"), h.createGroup)
		g.POST("/:id/members/:deviceID", middleware.RequirePermission("group:write"), h.addMember)
		g.DELETE("/:id/members/:deviceID", middleware.RequirePermission("group:write"), h.removeMember)
	}
}

type deviceRequest struct {
	Name           string            `json:"name" binding:"required"`
	Description    string            `json:"description"`
	Vendor         string            `json:"vendor"`
	DeviceType     string            `json:"device_type"`
	Host           string            `json:"host" binding:"required"`
	Port           int               `json:"port"`
	Scheme         string            `json:"scheme"`
	VerifyTLS      *bool             `json:"verify_tls"`
	CustomHeaders  map[string]string `json:"custom_headers"`
	Tags           []string          `json:"tags"`
	AllowUnmanaged bool              `json:"allow_unmanaged"`
	// RecordSessions is the device's recording policy. A pointer so that omitting
	// the key leaves it alone: only the device's owner or a super admin may change
	// it, and an ordinary edit must not have to send it at all.
	RecordSessions *bool `json:"record_sessions"`
	// DeliveryMode is "proxy" or "isolated". A pointer so that omitting the key
	// leaves it alone. It is a separate choice from recording: an appliance whose
	// UI is a real single-page app has to be isolated to work at all, regardless of
	// whether anyone wants the video.
	DeliveryMode *string `json:"delivery_mode"`
	// IdleTimeoutMinutes ends a session after this long with no activity. A
	// pointer so that omitting the key keeps the device's current value rather
	// than silently resetting it to zero, which would read as "never expire" —
	// the one value nobody means by omission.
	IdleTimeoutMinutes *int `json:"idle_timeout_minutes"`
	// GroupIDs replaces the device's asset-group membership. Omitting the key
	// leaves membership as it is; sending an empty array clears it.
	GroupIDs *[]string `json:"group_ids"`
	// Credential is the device's own credential, entered inline when adding a
	// device. It is optional — username and secret are not compulsory. When
	// omitted (or with an empty secret on create) the device is registered with
	// no credential.
	Credential *deviceCredentialRequest `json:"credential"`
}

// deviceCredentialRequest is the inline, device-owned credential. Username is
// optional (header injection needs none); secret is write-only and never echoed.
type deviceCredentialRequest struct {
	Username  string `json:"username"`
	Secret    string `json:"secret"`
	Injection string `json:"injection"`
}

// toInput carries the device's scheme alongside the credential, because the
// injection method is only checkable against the protocol it has to authenticate.
func (r deviceCredentialRequest) toInput(meta appvault.ReqMeta, name, scheme string) appvault.CredentialInput {
	return appvault.CredentialInput{
		Name:      name,
		Username:  r.Username,
		Injection: domvault.InjectionMethod(r.Injection),
		Scheme:    scheme,
		Secret:    r.Secret,
		Meta:      meta,
	}
}

func (r deviceRequest) toInput(meta appassets.ReqMeta) (appassets.DeviceInput, error) {
	verify := true
	if r.VerifyTLS != nil {
		verify = *r.VerifyTLS
	}
	in := appassets.DeviceInput{
		Name: r.Name, Description: r.Description, Vendor: r.Vendor, DeviceType: r.DeviceType,
		Host: r.Host, Port: r.Port, Scheme: r.Scheme, VerifyTLS: verify,
		CustomHeaders: r.CustomHeaders, Tags: r.Tags,
		AllowUnmanaged: r.AllowUnmanaged, RecordSessions: r.RecordSessions,
		DeliveryMode:       r.DeliveryMode,
		IdleTimeoutMinutes: r.IdleTimeoutMinutes, Meta: meta,
	}
	if r.IdleTimeoutMinutes != nil && (*r.IdleTimeoutMinutes < 0 || *r.IdleTimeoutMinutes > maxIdleTimeoutMinutes) {
		return in, fmt.Errorf("idle_timeout_minutes must be between 0 and %d", maxIdleTimeoutMinutes)
	}
	if r.GroupIDs != nil {
		ids := make([]uuid.UUID, 0, len(*r.GroupIDs))
		for _, raw := range *r.GroupIDs {
			id, err := uuid.Parse(raw)
			if err != nil {
				return in, err
			}
			ids = append(ids, id)
		}
		in.GroupIDs = &ids
	}
	return in, nil
}

// deviceDTO renders a device. When cred is non-nil, the device's owned
// credential metadata (never the secret) is included so the console can prefill
// its inline editor. Likewise groups, when non-nil, carries the device's
// asset-group membership. List responses pass nil for both and only the
// has-credential boolean, keeping the listing free of per-device lookups.
func deviceDTO(d *domassets.Device, actor iam.Claims, hasCredential bool, cred *appvault.CredentialView, groups []uuid.UUID) gin.H {
	out := gin.H{
		"id": d.ID.String(), "name": d.Name, "description": d.Description, "vendor": d.Vendor,
		"device_type": d.DeviceType, "host": d.Host, "port": d.Port, "scheme": d.Scheme,
		"verify_tls": d.VerifyTLS, "custom_headers": d.CustomHeaders, "tags": d.Tags,
		"status": d.Status, "url": d.BaseURL(),
		"allow_unmanaged": d.AllowUnmanaged, "has_credential": hasCredential,
		"record_sessions":      d.RecordSessions,
		"delivery_mode":        d.DeliveryMode,
		"idle_timeout_minutes": d.IdleTimeoutMinutes,
		// Whether this viewer may change the recording policy. The server decides
		// and says so, rather than leaving the console to re-derive the rule and
		// risk disagreeing with what the API will actually allow.
		"can_set_recording": d.CanSetRecording(actor.UserID, actor.IsSuperAdmin),
		"created_at":        rfc3339UTC(d.CreatedAt),
	}
	if cred != nil {
		out["credential"] = gin.H{
			"username": cred.Username, "injection": string(cred.Injection), "has_secret": cred.HasSecret,
		}
	}
	if groups != nil {
		ids := make([]string, 0, len(groups))
		for _, g := range groups {
			ids = append(ids, g.String())
		}
		out["group_ids"] = ids
	}
	if d.Health != nil {
		h := gin.H{"status": string(d.Health.Status)}
		if d.Health.CheckedAt != nil {
			h["checked_at"] = rfc3339UTC(*d.Health.CheckedAt)
		}
		if d.Health.LatencyMS != nil {
			h["latency_ms"] = *d.Health.LatencyMS
		}
		out["health"] = h
	}
	return out
}

// groupsFor returns the device's asset-group membership. Best-effort like
// credFor: a device that can be read is still worth rendering if its group
// lookup fails.
func (h *AssetsHandler) groupsFor(c *gin.Context, actor iam.Claims, id uuid.UUID) []uuid.UUID {
	g, err := h.svc.DeviceGroups(c.Request.Context(), actor, id)
	if err != nil {
		return nil
	}
	return g
}

func (h *AssetsHandler) create(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req deviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid device payload")
		return
	}
	in, err := req.toInput(assetsMeta(c))
	if err != nil {
		badRequest(c, "invalid group id")
		return
	}
	d, err := h.svc.CreateDevice(c.Request.Context(), actor, in)
	if err != nil {
		failAssets(c, err)
		return
	}
	// If the operator entered a credential inline, seal and bind it in the same
	// action. If that fails, the device would otherwise be orphaned, so we
	// compensate by removing the device the caller never got to see.
	if req.Credential != nil && req.Credential.Secret != "" {
		in := req.Credential.toInput(vaultMeta(c), d.Name+" credential", d.Scheme)
		if cerr := h.vault.SetForDevice(c.Request.Context(), actor, d.ID, in); cerr != nil {
			_ = h.svc.DeleteDevice(c.Request.Context(), actor, d.ID, assetsMeta(c))
			failAssets(c, cerr)
			return
		}
	}
	cred := h.credFor(c, actor, d.ID)
	c.JSON(http.StatusCreated, deviceDTO(d, actor, cred != nil, cred, h.groupsFor(c, actor, d.ID)))
}

func (h *AssetsHandler) update(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid device id")
		return
	}
	var req deviceRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid device payload")
		return
	}
	in, err := req.toInput(assetsMeta(c))
	if err != nil {
		badRequest(c, "invalid group id")
		return
	}
	d, err := h.svc.UpdateDevice(c.Request.Context(), actor, id, in)
	if err != nil {
		failAssets(c, err)
		return
	}
	cred := h.credFor(c, actor, d.ID)
	c.JSON(http.StatusOK, deviceDTO(d, actor, cred != nil, cred, h.groupsFor(c, actor, d.ID)))
}

func (h *AssetsHandler) get(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid device id")
		return
	}
	d, err := h.svc.GetDevice(c.Request.Context(), actor, id)
	if err != nil {
		failAssets(c, err)
		return
	}
	cred := h.credFor(c, actor, d.ID)
	c.JSON(http.StatusOK, deviceDTO(d, actor, cred != nil, cred, h.groupsFor(c, actor, d.ID)))
}

func (h *AssetsHandler) list(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	f := domassets.Filter{
		Vendor: c.Query("vendor"), Tag: c.Query("tag"), Search: c.Query("q"), Limit: queryLimit(c),
	}
	devices, err := h.svc.ListDevices(c.Request.Context(), actor, f)
	if err != nil {
		failAssets(c, err)
		return
	}
	// Annotate each device with whether a credential is bound, in one query.
	ids := make([]uuid.UUID, 0, len(devices))
	for i := range devices {
		ids = append(ids, devices[i].ID)
	}
	withCred, err := h.vault.DevicesWithCredential(c.Request.Context(), actor, ids)
	if err != nil {
		failAssets(c, err)
		return
	}
	// List stays a single batch query; per-device credential metadata is fetched
	// only on the detail endpoints, so listing many devices avoids N+1 lookups.
	out := make([]gin.H, 0, len(devices))
	for i := range devices {
		out = append(out, deviceDTO(&devices[i], actor, withCred[devices[i].ID], nil, nil))
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

// credFor returns the device's owned credential metadata (never the secret), or
// nil if it has none. Best-effort: on error it reports nil rather than failing
// the surrounding request, matching the previous has-credential annotation.
func (h *AssetsHandler) credFor(c *gin.Context, actor iam.Claims, id uuid.UUID) *appvault.CredentialView {
	v, err := h.vault.GetForDevice(c.Request.Context(), actor, id)
	if err != nil {
		return nil
	}
	return v
}

// setCredential creates or updates the credential a device owns. Leaving the
// secret blank on an existing credential preserves it (the console never echoes
// secrets back), while username and injection are always applied.
func (h *AssetsHandler) setCredential(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid device id")
		return
	}
	// Confirm the device exists in scope before touching the vault.
	d, err := h.svc.GetDevice(c.Request.Context(), actor, id)
	if err != nil {
		failAssets(c, err)
		return
	}
	var req deviceCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid credential payload")
		return
	}
	if err := h.vault.SetForDevice(c.Request.Context(), actor, id,
		req.toInput(vaultMeta(c), d.Name+" credential", d.Scheme)); err != nil {
		failAssets(c, err)
		return
	}
	cred := h.credFor(c, actor, id)
	c.JSON(http.StatusOK, deviceDTO(d, actor, cred != nil, cred, h.groupsFor(c, actor, id)))
}

// clearCredential removes the credential a device owns, returning it to the
// unmanaged state. It is idempotent.
func (h *AssetsHandler) clearCredential(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid device id")
		return
	}
	if err := h.vault.ClearForDevice(c.Request.Context(), actor, id, vaultMeta(c)); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AssetsHandler) remove(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid device id")
		return
	}
	if err := h.svc.DeleteDevice(c.Request.Context(), actor, id, assetsMeta(c)); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

type groupRequest struct {
	Name     string  `json:"name" binding:"required"`
	Type     string  `json:"type"`
	ParentID *string `json:"parent_id"`
}

func (h *AssetsHandler) createGroup(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req groupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid group payload")
		return
	}
	var parent *uuid.UUID
	if req.ParentID != nil {
		p, err := uuid.Parse(*req.ParentID)
		if err != nil {
			badRequest(c, "invalid parent id")
			return
		}
		parent = &p
	}
	g, err := h.svc.CreateGroup(c.Request.Context(), actor, req.Name, req.Type, parent)
	if err != nil {
		failAssets(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": g.ID.String(), "name": g.Name, "type": g.Type})
}

func (h *AssetsHandler) listGroups(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	groups, err := h.svc.ListGroups(c.Request.Context(), actor)
	if err != nil {
		failAssets(c, err)
		return
	}
	out := make([]gin.H, 0, len(groups))
	for _, g := range groups {
		var parent any
		if g.ParentID != nil {
			parent = g.ParentID.String()
		}
		out = append(out, gin.H{"id": g.ID.String(), "name": g.Name, "type": g.Type, "parent_id": parent})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (h *AssetsHandler) addMember(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	gid, err1 := uuid.Parse(c.Param("id"))
	did, err2 := uuid.Parse(c.Param("deviceID"))
	if err1 != nil || err2 != nil {
		badRequest(c, "invalid id")
		return
	}
	if err := h.svc.AddDeviceToGroup(c.Request.Context(), actor, gid, did); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *AssetsHandler) removeMember(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	gid, err1 := uuid.Parse(c.Param("id"))
	did, err2 := uuid.Parse(c.Param("deviceID"))
	if err1 != nil || err2 != nil {
		badRequest(c, "invalid id")
		return
	}
	if err := h.svc.RemoveDeviceFromGroup(c.Request.Context(), actor, gid, did); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func assetsMeta(c *gin.Context) appassets.ReqMeta {
	return appassets.ReqMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

func vaultMeta(c *gin.Context) appvault.ReqMeta {
	return appvault.ReqMeta{IP: c.ClientIP(), UserAgent: c.Request.UserAgent()}
}

// maxIdleTimeoutMinutes is a day. Beyond that the idle timeout stops being a
// control and the session's granted window is the only thing still bounding it.
const maxIdleTimeoutMinutes = 1440
