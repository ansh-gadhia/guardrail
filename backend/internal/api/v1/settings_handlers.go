package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/guardrail/guardrail/internal/api/middleware"
	domaccess "github.com/guardrail/guardrail/internal/domain/access"
)

// RegisterSettings mounts organization policy settings.
//
// Retention was the first of these. It used to be a constant compiled into the
// binary, stamped onto every recording as a deadline that nothing ever read —
// so it could not be changed without a rebuild, and changing it would not have
// done anything anyway. Branding and the source-address policy followed the same
// route: both were things a deployment needed to differ on and neither had
// anywhere to live but the source.
func (h *AccessHandler) RegisterSettings(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	s := rg.Group("/settings", authMW)
	{
		s.GET("", h.getSettings)
		// Readable by every signed-in user: the console shell paints the brand on
		// every page, so gating it behind org:read would show an operator a
		// different product from the one their manager sees.
		s.GET("/branding", h.getBranding)
		s.PUT("/recording-retention", middleware.RequirePermission("org:write"), h.setRetention)
		s.PUT("/branding", middleware.RequirePermission("org:write"), h.setBranding)
		s.PUT("/network-policy", middleware.RequirePermission("org:write"), h.setNetworkPolicy)
	}
}

func (h *AccessHandler) getSettings(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	set, err := h.svc.Settings(c.Request.Context(), actor)
	if err != nil {
		failAccess(c, err)
		return
	}
	out := settingsDTO(set)
	// The address this request arrived from. The console shows it beside the
	// address lists so an administrator can see, before saving, whether the
	// policy they are drafting still lets them in. Guessing your own public
	// address is exactly the thing people get wrong.
	out["your_ip"] = c.ClientIP()
	c.JSON(http.StatusOK, out)
}

func (h *AccessHandler) getBranding(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	b, err := h.svc.Branding(c.Request.Context(), actor)
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, brandingDTO(b))
}

type retentionRequest struct {
	// Days is how long recordings are kept. Zero means indefinitely, which is a
	// real policy — so this is a pointer: an omitted field and an explicit 0 are
	// different requests, and only one of them should turn retention off.
	Days *int `json:"days"`
}

func (h *AccessHandler) setRetention(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req retentionRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.Days == nil {
		badRequest(c, "days is required (0 keeps recordings indefinitely)")
		return
	}
	set, err := h.svc.SetRecordingRetention(c.Request.Context(), actor, *req.Days, accessMeta(c))
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, settingsDTO(set))
}

type brandingRequest struct {
	ClientName string `json:"client_name"`
	// ClientLogo is a data: URI. An omitted field leaves the stored artwork
	// alone; an explicit empty string removes it. They are different requests —
	// saving a changed name must not silently discard the logo — so this is a
	// pointer rather than a string.
	ClientLogo *string `json:"client_logo"`
	Enabled    *bool   `json:"enabled"`
}

func (h *AccessHandler) setBranding(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req brandingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid branding payload")
		return
	}
	current, err := h.svc.Branding(c.Request.Context(), actor)
	if err != nil {
		failAccess(c, err)
		return
	}
	b := domaccess.Branding{ClientName: req.ClientName, ClientLogo: current.ClientLogo, Enabled: current.Enabled}
	if req.ClientLogo != nil {
		b.ClientLogo = *req.ClientLogo
	}
	if req.Enabled != nil {
		b.Enabled = *req.Enabled
	}
	set, err := h.svc.SetBranding(c.Request.Context(), actor, b, accessMeta(c))
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, settingsDTO(set))
}

type ruleRequest struct {
	CIDR string `json:"cidr"`
	Note string `json:"note"`
}

type networkPolicyRequest struct {
	AllowEnabled bool          `json:"allowlist_enabled"`
	Allow        []ruleRequest `json:"allowlist"`
	BlockEnabled bool          `json:"blocklist_enabled"`
	Block        []ruleRequest `json:"blocklist"`
}

func (h *AccessHandler) setNetworkPolicy(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req networkPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid network policy payload")
		return
	}
	p := domaccess.NetworkPolicy{
		AllowEnabled: req.AllowEnabled,
		BlockEnabled: req.BlockEnabled,
		Allow:        toRules(req.Allow),
		Block:        toRules(req.Block),
	}
	set, err := h.svc.SetNetworkPolicy(c.Request.Context(), actor, p, accessMeta(c))
	if err != nil {
		failAccess(c, err)
		return
	}
	c.JSON(http.StatusOK, settingsDTO(set))
}

func toRules(in []ruleRequest) []domaccess.NetworkRule {
	out := make([]domaccess.NetworkRule, 0, len(in))
	for _, r := range in {
		out = append(out, domaccess.NetworkRule{CIDR: r.CIDR, Note: r.Note})
	}
	return out
}

func settingsDTO(s *domaccess.OrgSettings) gin.H {
	out := gin.H{
		"recording_retention_days": s.RecordingRetentionDays,
		// What this deployment's .env asked for, reported beside the live value.
		// The API cannot write that file — compose reads it on the host and the
		// container only receives the variables from it — so instead of pretending
		// to sync, the console shows both and says which is in force.
		"configured_default_days": s.ConfiguredDefaultDays,
		"branding":                brandingDTO(s.Branding),
		"network_policy": gin.H{
			"allowlist_enabled": s.Network.AllowEnabled,
			"allowlist":         rulesDTO(s.Network.Allow),
			"blocklist_enabled": s.Network.BlockEnabled,
			"blocklist":         rulesDTO(s.Network.Block),
		},
	}
	if !s.UpdatedAt.IsZero() {
		out["updated_at"] = rfc3339UTC(s.UpdatedAt)
	}
	if s.UpdatedByEmail != "" {
		out["updated_by"] = s.UpdatedByEmail
	}
	return out
}

func brandingDTO(b domaccess.Branding) gin.H {
	return gin.H{
		"client_name": b.ClientName,
		"client_logo": b.ClientLogo,
		"enabled":     b.Enabled,
		// Says whether the console should show the client's identity or fall back
		// to the vendor seal, so the shell does not have to re-derive the rule.
		"configured": b.Configured(),
	}
}

func rulesDTO(rules []domaccess.NetworkRule) []gin.H {
	out := make([]gin.H, 0, len(rules))
	for _, r := range rules {
		out = append(out, gin.H{"cidr": r.CIDR, "note": r.Note})
	}
	return out
}
