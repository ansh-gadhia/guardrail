package v1

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// Teams: who reaches which devices.
//
// The grant endpoints replace the whole set rather than patching one row at a
// time. "The IT team reaches these four groups" is the decision being made, and
// an API that adds and removes rows individually turns one decision into a
// sequence that can be interrupted half-applied — leaving reach that nobody
// chose and no single request to point at in the audit trail.

// RegisterTeams mounts the team routes.
func (h *Handler) RegisterTeams(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	t := rg.Group("/teams", authMW)
	{
		t.GET("", middleware.RequirePermission("team:read"), h.listTeams)
		t.POST("", middleware.RequirePermission("team:write"), h.createTeam)
		t.GET("/:id", middleware.RequirePermission("team:read"), h.getTeam)
		t.PUT("/:id", middleware.RequirePermission("team:write"), h.updateTeam)
		t.DELETE("/:id", middleware.RequirePermission("team:write"), h.deleteTeam)

		t.GET("/:id/members", middleware.RequirePermission("team:read"), h.listTeamMembers)
		t.PUT("/:id/members", middleware.RequirePermission("team:write"), h.setTeamMembers)

		// Editing a grant is editing device authorization, so it takes
		// team:write and not merely group:write — the asset group is not what is
		// changing, the reach into it is.
		t.GET("/:id/grants", middleware.RequirePermission("team:read"), h.getTeamGrants)
		t.PUT("/:id/grants", middleware.RequirePermission("team:write"), h.setTeamGrants)
	}
}

type teamRequest struct {
	Name        string `json:"name" binding:"required"`
	Description string `json:"description"`
	// AllDevicesLevel is "", "none", "view", "connect" or "manage". Absent and
	// "none" both mean no blanket grant.
	AllDevicesLevel string `json:"all_devices_level"`
}

func teamDTO(t *iam.Team) gin.H {
	return gin.H{
		"id":                t.ID.String(),
		"name":              t.Name,
		"description":       t.Description,
		"all_devices_level": string(t.AllDevicesLevel),
		"member_count":      t.MemberCount,
		"created_at":        t.CreatedAt.UTC().Format(time.RFC3339),
		"updated_at":        t.UpdatedAt.UTC().Format(time.RFC3339),
	}
}

func (h *Handler) listTeams(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	teams, err := h.svc.ListTeams(c.Request.Context(), actor)
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(teams))
	for i := range teams {
		out = append(out, teamDTO(&teams[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (h *Handler) getTeam(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, ok := teamID(c)
	if !ok {
		return
	}
	t, err := h.svc.GetTeam(c.Request.Context(), actor, id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, teamDTO(t))
}

func (h *Handler) createTeam(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req teamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "name is required")
		return
	}
	level, ok := parseLevel(c, req.AllDevicesLevel)
	if !ok {
		return
	}
	t, err := h.svc.CreateTeam(c.Request.Context(), actor, iam.Team{
		Name: req.Name, Description: req.Description, AllDevicesLevel: level,
	}, metaFrom(c))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, teamDTO(t))
}

func (h *Handler) updateTeam(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, ok := teamID(c)
	if !ok {
		return
	}
	var req teamRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "name is required")
		return
	}
	level, ok := parseLevel(c, req.AllDevicesLevel)
	if !ok {
		return
	}
	t, err := h.svc.UpdateTeam(c.Request.Context(), actor, iam.Team{
		ID: id, Name: req.Name, Description: req.Description, AllDevicesLevel: level,
	}, metaFrom(c))
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, teamDTO(t))
}

func (h *Handler) deleteTeam(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, ok := teamID(c)
	if !ok {
		return
	}
	if err := h.svc.DeleteTeam(c.Request.Context(), actor, id, metaFrom(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func (h *Handler) listTeamMembers(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, ok := teamID(c)
	if !ok {
		return
	}
	members, err := h.svc.ListTeamMembers(c.Request.Context(), actor, id)
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(members))
	for _, m := range members {
		out = append(out, gin.H{
			"user_id":  m.UserID.String(),
			"email":    m.Email,
			"status":   m.Status,
			"added_at": m.AddedAt.UTC().Format(time.RFC3339),
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

type teamMembersRequest struct {
	// UserIDs is the complete membership after the call. An empty array is a
	// legitimate value and empties the team; omitting the key is not, because
	// "no key" and "no members" would otherwise be indistinguishable.
	UserIDs *[]string `json:"user_ids" binding:"required"`
}

func (h *Handler) setTeamMembers(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, ok := teamID(c)
	if !ok {
		return
	}
	var req teamMembersRequest
	if err := c.ShouldBindJSON(&req); err != nil || req.UserIDs == nil {
		badRequest(c, `expected a JSON body of the form {"user_ids": ["<uuid>", ...]}`)
		return
	}
	ids, err := parseIDs(*req.UserIDs)
	if err != nil {
		badRequest(c, "invalid user id")
		return
	}
	if err := h.svc.SetTeamMembers(c.Request.Context(), actor, id, ids, metaFrom(c)); err != nil {
		fail(c, err)
		return
	}
	h.listTeamMembers(c)
}

type teamGrantsRequest struct {
	Groups []struct {
		AssetGroupID string `json:"asset_group_id"`
		Level        string `json:"level"`
	} `json:"groups"`
	DeviceTypes []struct {
		DeviceType string `json:"device_type"`
		Level      string `json:"level"`
	} `json:"device_types"`
}

func grantsDTO(g *iam.TeamGrants) gin.H {
	groups := make([]gin.H, 0, len(g.Groups))
	for _, gr := range g.Groups {
		groups = append(groups, gin.H{
			"asset_group_id": gr.AssetGroupID.String(),
			"name":           gr.Name,
			"level":          string(gr.Level),
		})
	}
	types := make([]gin.H, 0, len(g.DeviceTypes))
	for _, t := range g.DeviceTypes {
		types = append(types, gin.H{"device_type": t.DeviceType, "level": string(t.Level)})
	}
	return gin.H{"groups": groups, "device_types": types}
}

func (h *Handler) getTeamGrants(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, ok := teamID(c)
	if !ok {
		return
	}
	g, err := h.svc.GetTeamGrants(c.Request.Context(), actor, id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, grantsDTO(g))
}

func (h *Handler) setTeamGrants(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, ok := teamID(c)
	if !ok {
		return
	}
	var req teamGrantsRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, `expected {"groups": [{"asset_group_id": "...", "level": "view|connect|manage"}], "device_types": [...]}`)
		return
	}
	var in iam.TeamGrants
	for _, gr := range req.Groups {
		gid, err := uuid.Parse(gr.AssetGroupID)
		if err != nil {
			badRequest(c, "invalid asset_group_id")
			return
		}
		level, ok := parseGrantLevel(c, gr.Level)
		if !ok {
			return
		}
		in.Groups = append(in.Groups, iam.GroupGrant{AssetGroupID: gid, Level: level})
	}
	for _, t := range req.DeviceTypes {
		level, ok := parseGrantLevel(c, t.Level)
		if !ok {
			return
		}
		in.DeviceTypes = append(in.DeviceTypes, iam.TypeGrant{DeviceType: t.DeviceType, Level: level})
	}
	if err := h.svc.SetTeamGrants(c.Request.Context(), actor, id, in, metaFrom(c)); err != nil {
		fail(c, err)
		return
	}
	h.getTeamGrants(c)
}

func teamID(c *gin.Context) (uuid.UUID, bool) {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid team id")
		return uuid.UUID{}, false
	}
	return id, true
}

// parseLevel accepts the blanket-grant level, where absent means "none".
func parseLevel(c *gin.Context, raw string) (iam.AccessLevel, bool) {
	if raw == "" {
		return iam.AccessNone, true
	}
	l := iam.NormalizeAccessLevel(raw)
	if l == "" {
		badRequest(c, "all_devices_level must be one of: none, view, connect, manage")
		return "", false
	}
	return l, true
}

// parseGrantLevel accepts a grant's level, where absent defaults to connect —
// the level a grant meant before levels existed, so a client that does not send
// one gets the behaviour it would have got anyway. "none" is rejected: a grant
// that grants nothing is a row that should not be written, and silently dropping
// it would hide the mistake instead of reporting it.
func parseGrantLevel(c *gin.Context, raw string) (iam.AccessLevel, bool) {
	if raw == "" {
		return iam.AccessConnect, true
	}
	l := iam.NormalizeAccessLevel(raw)
	if !l.Valid() {
		badRequest(c, "level must be one of: view, connect, manage")
		return "", false
	}
	return l, true
}
