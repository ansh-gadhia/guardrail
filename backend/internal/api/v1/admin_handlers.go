package v1

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	appiam "github.com/guardrail/guardrail/internal/app/iam"
	"github.com/guardrail/guardrail/internal/domain/iam"
)

// ---- Users ----

type createUserRequest struct {
	Email        string   `json:"email" binding:"required,email"`
	Username     string   `json:"username"`
	Password     string   `json:"password" binding:"required"`
	RoleIDs      []string `json:"role_ids"`
	IsSuperAdmin bool     `json:"is_super_admin"`
}

func (h *Handler) createUser(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid user payload")
		return
	}
	roleIDs, err := parseIDs(req.RoleIDs)
	if err != nil {
		badRequest(c, "invalid role id")
		return
	}
	p, err := h.svc.CreateUser(c.Request.Context(), actor, appiam.CreateUserInput{
		Email: req.Email, Username: req.Username, Password: req.Password,
		RoleIDs: roleIDs, IsSuperAdmin: req.IsSuperAdmin, Meta: metaFrom(c),
	})
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, toPrincipalDTO(*p))
}

func (h *Handler) listUsers(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	users, err := h.svc.ListUsers(c.Request.Context(), actor, iam.Page{Limit: queryLimit(c)})
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]principalDTO, 0, len(users))
	for _, u := range users {
		out = append(out, toPrincipalDTO(u))
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (h *Handler) getUser(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid user id")
		return
	}
	p, err := h.svc.GetUser(c.Request.Context(), actor, id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, toPrincipalDTO(*p))
}

func (h *Handler) deleteUser(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid user id")
		return
	}
	if err := h.svc.DeleteUser(c.Request.Context(), actor, id, metaFrom(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

type assignRolesRequest struct {
	RoleIDs []string `json:"role_ids"`
}

func (h *Handler) assignRoles(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid user id")
		return
	}
	var req assignRolesRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid payload")
		return
	}
	roleIDs, err := parseIDs(req.RoleIDs)
	if err != nil {
		badRequest(c, "invalid role id")
		return
	}
	if err := h.svc.AssignRoles(c.Request.Context(), actor, id, roleIDs, metaFrom(c)); err != nil {
		fail(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// ---- Organizations ----

type createOrgRequest struct {
	Name string `json:"name" binding:"required"`
	Slug string `json:"slug" binding:"required,alphanum"`
}

func (h *Handler) createOrg(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req createOrgRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid organization payload")
		return
	}
	o, err := h.svc.CreateOrganization(c.Request.Context(), actor, appiam.CreateOrgInput{
		Name: req.Name, Slug: req.Slug, Meta: metaFrom(c),
	})
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"id": o.ID.String(), "name": o.Name, "slug": o.Slug, "status": o.Status,
	})
}

func (h *Handler) listOrgs(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	orgs, err := h.svc.ListOrganizations(c.Request.Context(), actor, iam.Page{Limit: queryLimit(c)})
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(orgs))
	for _, o := range orgs {
		out = append(out, gin.H{"id": o.ID.String(), "name": o.Name, "slug": o.Slug, "status": o.Status})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (h *Handler) getOrg(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid organization id")
		return
	}
	o, err := h.svc.GetOrganization(c.Request.Context(), actor, id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": o.ID.String(), "name": o.Name, "slug": o.Slug, "status": o.Status})
}

// ---- Roles & permissions ----

func (h *Handler) listRoles(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	roles, err := h.svc.ListRoles(c.Request.Context(), actor, iam.Page{Limit: queryLimit(c)})
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(roles))
	for _, r := range roles {
		scope := string(r.DeviceScope)
		if scope == "" {
			scope = string(iam.DeviceScopeAll)
		}
		out = append(out, gin.H{
			"id": r.ID.String(), "name": r.Name, "description": r.Description,
			"is_system": r.IsSystem, "permissions": r.Permissions, "device_scope": scope,
		})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (h *Handler) listPermissions(c *gin.Context) {
	perms, err := h.svc.ListPermissions(c.Request.Context())
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(perms))
	for _, p := range perms {
		out = append(out, gin.H{"key": p.Key, "description": p.Description})
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (h *Handler) getRoleDeviceAccess(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid role id")
		return
	}
	da, err := h.svc.GetRoleDeviceAccess(c.Request.Context(), actor, id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, roleDeviceAccessDTO(da))
}

type roleDeviceAccessRequest struct {
	DeviceScope string   `json:"device_scope" binding:"required"`
	DeviceTypes []string `json:"device_types"`
	GroupIDs    []string `json:"group_ids"`
}

func (h *Handler) setRoleDeviceAccess(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid role id")
		return
	}
	var req roleDeviceAccessRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "device_scope is required")
		return
	}
	groupIDs, err := parseIDs(req.GroupIDs)
	if err != nil {
		badRequest(c, "invalid group id")
		return
	}
	in := iam.RoleDeviceAccess{
		Scope:       iam.DeviceScope(req.DeviceScope),
		DeviceTypes: normalizeTypes(req.DeviceTypes),
		GroupIDs:    groupIDs,
	}
	if err := h.svc.SetRoleDeviceAccess(c.Request.Context(), actor, id, in, metaFrom(c)); err != nil {
		fail(c, err)
		return
	}
	da, err := h.svc.GetRoleDeviceAccess(c.Request.Context(), actor, id)
	if err != nil {
		fail(c, err)
		return
	}
	c.JSON(http.StatusOK, roleDeviceAccessDTO(da))
}

func roleDeviceAccessDTO(da *iam.RoleDeviceAccess) gin.H {
	types := da.DeviceTypes
	if types == nil {
		types = []string{}
	}
	groups := make([]string, 0, len(da.GroupIDs))
	for _, g := range da.GroupIDs {
		groups = append(groups, g.String())
	}
	return gin.H{"device_scope": string(da.Scope), "device_types": types, "group_ids": groups}
}

// normalizeTypes trims and drops blank device-type entries so a scoped role never
// stores an empty type that would match nothing (or everything, on a bad join).
func normalizeTypes(in []string) []string {
	out := make([]string, 0, len(in))
	for _, t := range in {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---- helpers ----

func parseIDs(raw []string) ([]iam.ID, error) {
	out := make([]iam.ID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(s)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}
