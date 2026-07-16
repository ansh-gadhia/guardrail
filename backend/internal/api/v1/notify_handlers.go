package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/guardrail/guardrail/internal/api/middleware"
	appnotify "github.com/guardrail/guardrail/internal/app/notify"
	domnotify "github.com/guardrail/guardrail/internal/domain/notify"
)

// NotifyHandler exposes notification-channel routes.
type NotifyHandler struct{ svc *appnotify.Service }

// NewNotifyHandler constructs a NotifyHandler.
func NewNotifyHandler(svc *appnotify.Service) *NotifyHandler { return &NotifyHandler{svc: svc} }

// Register mounts channel routes. Channels are org-admin configuration, gated on
// org:write.
func (h *NotifyHandler) Register(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	g := rg.Group("/notification-channels", authMW)
	{
		g.GET("", middleware.RequirePermission("org:read"), h.list)
		g.POST("", middleware.RequirePermission("org:write"), h.create)
		g.DELETE("/:id", middleware.RequirePermission("org:write"), h.remove)
	}
}

type channelRequest struct {
	Name   string         `json:"name" binding:"required"`
	Type   string         `json:"type" binding:"required,oneof=email slack webhook"`
	Config map[string]any `json:"config"`
	Events []string       `json:"events"`
}

func (h *NotifyHandler) create(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	var req channelRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		badRequest(c, "invalid channel payload")
		return
	}
	ch, err := h.svc.CreateChannel(c.Request.Context(), actor, appnotify.ChannelInput{
		Name: req.Name, Type: domnotify.ChannelType(req.Type), Config: req.Config, Events: req.Events,
	})
	if err != nil {
		failAssets(c, err)
		return
	}
	c.JSON(http.StatusCreated, channelDTO(ch))
}

func (h *NotifyHandler) list(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	channels, err := h.svc.ListChannels(c.Request.Context(), actor)
	if err != nil {
		failAssets(c, err)
		return
	}
	out := make([]gin.H, 0, len(channels))
	for i := range channels {
		out = append(out, channelDTO(&channels[i]))
	}
	c.JSON(http.StatusOK, gin.H{"data": out})
}

func (h *NotifyHandler) remove(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		badRequest(c, "invalid channel id")
		return
	}
	if err := h.svc.DeleteChannel(c.Request.Context(), actor, id); err != nil {
		failAssets(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

func channelDTO(ch *domnotify.Channel) gin.H {
	return gin.H{
		"id": ch.ID.String(), "name": ch.Name, "type": string(ch.Type),
		"events": ch.Events, "enabled": ch.Enabled,
	}
}
