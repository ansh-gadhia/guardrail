package v1

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/guardrail/guardrail/internal/api/middleware"
	domassets "github.com/guardrail/guardrail/internal/domain/assets"
)

// RegisterStatus mounts the device status feed.
//
// It is a deliberately narrow read: name, type, address and whether the device
// answered its last probe — the four things a NOC board or an external monitor
// needs, and nothing else. No credentials, no session history, no delivery or
// recording policy. A dashboard that only needs to know a firewall is up should
// not be handed the shape of the estate to go with it.
//
// It sits behind the same bearer auth and the same device:read permission as
// every other device read, and is org-scoped identically. That is the whole
// security story: a caller sees exactly the devices they could already list.
func (h *AssetsHandler) RegisterStatus(rg *gin.RouterGroup, authMW gin.HandlerFunc) {
	s := rg.Group("/status", authMW)
	{
		s.GET("/devices", middleware.RequirePermission("device:read"), h.statusDevices)
	}
}

// statusDevices returns every device in the caller's organization with its live
// reachability.
//
// The status is whatever the health poller last observed, so this endpoint is as
// fresh as GUARDRAIL_HEALTH_POLL_INTERVAL and no fresher. It reports checked_at
// alongside precisely so a consumer can tell a device that is up from one nobody
// has looked at recently — "online" with an hour-old timestamp is a different
// claim from "online" ten seconds ago, and collapsing the two is how a monitor
// ends up confidently green about a host that died forty minutes ago.
func (h *AssetsHandler) statusDevices(c *gin.Context) {
	actor, _ := middleware.ClaimsFrom(c)
	devices, err := h.svc.ListDevices(c.Request.Context(), actor, domassets.Filter{})
	if err != nil {
		fail(c, err)
		return
	}
	out := make([]gin.H, 0, len(devices))
	online, offline, unknown := 0, 0, 0
	for i := range devices {
		d := &devices[i]
		// "unknown" rather than "offline" when the device has never been probed.
		// They are different facts — "we looked and it is down" versus "we have
		// not looked" — and reporting the second as the first invents an outage.
		status := string(domassets.HealthUnknown)
		var checked any
		var latency any
		if d.Health != nil {
			status = string(d.Health.Status)
			if d.Health.CheckedAt != nil {
				checked = rfc3339UTC(*d.Health.CheckedAt)
			}
			if d.Health.LatencyMS != nil {
				latency = *d.Health.LatencyMS
			}
		}
		switch status {
		case string(domassets.HealthOnline):
			online++
		case string(domassets.HealthOffline):
			offline++
		default:
			unknown++
		}
		out = append(out, gin.H{
			"id":          d.ID.String(),
			"name":        d.Name,
			"device_type": d.DeviceType,
			// The device's own address, which is what an operator means by "device
			// IP" — the host it is reached at, not whatever DNS resolves today.
			"ip":         d.Host,
			"port":       d.Port,
			"status":     status,
			"checked_at": checked,
			"latency_ms": latency,
		})
	}
	// Not cacheable: the entire value of this endpoint is that it is current, and
	// an intermediary holding it for even a minute would make a monitor lie.
	c.Header("Cache-Control", "no-store")
	c.JSON(http.StatusOK, gin.H{
		"data": out,
		"summary": gin.H{
			"total": len(out), "online": online, "offline": offline, "unknown": unknown,
		},
	})
}
