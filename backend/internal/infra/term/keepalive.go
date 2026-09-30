package term

import (
	"context"
	"time"

	"github.com/coder/websocket"
)

// KeepAliveInterval is how often a live session socket is pinged.
//
// Under a minute with room to spare, because a minute is the limit it has to
// beat: nginx — and so Nginx Proxy Manager, which is nginx — closes a proxied
// connection after 60 seconds with nothing read from it (proxy_read_timeout),
// and cloud load balancers keep idle timers of the same order.
const KeepAliveInterval = 25 * time.Second

// KeepAlive pings c every interval until ctx ends, and closes it when a ping
// goes unanswered for a whole interval.
//
// Every session socket needs it, not only a terminal's. A terminal waiting at a
// prompt sends nothing; neither does an isolated browser showing a page that is
// not changing, because its frames only flow on a repaint. Behind a reverse
// proxy that silence was the end of the session a minute later — and it read as
// GuardRail dropping it. A ping is traffic the proxy sees and the operator does
// not, and its answer proves somebody is still on the other end, so a
// half-open connection is found and closed rather than holding a gateway slot
// until TCP gives up.
//
// Protocol-level, so no client has to know: browsers answer pings on their own.
// The answer is only read by a goroutine reading c, which every session socket
// has. It is not activity: a pong never reaches the reader as a message, so a
// socket kept open this way does not keep an idle session from expiring.
func KeepAlive(ctx context.Context, c *websocket.Conn, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			pctx, cancel := context.WithTimeout(ctx, every)
			err := c.Ping(pctx)
			cancel()
			if err != nil {
				if ctx.Err() == nil {
					// Nobody answered: close it, so the handler's read fails and
					// it tears down as it would for any dropped viewer.
					_ = c.CloseNow()
				}
				return
			}
		}
	}
}
