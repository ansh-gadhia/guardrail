package proxy

import (
	"fmt"
	"net"
	"strings"
)

// GuardSSRF blocks reaching cloud instance-metadata endpoints, the strongest
// SSRF risk for a component that reaches internal networks. Target hosts come
// from registered device records (not user-supplied URLs), so private/RFC1918
// ranges are intentionally allowed — that is where firewalls and appliances
// live. Egress allowlisting to specific device subnets is an additional
// operational control.
//
// It is exported so every component that dials a device — the proxy gateway and
// the health poller — applies one egress policy rather than each inventing its
// own.
func GuardSSRF(host string) error {
	h := host
	if i := strings.LastIndex(h, ":"); i > 0 && !strings.Contains(h[i:], "]") {
		h = h[:i] // strip port
	}
	h = strings.Trim(h, "[]")

	ips, err := net.LookupIP(h)
	if err != nil {
		// If it doesn't resolve, let the proxy attempt and fail normally; do not
		// block on transient DNS issues.
		return nil
	}
	for _, ip := range ips {
		if isBlocked(ip) {
			return fmt.Errorf("proxy: target %s resolves to a blocked address", host)
		}
	}
	return nil
}

// metadataV4 is the cloud metadata service address (AWS/GCP/Azure/OpenStack).
var metadataV4 = net.IPv4(169, 254, 169, 254)

func isBlocked(ip net.IP) bool {
	if ip.Equal(metadataV4) {
		return true
	}
	// Block link-local (169.254.0.0/16, fe80::/10) which hosts metadata and
	// has no legitimate management-UI use case.
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	return false
}
