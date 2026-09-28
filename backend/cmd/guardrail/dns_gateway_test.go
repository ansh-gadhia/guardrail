package main

import (
	"reflect"
	"strings"
	"testing"
)

// The gateway is configured entirely from the .env the installer writes, so
// what each combination of keys turns into is worth pinning down.
func TestGatewayConfigFromEnv(t *testing.T) {
	keys := []string{
		"GUARDRAIL_DNS_DOH", "GUARDRAIL_DNS_DOH_PORT", "GUARDRAIL_DNS_DOT", "GUARDRAIL_DNS_DOT_PORT",
		"GUARDRAIL_DNS_PLAIN", "GUARDRAIL_DNS_PLAIN_PORT", "GUARDRAIL_HTTPS_PORT",
		"GUARDRAIL_DNS_UPSTREAM", "GUARDRAIL_DNS_UPSTREAM2", "GUARDRAIL_DNS_BACKEND",
	}
	cases := []struct {
		name    string
		env     map[string]string
		check   func(t *testing.T, c gatewayConfig)
		wantErr string
	}{
		{
			// A .env from before 1.7.0 has none of these: plain DNS on 53 and
			// nothing encrypted, which is what such a server was running.
			name: "no keys at all",
			env:  map[string]string{},
			check: func(t *testing.T, c gatewayConfig) {
				if c.doh || c.dot || c.backend != "127.0.0.1:53" || len(c.upstreams) != 0 {
					t.Errorf("got doh=%v dot=%v backend=%s upstreams=%v", c.doh, c.dot, c.backend, c.upstreams)
				}
			},
		},
		{
			name: "everything on, own ports, plain DNS on 5353",
			env: map[string]string{
				"GUARDRAIL_DNS_DOH": "yes", "GUARDRAIL_DNS_DOH_PORT": "1010",
				"GUARDRAIL_DNS_DOT": "YES", "GUARDRAIL_DNS_DOT_PORT": "8853",
				"GUARDRAIL_DNS_PLAIN": "yes", "GUARDRAIL_DNS_PLAIN_PORT": "5353",
			},
			check: func(t *testing.T, c gatewayConfig) {
				if !c.doh || !c.dot || c.shared || c.dohPort != "1010" || c.dotPort != "8853" || c.backend != "127.0.0.1:5353" {
					t.Errorf("got %+v", c)
				}
			},
		},
		{
			// DoH on the console's port goes through Traefik.
			name: "DoH on the console's port",
			env:  map[string]string{"GUARDRAIL_DNS_DOH": "yes", "GUARDRAIL_DNS_DOH_PORT": "8443", "GUARDRAIL_HTTPS_PORT": "8443"},
			check: func(t *testing.T, c gatewayConfig) {
				if !c.shared {
					t.Error("not shared")
				}
			},
		},
		{
			// Plain DNS off: dnsmasq listens on loopback 5335 only, whatever
			// port plain DNS last had.
			name: "plain DNS off",
			env:  map[string]string{"GUARDRAIL_DNS_PLAIN": "no", "GUARDRAIL_DNS_PLAIN_PORT": "5353", "GUARDRAIL_DNS_DOT": "yes"},
			check: func(t *testing.T, c gatewayConfig) {
				if c.backend != "127.0.0.1:5335" {
					t.Errorf("backend = %s", c.backend)
				}
			},
		},
		{
			name: "only https upstreams are forwarded here",
			env:  map[string]string{"GUARDRAIL_DNS_UPSTREAM": "9.9.9.9", "GUARDRAIL_DNS_UPSTREAM2": "https://1.1.1.1/dns-query"},
			check: func(t *testing.T, c gatewayConfig) {
				if !reflect.DeepEqual(c.upstreams, []string{"https://1.1.1.1/dns-query"}) {
					t.Errorf("upstreams = %v", c.upstreams)
				}
			},
		},
		{
			name:    "a port that is not one",
			env:     map[string]string{"GUARDRAIL_DNS_DOT": "yes", "GUARDRAIL_DNS_DOT_PORT": "70000"},
			wantErr: `GUARDRAIL_DNS_DOT_PORT="70000"`,
		},
		{
			name:    "DoH and DoT on one port",
			env:     map[string]string{"GUARDRAIL_DNS_DOH": "yes", "GUARDRAIL_DNS_DOT": "yes", "GUARDRAIL_DNS_DOH_PORT": "853", "GUARDRAIL_DNS_DOT_PORT": "853"},
			wantErr: "cannot share port 853",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range keys {
				t.Setenv(k, tc.env[k])
			}
			c, err := gatewayConfigFromEnv()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one mentioning %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			tc.check(t, c)
		})
	}
}
