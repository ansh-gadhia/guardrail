# Local DNS records

The bundled resolver answers one thing out of the box: `*.<tunnel domain>` ->
this host, which is what makes browser sessions reachable. It had nowhere to put
anything else, so adding a record meant editing `docker-compose.yml`.

## How clients reach it

Three ways in, each switched on or off by itself and each on any port. Use one,
two or all three; the resolver runs while any of them is on.

| Way in | Clients use | Settings in `.env` |
|---|---|---|
| Plain DNS (UDP and TCP, unencrypted) | `<host ip>` port 53, or the port you chose | `GUARDRAIL_DNS_PLAIN`, `GUARDRAIL_DNS_PLAIN_PORT` |
| DNS over HTTPS | `https://<host ip>/dns-query` on 443, `https://<host ip>:<port>/dns-query` otherwise | `GUARDRAIL_DNS_DOH`, `GUARDRAIL_DNS_DOH_PORT` |
| DNS over TLS | `<host ip>` port 853, or the port you chose | `GUARDRAIL_DNS_DOT`, `GUARDRAIL_DNS_DOT_PORT` |

A fresh install turns all three off. An update of a server from before these
existed keeps what it ran: plain DNS on 53, nothing encrypted.

DNS over HTTPS on the console's own port shares the console's listener and
certificate — Traefik hands `/dns-query` to the `dns-gateway` service. On any
other port, and for DNS over TLS always, `dns-gateway` serves it itself with the
same certificate. Either way clients must trust that certificate: the
installer's is self-signed, so import `deploy/tls/cert.pem` on each client (or
replace it with one from your CA). With plain DNS off, the resolver listens on
loopback only and answers nothing but the gateway.

To change any of it, re-run the installer and choose **Update**. Every DNS
question is asked again with what is installed now as the default — Enter keeps
it, typing a new value replaces it. A port is checked before it is written:
the HTTP port, the resolver's internal ports (5053, 5335, 8053), a port another
answer took, or one something else listens on (named) is refused and asked
again. After start-up the installer asks each way in a real question and says
which answered.

## Your own records

Anything else goes in two directories. They are bind-mounted read-only into the
resolver and survive updates — `install.sh` merges the release over the top and
never deletes files you put here.

    deploy/dns/
      hosts/     A/AAAA records, /etc/hosts syntax. RELOADED LIVE.
      conf.d/    anything else, dnsmasq syntax, *.conf only. NEEDS A RESTART.

## hosts/ — the common case

One `IP  name [more names...]` per line, in any file you like. dnsmasq watches
the directory with inotify, so a new file or an edited one takes effect within a
second or two — no restart, no reload command.

    # deploy/dns/hosts/estate
    10.200.10.98   fw1.corp.lan fw1
    10.200.10.99   switch1.corp.lan
    2001:db8::10   core-rtr.corp.lan

Files whose names start with `.` are ignored, which is why `.gitkeep` sitting
here is not read as a record.

## conf.d/ — wildcards, CNAMEs, and the rest

Full dnsmasq configuration syntax. Only files matching `*.conf` are read, and
ONLY AT STARTUP — dnsmasq re-reads hosts files on the fly but never its own
configuration, so after adding or changing one:

    cd /opt/guardrail && docker compose --profile dns restart dns

    # deploy/dns/conf.d/lab.conf
    address=/lab.corp.lan/10.200.10.97      # the name AND everything under it
    cname=old-fw.corp.lan,fw1.corp.lan      # target must be a name dnsmasq knows
    srv-host=_ldap._tcp.corp.lan,dc1.corp.lan,389
    txt-record=corp.lan,"v=spf1 -all"

## Things that will confuse you once

- **The tunnel wildcard wins inside its own domain.** `address=/tunnel.corp.lan/`
  matches every name under it, so a `hosts/` entry for `foo.tunnel.corp.lan`
  never gets a look in. Put your own records under a different domain.
- **A name here is not reachable unless this resolver is the one being asked.**
  These records exist only in dnsmasq. A client using its own DNS sees nothing.
- **Every way in answers anyone who can reach its port.** The resolver does
  not filter clients by address — dnsmasq's `local-service` has no effect once
  it is told which address to listen on — so each port is an open resolver to
  whoever reaches it. With DoH on 443, that is everyone who can reach the
  console. Firewall the ports if that is wider than your LAN.
- **Anything not matched is forwarded** to the upstreams in `.env`
  (`GUARDRAIL_DNS_UPSTREAM`, `GUARDRAIL_DNS_UPSTREAM2`). Each is an IP (plain
  DNS) or an `https://` URL, which the gateway sends over DNS over HTTPS so the
  resolver's own lookups leave the host encrypted as well.

## Checking your work

    # each way in, the way clients ask (dig from BIND 9.18 or later)
    dig +short @<host ip> -p <port> fw1.corp.lan            # plain DNS
    dig +https +short @<host ip> -p <port> fw1.corp.lan     # DNS over HTTPS
    dig +tls +short @<host ip> -p <port> fw1.corp.lan       # DNS over TLS
    curl -sv --doh-insecure --doh-url https://<host ip>[:port]/dns-query \
        http://fw1.corp.lan/ 2>&1 | grep -m1 Trying         # the address it resolved to

    docker compose --profile dns logs dns dns-gateway   # startup: modes, ports, files read
    docker kill --signal=USR1 guardrail-dns-1   # dump the live cache to the log

A syntax error in a `hosts/` file is skipped line by line; a bad `*.conf` stops
dnsmasq from starting, so check the logs after a restart.
