# Local DNS records

The bundled resolver answers one thing out of the box: `*.<tunnel domain>` ->
this host, which is what makes browser sessions reachable. It had nowhere to put
anything else, so adding a record meant editing `docker-compose.yml`.

These two directories are that place. They are bind-mounted read-only into the
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
- **The resolver answers only local subnets.** The stock `local-service`
  directive is in force, so it is not an open resolver — but anything on your
  LAN can query it.
- **Anything not matched is forwarded** to the upstreams in `.env`
  (`GUARDRAIL_DNS_UPSTREAM`, `GUARDRAIL_DNS_UPSTREAM2`).

## Checking your work

    dig +short @<host ip> fw1.corp.lan          # ask this resolver directly
    docker compose --profile dns logs dns       # startup: which files were read
    docker kill --signal=USR1 guardrail-dns-1   # dump the live cache to the log

A syntax error in a `hosts/` file is skipped line by line; a bad `*.conf` stops
dnsmasq from starting, so check the logs after a restart.
