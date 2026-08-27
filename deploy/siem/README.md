# SIEM trust anchor

Put the SIEM's TLS certificate here when you wire up single sign-on, then point
the API at it:

```
GUARDRAIL_SIEM_JWKS_CA_BUNDLE=/etc/guardrail/siem/jwks-ca.pem
```

This directory is bind-mounted read-only into the API container at
`/etc/guardrail/siem`. It holds a **public certificate**, never a private key.

## What file, exactly

Whatever signed the certificate the JWKS host presents:

- the SIEM's own certificate, if it is self-signed (the usual case on a private
  network), or
- the internal CA that issued it.

Fetch and inspect it before you trust it — the whole point is that you decided
which certificate is the right one:

```
openssl s_client -connect siem.internal:443 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM > jwks-ca.pem
openssl x509 -in jwks-ca.pem -noout -subject -issuer -dates -fingerprint
```

The certificate must also match the host in `GUARDRAIL_SIEM_JWKS_URL`, so that
name or IP has to appear in its SAN. A certificate whose CN matches but whose
SAN does not will be refused, and correctly.

## Why there is no way to switch the check off

Whoever can answer the JWKS URL chooses the public key GuardRail will accept, and
from then on mints tokens it treats as genuine. That turns "needs the SIEM's
private key" into "needs to be on the network path". A verify-off switch would
make that trade available by accident, so there isn't one — the escape hatch for
a self-signed SIEM is this pinned certificate.

Two consequences worth putting in a calendar:

- If this file is named in the environment but missing or unreadable, the API
  refuses to use the SSO configuration at all rather than falling back to the
  system trust store. A trust anchor that silently disappears is worse than one
  that never worked.
- GuardRail stops trusting the SIEM the day this certificate expires, and the
  symptom is "SSO stopped working" with nothing else broken. Note the expiry
  from the `openssl x509` output above.
