# Security policy

Externalize decides whether data about the Stellar network is genuine, so a
verification bypass is the most serious bug it can have.

## Reporting

Please report vulnerabilities privately through
[GitHub security advisories](https://github.com/Externalize-Labs/externalize/security/advisories/new).
Do not open a public issue. We aim to acknowledge reports within three days.

In scope, most severe first:

1. A bundle or certificate that verifies but describes something the trust set
   did not externalize.
2. A way to make a valid bundle fail to verify (denial of service against
   honest users).
3. Panics, unbounded memory use or excessive CPU on malicious input.

## Status

The code has not had an independent security audit. Until it has, do not use
it as the sole safeguard for funds. The assumptions it does rely on are listed
in [docs/trust-model.md](docs/trust-model.md).
