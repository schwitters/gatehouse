# Security remediation — 2026-10-27

This iteration addresses SEC-01 through SEC-10 in the security review.

- SEC-01: Removed the Guacamole plaintext payload, encrypted bearer payload, and decoded shared-key logs.
  Operators must rotate previously exposed keys and review existing log copies.
- SEC-02: Added HTML escaping for text and attribute delimiters, applied it to
  login errors, invitation pages, portal values, and configurable HTML titles.
  The existing inline-script CSP remains; moving scripts to nonces is a further
  hardening step.
- SEC-03: Reject foreign or missing realms before contacting Kerberos and derive
  the local UID from the authenticated principal after checking its realm.
- SEC-04: Every invitation-session lookup now rejects revoked, completed, and
  expired invitations. All mutating routes use this lookup. Completion storage
  errors are reported explicitly.
- SEC-05: Reject cleartext LDAP at startup and at the bind boundary. Require
  certificate verification for both LDAPS and StartTLS. Local LDAPI is allowed.
- SEC-06: Honor secure-cookie configuration for invitation and CSRF cookies.
- SEC-07: Throttle by account, normalize the configured realm suffix, reclaim
  expired entries when the map reaches capacity, and saturate attempt counters.
  No forwarded headers are trusted. Network-wide abuse controls remain the
  responsibility of the ingress proxy; a targeted account can still be throttled.
- SEC-08: Serialize complete route operations using a shared database request lock.
  This prevents interleaving transactions on the single connection. It also
  serializes LDAP, Kerberos, and SMTP work inside those requests, reducing
  throughput. Multiple service processes sharing a database are outside this lock.
- SEC-09: Use systemd DynamicUser, an empty capability set, and UMask 0077.
  StateDirectory supplies persistent storage. Check ownership and access to any
  pre-existing database and external runtime files before deploying the unit.
- SEC-10: Set explicit SMTP connect (10 seconds) and total (30 seconds) timeouts.

Crow is pinned to the immutable commit for v1.3.4 and GoogleTest to v1.18.0.
The published WSS advisory mentioning v1.3.5 remains relevant for future WebSocket
use. No WebSocket routes are registered by this application.

## Validation

The build uses CMake with ASan/UBSan and the exact release source archives for
the pinned dependencies. The missing Boost.System development package was
extracted under /tmp for validation; no system packages were installed.

Regression tests cover HTML escaping, title injection, foreign/missing realms,
the executable help command, and an isolated HTTP server with a temporary SQLite
database and Unix socket. HTTP checks cover reflected XSS, Secure invitation
cookies, completion after revocation, and independent account rate limits.

External Kerberos, LDAP, SMTP and Guacamole interoperability still requires a
staging environment. The request lock does not make external provisioning and
SQLite updates a distributed transaction; provisioning failures still require
operational reconciliation.

Validation result: the complete CMake build succeeded and all 98 CTest tests
passed under ASan/UBSan. Existing compiler warnings remain; this iteration does
not claim a warning-free build.
