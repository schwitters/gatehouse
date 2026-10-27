# Production readiness implementation

## Scope

This change addresses the five follow-up priorities: recoverable provisioning,
integration tests, database isolation, automated checks, and presentation/service
boundaries. It does not assert that a deployment has passed staging acceptance.

## Provisioning state and recovery

`core::ProvisionAccount` operates through `ProvisionStore` and `AccountProvisioner`
interfaces. It has no database, HTTP, LDAP, Kerberos or logging dependency. The
application adapter supplies the actual directory and Kerberos operations.
Missing configuration or an unknown LDAP user now fails before external creation;
it can no longer silently complete an invitation.

Schema version 7 adds a durable `provisioning_job` and an append-only checkpoint
history. The journal binds operations to an invitation-session ID and must be protected
with the database. It contains no passwords, OTP codes, Guacamole tokens or
Kerberos caches.

| Stage | Meaning | Retry behavior |
| --- | --- | --- |
| 0 | Ready | Preparation can be retried. |
| 1 | Creation started; result may be uncertain | Operator reconciliation required. |
| 2 | Principal created | Verify the original password, then retry activation. |
| 3 | Activation started; result may be uncertain | Operator reconciliation required after a crash. |
| 4 | Activated | Verify the original password, then retry the database completion. |
| 5 | Completed | External effects are not repeated. |

Compare-and-set transitions reject concurrent claims. A partial unique index
allows only one active operation per tenant/user. The final profile write,
invitation completion, session consumption and job checkpoint commit in one
short SQLite transaction. LDAP activation occurs before that commit, so the UI
cannot report success after an activation failure. A retry after activation must
use the password supplied when the principal was originally created; it does not
silently assign a different password.

Revocation of a running or uncertain provisioning operation is blocked by a
SQLite trigger. Admin reset/reinvite paths propagate that failure and do not
continue deleting attributes. A failed directory cleanup after revocation returns
an explicit error and can be retried.

### Reconciliation procedure

Back up the database before upgrading. Include its WAL consistently, or use the
SQLite backup API / `.backup` command rather than copying a live database alone.
Test upgrades and existing file ownership in staging before deployment.

1. Stop **all** Gatehouse processes using this database. Do not reconcile an
   operation that is still executing against the external services.
2. Inspect the journal without changing it:

   ```sh
   python3 scripts/reconcile-provisioning.py /var/lib/gatehouse/gatehouse.db INVITE_ID
   ```

3. Inspect the actual principal and LDAP account using privileged service tools.
   Confirm the exact tenant/user identity; an already existing unrelated account
   must never be adopted automatically.
4. Record the verified observation:

   ```sh
   python3 scripts/reconcile-provisioning.py /var/lib/gatehouse/gatehouse.db INVITE_ID \
     --service-stopped --confirmed principal-created
   ```

   Allowed observations are `principal-absent` / `principal-created` for stage 1,
   and `activation-pending` / `activated` for stage 3. Mismatching stages fail.
   The tool records the local operator in the checkpoint history. It does not
   contact the external services or infer their state.
5. Restart the service. If the invite session expired, accept the still-valid
   invitation again and complete a fresh OTP verification. Ready, principal-created
   and activated jobs can bind to that verified session. An expired invitation
   requires an operator-reviewed extension or a separate account recovery process;
   this tool deliberately does not extend invitation lifetimes.

No automatic compensation deletes a principal on an uncertain network result.
That would risk destroying an account whose creation actually succeeded.

## Database concurrency

Each HTTP worker lazily opens its own connection to the file database. Repositories
resolve the handle for the calling worker; ownership remains in `SqliteDb` until
the server joins its workers and shuts down. The global request mutex is removed.
WAL and a five-second busy timeout allow readers to proceed during a writer's
transaction. Only short database state changes hold write transactions; Kerberos,
LDAP and SMTP calls run outside them.

Worker connection initialization is explicit and failures return HTTP 503. The
worker API rejects `:memory:` databases because independent connections would not
share their contents. The server's thread count bounds its connection count.
External database writers must honor the journal protocol and triggers.

## Presentation boundaries

The invitation route calls a provisioning service instead of implementing account
creation itself. Invitation rendering has its own view model and renderer.
Login and admin-invitation HTML are in `web/`; the portal and tenant-overview JavaScript are separate
assets served under the configured base URI. CMake embeds these trusted files into
the executable, so deployments do not depend on writable template directories.
Asset changes trigger CMake regeneration. Existing URLs, CSRF checks and HTML
escaping are retained. Other views can migrate incrementally without replacing
the HTTP framework or introducing a frontend build system.

## Automated validation

The CI workflow runs Debug builds with and without ASan/UBSan, project warnings as
errors, and CTest. Dependency headers are treated as system headers.
Optimized GCC builds report null-dereference diagnostics in Boost.Asio's
instantiated server internals; only that warning category in `http_server.cc`
is exempted from `-Werror`, and the warnings remain visible. The runtime
version macro now uses the CMake project version. Dependency audit failures are
not converted into successful checks when a remote API is unavailable.

The audit checks the exact fetched commit against its CMake pin, queries OSV,
and also checks published GitHub repository advisories. GitHub Actions updates
are proposed by Dependabot. System libraries are installed from the runner's
updated distribution repositories and their package versions are recorded;
the commit audit is not a vulnerability scan of every installed OS package.

Crow's WSS issue `GHSA-mxx5-m65w-5qv2` has an explicit exception limited to 1.3.4
and expiring on 2026-11-27. The audit rejects it if WebSocket code appears in the
application. Review the upstream fix before expiry; do not extend the exception
without reassessing reachability. Unknown advisory range syntax fails closed.

References:

- [OSV commit query API](https://google.github.io/osv.dev/api/)
- [Crow published advisories](https://github.com/CrowCpp/Crow/security/advisories)

### Local validation

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug \
  -DGATEHOUSE_ENABLE_ASAN=ON -DGATEHOUSE_WARNINGS_AS_ERRORS=ON
cmake --build build --parallel 2
ctest --test-dir build --output-on-failure
python3 scripts/check-dependencies.py build
```

The tests exercise service failures, uncertain creation, checkpoint failures,
activation/completion retries, transaction rollback, worker isolation, exclusive
claims, blocked revocation, migration repetition, reconciliation preconditions,
advisory parsing, HTTP injection defenses, missing provisioning configuration,
parallel requests, and CLI/tool smoke checks.

### External staging test

`gatehouse_staging_integration` is opt-in and returns skip code 77 when
`GATEHOUSE_STAGING_CONFIG` is absent. It requires a **disposable** LDAP user,
Kerberos admin credentials, an LDAP-backed MIT KDC with password-change service,
a TLS-capable test SMTP server delivering into a Mailpit inbox, and Guacamole
with the encrypted JSON extension. The user must already exist in the expected
LDAP tenant tree, have no principal yet, and be assigned to the specified host.
The test creates and changes that user's principal and finally revokes it.
It does not delete the LDAP user. Partial test failures can leave a principal;
use the journal and reconcile it before rerunning.

Install `klist` (the `krb5-user` package) on the staging runner.

Create a mode-0600 JSON file outside the repository, for example:

```json
{
  "disposable_user": true,
  "tenant": "test",
  "uid": "disposable-user",
  "email": "disposable-user@example.invalid",
  "hostname": "test-host",
  "admin_uid": "test-admin",
  "admin_password": "REPLACE",
  "guacamole_url": "https://guacamole.test.invalid/guacamole",
  "mailpit_api": "https://mailpit.test.invalid",
  "environment": {
    "GATEHOUSE_KADM5_ADMIN_PRINC": "admin/admin@TEST.INVALID",
    "GATEHOUSE_KADM5_ADMIN_PASS": "REPLACE",
    "GATEHOUSE_SMTP_URL": "smtps://smtp.test.invalid:465",
    "GATEHOUSE_SMTP_USER": "REPLACE",
    "GATEHOUSE_SMTP_PASS": "REPLACE"
  },
  "arguments": [
    "--realm", "TEST.INVALID",
    "--ldap-url", "ldaps://ldap.test.invalid",
    "--ldap-bind-dn", "cn=service,dc=test,dc=invalid",
    "--ldap-bind-pw", "REPLACE",
    "--ldap-base-dn", "dc=test,dc=invalid",
    "--admin-uids", "test-admin",
    "--email-backend", "curl",
    "--guacamole-url", "https://guacamole.test.invalid/guacamole",
    "--guacamole-secret", "REPLACE"
  ]
}
```

The example is a schema, not a working public endpoint. Configure trusted CA
certificates and `KRB5_CONFIG` for the runner. Existing legacy CLI secrets remain
visible to local process inspection; restrict access to the dedicated runner.
Do not use production credentials or production accounts.

```sh
export GATEHOUSE_STAGING_CONFIG=/secure/path/staging.json
ctest --test-dir build -L staging --output-on-failure
```

The real-service test checks SMTP OTP delivery and wrong-code accounting,
provisioning, successful login, password change, rejection of the old password,
Guacamole authentication, single-use credential fetch, and invite revocation.
GitHub's manual workflow can run it on a runner labelled `gatehouse-staging`;
configure the `staging` environment variable `GATEHOUSE_STAGING_CONFIG` to the
protected local file path. Ordinary PR jobs do not receive these credentials.

## Validation record (2026-10-27)

- Debug build with ASan/UBSan and project warnings as errors: succeeded.
- Release build with project warnings as errors: succeeded, with the documented
  Boost.Asio diagnostic exception in the server translation unit.
- Both CTest runs: 118 passed, one external staging test skipped (119 registered).
- Live dependency audit of fresh checkouts matching the CMake pins: succeeded,
  with the explicit, time-limited Crow WSS exception reported.
- Python, workflow YAML and extracted JavaScript syntax checks: passed.
- GitHub-hosted CI and the external staging environment have not been executed
  from this workspace. Staging credentials/services were not configured here.

Local builds used exact release source archives and the Boost.System package
extracted under `/tmp`; system packages were not modified.
