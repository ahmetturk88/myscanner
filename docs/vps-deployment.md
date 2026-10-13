# VPS core deployment rehearsal

This is an independent production-mode core stack. It does not deploy to a VPS,
change DNS, or modify the Docker-local or Render databases. Run the rehearsal
before purchasing a server. The first rehearsal uses a new, empty database.

## Prepare and validate (PowerShell)

```powershell
python -m unittest discover -s tests -p test_vps_deployment.py -v
python scripts/init_vps_stack.py
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml config --quiet
```

Secrets are generated once under `.deploy/rehearsal`; do not send them, commit
that directory, or print an expanded Compose environment. File secrets are bind
mounts, not an encrypted secret vault. The private parent directory protects the
readable secret files on Linux; restrict Windows directory ACLs to your account.
Do not regenerate passwords for an existing database volume.

## Rehearse locally

```powershell
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml up -d --build
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml ps -a
curl.exe -k https://localhost:8443/health/live
curl.exe -k https://localhost:8443/health/ready
```

Expect alive and ready. Caddy uses its own local CA for localhost: `-k` is only
for this rehearsal, never a public-production verification. The database role
initializer, migrations and source initializer must exit 0 before runtime starts.
Worker stop/restart should change readiness without changing liveness.
No real scan, account creation or backup restoration is implied by these checks.

Only the HTTPS proxy publishes ports, on loopback by default. PostgreSQL and
password-protected Redis are private. Runtime processes run as UID 10001 with
read-only image files and without migration/admin secrets. Redis persists queue
data with AOF and no eviction. One Beat service schedules tasks.

## Production gate (not yet authorized or verified)

Use a separate production secret directory and environment file, an immutable
image tag from the reviewed commit, and a unique Compose project. Set the domain
and public port bindings only on the intended VPS. A real domain requires DNS
and ports 80/443 to reach Caddy for certificate issuance. Do not reuse Render's
proxy profile. This configuration trusts only its private Caddy peer, overwrites
forwarded headers and removes Cloudflare IP headers. Use direct DNS during this
stage; Cloudflare proxying needs a separately verified client-IP boundary.
Check that subnet 172.31.240.0/24 does not overlap existing networks.

URLVet defaults to the existing local host service on 8080 for rehearsal.
Its production endpoint and deployment are a separate integration gate. ZAP/GVM
are not included; active scanning remains disabled. Private database networking
is not a complete target egress firewall. Provider coverage, outgoing target
isolation, load tests, monitored backups and production recovery remain gates.

## Update and rollback procedure

Before an update: verify an off-host backup and restoration rehearsal, record
the current image tag and migration revision, and test the new revision against
a restored database. Stop web, worker and Beat to prevent mixed versions. Run
bootstrap/migrate/seed using the new immutable image, then start runtime and
check HTTPS readiness, a queue job and an existing report. Never remove volumes.

If application checks fail, stop runtime and restore the previous image tag
only when its schema compatibility was tested. Do not automatically downgrade
migrations or restore over a live database. A destructive schema change requires
a separately rehearsed database recovery and maintenance plan. This document
is a reviewable procedure, not a claim that production rollback is validated.

## Browser rehearsal account

After successful HTTPS and queue checks, create the account interactively:

```powershell
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml exec -e VPS_REHEARSAL=1 web python scripts/vps_runtime.py create-user
```

The password must match and contain at least 12 characters; it is not echoed.
The fixed account is `rehearsal-admin@example.invalid`, verified and admin only
in this isolated database. Existing accounts are never changed by the command.
Open https://localhost:8443 and sign in. The local certificate is issued by
Caddy's rehearsal CA; accept the browser warning only for this localhost test.
Production account onboarding and real domain certificates are separate steps.

## Password-gated test server

A public test server (for example `test.myscanners.com`) keeps every page behind
HTTP basic authentication until launch. On the server, after
`python3 scripts/init_vps_stack.py`, edit `.env.vps.rehearsal`:

```
SITE_DOMAIN=test.myscanners.com
HTTP_BIND=0.0.0.0:80
HTTPS_BIND=0.0.0.0:443
GATE_USER=<login name>
GATE_PASSWORD_HASH='<output of the hash command>'
```

Create the hash interactively, so the password never lands in shell history:
`docker run --rm -it caddy:2-alpine caddy hash-password`. Keep the single
quotes: the bcrypt hash contains `$`, which Compose would otherwise expand.
Start the stack with the gate overlay:

```
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.gate.yml up -d --build
```

The overlay replaces the proxy's Caddyfile with `deploy/Caddyfile.gate`, which
must stay identical to `deploy/Caddyfile` apart from the `basic_auth` block
(enforced by `tests/test_vps_deployment.py`). Compose refuses to start when
either gate variable is missing. Drop `-f compose.gate.yml` to open the site.

## Daily database backup

`scripts/vps_backup.sh` writes a PostgreSQL custom-format dump and a SHA-256
file to `/var/backups/myscanner` (root-only), checks the archive catalogue with
`pg_restore --list` before publishing it, and deletes only its own archives
older than `KEEP_DAYS` (default 14). Run it once by hand, then schedule it:

```
sudo scripts/vps_backup.sh
echo "17 3 * * * root $PWD/scripts/vps_backup.sh >> /var/log/myscanner-backup.log 2>&1" | sudo tee /etc/cron.d/myscanner-backup
```

The archives are unencrypted and stay on the same server, so they protect
against mistakes, not against losing the server. Before real users: copy them
off the server encrypted and rehearse a restore into a separate database.
