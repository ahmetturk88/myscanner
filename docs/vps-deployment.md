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

## Public launch on the main domain

`compose.launch.yml` replaces the gate overlay. It mounts `deploy/Caddyfile.launch`,
which is `deploy/Caddyfile` plus one block that permanently redirects
`www.$SITE_DOMAIN` and `test.$SITE_DOMAIN` to `https://$SITE_DOMAIN`.

1. In `.env.vps.rehearsal` set `SITE_DOMAIN=myscanners.com` and remove the
   `GATE_*` lines.
2. In Cloudflare DNS point `myscanners.com` (A), `www` and `test` at the VPS with
   **DNS only** (grey cloud). The proxy reads the client address from the TCP
   connection and drops Cloudflare headers, so a proxied (orange) record would
   make every visitor look like Cloudflare to rate limits. Leave MX, SPF,
   DKIM and DMARC records unchanged.
3. Once `dig +short myscanners.com` returns the VPS address, recreate the proxy
   and web services so Caddy requests certificates and `BASE_URL` follows:

```
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml -f compose.app-egress.yml -f compose.launch.yml up -d --force-recreate proxy web
```

4. Update the OAuth callback URLs at Google and GitHub to
   `https://myscanners.com/auth/<provider>/callback`.

## Daily database backup

`scripts/vps_backup.sh` writes a PostgreSQL custom-format dump and a SHA-256
file to `/var/backups/myscanner` (root-only), checks the archive catalogue with
`pg_restore --list` before publishing it, and deletes only its own archives
older than `KEEP_DAYS` (default 14). Run it once by hand, then schedule it:

```
sudo scripts/vps_backup.sh
echo "17 3 * * * root $PWD/scripts/vps_backup.sh >> /var/log/myscanner-backup.log 2>&1" | sudo tee /etc/cron.d/myscanner-backup
```

Local archives are unencrypted and stay on the same server, so on their own they
protect against mistakes, not against losing the server.

### Encrypted off-site copy

Set `OFFSITE_REMOTE` and the script also encrypts each dump with
[age](https://age-encryption.org) and uploads it with rclone, then deletes
remote copies older than `OFFSITE_KEEP_DAYS` (default 30). Only the age
**public** key lives on the server; a stolen server cannot read the copies.

1. On your own computer, create the key pair and keep the file safe (password
   manager plus an offline copy). Without it the backups cannot be restored.
   `age-keygen -o myscanner-backup-key.txt` prints the public key (`age1…`).
2. On the server, store only that public key:
   `sudo install -d -m 700 /etc/myscanner` then write it to
   `/etc/myscanner/backup-recipients.txt`.
3. Install the tools: `sudo apt install age rclone`.
4. Create an rclone remote as root (for Cloudflare R2: an S3 remote with
   `provider=Cloudflare`, a bucket-scoped Object Read & Write token and
   `no_check_bucket=true`).
5. Write `/etc/myscanner/backup.env` (mode 600):

```
OFFSITE_REMOTE=r2:myscanner-backups
OFFSITE_KEEP_DAYS=30
```

Run `sudo scripts/vps_backup.sh` once; it ends with `PASS: off-site …`. Any
upload problem makes the run fail, so the cron log shows it.

### Restore rehearsal

Download one `.dump.age` and its `.sha256`, then on a machine that has the key:

```
age -d -i myscanner-backup-key.txt -o myscanner-YYYYMMDD-HHMMSS.dump myscanner-YYYYMMDD-HHMMSS.dump.age
sha256sum -c myscanner-YYYYMMDD-HHMMSS.dump.sha256
pg_restore --list myscanner-YYYYMMDD-HHMMSS.dump | head
```

Restore into a separate, empty database to prove the archive is usable; never
over the live one during a rehearsal.

## AI assistant

Report pages offer an AI explanation (Arabic or English) and follow-up questions.
The assistant explains the evidence; verdicts stay with the scanners. Report
evidence is sent as delimited, untrusted data with secrets and images removed,
and answers are validated and rendered as text.

- Providers are tried in `AI_PROVIDERS` order (default `gemini,groq`); the next
  one answers when one fails or is rate limited. Models: `AI_GEMINI_MODEL`
  (default `gemini-flash-latest`) and `AI_GROQ_MODEL` (default
  `openai/gpt-oss-120b`), both overridable in `.env.vps.rehearsal`.
- Keys live in `.deploy/rehearsal/gemini_api_key` and `groq_api_key` (empty
  disables a provider; with both empty the panel is hidden).
- Each new explanation or chat answer costs one `ai_assistant` unit (10 per day
  for users); cached explanations are free and failed calls are refunded.
- Contexts are kept 30 days, at most 50 per user.

Check the setup from the server: `docker compose ... exec web python scripts/ai_selfcheck.py`.

## Google and GitHub sign-in

A provider button appears only when both its client id and secret are set.
Callback URLs (replace the host for production):

- Google: `https://test.myscanners.com/auth/google/callback`
- GitHub: `https://test.myscanners.com/auth/github/callback`

Put the client ids in `.env.vps.rehearsal` (`GOOGLE_CLIENT_ID=…`,
`GITHUB_CLIENT_ID=…`) and each secret in its own file,
`.deploy/rehearsal/google_client_secret` and
`.deploy/rehearsal/github_client_secret` (created empty by
`scripts/init_vps_stack.py`; keep them mode 0444 inside the private directory).
Recreate `web` afterwards. Only provider-verified email addresses are accepted.
