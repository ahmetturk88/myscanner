# MyScanner İşletme (Business): stage 1, foundations

Website only. Nothing in the mobile app links to it or sells it (Google Play requires Play Billing for
in-app digital subscriptions, so the business plan is sold on the website only).

## What this stage adds
- **Public page** `/isletme` (Turkish by default, `?lang=en`; `/business` redirects to it): the plan, the
  planned price (≈ $25/month, free during the pilot, no payment), honest limits, FAQ, and a
  **pre-registration form** (work email, optional website, business type, explicit consent). A hidden
  honeypot field drops bots; each email is kept once. The visit source (`utm_source`/`ref`/referrer)
  is stored with the lead.
- **Admin view** `/admin/business-leads`: pre-registrations by business type and the latest 50.
- **Workspace** `/isletme/panel` (login required, `Cache-Control: private, no-store`, `noindex`): open to
  administrators and to email-verified accounts listed in `BUSINESS_PILOT_EMAILS`. A workspace is
  created on first visit (one per account).
- **Domain ownership proof**: add up to 3 domains (pilot limit); each gets a random 128-bit token.
  The owner adds `TXT _myscanner.<domain> = myscanner-business=<token>`. Verification reads that exact
  name (2 s timeout, 4 s lifetime, at most 32 values of 256 bytes) and compares in constant time.
  NXDOMAIN or a missing value is "not found yet"; any other DNS error never verifies. Limits:
  20 additions/hour, 20 checks/hour and 5/minute per account (database-backed).
- Domains are always looked up through the owner's workspace: another account, including an
  administrator, gets 404 for someone else's domain. All changes are CSRF-protected POSTs.

## Configuration
`BUSINESS_PILOT_EMAILS=owner@company.com,second@company.com` in the server environment
(`.env.vps.rehearsal`), then `dc up -d web`. Empty means only administrators can open a workspace.

## Data and privacy
New tables (migration `b7e2c4a9d1f6`): `business_workspace`, `business_domain`, `business_lead`.
A lead holds the email, optional website, business type, language and visit source. The privacy
policy gets a website-only section for this before the pilot invites anyone (deliberately not changed
while the Play production review is open).

## Next stages
2. Monitoring engine (scheduled SSL/domain expiry, blocklists, DNS/SPF/DMARC changes, weekly site posture).
3. Alerts (email, severity, dedupe, digest). 4. Look-alike / impersonation watch. 5. Monthly PDF, team members.

# Stage 2: monitoring engine

Every verified domain is checked about once a day. The `business-monitor-due` beat entry runs every 15 minutes
on the `bulk` queue (its own worker, so customer scans are never delayed) and picks up to 25 verified domains whose
last run is older than 23.5 hours, never-run ones first. The owner can also press "Check now" (5 per account per day,
queued as `business_check_now`).

| Check | Source | ok / warn / bad |
|---|---|---|
| Ownership | our TXT record | present / missing (3 runs in a row → monitoring pauses, proof needed again) |
| SSL | one verified TLS handshake (`ssl_analyzer`) | valid / < 14 days / invalid or < 7 days |
| Domain expiry | registry RDAP (`domain_analyzer`) | / < 30 days / < 7 days |
| DNS | A, AAAA, MX, NS | has an address / — / no address |
| Email protection | SPF and DMARC (`site_posture.mail_security`) | DMARC quarantine/reject / weak / neither |
| Blocklists | the email check's DNSBLs on the site's first IPv4 | not listed / — / listed |
| Threat lists | Google Web Risk, URLhaus | not listed / — / listed |

A check that cannot run is `na`, never `ok`. The score is 100 minus fixed deductions for warn/bad states and is
withheld when fewer than three checks answered. Each run is stored as a `business_snapshot`; comparing it with the
previous one creates `business_event` rows: new problems, fixes, a renewed certificate, changed A/AAAA/MX/NS records,
changed SPF/DMARC, a registrar change, missing ownership proof. Events keep a code and parameters; the workspace
renders them in Turkish or English. `notified_at` is for stage 3 (alerts).

Licensing note: URLhaus and the Spamhaus DNSBL are used as on the rest of the site. abuse.ch confirmed in writing that
the free use is fine while the service is free; before charging for this plan both need commercial terms (Spamhaus),
or these sources are switched off for paying workspaces (`MYSCANNER_DISABLED_SOURCES`).

Migration `c3f9a2e6b8d4` adds the two tables and three columns on `business_domain`.

# Stage 3: alerts and the weekly site inspection

**Alerts** (`services/business_alerts.py`) go only to the workspace owner's verified email, in the workspace's
language (`alert_lang`), and each event is emailed once (`notified_at`; a failed send leaves it pending).
- **Instant** (`instant_alerts`, on by default): right after the run that found them, every `bad` event and the
  quiet changes attackers cause: changed DNS records, registrar or SPF/DMARC, a missing ownership record.
- **Daily digest** (`daily_digest`, on by default): everything not sent yet from the last 7 days, at most once per
  23 hours and only between 09:00 and 21:00 Türkiye time; no email when nothing happened. Beat:
  `business-send-digests` every 30 minutes.
- Every value in the HTML email is escaped; the email links to the workspace.

**Weekly site inspection**: `business-weekly-due` (hourly, at most 3 domains per run, bulk queue) runs the public,
passive website check (the same as /site-scanner, without the provider or discovery options) for verified domains
whose last inspection is older than 7 days. New warning reasons become `site_issue` events, resolved ones
`site_issue_fixed`. Titles are stored in English and translated with the site's report catalog when shown.

Migration `d5a1c7e3f9b2` adds `alert_lang`, `instant_alerts`, `daily_digest`, `last_digest_at` to `business_workspace`.
The workspace has an alert settings card (CSRF-protected POST `/isletme/panel/settings`).
