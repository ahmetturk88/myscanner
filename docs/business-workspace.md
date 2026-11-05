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
3. Alerts (email, severity, dedupe, digest). 4. Look-alike / impersonation watch. 5. Monthly PDF, team members (all done, see below).

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
| Blocklists | the email check's DNSBLs on the site's first IPv4 | not listed (also when only some lists answered: Spamhaus refuses public resolvers; the row says how many answered) / — / listed |
| Threat lists | Google Web Risk, URLhaus (keys mounted in bulk-worker by `compose.urlvet.yml`) | not listed / — / listed |

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

# Stage 4: look-alike (impersonation) watch

`services/business_lookalike.py`, beat `business-lookalike-due` (hourly, at most 5 domains per run, each domain about
once a day, bulk queue).
- **Generated candidates** (about 400 for a typical name): the same name under other endings (.com, .net, .com.tr,
  .shop, .xyz…), typos of the name (missing, doubled, swapped or neighbouring-key letters, inserted hyphen, look-alike
  digits such as 0/o, 1/l, rn/m), and the name joined with words scams use (giris, odeme, destek, kampanya, login…).
  Each run resolves the next 120 in DNS (8 in parallel, 3 s budget each), so the whole list is covered every few days.
- **Certificate Transparency** (crt.sh, `%name%`, bounded to 4 MB and 3000 rows): registrable names whose name carries
  the brand, also written with look-alike letters. Switched off with the existing `crtsh` source switch.
- A name that resolves is recorded once (`business_lookalike`). Its home page is read once through the public-network
  session (1 MB, nothing submitted): **high** risk when it shows the brand or asks for a password or card, **medium**
  when it is a live site, **low** when it only exists in DNS. A recorded name that later goes live is read again.
- DNS errors and an unavailable certificate index conclude nothing. New names (`lookalike_found`) and names that go
  live (`lookalike_live`) are events and **instant alerts**. The workspace lists open names as plain text (never as
  links), with the page title, a "dismiss" button (workspace-scoped, 404 otherwise) and response steps (warn
  customers, report to USOM, abuse report to the registrar, trademark advice).

Migration `e8b4d2f6a1c9`: `business_lookalike`, and `lookalike_at` / `lookalike_cursor` on `business_domain`.

# Stage 5: team members and the monthly report

**Team** (`business_member`): the owner invites up to 4 colleagues by email (five people in all). The invitation email
links to `/isletme/davet/<token>` (random 256-bit token, `no-store`, `no-referrer`). It is accepted only while signed in
with the **same, verified** email address; any other account gets 403, an unknown token 404. Members do not need to be
pilot accounts.
- Roles: the owner changes everything; members see the workspace, press "check now" and download the report. Every
  changing route (domains, settings, dismiss, team) answers 403 to a member. Removing a member ends their access at once.
- Alerts (instant, digest, monthly) go to the owner and to accepted members whose alerts are on, verified addresses only,
  each address once.
- Limits: 20 invitations per owner per day; re-inviting a pending address re-sends the same invitation.

**Monthly PDF** (`services/business_report.py`, GET `/isletme/panel/report.pdf`, 10 per account per hour, `?lang=tr|en`):
the last 30 days from stored data only (nothing is scanned): average status, number of changes, open look-alikes, a
"what to do" list built from current warnings/problems and high-risk look-alikes, then per verified domain the current
checks, the status week by week, the changes and the open look-alikes, and how to read the report.

**Monthly email**: beat `business-monthly-reports` (hourly, bulk queue) on days 1–3 of the month, 09:00–21:00 Türkiye
time, once a month per workspace (`last_report_month`): a short note with a link to the workspace (no attachment, so no
report data travels by email). Workspaces without a verified domain are skipped for that month.

Migration `f2c6e9a4b7d1`: `business_member`, and `last_report_month` on `business_workspace`.

**Telling your own names from imitations** (migration `a4d9c3e7f1b5`): each recorded look-alike also gets public facts,
read from DNS and RDAP (the site is never opened), at most 12 lookups per run, new names first, older names later:
- a hint when it shares **all** name servers, an IP address or a mail server with the watched domain: shown as "might be
  yours: … A hint, not proof" (customers of the same provider can share them);
- the registration date and registrar; a name registered in the last 30 days moves up one risk step;
- the owner can press **This is mine** (status `mine`): no more alerts, listed separately as "marked as yours";
- a "Is this name mine?" help list (check the registrar's domain list, ask the agency, then dismiss or follow the
  fake-site steps).
- In alert emails and the monthly PDF, look-alike names are written defanged (`magazam-giris[.]com`): mail apps and PDF
  viewers turn bare domain names into links, and an imitation must never become a clickable link from us.

# Business+ 1: uptime (availability) monitoring

`services/business_uptime.py`, beat `business-uptime-due` every 5 minutes (bulk queue, `expires` 280 s so a busy worker
never builds a backlog). Each run fetches the home page of every verified domain once through the public-network
session (HTTPS; plain HTTP only when HTTPS cannot connect; at most 64 KB read; nothing submitted).
- Down = timeout, refused/broken connection or a 5xx answer; any other answer (also a firewall's 4xx) means up.
- Two failures in a row open an outage (`site_down`, bad); the first success after it closes it (`site_up`, with the
  minutes). Both are instant alerts. A single slow answer never alerts.
- A control address (Google / Cloudflare) is asked first; when even that fails, our own network is down and the run
  concludes nothing.
- Daily counts (`business_uptime_day`: checks, answers, total response time) give the 30-day percentage and average
  response time shown in the workspace and the monthly PDF (below 99% it becomes a to-do item).
- The bulk worker runs one task at a time: during a long look-alike or weekly run, uptime checks wait (the outage is
  still detected, a few minutes later).

Migration `c7e1f4a8b2d6`: uptime columns on `business_domain`, table `business_uptime_day`.
