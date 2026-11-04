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
