# Email evidence assessment

The email page has a responsive input view and a single result report. Five categories contribute to an evidence index: routing 20, sender records 25, domain reputation 25, SMTP acceptance 15, domain history 15. Findings deduct points within each category; unavailable checks deduct five points each, limited by the remaining category weight. The index is neither a probability of safety nor a delivery guarantee.

SMTP is off by default. Selecting its checkbox explicitly requests a recipient probe that discloses the address to the receiving mail server. No email body is sent. Bulk checks use the default and skip SMTP. A server acceptance or rejection only describes that probe, and does not establish ownership or future delivery.

## Engine v2

All API verdict and quality fields now come from the same evidence assessment. SMTP returns PROBE_ACCEPTED/PROBE_REJECTED/UNKNOWN, rather than asserting deliverability. It requires authenticated STARTTLS before sending the address; a provider without usable STARTTLS remains unavailable. Public SMTP sockets retain hostname verification while pinning the validated destination.

SPF audits literal include/redirect dependencies, loops, duplicate records/modifiers, permissive all and malformed IP networks. Traversal is limited to ten DNS terms, with an overall 20-second DNS audit budget. Macros and failed dependencies remain partial; this is a static configuration audit, not a sender-IP SPF evaluation. DMARC audits exact-domain record multiplicity, duplicate tags, policy and alignment modes, and the RFC 9989 defaults/test flag. Organizational-domain policy discovery and message alignment are not implemented.

DNS discovery samples three preferred MX hosts (A/AAAA), and discovers MTA-STS/TLS-RPT TXT records. It does not fetch MTA-STS HTTPS policy or prove enforcement. Blocklist checks use actual query zones (zen.spamhaus.org and bl.spamcop.net), source control queries, and up to four sampled MX IPv4 addresses. Control-query failure cannot become a clean result. MX reputation does not establish the reputation of an outbound sender or a mailbox. IPv6 blocklist coverage is not provided. Spamhaus may require an authorized resolver/access subscription; provider restrictions remain unavailable, never bypassed.

Registration dates normalize naive/aware timestamps to UTC; old failed cache entries are not reused. Known email providers never receive a different-provider spelling suggestion; suggestions are limited to explicit typo mappings.

DNS failures remain unavailable. DKIM message verification and breach exposure are explicitly not checked. SPF/DMARC record presence is reported; full sender-policy evaluation is not implemented. DNS blocklist results describe an IP and do not establish that a mailbox is malicious. Unrecognized blocklist response codes remain unavailable.

The report explains findings and coverage deductions, exposes source details in native expandable sections, and offers JSON, CSV and clipboard exports. CSV cells neutralize leading spreadsheet formula characters. Provider text is escaped or assigned with textContent. Exported reports contain the address and evidence; handle them accordingly.

Validation: email assessment, DNS failure and source-code handling, SMTP opt-in and public-target tests, template rendering and Node execution of hostile result data. Browser layout and a fresh end-to-end email scan must also be reviewed in the Docker rehearsal before merge.
