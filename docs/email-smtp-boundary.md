# Public SMTP boundary

User-controlled MX records must resolve exclusively to public addresses before any connection is made. The SMTP adapter validates all returned A/AAAA addresses through safe_http, then connects to one validated literal address at fixed TCP port 25 without a second DNS lookup. It closes failed sockets and the checker closes SMTP sessions in finally. Private, loopback, link-local and mixed public/private DNS answers are rejected before connecting.

A timeout, denied address or temporary SMTP response yields valid=null, unavailable coverage and UNKNOWN deliverability. These failures do not reduce quality as if the mailbox were rejected, and do not yield a safe verdict. Explicit recipient acceptance/rejection retain existing checked behavior; SMTP acceptance cannot establish mailbox ownership or actual future delivery. Legacy cached results lacking coverage status are not reused for SMTP verification.

Tests use mocked DNS and SMTP only; no messages are delivered and no real private services are contacted. Network-level protection of web/worker remains separate work. TCP/25 may be blocked by hosting providers: such failure must remain unavailable rather than undeliverable. This change does not resolve separate DNS/blacklist coverage or third-party privacy/consent policies.
