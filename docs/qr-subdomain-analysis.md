# QR and subdomain evidence reports

This change replaces the mismatch between provider trust-score data and legacy threat-engine counters. It adds a shared version-2 web report and DOM-only renderer. VirusTotal is not a dependency or integration; the regression test checks runtime Python literals/imports for its endpoint/client. This is not an inspection of an external provider's internal implementation.

## QR / hostname URL inspection

- QR images are decoded in the browser (5 MB, 16 megapixels). The image is not uploaded. Non-web content is displayed as text and never opened automatically.
- Local URL/DNS/HTTP/redirect/TLS/static-HTML checks run without an external analyzer. HTML scripts are not run, forms are not submitted, and files are not executed.
- DNS types: A, AAAA, CNAME, MX, NS, TXT. Records belong to the input hostname, not a claimed parent registrable domain. No-record, NXDOMAIN and lookup failure are separate observations.
- TLS uses the existing pinned public TCP connection with default certificate identity/trust validation. The report exposes issuer, expiry, protocol and cipher, with no synthetic certificate grade.
- Up to five redirects; each transport connection rechecks public addresses. Redirect evidence is preserved when a later destination is blocked. An opted-in provider is skipped after a local network-policy block.
- HTTPS downgrade, insecure password submission and cross-host password forms are warnings. Punycode, shorteners, destination parameters and cross-host redirects are observations, not standalone proof of phishing.
- Missing HTTP security headers are configuration observations, never automatic malware verdicts.
- url.vet is optional, unchecked by default and requires `URLVET_URL`. The checkbox explains that the full URL/query is sent. Leave it unchecked for local checks. No fallback to another provider. Provider outage stays unavailable; local evidence remains visible.
- Local absence of indicators remains inconclusive. A no-indicators outcome requires local checks and a valid harmless provider response; even then it is not a safety guarantee. A threat response or local warning survives partial coverage.
- HTTP responses capped at 1 MB; static HTML is parsed from that bounded response. DNS calls use one-second lifetimes. A nominal 18-second orchestration budget stops scheduling later steps; per-request connect/read limits apply. OS address resolution and blocking I/O mean this is **not a hard process deadline**. Whole-job worker limits remain a deployment task.

## Subdomain discovery

- Source 1: public certificate names from `https://crt.sh/?q=%.domain&output=json`. The UI discloses the domain-name query and allows disabling it. Wildcard certificate identities and out-of-scope suffixes are rejected; duplicates removed. Certificate history may be stale; every selected name receives DNS checks.
- Source 2: deduplicated common-name DNS candidates. This is a bounded sample, not exhaustive enumeration. No zone-transfer, port scan, browser crawler or exploit requests.
- Default 80 / maximum 100 candidates, 8 per-request workers, up to 20 web observations. CT candidates are considered first; remaining candidate count is disclosed. CT response cap 2 MB / first 2,000 certificate rows; failures leave DNS discovery available.
- Two random-label A/AAAA/CNAME probes detect possible wildcard DNS. Matching addresses are marked rather than advertised as independent confirmed hosts. Rotating wildcard answers may evade this heuristic.
- A/AAAA/CNAME values retained. Public-address-only hosts may receive HEAD on HTTPS, falling back to HTTP on connection failure, never after TLS identity failure. Redirects are recorded, not followed during discovery. HTTP errors remain response observations, not “inactive.” TLS metadata is attempted for enriched HTTPS hosts.
- Transport validation pins DNS again, rejects mixed/private results, disables environment proxies, and keeps TLS verification. DNS-only names, policy blocks, unavailable DNS and uninspected hosts are visible.
- Nominal 20-second scheduling budget; connect/read/DNS/body caps are enforced separately. These per-request limits do not provide global worker concurrency, CPU/RAM isolation or a hard job deadline.
- Search/filter observed rows; export complete report JSON or CSV; copy discovered names. CSV cells neutralize spreadsheet-formula prefixes. Exports include source/coverage information; they do not claim exhaustive discovery.

## Authentication and validation

All three APIs retain login and global CSRF. Malformed fields/options are rejected before service quotas. Hostname inspections now consume the existing `subdomain_finder` quota; discovery and manual deep inspection share this quota. Invalid payloads do not consume it. Overall atomic daily quotas are still tracked separately in readiness item 13. Successful responses are `Cache-Control: no-store` and new analyzer results are not written to a cache.

## Validation

Run on the branch:

```powershell
python -m unittest discover -s tests -p "test_web_assessment*.py" -v
python -m unittest discover -s tests -p test_qr_subdomain_xss.py -v
python -m unittest discover -s tests -p test_ssrf_protection.py -v
python -m unittest discover -s tests -p test_csrf_protection.py -v
```

JavaScript execution tests require Node.js; without it they are explicitly skipped. Tests use mocked DNS, HTTP, provider and certificate data. No real external scan or browser visual verification is implied.

Manual staging checks: decode a QR URL, copy/open/rescan/export; inspect local report with optional provider off, then unavailable provider on; discover your domain with CT both enabled/disabled, search/filter rows, verify CSV/JSON, open/close inspection dialog and Escape/Tab focus; check mobile width and button contrast. Confirm HTTPS redirection, private-target rejection, no false safe result on outages and no unexpected provider traffic. Production performance still requires a staged workload before declaring launch readiness.
