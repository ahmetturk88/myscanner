# Subdomain discovery workspace

The workspace combines a responsive asset-map illustration, domain input, source disclosure, elapsed loading state, source and verification breakdown, five-line evidence brief, expandable hostname observations, combined filters, sorting, clipboard copy and export.

The completion ring measures selected verification checks, not safety or the percentage of all subdomains discovered. DNS has weight 60, HTTP 25 and TLS 15; components with no applicable rows are excluded. An invalid certificate is a completed verification observation, not a safe result. Source failures are shown independently. Discovery always remains a bounded sample, even when selected checks complete.

Candidates alternate common-name and certificate-index names within the configured limit, preserving both source labels on duplicates. Partial A/AAAA/CNAME failures remain explicit, even when another record resolves. Two random-label wildcard probes cover address and CNAME evidence; incomplete probes report unknown wildcard state. Matching names are not asserted to be independent hosts.

Existing network controls remain: no requests to private, loopback, link-local or mixed-address targets; public HTTP connections revalidate destinations; redirects are recorded without being followed. Limits remain 1–100 candidates (80 default), 20 web hosts, eight workers, bounded response sizes and a shared 20-second scheduling deadline. In-flight operations use connection/DNS timeouts and may finish after the deadline; this is not a process-kill wall-clock guarantee. Certificate timeout is capped by the remaining scheduling budget.

Copy and CSV export operate on the shown filtered results; JSON export preserves the full report and limitations. CSV cells escape spreadsheet formula prefixes. Provider names, hostnames and certificate fields use native DOM text rendering. Loading displays elapsed time rather than invented percentage progress. Keyboard modal navigation, focus return and reduced-motion preference are supported.

Validation commands:

```powershell
python -m unittest discover -s tests -p test_subdomain_workspace.py -v
python -m unittest discover -s tests -p test_web_assessment.py -k Discovery -v
python -m unittest discover -s tests -p test_qr_subdomain_xss.py -v
node tests/test_subdomain_workspace.cjs
```

Offline mocks cover source outages, partial DNS, truncation, wildcard CNAME, network blocking and deadline behavior. JavaScript execution tests cover filters, sorting, malicious text, CSV formula escaping, copy, JSON/CSV export and modal inspection actions. The actual Docker stack and desktop/mobile visual presentation require user rehearsal; no live discovery or screenshot-based visual validation was performed in the implementation environment.
