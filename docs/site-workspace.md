# Site evidence workspace

Site Scanner collects read-only observations from a public domain or HTTP(S) URL. It follows bounded, validated redirects, verifies TLS during HTTPS connections, observes DNS and browser headers, and inspects static HTML without executing scripts, submitting forms or downloading referenced resources. Legacy SQLi/XSS keyword heuristics are excluded from the comprehensive report.

The displayed percentage is **inspection coverage**, not safety or performance. Optional url.vet and discovery documents are excluded when not requested. Requested unavailable checks reduce coverage; a valid negative response such as a missing robots.txt remains a usable observation. Local observations alone do not establish safety. Security headers are presence/configuration observations, not confirmed vulnerabilities.

Optional robots.txt and sitemap.xml inspection requests only these fixed origin paths and permitted redirects, under the public-network policy and response budget. Listed paths are never fetched. XML entity/DOCTYPE declarations are rejected. Optional url.vet inspection sends the target to the configured service; unavailable source results remain explicit.

The report includes a brief, check states, redirect trail, certificate details, header observations, static page elements, DNS records and optional source/discovery observations. JSON export preserves evidence; CSV exports check states and neutralizes spreadsheet formula prefixes. Remote strings are rendered with native text nodes.

Active vulnerability scanning remains disabled until target authorization is enforced. This workspace does not run exploit probes or replace a penetration test.

## Validation

Run:
- python -m unittest discover -s tests -p test_site_workspace.py -v
- node tests/test_site_workspace.cjs
- python -m unittest discover -s tests -p test_web_assessment.py -v

Rebuild the rehearsal stack, then inspect an authorized public site through /site-scanner. Test both optional check settings, an unavailable target and a private target. Check responsive layout and keyboard navigation. Local unit tests do not verify a running Docker stack.

Header context: [OWASP HTTP Headers Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html) and [MDN HSTS](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security). Header presence alone does not validate policy effectiveness.
