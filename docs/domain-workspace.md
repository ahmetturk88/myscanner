# Domain intelligence workspace

The domain page presents DNS and registration observations, a five-line brief, record filtering, clipboard summary and JSON/CSV export. Responsive layout and reduced-motion support are included. Provider values use native text nodes; spreadsheet formula prefixes are escaped in CSV.

Coverage counts seven DNS queries and one registration lookup. Completed, no-record and NXDOMAIN DNS responses count as answered checks; source failures do not. This is metadata coverage, never a safety percentage. No website content, mailbox, owner identity or threat reputation is checked.

Registration uses IANA's RDAP DNS bootstrap and an HTTPS registry endpoint, with exact returned domain identity validation. Missing or redacted dates stay unavailable. Registration failure does not imply an unregistered domain. DNS observations preserve actual RR types (including CNAME answers), TTL and source state. DNSSEC AD is an observation, not a domain safety verdict.

All source traffic uses the existing public-address-pinned HTTP session, a 30-second overall deadline and 1 MiB response bound. Source redirects are not followed. No direct connection to the submitted website is performed. Errors and credentials are never returned. Geolocation and external map embeds were removed from this metadata workflow.

References: https://www.iana.org/assignments/rdap-dns/ and https://developers.google.com/speed/public-dns/docs/doh/json

Validation: `python -m unittest discover -s tests -p test_domain_workspace.py -v` and `node tests/test_domain_workspace.cjs`. Live registry access and browser/Docker visual acceptance still require rehearsal testing.
