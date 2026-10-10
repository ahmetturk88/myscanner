# IP intelligence workspace

Public IPv4 and IPv6 addresses only. No network connection is made to the submitted address. Queries use the existing public-address-pinned HTTP transport, HTTPS, a 25-second overall deadline, bounded provider responses and no redirects. Sessions and responses close even on failure. Authentication, permission and global CSRF controls remain on the API route; malformed JSON is rejected and successful responses are not cached.

The interface has an SVG network illustration, actual elapsed loading time, a five-line brief, network identity cards, source evidence, scope details, clipboard summary and JSON/CSV export. CSV formula prefixes are escaped. Provider values render through textContent. The approximate map opens only on an explicit click, using validated numeric coordinates and a fixed OpenStreetMap origin; no external map or flag is loaded automatically. Keyboard focus and reduced-motion styles are included.

Network metadata comes from https://ipwho.is/ and must return the requested canonical IP with success=true. Approximate country, region, city, timezone, ASN, ISP and organization are shown where available. Missing classifications remain unknown; VPN/proxy/hosting/mobile are not inferred. This is not owner identity verification.

AbuseIPDB is checked only when the existing ABUSEIPDB_API_KEY is configured. Its 90-day report count, distinct reporters, last report, usage and provider confidence are shown separately. Reports with zero confidence still count as observed reports. Reports are community evidence, not a confirmed malware verdict, universal blocklist membership or a claim about every user of a shared/reassigned IP. An unavailable, denied or rate-limited source never becomes a no-match result. Legacy blacklist fields remain null because this workflow does not check blocklist membership.

Source coverage counts the two returned provider responses. A score of 100% means both sources returned usable responses, not that the IP is safe or every optional field is present. A missing key remains a visible coverage gap. No new key is stored by this change.

Validation commands:

    python -m unittest discover -s tests -p 'test_ip_workspace*.py' -v
    python -m unittest discover -s tests -p test_platform_evidence.py -v
    python -m unittest discover -s tests -p test_tool_result_xss.py -v
    node tests/test_ip_workspace.cjs
    node tests/test_platform_evidence_ui.cjs

Live provider responses, Docker and browser visual acceptance require rehearsal testing. References: https://ipwhois.io/documentation and https://docs.abuseipdb.com/.
