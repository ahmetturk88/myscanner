# Scanner egress rehearsal

This optional overlay restricts URLVet and its headless browser in separate Linux network namespaces. A gateway installs OUTPUT rules before the scanner starts; only gateways have NET_ADMIN, not scanners. No host firewall is changed and no ports are published. Established replies are retained; new IPv4 web connections use public destinations on TCP 80/443 (and public WHOIS TCP 43). IPv6 new connections are closed deliberately, so IPv6-only sites may lose coverage.

Docker's embedded DNS is permitted only at 127.0.0.11 TCP/UDP 53. Provider service exceptions are resolved once at startup to exact IPv4 addresses: cache TCP 6379 and browser TCP 9222. Browser has no service exceptions. A gateway restart is required if those service addresses change. Gateways have no automatic restart: failed initialization stops startup; a successful namespace retains its firewall if the gateway process exits.

These exceptions are necessary for provider operation and are NOT a blanket guarantee against all SSRF: URLVet can still reach its cache/browser at these exact ports. Initial input validation restricts user web URLs to 80/443; upstream redirect validation must also be audited before public launch. Worker/web still share legitimate database/queue connectivity and require their existing pinned safe_http layer; this overlay does not secure their entire output path. Provider browser compromise, DNS tunneling and the remaining core-service egress work are separate gates.

The URLVet in-container loopback health probe is disabled because loopback target connections are blocked. Gateway health checks confirm rule initialization, not application health. Verify the provider externally from worker after startup, plus real queued scans and application readiness. Do not mark deployment ready based only on gateway health.

## Rehearsal commands (PowerShell)

Use the three overlays together for every command while testing:

```powershell
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml config --quiet
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml up -d --build --force-recreate urlvet-browser-egress urlvet-egress urlvet-browser urlvet
```

The gateway addresses replace the old services' network attachments. The old scanner containers must be recreated. Confirm external API health from worker; then perform a fresh public URL scan. Inspect gateway logs if initialization fails. NET_ADMIN is namespace-scoped; do not add privileged mode or NET_ADMIN to scanner containers to bypass failures.

Rollback preserves data volumes:

```powershell
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml stop urlvet urlvet-browser
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml up -d --force-recreate urlvet-browser urlvet
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml rm -s -f urlvet-egress urlvet-browser-egress
```

No Docker integration test has been run by the authoring environment. Unit tests verify policy construction, exact exceptions, IPv6 failure behavior, and namespace configuration; actual Linux Docker startup and connectivity checks remain mandatory before merge.
