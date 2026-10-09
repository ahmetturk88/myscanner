# Platform network and provider evidence rehearsal

This change extends the existing URLVet/browser namespace policy to Flask web and Celery worker processes. Apply `compose.app-egress.yml` **last**, after `compose.vps.yml`, `compose.urlvet.yml`, and `compose.egress.yml`. This is a rehearsal profile; actual Docker firewall verification is required before deployment.

The gateways alone hold NET_ADMIN. Web/worker containers inherit no new capabilities or administrator secrets. Rules default-deny new output, reject non-public IPv4 ranges and new IPv6, and allow public TCP 80/443/43/25. Port 25 supports the existing explicit SMTP opt-in; it does not send a message. Docker DNS is narrowly permitted. Exact resolved private dependency IP/port exceptions permit PostgreSQL 5432, Redis 6379, and URLVet 8080. The web namespace alone permits loopback 8000 for its health check. User HTTP/TLS target transports still restrict target ports to 80/443 and pin validated addresses.

Exceptions are installed at namespace startup. Recreate the gateways and their attached application containers when dependency addresses change. Beat performs scheduled dispatch on the private data network; it is not a target scanner. Migration/bootstrap roles retain their existing private-only networks. ZAP/GVM are not enabled or validated by this profile; internal scanner control ports require a separate reviewed integration, not blanket private-network exceptions.

IP and domain provider HTTP sessions now use bounded public transports with environment proxies disabled. Fixed provider URLs take encoded parameters and do not follow redirects carrying credentials. IP inputs must be public numeric addresses. Existing site/URL/subdomain/QR HTTP paths and direct TLS/SMTP transports remain subject to their validated, pinned target layers. WHOIS library connections are also constrained by namespace output rules.

## Evidence changes

- IP geography and hosting flags do not imply safety. AbuseIPDB `not_found` requires a valid response for the exact IP with validated numeric fields. Missing key, malformed response or provider failure is unavailable/not configured; blacklist count is unknown, not zero.
- Domain WHOIS has no demo-key fallback. Configure WHOISXML_API_KEY through your existing private secret delivery if you choose this provider; otherwise WHOIS is explicitly not configured. DNS provider failures are distinguished from valid empty answers. Metadata is not a domain safety verdict.
- SSL timeout/refusal is unknown, while an actual certificate verification failure is invalid. The existing grade is labeled as certificate lifetime rather than a full TLS security audit.
- MalwareBazaar requires a matching SHA-256 record for a positive finding, or an explicit successful `hash_not_found` for a negative dataset match. HTTP/auth/parser failures remain unknown. Only hashes are sent; no samples are executed or uploaded by this lookup. Local byte-pattern heuristics are not advertised as a YARA engine.
- File results preserve positive evidence despite unavailable sources. The same hash lookup is reused in the combined scan rather than called twice. Local metadata fields are carried into the combined result. An apparently benign local file is not labeled safe when coverage is missing. A hash dataset match overrides benign heuristics.
- Passive site DNS failures do not become missing-record findings. The unimplemented reputation stub is marked not checked, rather than not blacklisted. Missing header evidence no longer sets HSTS/CSP to true.

## Safe update and verification

Do not run `down -v`; it deletes data volumes. Stop the runtime/proxy before moving the existing static web address into its gateway, to avoid address collisions:

```powershell
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml stop proxy web worker

docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml rm -f web worker

docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml -f compose.app-egress.yml config --quiet

docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml -f compose.app-egress.yml up -d --build
```

The `rm` step removes only stopped web/worker containers so their old network endpoints cannot reserve the gateway address. Named database, upload and report volumes remain intact.

Run the namespace-only fixture in both new gateways:

```powershell
docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml -f compose.app-egress.yml exec web-egress python3 /app/egress-check.py

docker compose --env-file .env.vps.rehearsal -f compose.vps.yml -f compose.urlvet.yml -f compose.egress.yml -f compose.app-egress.yml exec worker-egress python3 /app/egress-check.py
```

It checks public HTTPS and active namespace-local listeners at loopback, private and link-local addresses on 80/443/43/25; it removes temporary addresses in finally. This fixture does not probe the real metadata service or database.

Then verify HTTPS `/health/live` and `/health/ready`, the existing `smoke-queue`, `role-check`, a new authorized URL/site scan, and email/domain/IP/SSL/file results. Confirm unknown-provider states are visible and no positive finding is lost. Keep this branch unmerged until the actual firewall and runtime checks pass.
