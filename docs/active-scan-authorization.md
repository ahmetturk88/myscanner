# Active target authorization — containment stage

This change does not implement ownership verification. It closes unverified scanning until verified scope and execution limits are implemented. Item 6 of the readiness review remains partially complete.

General Site Scanner analysis no longer sends SQL injection or reflected XSS payloads. Its compatibility dynamic result is explicitly `not_performed`, with no fabricated zero findings or risk score. New reports declare `analysis_mode=passive` and `active_scan_performed=false`. The site cache namespace is versioned so previous active-analysis cache entries are not reused; saved historical reports are not deleted.

New `/vulnerability/start` requests are rejected with HTTP 403 and code `target_authorization_required` for regular users and administrators, all scan types, and `active_scan=false`. ZAP spidering and OpenVAS network tests can still generate intrusive traffic, so that flag does not bypass the gate. Direct orchestrator dispatch raises TargetAuthorizationRequired before database writes or executor submission. No environment flag or client-supplied verified field can re-enable it.

The dashboard explains the temporary suspension and disables new-scan inputs. Existing reports, status and authorized stop operations remain available. Work already running before deployment is not retroactively cancelled; stop it through its authorized stop operation if needed. Direct scanner clients are internal tools, not a public authorization API.

Next stage: persist user-specific proof of domain control, validate exact scheme/host/port scope and proof expiry before dispatch, prevent redirects/crawls from leaving the authorized scope, and enforce worker resource/concurrency/timeout limits. A checkbox asserting permission and an administrator flag are not target proof. Network/IP ownership and delegated authorization require a separate policy; keep those scans closed until it exists. Reopening requires reviewed code plus tests, not a configuration toggle.

This is a containment measure, not evidence that the entire scanner or VPS deployment is ready.

## Stage 2: account-bound DNS proof

The authenticated, email-verified user can open `/vulnerability/targets`, generate a TXT challenge, verify it and revoke it. Each record is bound to one account and an exact HTTP/80 or HTTPS/443 origin. Schemes and subdomains do not inherit proof; IP literals and internal/testing suffixes are not accepted. Tokens are cryptographically random and are public DNS proof values, not application secrets. Existing records are rotated when the same origin is submitted again; this invalidates previous proof.

Both a challenge and a successful proof last 24 hours. Checks are bounded by a 4-second DNS lifetime and DB-backed per-account quotas: 10 challenge requests/hour, 20 verification attempts/hour and 5/minute. All mutations require CSRF. Other users, including admins, cannot inspect, verify or revoke another account's record. A conditional update prevents a concurrent revoke/rotation/expiry during DNS lookup from restoring proof. DNS errors and mismatches never create proof. Results are not cached by HTTP.

This verifies observed domain control, not legal permission to attack a service or ownership of its infrastructure. There is no wildcard, network range or IP proof. DNS records may be cached by recursive resolvers; proof validity is bounded, and deleting TXT alone is not immediate revocation—use the revoke action. The checker uses the configured recursive resolver and is not a DNSSEC attestation. Records expire by timestamp without requiring Beat. Keep requests limited and remove old proof records from DNS when renewing.

The new table has migration `c291ed857a40`, following `a6b738de2104`; it tolerates the existing startup create_all behavior. Migration tests run on isolated SQLite; full migration-chain and PostgreSQL staging checks remain readiness tasks. No migration command against production was run by this change.

Active scans remain closed even after DNS verification. Before reopening, connect a valid account-bound proof to dispatch, revalidate public DNS and scope immediately before execution, contain all redirects/crawls to the authorized exact origin, and add worker resource limits and restart-safe state. The current proof helper is preparatory and is not called to bypass the active-scan gate. Readiness item 6 remains open.

## Stage 3: exact-origin HTTP transport (preparation)

`prepare_verified_target` checks a current account-specific proof, confirmed account email, and public DNS before returning an exact-origin scope. The new `VerifiedTargetSession` checks proof again before each HTTP request, including redirects, and rejects other hosts, subdomains, schemes, credentials and nondefault ports before transport. Paths and queries on the same origin are allowed. The existing public HTTP adapter revalidates DNS when selecting the connection pool and connects to a validated IP with the original TLS hostname. Preflight DNS results alone are never sufficient to authorize an unpinned later connection.

Scalar database queries avoid reusing a stale ORM proof object after revocation. Storage failures propagate and do not grant access. Proof checks cannot cancel a request already in flight; a concurrent expiry or revocation can happen after a check. Resource deadlines and cancellation still need worker integration.

This transport is preparatory and does not protect traffic emitted by ZAP, OpenVAS, browser engines, or other processes. Those clients must have independently enforced scope and network isolation before activation. `/vulnerability/start` and direct orchestrator dispatch remain closed. Stage 3 introduces no production scan requests or UI behavior change. Tests mock HTTP and DNS; live scanner and PostgreSQL deployment validation remain pending.
