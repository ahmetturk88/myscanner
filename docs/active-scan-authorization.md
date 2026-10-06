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

## Stage 4: ZAP context preparation and report separation

The ZAP client now creates a unique context from a verified account scope, restricts its include regex to the exact scheme/host/default port, and configures it out of scope until the include rule is accepted. Context configuration errors abort and trigger best-effort removal. The prepared spider call uses contextName and subtreeOnly; the active call uses contextId. The previous unscoped accessUrl request is removed. These API actions are based on the official ZAP API reference: https://www.zaproxy.org/docs/api/ and https://github.com/zaproxy/zaproxy/wiki/ApiGen_Full .

Direct ZAP spider/active calls and the orchestrator's private ZAP entry remain closed by the existing unconditional activation gate. Context configuration alone does not send target traffic. No environment flag or administrator permission opens this gate. Tests of prepared scan parameters patch that gate locally and mock the ZAP API; this is not a production bypass.

Reports no longer fall back to all alerts in the shared ZAP session. A supplied client-owned context is required, and returned alert URLs are filtered by exact account scope. This avoids mixing different origins but does not separate historical alerts for repeated scans of the same origin: isolated per-job ZAP sessions are still required. Scan timeouts and ZAP failures propagate rather than returning empty successful results. The orchestrator removes its context in a finally block.

Contexts are URL scope configuration, not an egress firewall or DNS pinning for the external ZAP process. Redirect enforcement, DNS rebinding protection, browser traffic, per-job worker isolation, cancellation and hard resource limits still require deployment integration and real scanner tests before activation. Removing a context does not stop an already-running external scan. Passive queues remain shared until worker isolation is implemented. OpenVAS/network scans remain outside the domain proof policy and stay closed.

## Stage 5: fresh per-job Linux ZAP process/session

The prepared orchestrator now gets a new local ZAP client from `isolated_zap_job`, instead of using the shared metadata/availability client for scan work. The factory starts a new ZAP process with a private temporary home and `-newsession` path, a random per-job API key in a mode-0600 config file, and loopback-only API binding. The key is not in argv or logs. It requires an explicitly configured absolute executable `ZAP_EXECUTABLE`; there is no fallback to the shared daemon. Startup probes require the new key and a valid version response and reject redirects. API readiness errors are generic and do not include secret query parameters.

The factory closes the HTTP client and terminates the process group on normal exit, body failure or startup failure, escalating to SIGKILL when necessary; it removes temporary files afterward. Cleanup errors propagate. An exit of the launcher before readiness is a failure. The worker must use a ZAP startup script whose descendants remain in the process group. A daemon that detaches itself requires a stronger container/cgroup lifecycle manager. Reserving an ephemeral loopback port has a small close-to-launch race; a conflicting service cannot cause a shared-daemon fallback and readiness must authenticate with the fresh key.

This is process/session separation, not a sandbox. It does not yet enforce egress filtering, cgroup CPU/memory/PID limits, a hard whole-job deadline, restart recovery or distributed concurrency limits. Those deployment prerequisites still block activation. The Linux worker needs installed ZAP/add-ons and its own permissions; Render receives no ZAP executable setting in this change. Windows tests mock process creation and signals; they do not run ZAP. The public and private activation gates remain closed, so no new subprocess launches in production. A real Linux ZAP integration test is pending before activation.

ZAP startup flags follow the official command-line reference: https://www.zaproxy.org/docs/desktop/cmdline/ .
