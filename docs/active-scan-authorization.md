# Active target authorization — containment stage

This change does not implement ownership verification. It closes unverified scanning until verified scope and execution limits are implemented. Item 6 of the readiness review remains partially complete.

General Site Scanner analysis no longer sends SQL injection or reflected XSS payloads. Its compatibility dynamic result is explicitly `not_performed`, with no fabricated zero findings or risk score. New reports declare `analysis_mode=passive` and `active_scan_performed=false`. The site cache namespace is versioned so previous active-analysis cache entries are not reused; saved historical reports are not deleted.

New `/vulnerability/start` requests are rejected with HTTP 403 and code `target_authorization_required` for regular users and administrators, all scan types, and `active_scan=false`. ZAP spidering and OpenVAS network tests can still generate intrusive traffic, so that flag does not bypass the gate. Direct orchestrator dispatch raises TargetAuthorizationRequired before database writes or executor submission. No environment flag or client-supplied verified field can re-enable it.

The dashboard explains the temporary suspension and disables new-scan inputs. Existing reports, status and authorized stop operations remain available. Work already running before deployment is not retroactively cancelled; stop it through its authorized stop operation if needed. Direct scanner clients are internal tools, not a public authorization API.

Next stage: persist user-specific proof of domain control, validate exact scheme/host/port scope and proof expiry before dispatch, prevent redirects/crawls from leaving the authorized scope, and enforce worker resource/concurrency/timeout limits. A checkbox asserting permission and an administrator flag are not target proof. Network/IP ownership and delegated authorization require a separate policy; keep those scans closed until it exists. Reopening requires reviewed code plus tests, not a configuration toggle.

This is a containment measure, not evidence that the entire scanner or VPS deployment is ready.
