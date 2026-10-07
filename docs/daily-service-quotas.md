# Daily scan allowances

Daily allowances are stored in existing `user.*_remaining` columns. No new table,
migration or Redis dependency is introduced. SQLite and PostgreSQL use a single
conditional SQL UPDATE to reset expired balances and reserve the complete cost.
The provider or broker is called only after that reservation commits.

## Charging policy

- One accepted service request uses one unit, including an accepted attempt whose
  provider later fails or whose broker returns an error. Failure is not refunded:
  a broker error does not prove that publication did not occur, and unbounded
  retry work must not become free. This policy does not provide task idempotency.
- URL batches reserve the number of URLs from `url_analyzer`; email batches reserve
  the number of emails from `email_check`. Both accept 1–20 typed nonempty strings.
  The entire batch fits or nothing runs. No accepted email list is silently cut
  down to 20 after claiming to accept 100.
- Synchronous, deep and async file analysis and Sandbox file/hash requests share
  `file_scan`. File size/extension/content and hash hex checks run before charging.
- Synchronous and async site requests share `site_scan`. The old dashboard URL form,
  direct URL API, URL batch and Sandbox URL requests share `url_analyzer`.
- QR analysis uses `qr_scan`; discovery and per-host inspection share
  `subdomain_finder`. Other standard services retain their named allowances.
- Anonymous, rejected CSRF, malformed JSON/typed payload and invalid upload requests
  do not reserve units. A typed accepted input later rejected by an analyzer can
  still consume an attempt. Discovery/provider preflight logic remains unchanged.
- Missing quota storage blocks dispatch with generic HTTP 503; insufficient balance
  returns HTTP 429 with remaining units. A form URL scan redirects with a notice.
- Viewing saved URL analysis or downloading PDF never invokes a fresh analyzer and
  does not reserve quota. A legacy/malformed record lacking saved analysis returns
  HTTP 409 and asks for an explicit new scan. Pending reports should be polled until
  their saved analysis is available.

## UTC rollover and roles

The first accepted request or allowance read after UTC midnight refreshes all
persisted service balances. Reset compatibility hooks update only expired rows;
calling them twice cannot replenish today's used balance. Unknown roles use basic
limits. Admin flags and `admin`/`premium` roles determine rollover limits from the
same policy. Existing same-day balances are preserved, capped to the effective
role limit. Raising a role does not retroactively replenish a same-day balance;
its larger allowance applies on the next reset. A lower role cannot retain excess
legacy allowance. Existing future reset timestamps do not grant an early reset.

Basic limits: URL and password 3; file and discovery 5; site 10; email, IP,
domain, SSL and QR 15. The old `remaining_scans` aggregate is not an alternative URL
allowance. Legacy `can_scan` is only a check; atomic reservation still occurs in
`increment_scan_count`. The copied unused `models.py` is outside the runtime package
and remains part of the model consolidation audit.

`DAILY_LIMITS` is re-exported by `services.permissions` for compatibility. The
old `sandbox_analysis` policy entry has no persistent User column; it is not
advertised as an enforceable separate counter. Sandbox currently uses file/URL
allowances as described above. Dedicated resource quotas are a separate milestone.

## Validation

Run `python -m unittest discover -s tests -p test_daily_quotas.py -v`.
Tests use disposable SQLite databases and mocked providers/brokers. Concurrent
connections exercise the last units and the first requests on a new UTC day;
production endpoint tests cover bulk/async/file/form/hash paths and saved report
reads. They never use the developer's configured production database.

PostgreSQL concurrency, deployed multi-process/worker behavior, clock skew, queue
idempotency and resource-volume limits still need staging checks. SQLite busy or
storage errors fail closed; there is no local-memory fallback.

## Administrator exemption

Accounts with is_admin=true or role=admin have no daily service quota. Reservations check current database privileges atomically and do not debit administrator counters, even when counters are zero or cost exceeds the old numeric cap. None/null represents an unlimited allowance; get_user_limits exposes unlimited=true. Promotion applies immediately; demotion restores normal quota enforcement. Ordinary and premium policies are unchanged. Authentication throttles, request validation, upload/batch limits, target ownership and worker resource limits still apply.
