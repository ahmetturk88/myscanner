# Durable dashboard URL jobs

POST `/dashboard` now commits a queued Scan and AsyncScanTask ownership together before publishing `scan_url_task` on `scans`. Only the exact owner, URL and task ID can atomically claim the queued record. The worker stores the full report before returning success; duplicate delivery does not repeat analysis. URLs are bounded to the existing database column's 500-character capacity. Invalid inputs do not consume quota; accepted broker failures retain the charged attempt under the existing quota policy.

The existing Scan columns are used; no new schema is introduced. Generic failures never expose exception text. Broker ambiguity retains task ownership; a failed or completed record cannot be overwritten by a late worker. There is no automatic provider retry, to avoid repeating expensive network work without a reviewed retry policy.

## Deployment prerequisite

Do not deploy this branch until the web and Linux worker share a working Redis broker, result backend and DATABASE_URL, and exactly one Beat is running. Production without Redis rejects publishing rather than falling back to a web thread. Verify the existing Text migration on PostgreSQL before large reports. Copy no credentials into tests or reports.

Use the commands documented in `celery-runtime.md`. Workers must be restarted with the new task registry before the new web publisher is deployed. A plain git pull does not rebuild a Docker image. Existing queued/running scans from the old daemon thread do not acquire the new marker or expiry policy automatically; review and close these separately during rollout, without rerunning targets silently.

## Deadlines and crash behavior

URL execution has a 20-minute soft limit and 21-minute hard limit on Linux prefork. Publication expires after 45 minutes. The database permits claims and completion only inside the same 45-minute window from creation. `expire_url_scan_jobs` runs every 60 seconds via Beat on the scans queue, marking tagged queued/running rows older than 45 minutes as error. It does not touch site/file jobs or overwrite completed/cancelled records.

This is bounded failure recovery, not guaranteed delivery or automatic continuation: a web crash between commit and broker publish leaves a queued row that eventually expires. A killed worker leaves running until the sweeper executes. If Beat or all workers are down, expiration is delayed until services recover. There is no outbox, lease renewal, cancellation endpoint, retry/resume or guaranteed cleanup after SIGKILL yet. Those remain audit item 9 work. Queued jobs may expire under heavy backlog; capacity and prioritization must be measured before launch.

## Verification

`python -m unittest discover -s tests -p test_url_job_queue.py -v`

`python -m unittest discover -s tests -p test_celery_runtime.py -v`

Tests use isolated SQLite and mocked analyzers/publishing, plus memory-transport message routing. They check committed ownership before publish, duplicate/wrong-owner/wrong-target/task-ID rejection, durable large Unicode reports, partial coverage, database/publish/provider failure, deadline expiration, protected reads and worker cleanup. They do not prove real Redis persistence, process termination, PostgreSQL concurrency, provider behavior or Linux time-limit enforcement. Live restart, broker persistence and quota/load checks are mandatory before deployment.
