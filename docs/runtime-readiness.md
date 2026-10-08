# Runtime readiness

- `GET /health/live`: 200 while Flask can handle a request; no dependency probe.
- `GET /health/ready`: 200 only when database, broker, result backend and a responding
  worker consuming the `scans` queue are available; otherwise 503. Public responses
  contain only `status`, with Cache-Control no-store.
- `GET /admin/runtime-status`: administrator-only human-readable diagnosis.
- `GET /admin/runtime-info`: administrator-only JSON, containing fixed status values
  and reason codes, never URLs, credentials, database rows or exception messages.

Dependency results are cached per web process for five seconds, with serialized
collection to reduce duplicate probes. PostgreSQL uses a separate short-lived
connection with connect/statement timeouts; Redis clients have bounded socket I/O.
Worker inspection uses a separate transport with short timeouts and reads queue
metadata. No scan is dispatched, quota is consumed or provider contacted.

A worker response is a point-in-time observation, not proof of successful analysis.
The end-to-end local smoke-queue test remains necessary. URLVet and other providers
are not tested by these endpoints. A service accepting TCP connections might still
fail when processing work.

Use `/health/live` for process liveness and Render's web health check while background
scan infrastructure is intentionally absent. `/health/ready` is for full background
scan readiness; it deliberately returns 503 on a web-only deployment with no broker
or scan worker. A 503 there does not mean saved reports or login are unavailable.
Do not purchase or configure resources solely to silence a readiness status.

Local Docker validation after rebuilding: check /health/live, /health/ready, and
open /admin/runtime-status as local administrator. Stop worker only and wait at
least five seconds; readiness should become 503 and explain no scan worker. Restart
worker and confirm readiness returns 200. Do not stop the production database.
