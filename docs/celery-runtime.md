# Shared Celery runtime

Audit item 8: publishers, task registration, result reads, workers and Beat now share `celery_app.celery`. `tasks.celery` and `celery_config.celery` remain compatibility aliases; `make_celery(flask_app)` binds that same object to the Flask extensions without creating a second application. Existing tasks explicitly enter Flask contexts when they access application data. Worker configuration import alone does not import Flask or mutate a database.

## Configuration

Set the same environment on web, workers and Beat:

- `CELERY_BROKER_URL` overrides `REDIS_URL` for job transport.
- `CELERY_RESULT_BACKEND` overrides the broker URL for task results; otherwise the same Redis URL is used.
- Supported connection schemes: `redis://` and `rediss://` (TLS with certificate verification required). Malformed URLs are rejected without echoing their credentials.
- Development alone has the old local Redis default. Production without a broker keeps the web importable but disables publishing; it uses no network fallback. The validated worker/Beat entry point refuses to start until a broker is configured. A result backend alone is not enough.
- Test-only in-memory URLs are allowed when `APP_ENV=testing`.

The local `.env` is loaded before configuration and service imports, without overriding shell variables. Production uses its environment. This does not remove demo values from unrelated provider settings or repair all configuration duplicates.

## Queues and commands

| Queue | Tasks |
|---|---|
| `scans` | Site, file, large-file and batch scans |
| `tip` | IoC fetch/cleanup, MISP pull/push, source initialization |
| `celery` | Default/legacy queue retained to drain existing messages |

Linux worker:

```sh
celery -A celery_worker:celery worker --loglevel=info --pool=prefork --concurrency=1 -Q scans,tip,celery
```

Exactly one separate Beat process:

```sh
celery -A celery_worker:celery beat --loglevel=info
```

TIP fetch is hourly, cleanup daily and MISP pull daily. The schedule exists on the same app the worker uses; scheduled and manually dispatched TIP tasks route to `tip`. An unconfigured MISP task retains its existing skipped result. Daily user quotas reset at request time and need no Beat entry.

Keep one Beat instance for this schedule. Do not use worker `-B` alongside standalone Beat. During rollout stop old publishers/workers and restart all with the shared configuration. Redis URLs and credentials must match across services. Existing queues are retained; new scans route to `scans`, so workers must consume it explicitly.

The Render blueprint updates commands only; it does not provision or update services by itself. Its current worker explicitly consumes all three queues, using a single prefork child as a conservative starting point, not a measured production capacity recommendation. Other blueprint gaps, Flower security and provider placeholders remain separate launch blockers.

## Limits and remaining validation

JSON serialization only, UTC, prefetch one, a 25-minute soft and 30-minute hard task limit, and one-hour Redis visibility timeout are configured centrally. Prefork is required for process time limits; Windows/solo behavior does not prove production enforcement. Late acknowledgements are deliberately not enabled until all tasks have safe retry/idempotency semantics. A crash can still lose accepted work; audit item 9 is not closed.

Offline tests validate singleton identity, registered tasks, routing, serialized messages, schedule and configuration failures. Live Redis worker/Beat integration, actual Linux time limits, restart behavior and resource sizing remain pending. Item 8 becomes partial, not fully closed.

References: https://docs.celeryq.dev/en/stable/userguide/configuration.html and https://docs.celeryq.dev/en/stable/userguide/periodic-tasks.html .
