# Explicit database migrations

Web and worker imports no longer create tables, alter PostgreSQL columns, or seed TIP sources. Schema initialization is a separate operation. The local `init-db` service applies Alembic migrations, then explicitly seeds the default sources.

The frozen baseline `0b21a5e798c0` precedes the original empty `5594693f7fdb` revision. It creates the ten original application tables, followed by the existing ownership, authentication counters, target verification and report-storage migrations. Existing databases already stamped at an old revision retain that revision path; no blind `stamp head` is used. Unversioned compatible tables are retained, including rows and extra legacy columns.

The runner rejects missing columns, incompatible type families, nullability, primary keys, unknown migration history, and a head revision with missing tables. It does not automatically guess repairs for arbitrary legacy drift. Stop and test an explicit repair on a restored copy if validation fails. Schema evolution is frozen in migration files; the baseline does not import live models. Baseline downgrade is deliberately rejected; shrinking report storage is also not supported.

## Local verification

Keep the current main checkout and running volumes intact until you have backed up the local database. Checkout the review branch and run:

```powershell
python -m unittest discover -s tests -p test_schema_migrations.py -v
```

Before applying the branch to the Docker database, take a PostgreSQL backup and verify a restore to a separate database. This procedure is the next implementation stage. Do not delete volumes or run migrations against Render yet.

After that restore check, rebuild the application image and run the dedicated local init service once with web/worker/Beat stopped. All three application processes must start only after schema initialization succeeds. The existing `scripts/local_runtime.py init-db` guard still accepts only the isolated local stack and its exact PostgreSQL database identity.

## Production deployment requirements

Use a single migration process under a dedicated schema-owner credential, separate from the everyday application role. Hold application processes until migrations complete. Validate a backup restore and apply migrations to that copy first; compare account and report data afterward. The current change does not provision those roles, execute a Render migration, provide a backup tool, or prove PostgreSQL compatibility by itself.

Tests cover a fresh database, a complete unversioned legacy database, original stamped history, widening old report storage, preserved large Unicode reports, rejected incomplete/unknown schemas, and application imports that never access the database. SQLite tests pass; real PostgreSQL deployment and backup/restore remain launch blockers.
