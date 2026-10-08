# Local PostgreSQL runtime roles

This change applies only to the isolated local Docker database, not Render.

| Account | Purpose |
| --- | --- |
| myscanner_local | Existing cluster administrator; PostgreSQL and bootstrap only |
| myscanner_schema_owner | No login; owns public schema and application objects |
| myscanner_migrator | Initialization only; can assume the schema owner role |
| myscanner_app | Web, worker and beat; data access without schema ownership |

The application has SELECT/INSERT/UPDATE/DELETE and sequence USAGE/SELECT. It has
no schema CREATE, database CREATE/TEMP, TRUNCATE, owner role membership or
migration-version writes. Owner default privileges cover future tables and
sequences. Migration execution assumes the owner explicitly; grants are reapplied
at the end of initialization. Bootstrap rejects unexpected elevated roles,
memberships and object owners instead of silently accepting them.

## Existing local stack transition

1. Run `python scripts/init_local_stack.py`. It preserves existing secrets and adds
   two random passwords; do not display or send the environment file.
2. Validate Compose and take a fresh custom-format backup using the existing
   administrator and database `myscanner_local`. Verify the copied backup exists.
3. Stop web, worker and beat. Build the updated image with `build web`.
4. Run `docker compose --env-file .env.docker.local -f compose.local.yml run --rm bootstrap-roles`.
5. Run the same Compose command with `run --rm init-db`.
6. Start `up -d web worker beat` and wait for healthy web and worker.
7. Run `exec web python scripts/local_runtime.py role-check`, then `smoke-queue`.
   Open a pre-existing report to verify continuity.

The permission check inserts, reads, updates and deletes its own temporary user
and large report inside a rolled-back transaction. Administrative SQL probes use
savepoints and are rolled back even if a permission is unexpectedly granted.
Only PostgreSQL SQLSTATE 42501 counts as a successful denial. Sequence counters
may advance; accounts and reports are not retained by the check.

Do not remove volumes or rotate LOCAL_DB_PASSWORD during this transition.
Bootstrap is transactional and may be rerun with the same configuration.
Ownership changes mean restores into a separate test database should continue
using `pg_restore --no-owner --no-privileges` before migration/provisioning.

## Production follow-up

Render's current credentials and deployment are unchanged. Production needs a
provider-approved bootstrap procedure, separate migration secret, backup and
restore rehearsal, and a deployment migration step before applying this pattern.
Do not copy local credentials or fixed Docker hostnames into Render.
