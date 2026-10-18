#!/usr/bin/env bash
# Restore rehearsal for the VPS backups. Run as root (sudo).
# Restores one dump (default: the newest in BACKUP_DIR) into a throwaway
# PostgreSQL container that has no network and keeps its data in memory, then
# compares its tables and row counts with the live database. The live database
# is only read; the throwaway container is removed on every exit.
#
#   sudo scripts/vps_restore_check.sh                       # newest local dump
#   sudo scripts/vps_restore_check.sh /path/to/file.dump    # a specific dump
#
# Live rows written after the dump was taken show up as "live has more"; that is
# expected. A table missing from the restore, or an empty restore of a non-empty
# database, fails the rehearsal.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${BACKUP_CONFIG:-/etc/myscanner/backup.env}"
# shellcheck source=/dev/null
[[ -f "$CONFIG" ]] && source "$CONFIG"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/myscanner}"
ENV_FILE="${ENV_FILE:-$ROOT/.env.vps.rehearsal}"
POSTGRES_IMAGE="${POSTGRES_IMAGE:-postgres:18-alpine}"
container="myscanner-restore-check-$$"
work="$(mktemp -d)"
finish() {
  local status=$?
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap finish EXIT
compose() { docker compose --env-file "$ENV_FILE" -f "$ROOT/compose.vps.yml" "$@"; }

dump="${1:-}"
if [[ -z "$dump" ]]; then
  dump="$(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'myscanner-*.dump' | sort | tail -n 1)"
  [[ -n "$dump" ]] || { echo "FAIL: no dump found in $BACKUP_DIR; run scripts/vps_backup.sh first" >&2; exit 1; }
fi
[[ -s "$dump" ]] || { echo "FAIL: dump missing or empty: $dump" >&2; exit 1; }
if [[ -f "$dump.sha256" ]]; then
  (cd "$(dirname "$dump")" && sha256sum -c --quiet "$(basename "$dump").sha256") \
    || { echo "FAIL: checksum does not match $dump" >&2; exit 1; }
  echo "PASS: checksum $(basename "$dump")"
else
  echo "WARN: no .sha256 next to $dump; checksum not verified"
fi

# Exact row count of every table, one "schema.table<TAB>count" line each, sorted.
COUNT_SQL="select table_schema||'.'||table_name||E'\\t'||(xpath('/row/c/text()', query_to_xml(format('select count(*) as c from %I.%I', table_schema, table_name), false, true, '')))[1]::text from information_schema.tables where table_type='BASE TABLE' and table_schema not in ('pg_catalog','information_schema') order by 1"

docker run -d --rm --name "$container" --network none --tmpfs /var/lib/postgresql:size=2g \
  -e POSTGRES_PASSWORD="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')" -e POSTGRES_DB=restore_check \
  "$POSTGRES_IMAGE" >/dev/null
# The image's first-start setup listens only on its socket; TCP answers once the real server is up.
for _ in $(seq 60); do
  docker exec "$container" pg_isready -q -h 127.0.0.1 -U postgres -d restore_check 2>/dev/null && break
  sleep 1
done
docker exec "$container" pg_isready -q -h 127.0.0.1 -U postgres -d restore_check \
  || { echo "FAIL: throwaway PostgreSQL did not start" >&2; exit 1; }

started=$SECONDS
docker exec -i "$container" pg_restore -U postgres -d restore_check --no-owner --no-privileges \
  --exit-on-error --single-transaction < "$dump" \
  || { echo "FAIL: pg_restore reported an error; the dump is not restorable as is" >&2; exit 1; }
echo "PASS: restored into a separate throwaway database in $((SECONDS - started))s"

docker exec "$container" psql -U postgres -d restore_check -Atqc "$COUNT_SQL" > "$work/restored"
compose exec -T postgres psql -U myscanner_bootstrap -d myscanner_vps -Atqc "$COUNT_SQL" > "$work/live"

missing=0 restored_rows=0 live_rows=0
printf '%-44s %10s %10s\n' TABLE BACKUP 'LIVE NOW'
while IFS=$'\t' read -r table live; do
  backup="$(awk -F '\t' -v t="$table" '$1 == t {print $2}' "$work/restored")"
  live_rows=$((live_rows + live))
  if [[ -z "$backup" ]]; then
    missing=$((missing + 1))
    printf '%-44s %10s %10s  MISSING FROM BACKUP\n' "$table" - "$live"
    continue
  fi
  restored_rows=$((restored_rows + backup))
  note=""
  (( live > backup )) && note="  live has more (written after the dump)"
  (( live < backup )) && note="  live has fewer (deleted after the dump)"
  printf '%-44s %10s %10s%s\n' "$table" "$backup" "$live" "$note"
done < "$work/live"

(( missing == 0 )) || { echo "FAIL: $missing live table(s) missing from the backup" >&2; exit 1; }
(( restored_rows > 0 || live_rows == 0 )) || { echo "FAIL: the backup restored no rows" >&2; exit 1; }
echo "PASS: restore rehearsal $(basename "$dump"): $(wc -l < "$work/restored") tables, $restored_rows rows"
