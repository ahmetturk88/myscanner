#!/usr/bin/env bash
# Daily PostgreSQL backup for the VPS stack. Run as root (cron or sudo).
# Writes a custom-format dump plus a SHA-256 file to BACKUP_DIR, validates the
# archive catalogue, and deletes only this script's own archives older than
# KEEP_DAYS. Archives hold account and report data: they are not encrypted, so
# keep BACKUP_DIR root-only and copy them off the server encrypted.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/myscanner}"
KEEP_DAYS="${KEEP_DAYS:-14}"
ENV_FILE="${ENV_FILE:-$ROOT/.env.vps.rehearsal}"

[[ "$KEEP_DAYS" =~ ^[1-9][0-9]*$ ]] || { echo "KEEP_DAYS must be a positive integer" >&2; exit 2; }
compose() { docker compose --env-file "$ENV_FILE" -f "$ROOT/compose.vps.yml" "$@"; }

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
name="myscanner-$(date -u +%Y%m%d-%H%M%S).dump"
partial="$BACKUP_DIR/.$name.partial"
trap 'rm -f "$partial"' EXIT

compose exec -T postgres pg_dump -U myscanner_bootstrap -d myscanner_vps -Fc > "$partial"
[[ -s "$partial" ]] || { echo "FAIL: empty backup" >&2; exit 1; }
compose exec -T postgres pg_restore --list < "$partial" > /dev/null
mv "$partial" "$BACKUP_DIR/$name"
(cd "$BACKUP_DIR" && sha256sum "$name" > "$name.sha256")

find "$BACKUP_DIR" -maxdepth 1 -type f \( -name 'myscanner-*.dump' -o -name 'myscanner-*.dump.sha256' \) \
  -mtime +"$KEEP_DAYS" -delete
echo "PASS: $(date -u +%FT%TZ) $name $(stat -c %s "$BACKUP_DIR/$name") bytes"
