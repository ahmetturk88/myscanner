#!/usr/bin/env bash
# Daily PostgreSQL backup for the VPS stack. Run as root (cron or sudo).
# Writes a custom-format dump plus a SHA-256 file to BACKUP_DIR, validates the
# archive catalogue, and deletes only this script's own archives older than
# KEEP_DAYS. Local archives are not encrypted, so keep BACKUP_DIR root-only.
#
# Off-site copy (optional): when OFFSITE_REMOTE is set (for example
# r2:myscanner-backups), the dump is encrypted with age to the public keys in
# AGE_RECIPIENTS and uploaded with rclone. The server holds no decryption key.
# Remote copies older than OFFSITE_KEEP_DAYS are deleted. Settings may live in
# BACKUP_CONFIG (default /etc/myscanner/backup.env).
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${BACKUP_CONFIG:-/etc/myscanner/backup.env}"
# shellcheck source=/dev/null
[[ -f "$CONFIG" ]] && source "$CONFIG"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/myscanner}"
KEEP_DAYS="${KEEP_DAYS:-14}"
ENV_FILE="${ENV_FILE:-$ROOT/.env.vps.rehearsal}"
OFFSITE_REMOTE="${OFFSITE_REMOTE:-}"
AGE_RECIPIENTS="${AGE_RECIPIENTS:-/etc/myscanner/backup-recipients.txt}"
OFFSITE_KEEP_DAYS="${OFFSITE_KEEP_DAYS:-30}"
# Optional heartbeat monitor (for example a healthchecks.io check URL): pinged after
# every run, with /fail appended on failure, so a failed or missed backup raises an alert.
HEALTHCHECK_URL="${HEALTHCHECK_URL:-}"
partial=""
encrypted=""
finish() {
  local status=$?
  rm -f "$partial" "$encrypted"
  if [[ -n "$HEALTHCHECK_URL" ]]; then
    local suffix=""
    [[ $status -eq 0 ]] || suffix="/fail"
    curl -fsS -m 10 --retry 3 -o /dev/null "$HEALTHCHECK_URL$suffix" || echo "WARN: backup monitor could not be notified" >&2
  fi
  exit "$status"
}
trap finish EXIT
[[ -z "$HEALTHCHECK_URL" || "$HEALTHCHECK_URL" =~ ^https://[^[:space:]]+$ ]] || { echo "HEALTHCHECK_URL must be an https URL" >&2; HEALTHCHECK_URL=""; exit 2; }

[[ "$KEEP_DAYS" =~ ^[1-9][0-9]*$ ]] || { echo "KEEP_DAYS must be a positive integer" >&2; exit 2; }
if [[ -n "$OFFSITE_REMOTE" ]]; then
  [[ "$OFFSITE_KEEP_DAYS" =~ ^[1-9][0-9]*$ ]] || { echo "OFFSITE_KEEP_DAYS must be a positive integer" >&2; exit 2; }
  [[ -s "$AGE_RECIPIENTS" ]] || { echo "AGE_RECIPIENTS file is missing or empty: $AGE_RECIPIENTS" >&2; exit 2; }
  command -v age >/dev/null && command -v rclone >/dev/null || { echo "off-site copy needs age and rclone installed" >&2; exit 2; }
fi
compose() { docker compose --env-file "$ENV_FILE" -f "$ROOT/compose.vps.yml" "$@"; }

mkdir -p "$BACKUP_DIR"
chmod 700 "$BACKUP_DIR"
name="myscanner-$(date -u +%Y%m%d-%H%M%S).dump"
partial="$BACKUP_DIR/.$name.partial"
encrypted="$BACKUP_DIR/.$name.age.partial"

compose exec -T postgres pg_dump -U myscanner_bootstrap -d myscanner_vps -Fc > "$partial"
[[ -s "$partial" ]] || { echo "FAIL: empty backup" >&2; exit 1; }
compose exec -T postgres pg_restore --list < "$partial" > /dev/null
mv "$partial" "$BACKUP_DIR/$name"
(cd "$BACKUP_DIR" && sha256sum "$name" > "$name.sha256")

find "$BACKUP_DIR" -maxdepth 1 -type f \( -name 'myscanner-*.dump' -o -name 'myscanner-*.dump.sha256' \) \
  -mtime +"$KEEP_DAYS" -delete
echo "PASS: $(date -u +%FT%TZ) $name $(stat -c %s "$BACKUP_DIR/$name") bytes"

if [[ -n "$OFFSITE_REMOTE" ]]; then
  age -R "$AGE_RECIPIENTS" -o "$encrypted" "$BACKUP_DIR/$name"
  rclone copyto "$encrypted" "$OFFSITE_REMOTE/$name.age"
  rclone copyto "$BACKUP_DIR/$name.sha256" "$OFFSITE_REMOTE/$name.sha256"
  # Confirm the upload landed with the expected size before trusting it.
  remote_size="$(rclone lsf --format s "$OFFSITE_REMOTE/$name.age")"
  [[ "$remote_size" == "$(stat -c %s "$encrypted")" ]] || { echo "FAIL: off-site upload size mismatch" >&2; exit 1; }
  rclone delete --min-age "${OFFSITE_KEEP_DAYS}d" --include 'myscanner-*.dump.age' --include 'myscanner-*.dump.sha256' "$OFFSITE_REMOTE"
  echo "PASS: off-site $OFFSITE_REMOTE/$name.age $remote_size bytes"
fi
