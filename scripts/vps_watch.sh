#!/usr/bin/env bash
# Alert when a service of the VPS stack is down or unhealthy. Run as root (sudo).
#
# Every 5 minutes cron runs "check": each long-running service must be running,
# and healthy where it has a health check. The result pings a heartbeat monitor
# (for example a healthchecks.io check with a 5-minute period): the plain URL
# when all is well, URL/fail with the list of broken services otherwise. A
# missed ping (server down, cron stopped) alerts too.
#
#   sudo scripts/vps_watch.sh install   # once: adds /etc/cron.d/myscanner-watch
#   sudo scripts/vps_watch.sh check     # what cron runs; prints PASS or FAIL
#
# The monitor URL lives in WATCH_CONFIG (default /etc/myscanner/watch.env) as
#   WATCH_HEALTHCHECK_URL=https://hc-ping.com/<your-check-uuid>
# Without it, check still prints the result but alerts nobody.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${WATCH_CONFIG:-/etc/myscanner/watch.env}"
# shellcheck source=/dev/null
[[ -f "$CONFIG" ]] && source "$CONFIG"
WATCH_HEALTHCHECK_URL="${WATCH_HEALTHCHECK_URL:-}"
SERVICES=(proxy web worker bulk-worker tip-worker beat postgres redis clamav)
FILES=(compose.vps.yml compose.urlvet.yml compose.egress.yml compose.app-egress.yml compose.launch.yml)
compose() {
  local args=(--env-file "$ROOT/.env.vps.rehearsal")
  for file in "${FILES[@]}"; do args+=(-f "$ROOT/$file"); done
  docker compose --project-directory "$ROOT" "${args[@]}" "$@"
}

ping_monitor() {
  [[ -n "$WATCH_HEALTHCHECK_URL" ]] || return 0
  [[ "$WATCH_HEALTHCHECK_URL" =~ ^https://[^[:space:]]+$ ]] || { echo "WATCH_HEALTHCHECK_URL must be an https URL" >&2; return 0; }
  curl -fsS -m 10 --retry 3 -o /dev/null --data-raw "$2" "$WATCH_HEALTHCHECK_URL$1" || echo "WARN: monitor could not be notified" >&2
}

check() {
  local states problems
  states="$(compose ps --all --format json 2>/dev/null || true)"
  problems="$(STATES="$states" python3 - "${SERVICES[@]}" <<'EOF'
import json, os, sys
text = os.environ['STATES'].strip()
rows = json.loads(text) if text.startswith('[') else [json.loads(line) for line in text.splitlines() if line.strip()]
by_service = {row.get('Service'): row for row in rows}
for name in sys.argv[1:]:
    row = by_service.get(name)
    if row is None:
        print(f'{name}: missing')
    elif row.get('State') != 'running':
        print(f"{name}: {row.get('State')}")
    elif row.get('Health') not in ('', None, 'healthy'):
        print(f"{name}: {row.get('Health')}")
EOF
)" || problems="docker compose could not be read"
  if [[ -z "$problems" ]]; then
    echo "PASS: ${#SERVICES[@]} services running"
    ping_monitor "" "all services running"
  else
    echo "FAIL:"; echo "$problems"
    ping_monitor "/fail" "$problems"
    return 1
  fi
}

install() {
  cat > /etc/cron.d/myscanner-watch <<EOF
# MyScanner: alert when a service is down (scripts/vps_watch.sh)
*/5 * * * * root $ROOT/scripts/vps_watch.sh check >/dev/null 2>&1
EOF
  chmod 644 /etc/cron.d/myscanner-watch
  mkdir -p "$(dirname "$CONFIG")"
  [[ -f "$CONFIG" ]] || { command install -m 600 /dev/null "$CONFIG"; echo "WATCH_HEALTHCHECK_URL=" > "$CONFIG"; }
  echo "Installed /etc/cron.d/myscanner-watch. Put the monitor URL in $CONFIG (sudo nano $CONFIG)."
}

case "${1:-}" in
  check) check ;;
  install) install ;;
  *) echo "usage: sudo $0 install|check" >&2; exit 2 ;;
esac
