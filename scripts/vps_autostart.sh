#!/usr/bin/env bash
# Bring the whole VPS stack back after every reboot. Run as root (sudo).
#
# Every long-running service has restart: unless-stopped, but Docker restarts them
# all at once and ignores depends_on, and web, the workers and urlvet live in the
# network of their egress containers (network_mode: service:...). One container
# that stays down leaves the others restarting forever, as on 18 Oct 2026 when the
# urlvet egress containers had no restart policy. And when an egress container
# restarts on its own, the containers already joined to its old network keep
# running without a working one. So at boot this unit recreates the whole stack
# with "docker compose up -d --force-recreate": dependency order, fresh networks.
# Data lives in volumes and survives.
#
#   sudo scripts/vps_autostart.sh install   # once: adds and enables myscanner.service
#   sudo scripts/vps_autostart.sh start     # what the service runs at boot
#   sudo scripts/vps_autostart.sh status    # is the unit enabled, and its last run
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
UNIT="myscanner.service"
# Same files, in the same order, as the documented production command.
FILES=(compose.vps.yml compose.urlvet.yml compose.egress.yml compose.app-egress.yml compose.launch.yml)
compose() {
  local args=(--env-file "$ROOT/.env.vps.rehearsal")
  for file in "${FILES[@]}"; do args+=(-f "$ROOT/$file"); done
  docker compose --project-directory "$ROOT" "${args[@]}" "$@"
}

start() {
  for _ in $(seq 60); do docker info >/dev/null 2>&1 && break; sleep 2; done
  docker info >/dev/null 2>&1 || { echo "FAIL: Docker is not running" >&2; exit 1; }
  # A slow first start (database recovery after a hard stop) can fail a health
  # dependency once; try a few times before giving up and letting monitoring alert.
  for attempt in 1 2 3; do
    if compose up -d --no-build --force-recreate; then
      echo "PASS: stack started (attempt $attempt)"
      return 0
    fi
    sleep 20
  done
  echo "FAIL: stack did not start after 3 attempts" >&2
  exit 1
}

install() {
  cat > "$UNIT_DIR/$UNIT" <<EOF
[Unit]
Description=MyScanner stack (docker compose up after boot)
Requires=docker.service
After=docker.service network-online.target
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$ROOT/scripts/vps_autostart.sh start
TimeoutStartSec=900

[Install]
WantedBy=multi-user.target
EOF
  chmod 644 "$UNIT_DIR/$UNIT"
  systemctl daemon-reload
  systemctl enable "$UNIT"
  echo "PASS: $UNIT installed and enabled; it runs $ROOT/scripts/vps_autostart.sh start at every boot"
}

case "${1:-}" in
  start) start ;;
  install) install ;;
  status) systemctl is-enabled "$UNIT"; systemctl status --no-pager --lines=5 "$UNIT" || true ;;
  *) echo "usage: $0 install|start|status" >&2; exit 2 ;;
esac
