#!/usr/bin/env bash
# Implant 2 — systemd user unit.
# Persistence: a ~/.config/systemd/user/ service enabled to start at login.
# MITRE ATT&CK: T1543.002 (Create or Modify System Process: systemd service).
PD_TECH="systemd_user"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

UNIT_NAME="pd-persist.service"
UNIT_DIR="$HOME/.config/systemd/user"
UNIT_FILE="$UNIT_DIR/$UNIT_NAME"

do_paths() { echo "$UNIT_FILE"; }

do_plant() {
  mkdir -p "$UNIT_DIR"
  cat > "$UNIT_FILE" <<EOF
[Unit]
Description=${PD_TAG} ${PD_TECH} (harmless marker)

[Service]
Type=oneshot
ExecStart=$(pd_payload_cmd)

[Install]
WantedBy=default.target
EOF
  systemctl --user daemon-reload
  systemctl --user enable "$UNIT_NAME" >/dev/null 2>&1 || true
  pd_info "planted + enabled (starts at next login)"
}

do_cleanup() {
  systemctl --user disable "$UNIT_NAME" >/dev/null 2>&1 || true
  rm -f "$UNIT_FILE"
  systemctl --user daemon-reload 2>/dev/null || true
  pd_info "cleaned up"
}

# Real trigger: start the unit now.
do_trigger() { systemctl --user start "$UNIT_NAME"; }

pd_main "$@"
