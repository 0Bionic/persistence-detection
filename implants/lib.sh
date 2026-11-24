# shellcheck shell=bash
# Shared helpers for the persistence implants. Source this from an implant
# script, set PD_TECH, define do_plant/do_cleanup/etc, then call `pd_main "$@"`.
#
# Every implant is HARMLESS: it only arranges for a marker line to be appended
# to the markers log when the persistence mechanism fires. Nothing malicious.
set -euo pipefail

PD_IMPLANT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PD_REPO="$(cd "$PD_IMPLANT_DIR/.." && pwd)"

# State we own (backups, generated keys, the compiled .so) lives here.
PD_STATE_DIR="${PD_STATE_DIR:-$PD_REPO/results/.pd_state}"
PD_BACKUP_DIR="$PD_STATE_DIR/backups"

# Where implants write their "I ran" marker lines. One file, all techniques.
PD_MARKER_DIR="${PD_MARKER_DIR:-$HOME/.local/share/pd-markers}"
PD_MARKER_FILE="${PD_MARKER_FILE:-$PD_MARKER_DIR/markers.log}"
export PD_MARKER_FILE

# Tag that identifies our lines inside shared files (.bashrc, authorized_keys).
PD_TAG="pd-persist"

# Canonical list of techniques (script basenames in this folder).
PD_TECHNIQUES="cron systemd_user bashrc ssh_key xdg_autostart ld_preload"

mkdir -p "$PD_STATE_DIR" "$PD_BACKUP_DIR"

pd_now()  { date +%s.%N; }
pd_info() { printf '[%s] %s\n' "${PD_TECH:-implant}" "$*" >&2; }
pd_die()  { printf '[%s] ERROR: %s\n' "${PD_TECH:-implant}" "$*" >&2; exit 1; }

# The command a persistence mechanism runs. Absolute paths + an explicit
# PD_MARKER_FILE so it works identically from cron, systemd, a shell, etc.
pd_payload_cmd() {
  printf '/usr/bin/env PD_MARKER_FILE=%s bash %s %s' \
    "$PD_MARKER_FILE" "$PD_IMPLANT_DIR/_marker.sh" "$PD_TECH"
}

# --- shared-file editing (append a tagged block, remove it later) ----------
pd_add_block() {
  local file="$1" body="$2"
  touch "$file"
  {
    echo "# >>> ${PD_TAG} ${PD_TECH} >>>"
    echo "$body"
    echo "# <<< ${PD_TAG} ${PD_TECH} <<<"
  } >> "$file"
}

pd_remove_block() {
  local file="$1"
  [ -e "$file" ] || return 0
  sed -i "/>>> ${PD_TAG} ${PD_TECH} >>>/,/<<< ${PD_TAG} ${PD_TECH} <<</d" "$file"
}

# --- backup / restore of files we overwrite (e.g. /etc/ld.so.preload) ------
# Uses sudo for paths the user can't write. Records "was absent" so cleanup
# can delete a file we created.
pd_backup() {
  local f="$1" sudo="${2:-}"
  local key dest
  key="$(printf '%s' "$f" | tr '/' '_')"
  dest="$PD_BACKUP_DIR/$key"
  if [ -e "$dest" ] || [ -e "$dest.absent" ]; then return 0; fi
  if [ -e "$f" ]; then
    $sudo cp -a "$f" "$dest"
  else
    : > "$dest.absent"
  fi
}

pd_restore() {
  local f="$1" sudo="${2:-}"
  local key dest
  key="$(printf '%s' "$f" | tr '/' '_')"
  dest="$PD_BACKUP_DIR/$key"
  if [ -e "$dest.absent" ]; then
    $sudo rm -f "$f"
    rm -f "$dest.absent"
  elif [ -e "$dest" ]; then
    $sudo cp -a "$dest" "$f"
    rm -f "$dest"
  fi
}

# --- default verb implementations ------------------------------------------
# A technique "ran" if the markers log has a line whose 2nd column is PD_TECH.
pd_verify_marker() {
  if [ -f "$PD_MARKER_FILE" ] && \
     awk -F'\t' -v t="$PD_TECH" '$2==t{f=1} END{exit !f}' "$PD_MARKER_FILE"; then
    pd_info "marker present"
    return 0
  fi
  pd_info "no marker yet"
  return 1
}

# Run the payload directly. Proves the payload is well-formed; it does NOT
# prove the mechanism's natural trigger works (that is the experiment's job).
pd_trigger_default() {
  pd_info "running payload directly (not via the real trigger)"
  eval "$(pd_payload_cmd)"
}

pd_status() {
  local p
  echo "technique : $PD_TECH"
  echo "paths     :"
  do_paths | sed 's/^/  /'
  if pd_verify_marker >/dev/null 2>&1; then echo "marker    : present"; else echo "marker    : absent"; fi
}

pd_usage() {
  cat >&2 <<EOF
usage: $PD_TECH.sh <verb>
  plant     install the persistence
  trigger   make it fire now (smoke test)
  verify    did it run? (checks the markers log)
  cleanup   remove it, restore any changed files
  paths     print the file path(s) a detector should watch
  status    show paths + whether a marker exists
  evade     install the evasion variant (if this technique has one)
EOF
}

pd_main() {
  local verb="${1:-}"
  shift || true
  case "$verb" in
    plant)   do_plant "$@" ;;
    cleanup) do_cleanup "$@" ;;
    paths)   do_paths "$@" ;;
    verify)  if declare -F do_verify >/dev/null; then do_verify "$@"; else pd_verify_marker; fi ;;
    trigger) if declare -F do_trigger >/dev/null; then do_trigger "$@"; else pd_trigger_default; fi ;;
    evade)   if declare -F do_evade >/dev/null; then do_evade "$@"; else pd_die "no evasion variant for $PD_TECH"; fi ;;
    status)  pd_status ;;
    ""|-h|--help|help) pd_usage ;;
    *) pd_die "unknown verb: $verb (try --help)" ;;
  esac
}
