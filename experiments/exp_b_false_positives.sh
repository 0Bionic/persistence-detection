#!/usr/bin/env bash
# Experiment B — false positives (proposal section 4.2).
#
# No implants are planted here. Instead we perform ordinary admin activity
# while each detector is running, and count every alert it raises: since
# nothing in this run is an implant, every alert counted is by definition a
# false positive.
#
# Normal activities exercised (each is attempted and then undone):
#   1. install a small, harmless package
#   2. edit ~/.bashrc directly (a real alias, not an implant)
#   3. add a real personal cron job
#   4. log in over SSH
#
# Usage:
#   experiments/exp_b_false_positives.sh [options]
#     --detectors "diff inotify auditd"  which detectors to run (default: all available)
#     --iterations N                     repeats of the whole activity sequence (default: 3)
#     --diff-interval N                  scan interval (s) to use for the diff detector (default: 10)
#     --skip-pkg-install                 skip the package-install activity (no net/sudo in CI, etc.)
#
# Output: results/exp_b_false_positives_<timestamp>.csv
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

detectors="$PD_ALL_DETECTORS"
iterations=3
diff_interval=10
skip_pkg_install=0

while [ $# -gt 0 ]; do
  case "$1" in
    --detectors) detectors="$2"; shift 2 ;;
    --iterations) iterations="$2"; shift 2 ;;
    --diff-interval) diff_interval="$2"; shift 2 ;;
    --skip-pkg-install) skip_pkg_install=1; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) exp_die "unknown option: $1" ;;
  esac
done

out_csv="$PD_RESULTS_DIR/exp_b_false_positives_$(date +%Y%m%d_%H%M%S).csv"
exp_csv_header_if_new "$out_csv" "detector,scan_interval,activity,iteration,start_ts,end_ts,alert_count"

run_dir="$PD_RESULTS_DIR/.exp_b_run"
rm -rf "$run_dir"

# Settle time: long enough for every detector type to have had a chance to
# notice. The diffing detector can only notice at its next scan.
settle_s() { [ "$1" = "diff" ] && echo $(( diff_interval + 5 )) || echo 5; }

record_window() {
  # record_window <detector> <interval> <activity> <iter> <since_line>
  local name="$1" interval="$2" activity="$3" iter="$4" since="$5" start_ts end_ts count
  start_ts="$(pd_now)"
  sleep "$(settle_s "$name")"
  end_ts="$(pd_now)"
  count="$(tail -n +"$((since + 1))" "$PD_ALERT_LOG" 2>/dev/null | wc -l)"
  echo "$name,$interval,$activity,$iter,$start_ts,$end_ts,$count" >> "$out_csv"
  exp_log "[$name interval=$interval] $activity iter $iter: $count alert(s)"
}

act_install_package() {
  local name="$1" interval="$2" iter="$3" since
  since="$(exp_alert_log_lines)"
  if [ "$skip_pkg_install" = 1 ]; then
    exp_log "skipping package install (--skip-pkg-install)"
  elif command -v sudo >/dev/null && command -v apt-get >/dev/null; then
    sudo DEBIAN_FRONTEND=noninteractive apt-get install -y sl >/dev/null 2>&1 \
      || exp_log "WARN: package install failed (no net/sudo cached?) — counting window anyway"
  else
    exp_log "WARN: apt-get/sudo unavailable — counting empty window"
  fi
  record_window "$name" "$interval" "install_package" "$iter" "$since"
}

act_edit_bashrc() {
  local name="$1" interval="$2" iter="$3" since marker
  marker="# pd-exp-b-real-edit-$$"
  since="$(exp_alert_log_lines)"
  { echo "$marker"; echo "alias pd_exp_b_real='echo hi'"; } >> "$HOME/.bashrc"
  record_window "$name" "$interval" "edit_bashrc" "$iter" "$since"
  sed -i "\|${marker}|,+1d" "$HOME/.bashrc"
}

act_add_real_cron() {
  local name="$1" interval="$2" iter="$3" since tag line
  tag="pd-exp-b-real-cron-$$"
  line="17 3 * * * /bin/true # ${tag}"
  since="$(exp_alert_log_lines)"
  { crontab -l 2>/dev/null; echo "$line"; } | crontab -
  record_window "$name" "$interval" "add_real_cron" "$iter" "$since"
  crontab -l 2>/dev/null | grep -vF "$tag" | crontab - || true
}

act_ssh_login() {
  local name="$1" interval="$2" iter="$3" since
  since="$(exp_alert_log_lines)"
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
      -o BatchMode=yes -o ConnectTimeout=5 -o LogLevel=ERROR \
      "$(id -un)@localhost" true 2>/dev/null \
    || exp_log "note: ssh login didn't complete (no passwordless key set up) — counting window anyway"
  record_window "$name" "$interval" "ssh_login" "$iter" "$since"
}

for name in $detectors; do
  if ! exp_detector_available "$name"; then
    exp_log "skipping '$name': detectors/$name.sh not found yet"
    continue
  fi

  interval="$([ "$name" = "diff" ] && echo "$diff_interval" || echo "n/a")"
  exp_detector_start "$name" "$run_dir/$name" "$([ "$name" = "diff" ] && echo "$diff_interval" || echo "")"

  for iter in $(seq 1 "$iterations"); do
    act_install_package "$name" "$interval" "$iter"
    act_edit_bashrc "$name" "$interval" "$iter"
    act_add_real_cron "$name" "$interval" "$iter"
    act_ssh_login "$name" "$interval" "$iter"
  done

  exp_detector_stop "$name"
done

rm -rf "$run_dir"
exp_log "done. results in $out_csv"
