#!/usr/bin/env bash
# Experiment A — coverage and latency (proposal section 4.2).
#
# For each (detector, scan-interval) cell: start the detector watching every
# technique's path, then plant each of the six implants in turn and measure
# whether/when an alert for that path shows up. Repeated --iterations times
# per technique so we can report an average and spread.
#
# Usage:
#   experiments/exp_a_coverage_latency.sh [options]
#     --detectors "diff inotify auditd"   which detectors to run (default: all available)
#     --techniques "cron bashrc ..."      which implants to test (default: all)
#     --iterations N                      repeats per (detector,technique) cell (default: 10)
#     --diff-intervals "5 30 60"          scan intervals to test for the diff detector
#
# Output: results/exp_a_coverage_latency_<timestamp>.csv
set -uo pipefail
source "$(cd "$(dirname "$0")" && pwd)/lib.sh"

detectors="$PD_ALL_DETECTORS"
techniques="$PD_TECHNIQUES"
iterations=10
diff_intervals="5 30 60"

while [ $# -gt 0 ]; do
  case "$1" in
    --detectors) detectors="$2"; shift 2 ;;
    --techniques) techniques="$2"; shift 2 ;;
    --iterations) iterations="$2"; shift 2 ;;
    --diff-intervals) diff_intervals="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) exp_die "unknown option: $1" ;;
  esac
done

out_csv="$PD_RESULTS_DIR/exp_a_coverage_latency_$(date +%Y%m%d_%H%M%S).csv"
exp_csv_header_if_new "$out_csv" "detector,scan_interval,technique,iteration,plant_ts,detect_ts,latency_s,detected"

run_dir="$PD_RESULTS_DIR/.exp_a_run"
rm -rf "$run_dir"

# One pass of planting every technique once and recording the result for a
# detector session that is already running.
run_cell() {
  local name="$1" interval="$2" iter="$3" tech timeout since plant_ts detect_ts path latency detected

  for tech in $techniques; do
    bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true
    path="$(exp_technique_path "$tech")"
    since="$(exp_alert_log_lines)"
    timeout="$(exp_timeout_for "$name" "$interval")"

    plant_ts="$(pd_now)"
    if ! bash "$PD_IMPLANTS_DIR/$tech.sh" plant >/dev/null 2>&1; then
      exp_log "WARN: planting $tech failed (iteration $iter) — needs root/gcc/sshd? skipping cell"
      bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true
      echo "$name,$interval,$tech,$iter,$plant_ts,,,plant_failed" >> "$out_csv"
      continue
    fi

    if detect_ts="$(exp_wait_for_alert "$path" "$since" "$timeout")"; then
      latency="$(awk -v a="$detect_ts" -v b="$plant_ts" 'BEGIN{printf "%.3f", a-b}')"
      detected=1
      exp_log "[$name interval=$interval] $tech iter $iter: detected in ${latency}s"
    else
      detect_ts=""; latency=""; detected=0
      exp_log "[$name interval=$interval] $tech iter $iter: NOT detected within ${timeout}s"
    fi

    echo "$name,$interval,$tech,$iter,$plant_ts,$detect_ts,$latency,$detected" >> "$out_csv"
    bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true
  done
}

for name in $detectors; do
  if ! exp_detector_available "$name"; then
    exp_log "skipping '$name': detectors/$name.sh not found yet"
    continue
  fi

  if [ "$name" = "diff" ]; then
    intervals="$diff_intervals"
  else
    intervals="n/a"
  fi

  for interval in $intervals; do
    exp_detector_start "$name" "$run_dir/${name}_${interval}" "$([ "$interval" = "n/a" ] && echo "" || echo "$interval")"
    for iter in $(seq 1 "$iterations"); do
      run_cell "$name" "$interval" "$iter"
    done
    exp_detector_stop "$name"
  done
done

rm -rf "$run_dir"
exp_log "done. results in $out_csv"
