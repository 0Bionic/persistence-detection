#!/usr/bin/env bash
# Experiment D — evasion (proposal section 4.2).
#
# Tests an attacker who knows the detector, in the two ways the proposal
# gives as examples:
#
#   timing  — plant the implant, then remove it again before the detector's
#             next check has a chance to run, same as "plant and remove
#             between two diff scans". Mainly bites the polling detector,
#             but every detector is exercised the same way.
#   path    — plant the implant's `evade` variant, which writes to a path
#             outside the canonical list in implants/<tech>.sh's `paths`
#             verb — e.g. ~/.profile instead of ~/.bashrc, or the
#             system-wide autostart dir instead of the per-user one — the
#             same blind spot a narrowly-scoped inotify watch list has.
#             Techniques with no meaningful alternate location (cron,
#             systemd_user) are skipped and recorded as such.
#
# "Still detected" means any new alert appeared in the detector's log during
# the test window, whether or not it names the exact path we touched — a
# detector watching a path that happens to overlap with where the evasion
# landed (e.g. the ld_preload evasion rewrites ~/.bashrc) should get credit
# for catching it.
#
# Usage:
#   experiments/exp_d_evasion.sh [options]
#     --detectors "diff inotify auditd"  which detectors to run (default: all available)
#     --techniques "cron bashrc ..."     which implants to test (default: all)
#     --iterations N                     repeats per (detector,technique) cell (default: 10)
#     --diff-intervals "5 30 60"         scan intervals to test for the diff detector
#
# Output: results/exp_d_evasion_<timestamp>.csv
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

out_csv="$PD_RESULTS_DIR/exp_d_evasion_$(date +%Y%m%d_%H%M%S).csv"
exp_csv_header_if_new "$out_csv" "detector,scan_interval,evasion_type,technique,iteration,event_ts,alert_count,still_detected"

run_dir="$PD_RESULTS_DIR/.exp_d_run"
rm -rf "$run_dir"

has_evade() {
  # True if implants/<tech>.sh defines do_evade (its `evade` verb works).
  grep -q '^do_evade()' "$PD_IMPLANTS_DIR/$1.sh" 2>/dev/null
}

# How long to hold the implant in place before removing it again, for the
# timing-evasion case. Short relative to the diff detector's interval so it
# has a real chance of falling inside one scan gap; a flat couple of seconds
# for the event-driven detectors, since they have no interval to time
# against. This can't account for the diff detector's exact scan phase, so
# treat the result as approximate, same as the proposal's own framing of
# this as "for example" rather than a guaranteed miss.
timing_delay_for() {
  local name="$1" interval="$2"
  if [ "$name" = "diff" ] && [ -n "$interval" ]; then
    awk -v i="$interval" 'BEGIN{d=i/3; if(d<1)d=1; printf "%d", d}'
  else
    echo 1
  fi
}

run_timing_cell() {
  local name="$1" interval="$2" iter="$3" tech delay timeout since event_ts path remaining alert_ts alert_count still

  for tech in $techniques; do
    bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true
    since="$(exp_alert_log_lines)"
    delay="$(timing_delay_for "$name" "$interval")"
    timeout="$(exp_timeout_for "$name" "$interval")"
    path="$(exp_technique_path "$tech")"

    event_ts="$(pd_now)"
    if ! bash "$PD_IMPLANTS_DIR/$tech.sh" plant >/dev/null 2>&1; then
      exp_log "WARN: planting $tech failed — skipping timing-evasion cell"
      bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true
      echo "$name,$interval,timing,$tech,$iter,$event_ts,,plant_failed" >> "$out_csv"
      continue
    fi
    sleep "$delay"
    bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true

    remaining=$(( timeout - delay )); [ "$remaining" -lt 1 ] && remaining=1
    if alert_ts="$(exp_wait_for_alert "$path" "$since" "$remaining")"; then
      still=1
    else
      still=0
    fi
    alert_count="$(tail -n +"$((since + 1))" "$PD_ALERT_LOG" 2>/dev/null | wc -l)"
    exp_log "[$name interval=$interval] timing-evade $tech iter $iter: still_detected=$still (held ${delay}s)"
    echo "$name,$interval,timing,$tech,$iter,$event_ts,$alert_count,$still" >> "$out_csv"
  done
}

run_path_cell() {
  local name="$1" interval="$2" iter="$3" tech since event_ts settle alert_count still

  for tech in $techniques; do
    bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true

    if ! has_evade "$tech"; then
      echo "$name,$interval,path,$tech,$iter,,,no_evasion_variant" >> "$out_csv"
      continue
    fi

    since="$(exp_alert_log_lines)"
    settle="$(exp_timeout_for "$name" "$interval")"
    event_ts="$(pd_now)"
    if ! bash "$PD_IMPLANTS_DIR/$tech.sh" evade >/dev/null 2>&1; then
      exp_log "WARN: evade for $tech failed (needs root?) — skipping path-evasion cell"
      bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true
      echo "$name,$interval,path,$tech,$iter,$event_ts,,evade_failed" >> "$out_csv"
      continue
    fi
    sleep "$settle"
    alert_count="$(tail -n +"$((since + 1))" "$PD_ALERT_LOG" 2>/dev/null | wc -l)"
    [ "$alert_count" -gt 0 ] && still=1 || still=0
    exp_log "[$name interval=$interval] path-evade $tech iter $iter: still_detected=$still ($alert_count alert(s))"
    echo "$name,$interval,path,$tech,$iter,$event_ts,$alert_count,$still" >> "$out_csv"
    bash "$PD_IMPLANTS_DIR/$tech.sh" cleanup >/dev/null 2>&1 || true
  done
}

for name in $detectors; do
  if ! exp_detector_available "$name"; then
    exp_log "skipping '$name': detectors/$name.sh not found yet"
    continue
  fi

  if [ "$name" = "diff" ]; then intervals="$diff_intervals"; else intervals="n/a"; fi

  for interval in $intervals; do
    exp_detector_start "$name" "$run_dir/${name}_${interval}" "$([ "$interval" = "n/a" ] && echo "" || echo "$interval")"
    for iter in $(seq 1 "$iterations"); do
      run_timing_cell "$name" "$interval" "$iter"
      run_path_cell "$name" "$interval" "$iter"
    done
    exp_detector_stop "$name"
  done
done

rm -rf "$run_dir"
exp_log "done. results in $out_csv"
