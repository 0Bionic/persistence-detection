#!/usr/bin/env bash
# Harmless payload run by every implant. Appends one line to the markers log
# to prove the persistence mechanism fired. Takes the technique name as $1.
#
# Line format (tab-separated):  <epoch.ns>  <technique>  <pid>  <user>
set -u
tech="${1:-unknown}"
file="${PD_MARKER_FILE:-$HOME/.local/share/pd-markers/markers.log}"
mkdir -p "$(dirname "$file")"
printf '%s\t%s\t%s\t%s\n' "$(date +%s.%N)" "$tech" "$$" "$(id -un)" >> "$file"
