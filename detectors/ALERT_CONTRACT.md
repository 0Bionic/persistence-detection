# Shared event contract

The experiment runner writes `plant` records. Detectors write raw `alert`
records. Both are JSON Lines records using schema version `1.0`.

## Detector lifecycle and metadata

Detectors are restarted for every trial. Each trial begins from the clean VM
state and each detector invocation creates a fresh baseline or watch state.
This matches the proposal's repeated-trial design and prevents alerts or
baselines from leaking between trials.

Every record has:

- `experiment_id`: proposal experiment identifier, such as `A`, `B`, `C`, or `D`;
- `run_id`: runner-created identifier for one plant attempt and its clean trial;
- `trial`: non-negative trial number, or `null` for an unassigned raw alert;
- `trial_source`: `runner`, `detector_cli`, or `unassigned`.

Plant records always have a runner-supplied `trial` and
`trial_source: "runner"`. An alert may have a numbered trial only when the
runner supplies it or the detector is launched with that trial ID. Otherwise
the alert must use `trial: null` and `trial_source: "unassigned"`. A detector
must not infer a trial from timing, paths, or technique.

The runner creates exactly one `run_id` for each plant attempt. The plant
record and every detector alert produced for that attempt use the same
`run_id`. If multiple detectors observe the same attempt, they still share
that `run_id`; the `detector` field distinguishes their alerts.

## Correlation

Every record contains `run_id`, `trial`, `technique`, and `paths`.

The runner owns `plant_event_id`. A raw detector alert must omit
`plant_event_id` unless the runner explicitly provides that ID to the detector.
When supplied, the alert must include `plant_event_id_source: "runner"`.
Detectors must never invent or infer a plant-event ID.

Raw alerts must not contain `false_positive`, `is_false_positive`, or
`classification`. Analysis classifies alerts only after matching them against
plant records and normal-activity windows.

## Timestamps

Plant records use `plant_time_epoch_ns` and `plant_time_utc`.

Alert records use `observation_time_epoch_ns` and `observation_time_utc`. These
are the wall-clock times when the detector observes, normalizes, and emits the
alert; they are not claimed to be the attacker’s plant time. The numeric epoch
nanosecond value is authoritative. The ISO-8601 UTC value is for readability.

All mechanisms use the same field names, but their effective timing precision
differs: baseline diffing observes changes at its next scan, inotify observes
events when the detector reads them from the kernel event stream, and auditd
observes events after audit logging and userspace parsing. Nanosecond formatting
does not imply nanosecond mechanism accuracy.

## Duplicate grouping

Before grouping, paths are expanded and normalized to absolute lexical paths.
Operations are mapped to groups as follows:

- `create`, `modify`, `write`, and `move` -> `write`
- `delete` -> `delete`
- `metadata` -> `metadata`
- `unknown` -> `unknown`

Two raw events belong to the same logical alert when they have the same
`detector`, `experiment_id`, `run_id`, `trial`, `trial_source`, `technique`, sorted normalized `paths`, and
operation group, and the later observation occurs no more than 250 ms after
the first observation in that group. Otherwise a new `alert_group_id` starts.

Each alert keeps every contributing raw event under
`evidence.raw_events`; grouping never discards the original event name or
mechanism-specific fields. A detector should use one path per alert unless it
observes a single multi-path operation as one event.

## Technique paths

The configured paths are derived from the six techniques in the proposal:

| Technique | Watched path |
|---|---|
| `cron` | `/var/spool/cron/crontabs/{user}` |
| `systemd_user` | `{home}/.config/systemd/user` |
| `shell_rc` | `{home}/.bashrc` |
| `ssh_authorized_keys` | `{home}/.ssh/authorized_keys` |
| `xdg_autostart` | `{home}/.config/autostart` |
| `ld_preload` | `/etc/ld.so.preload` |

`{home}` and `{user}` are resolved on the Ubuntu VM. The cron path is the
Ubuntu per-user crontab storage path corresponding to the proposal’s crontab
entry; Student 1 should confirm that this matches the implant’s actual write
path.
