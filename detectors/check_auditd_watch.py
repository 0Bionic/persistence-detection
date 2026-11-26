"""Hand-written, side-effect-free checks for auditd_watch.py."""

from __future__ import annotations

import io
import tempfile
from pathlib import Path

import auditd_watch
from config_loader import load_config


BASE_SECONDS = 1_700_000_000
TARGET = "/tmp/auditd-watch-check/.bashrc"


def line(
    record_type: str,
    serial: int,
    suffix: str = "",
    *,
    seconds: int = BASE_SECONDS,
    fraction: str = "100000",
) -> str:
    return (
        f'type={record_type} msg=audit({seconds}.{fraction}:{serial}):'
        f" {suffix}".rstrip()
    )


def emitter(
    *, observation_clock=lambda: BASE_SECONDS * 1_000_000_000 + 900_000_000
) -> auditd_watch.AuditAlertEmitter:
    return auditd_watch.AuditAlertEmitter(
        configured_paths=[TARGET],
        path_kind="file",
        experiment_id="check-experiment",
        run_id="check-run",
        trial=0,
        trial_source="detector_cli",
        technique="shell_rc",
        observation_clock=observation_clock,
    )


def serial_group(serial: int, seconds: int) -> auditd_watch.AuditSerialGroup:
    grouper = auditd_watch.AuditSerialGrouper()
    key = 'key="persistence_detection_shell_rc"'
    assert grouper.add(auditd_watch.parse_audit_line(line("SYSCALL", serial, key, seconds=seconds))) == []
    assert grouper.add(
        auditd_watch.parse_audit_line(
            line("PATH", serial, f'name="{TARGET}" nametype=MODIFY', seconds=seconds)
        )
    ) == []
    closed = grouper.add(auditd_watch.parse_audit_line(line("EOE", serial, seconds=seconds)))
    assert len(closed) == 1
    return closed[0]


def test_eoe_closes_serial_group_immediately() -> None:
    grouper = auditd_watch.AuditSerialGrouper()
    syscall = auditd_watch.parse_audit_line(
        line(
            "SYSCALL",
            101,
            'pid=42 uid=1000 exe="/usr/bin/touch" key="persistence_detection_shell_rc"',
        )
    )
    eoe = auditd_watch.parse_audit_line(line("EOE", 101))
    assert grouper.add(syscall) == []
    closed = grouper.add(eoe)
    assert len(closed) == 1
    assert [record.record_type for record in closed[0].records] == ["SYSCALL", "EOE"]
    assert grouper.flush_all() == []


def test_serial_group_has_no_eoe_fallback() -> None:
    grouper = auditd_watch.AuditSerialGrouper()
    record = auditd_watch.parse_audit_line(
        line(
            "SYSCALL",
            103,
            'pid=44 uid=1000 key="persistence_detection_shell_rc"',
        )
    )
    assert grouper.add(record) == []
    closed = grouper.flush_stale(record.epoch_ns + auditd_watch.SERIAL_FALLBACK_TIMEOUT_NS)
    assert len(closed) == 1
    assert closed[0].serial == 103


def test_duplicate_group_flushes_without_later_event() -> None:
    detector = emitter()
    detector.consume_line(
        line(
            "SYSCALL",
            101,
            'pid=42 uid=1000 exe="/usr/bin/touch" key="persistence_detection_shell_rc"',
        )
    )
    detector.consume_line(line("PATH", 101, f'name="{TARGET}" nametype=MODIFY'))
    assert detector.consume_line(line("EOE", 101)) == []
    alerts = detector.flush_expired(
        BASE_SECONDS * 1_000_000_000 + 900_000_000 + 250_000_001
    )
    assert len(alerts) == 1
    assert alerts[0]["run_id"] == "check-run"
    assert len(alerts[0]["evidence"]["raw_events"]) == 1


def test_detector_clock_controls_grouping_and_preserves_audit_time() -> None:
    audit_time_one = BASE_SECONDS * 1_000_000_000 + 100_000_000
    audit_time_two = (BASE_SECONDS + 1) * 1_000_000_000 + 100_000_000
    detector_time_one = 10_000_000_000_000
    detector_time_two = detector_time_one + 100_000_000
    detector_emit_time = detector_time_two + 250_000_001
    detector_times = iter((detector_time_one, detector_time_two, detector_emit_time))
    detector = emitter(observation_clock=lambda: next(detector_times))
    assert detector._consume_serial_group(serial_group(104, BASE_SECONDS)) == []
    assert detector._consume_serial_group(serial_group(105, BASE_SECONDS + 1)) == []
    alerts = detector.flush_expired(detector_emit_time)
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["observation_time_epoch_ns"] == detector_emit_time
    raw_events = alert["evidence"]["raw_events"]
    assert [event["audit_time_epoch_ns"] for event in raw_events] == [
        audit_time_one,
        audit_time_two,
    ]
    assert [event["audit_timestamp_precision_ns"] for event in raw_events] == [1_000, 1_000]
    assert alert["metadata"]["audit_timestamp_epoch_ns"] == audit_time_one
    assert alert["metadata"]["audit_timestamps_epoch_ns"] == [
        audit_time_one,
        audit_time_two,
    ]
    assert alert["metadata"]["audit_timestamp_precision_ns"] == 1_000


def test_unrelated_key_is_ignored() -> None:
    detector = emitter()
    detector.consume_line(
        line(
            "SYSCALL",
            102,
            'pid=43 uid=1000 exe="/usr/bin/touch" key="unrelated_key"',
        )
    )
    detector.consume_line(line("PATH", 102, f'name="{TARGET}" nametype=MODIFY'))
    detector.consume_line(line("EOE", 102))
    assert detector.flush_all() == []


class FakeProcess:
    pid = 12345

    def __init__(self, return_code: int | None = None) -> None:
        self.return_code = return_code
        self.terminated = False
        self.killed = False
        self.stdout = io.BytesIO()
        self.stderr = io.BytesIO()

    def poll(self) -> int | None:
        return self.return_code

    def terminate(self) -> None:
        self.terminated = True
        self.return_code = 0

    def kill(self) -> None:
        self.killed = True
        self.return_code = -9

    def wait(self, timeout: float | None = None) -> int:
        return self.return_code or 0


def test_follower_readiness_and_timeout_cleanup() -> None:
    ready_process = FakeProcess()
    ready_follower = auditd_watch.AuditLogProcess(ready_process, TARGET)
    probes = iter((False, True))
    auditd_watch.wait_for_log_follower_ready(
        ready_follower,
        timeout_seconds=1.0,
        ready_probe=lambda _: next(probes),
        clock=lambda: 0.0,
        sleep=lambda _: None,
    )

    timed_out_process = FakeProcess()
    timed_out_follower = auditd_watch.AuditLogProcess(timed_out_process, TARGET)
    try:
        auditd_watch.wait_for_log_follower_ready(
            timed_out_follower,
            timeout_seconds=1.0,
            ready_probe=lambda _: False,
            clock=iter((0.0, 1.0)).__next__,
            sleep=lambda _: None,
        )
    except auditd_watch.AuditMonitorError as exc:
        assert "timed out" in str(exc)
    else:
        raise AssertionError("readiness timeout was not reported")
    auditd_watch._stop_log_follower(timed_out_follower)
    assert timed_out_process.terminated

    exited_process = FakeProcess(return_code=17)
    exited_follower = auditd_watch.AuditLogProcess(exited_process, TARGET)
    try:
        auditd_watch.wait_for_log_follower_ready(
            exited_follower,
            ready_probe=lambda _: False,
            clock=lambda: 0.0,
            sleep=lambda _: None,
        )
    except auditd_watch.AuditMonitorError as exc:
        assert "exited before readiness" in str(exc)
    else:
        raise AssertionError("early follower exit was not reported")


def test_monitor_cleans_up_when_readiness_fails() -> None:
    config = load_config(Path(__file__).with_name("config.json"))
    process = FakeProcess()
    follower = auditd_watch.AuditLogProcess(process, TARGET)
    original_start = auditd_watch._start_log_follower
    original_wait = auditd_watch.wait_for_log_follower_ready

    def fail_readiness(_: auditd_watch.AuditLogProcess) -> None:
        raise auditd_watch.AuditMonitorError("mock readiness timeout")

    auditd_watch._start_log_follower = lambda _: follower
    auditd_watch.wait_for_log_follower_ready = fail_readiness
    try:
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                auditd_watch.monitor_log(
                    config=config,
                    technique="shell_rc",
                    experiment_id="check-experiment",
                    run_id="check-run",
                    trial=0,
                    home=temp_dir,
                    user="check-user",
                    output=io.StringIO(),
                    log_path=str(Path(temp_dir) / "audit.log"),
                    diagnostics=io.StringIO(),
                )
            except auditd_watch.AuditMonitorError as exc:
                assert "mock readiness timeout" in str(exc)
            else:
                raise AssertionError("readiness failure was not propagated")
    finally:
        auditd_watch._start_log_follower = original_start
        auditd_watch.wait_for_log_follower_ready = original_wait
    assert process.terminated


def main() -> None:
    checks = [
        test_eoe_closes_serial_group_immediately,
        test_serial_group_has_no_eoe_fallback,
        test_duplicate_group_flushes_without_later_event,
        test_detector_clock_controls_grouping_and_preserves_audit_time,
        test_unrelated_key_is_ignored,
        test_follower_readiness_and_timeout_cleanup,
        test_monitor_cleans_up_when_readiness_fails,
    ]
    for check in checks:
        check()
        print(f"PASS {check.__name__}")


if __name__ == "__main__":
    main()
