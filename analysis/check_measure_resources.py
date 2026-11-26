"""Hand-written checks for measure_resources.py using a fake /proc tree."""

from __future__ import annotations

import csv
import io
import tempfile
from pathlib import Path

import measure_resources


def write_fake_process(
    root: Path,
    pid: int,
    *,
    user_ticks: int,
    system_ticks: int,
    start_time_ticks: int = 100,
    rss_kb: int,
    read_bytes: int,
    write_bytes: int,
) -> None:
    process = root / str(pid)
    process.mkdir(parents=True, exist_ok=True)
    after_comm = (
        ["S"]
        + ["0"] * 10
        + [str(user_ticks), str(system_ticks)]
        + ["0"] * 6
        + [str(start_time_ticks)]
    )
    (process / "stat").write_text(
        f"{pid} (fake detector) " + " ".join(after_comm) + "\n",
        encoding="utf-8",
    )
    (process / "status").write_text(
        f"Name:\tfake\nVmRSS:\t{rss_kb} kB\n",
        encoding="utf-8",
    )
    (process / "io").write_text(
        f"read_bytes: {read_bytes}\nwrite_bytes: {write_bytes}\n",
        encoding="utf-8",
    )


def test_fake_proc_sampling_and_deltas() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        write_fake_process(
            root,
            101,
            user_ticks=100,
            system_ticks=50,
            rss_kb=2048,
            read_bytes=4096,
            write_bytes=8192,
        )
        write_fake_process(
            root,
            202,
            user_ticks=10,
            system_ticks=5,
            rss_kb=1024,
            read_bytes=100,
            write_bytes=200,
        )
        sampler = measure_resources.ProcResourceSampler(
            [101, 202],
            proc_root=root,
            ticks_per_second=100,
        )
        first = sampler.sample_once(sample_time_epoch_ns=1_700_000_000_000_000_000, monotonic_time=0.0)
        assert [row["pid"] for row in first] == [101, 202]
        assert all(row["read_bytes_delta"] is None for row in first)
        assert all(row["write_bytes_delta"] is None for row in first)

        write_fake_process(
            root,
            101,
            user_ticks=120,
            system_ticks=70,
            rss_kb=3072,
            read_bytes=8192,
            write_bytes=12288,
        )
        write_fake_process(
            root,
            202,
            user_ticks=15,
            system_ticks=10,
            rss_kb=1536,
            read_bytes=300,
            write_bytes=500,
        )
        second = sampler.sample_once(
            sample_time_epoch_ns=1_700_000_001_000_000_000,
            monotonic_time=1.0,
        )
        assert second[0]["cpu_percent"] == 40.0
        assert second[0]["resident_memory_kb"] == 3072
        assert second[0]["read_bytes_delta"] == 4096
        assert second[0]["write_bytes_delta"] == 4096
        assert second[1]["read_bytes_delta"] == 200
        assert second[1]["write_bytes_delta"] == 300
        assert second[0]["sample_time_epoch_ns"] == 1_700_000_001_000_000_000


def test_missing_io_is_not_zero_and_process_exit_is_clear() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        write_fake_process(
            root,
            303,
            user_ticks=1,
            system_ticks=1,
            rss_kb=512,
            read_bytes=10,
            write_bytes=20,
        )
        sampler = measure_resources.ProcResourceSampler(
            [303], proc_root=root, ticks_per_second=100
        )
        sampler.sample_once(sample_time_epoch_ns=1, monotonic_time=0.0)
        (root / "303" / "io").unlink()
        inaccessible = sampler.sample_once(sample_time_epoch_ns=2, monotonic_time=1.0)[0]
        assert inaccessible["sample_status"] == "inaccessible"
        assert inaccessible["read_bytes_delta"] is None
        assert inaccessible["write_bytes_delta"] is None
        assert "io" in str(inaccessible["error"])

        for child in (root / "303").iterdir():
            child.unlink()
        (root / "303").rmdir()
        exited = sampler.sample_once(sample_time_epoch_ns=3, monotonic_time=2.0)[0]
        assert exited["sample_status"] == "exited"
        assert exited["cpu_time_jiffies"] is None
        assert exited["resident_memory_kb"] is None
        assert exited["read_bytes_delta"] is None
        assert "no longer present" in str(exited["error"])


def test_pid_reuse_starts_a_fresh_baseline() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        write_fake_process(
            root,
            404,
            user_ticks=100,
            system_ticks=50,
            start_time_ticks=111,
            rss_kb=2048,
            read_bytes=1000,
            write_bytes=2000,
        )
        sampler = measure_resources.ProcResourceSampler(
            [404], proc_root=root, ticks_per_second=100
        )
        sampler.sample_once(sample_time_epoch_ns=10, monotonic_time=0.0)

        write_fake_process(
            root,
            404,
            user_ticks=200,
            system_ticks=100,
            start_time_ticks=222,
            rss_kb=4096,
            read_bytes=9000,
            write_bytes=12000,
        )
        reused = sampler.sample_once(sample_time_epoch_ns=20, monotonic_time=1.0)[0]
        assert reused["sample_status"] == "new_process_baseline"
        assert reused["cpu_percent"] is None
        assert reused["read_bytes_delta"] is None
        assert reused["write_bytes_delta"] is None
        assert "start time changed" in str(reused["error"])

        write_fake_process(
            root,
            404,
            user_ticks=210,
            system_ticks=105,
            start_time_ticks=222,
            rss_kb=4096,
            read_bytes=9100,
            write_bytes=12100,
        )
        next_sample = sampler.sample_once(sample_time_epoch_ns=30, monotonic_time=2.0)[0]
        assert next_sample["cpu_percent"] == 15.0
        assert next_sample["read_bytes_delta"] == 100
        assert next_sample["write_bytes_delta"] == 100


def test_csv_keeps_metadata_and_per_process_rows() -> None:
    rows = [
        {
            "pid": 101,
            "sample_source": "proc",
            "sample_time_epoch_ns": 1,
            "sample_time_utc": "1970-01-01T00:00:00.000000001Z",
            "sample_status": "ok",
            "cpu_percent": 1.5,
            "cpu_time_jiffies": 3,
            "resident_memory_kb": 4,
            "read_bytes_delta": 5,
            "write_bytes_delta": 6,
            "error": None,
        },
        {
            "pid": 202,
            "sample_source": "proc",
            "sample_time_epoch_ns": 1,
            "sample_time_utc": "1970-01-01T00:00:00.000000001Z",
            "sample_status": "ok",
            "cpu_percent": 2.5,
            "cpu_time_jiffies": 7,
            "resident_memory_kb": 8,
            "read_bytes_delta": None,
            "write_bytes_delta": None,
            "error": "permission denied reading /proc/202/io",
        },
    ]
    output = io.StringIO()
    measure_resources._write_rows(
        output,
        rows,
        experiment_id="experiment",
        run_id="run",
        trial=2,
        detector="auditd",
        phase="active",
    )
    records = list(csv.DictReader(io.StringIO(output.getvalue())))
    assert len(records) == 2
    assert records[0]["run_id"] == "run"
    assert records[0]["pid"] == "101"
    assert records[1]["pid"] == "202"
    assert records[1]["read_bytes_delta"] == ""
    assert "permission denied" in records[1]["error"]


def main() -> None:
    checks = [
        test_fake_proc_sampling_and_deltas,
        test_missing_io_is_not_zero_and_process_exit_is_clear,
        test_pid_reuse_starts_a_fresh_baseline,
        test_csv_keeps_metadata_and_per_process_rows,
    ]
    for check in checks:
        check()
        print(f"PASS {check.__name__}")


if __name__ == "__main__":
    main()
