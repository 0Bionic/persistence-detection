"""Hand-written offline pipeline checks using only synthetic fixtures."""

from __future__ import annotations

import csv
import tempfile
from pathlib import Path

import compute_metrics
import make_plots
import make_tables
from load_events import AnalysisInputError, load_classifications, load_events, load_resource_csv


FIXTURES = Path(__file__).with_name("fixtures")


def load_fixture_inputs():
    plants, alerts = load_events(FIXTURES / "plants.jsonl", FIXTURES / "alerts.jsonl")
    resources = load_resource_csv(FIXTURES / "resources.csv")
    classifications = load_classifications(FIXTURES / "classifications.jsonl")
    return plants, alerts, resources, classifications


def test_fixture_loading_and_expected_metrics() -> None:
    plants, alerts, resources, classifications = load_fixture_inputs()
    assert len(plants) == 2
    assert len(alerts) == 4
    assert len(resources) == 8
    metrics = compute_metrics.compute_all_metrics(
        plants,
        alerts,
        resources,
        classifications=classifications,
    )

    detection = {
        (row["detector"], row["technique"]): row["detection_rate"]
        for row in metrics["detection_rate"]
    }
    assert detection["baseline_diff", "shell_rc"] == 1.0
    assert detection["baseline_diff", "systemd_user"] == 0.0
    assert detection["inotify", "shell_rc"] == 0.0
    assert detection["inotify", "systemd_user"] == 1.0
    assert detection["auditd", "shell_rc"] == 1.0
    assert detection["auditd", "systemd_user"] == 0.0

    latency = {
        (row["detector"], row["technique"]): row["mean_latency_ms"]
        for row in metrics["latency"]
    }
    assert latency["baseline_diff", "shell_rc"] == 250.0
    assert latency["inotify", "systemd_user"] == 125.0
    assert latency["auditd", "shell_rc"] == 300.0

    false_positive = {
        (row["experiment_id"], row["detector"], row["technique"]): row
        for row in metrics["false_positives"]
    }
    fp_row = false_positive["B", "auditd", "shell_rc"]
    assert fp_row["false_positive_count"] == 1
    assert fp_row["data_status"] == "ok"

    resource = metrics["resource_summary"]
    baseline = next(
        row
        for row in resource
        if row["detector"] == "baseline_diff" and row["phase"] == "idle"
    )
    assert baseline["mean_cpu_percent"] == 2.0
    assert baseline["mean_resident_memory_kb"] == 11000.0
    assert baseline["mean_read_bytes_delta"] == 200.0
    assert baseline["total_write_bytes_delta"] == 150
    assert baseline["data_status"] == "partial"
    assert baseline["missing_measurement_fields"] == 4


def test_malformed_and_missing_inputs_are_clear() -> None:
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        malformed = root / "malformed.jsonl"
        malformed.write_text('{"record_type":"plant"\n', encoding="utf-8")
        try:
            load_events(malformed, FIXTURES / "alerts.jsonl")
        except AnalysisInputError as exc:
            assert "malformed JSON" in str(exc)
            assert ":1:" in str(exc)
        else:
            raise AssertionError("malformed JSON was accepted")

        missing = root / "missing.csv"
        missing.write_text("experiment_id,run_id\nA,B\n", encoding="utf-8")
        try:
            load_resource_csv(missing)
        except AnalysisInputError as exc:
            assert "missing columns" in str(exc)
            assert "sample_time_epoch_ns" in str(exc)
        else:
            raise AssertionError("missing CSV columns were accepted")

        try:
            load_events(root / "does-not-exist.jsonl", FIXTURES / "alerts.jsonl")
        except AnalysisInputError as exc:
            assert "does not exist" in str(exc)
        else:
            raise AssertionError("missing JSONL input was accepted")


def test_tables_are_reproducible_and_evasion_is_not_fabricated() -> None:
    plants, alerts, resources, classifications = load_fixture_inputs()
    metrics = compute_metrics.compute_all_metrics(
        plants,
        alerts,
        resources,
        classifications=classifications,
    )
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        table_dir = root / "tables"
        plot_dir = root / "plots"
        paths = make_tables.write_metric_tables(metrics, table_dir)
        assert {path.name for path in paths} == {
            "detection_rate.csv",
            "latency.csv",
            "false_positives.csv",
            "resource_summary.csv",
            "evasion.csv",
        }
        with (table_dir / "detection_rate.csv").open(newline="", encoding="utf-8") as stream:
            table_rows = list(csv.DictReader(stream))
        assert table_rows[0]["detector"] == "auditd"

        generated, messages = make_plots.generate_plots(table_dir, plot_dir)
        assert {path.name for path in generated} == {
            "detection-rate.svg",
            "latency.svg",
            "false-positive.svg",
            "resource-cost.svg",
        }
        assert not (plot_dir / "evasion.svg").exists()
        assert any("evasion plot cannot be generated" in message for message in messages)


def main() -> None:
    checks = [
        test_fixture_loading_and_expected_metrics,
        test_malformed_and_missing_inputs_are_clear,
        test_tables_are_reproducible_and_evasion_is_not_fabricated,
    ]
    for check in checks:
        check()
        print(f"PASS {check.__name__}")


if __name__ == "__main__":
    main()
