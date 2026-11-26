"""Generate dependency-free SVG plots from the offline metric tables."""

from __future__ import annotations

import argparse
import csv
import html
import sys
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


class PlotUnavailable(RuntimeError):
    """Raised when a table has no valid observations for a requested plot."""


def _read_table(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        raise PlotUnavailable(f"missing table: {path}")
    with path.open("r", newline="", encoding="utf-8") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames is None:
            raise PlotUnavailable(f"table has no header: {path}")
        return [dict(row) for row in reader]


def _number(value: str | None) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _label(row: Mapping[str, str], fields: Sequence[str]) -> str:
    return " / ".join(row.get(field, "") for field in fields)


def _svg_text(value: str) -> str:
    return html.escape(value, quote=True)


def _svg_header(title: str, width: int, height: int) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">',
        '<style>text{font-family:Arial,sans-serif;fill:#202124} '
        '.axis{stroke:#6b7280;stroke-width:1} .grid{stroke:#d1d5db;stroke-width:1} '
        '.bar{fill:#2563eb} .note{fill:#6b7280;font-size:12px}</style>',
        f'<text x="{width / 2:.1f}" y="28" text-anchor="middle" font-size="18" '
        f'font-weight="bold">{_svg_text(title)}</text>',
    ]


def _finish_svg(lines: Iterable[str]) -> str:
    return "\n".join([*lines, "</svg>", ""])


def _bar_chart_svg(
    rows: Sequence[Mapping[str, str]],
    *,
    title: str,
    value_field: str,
    label_fields: Sequence[str],
    output: Path,
    y_max: float | None = None,
    value_suffix: str = "",
) -> Path:
    values = [(_label(row, label_fields), _number(row.get(value_field))) for row in rows]
    values = [(label, value) for label, value in values if value is not None]
    if not values:
        raise PlotUnavailable(f"{title} cannot be generated: no valid {value_field} values")

    width, height = 1000, 560
    left, right, top, bottom = 80, 30, 60, 130
    plot_width = width - left - right
    plot_height = height - top - bottom
    maximum = y_max if y_max is not None else max(value for _, value in values)
    if maximum <= 0:
        maximum = 1.0
    lines = _svg_header(title, width, height)
    for tick in range(6):
        value = maximum * tick / 5
        y = top + plot_height - plot_height * value / maximum
        lines.append(f'<line class="grid" x1="{left}" x2="{width - right}" y1="{y:.1f}" y2="{y:.1f}"/>')
        lines.append(
            f'<text x="{left - 10}" y="{y + 4:.1f}" text-anchor="end" font-size="11">'
            f'{value:.2f}{_svg_text(value_suffix)}</text>'
        )
    lines.append(f'<line class="axis" x1="{left}" x2="{left}" y1="{top}" y2="{top + plot_height}"/>')
    lines.append(f'<line class="axis" x1="{left}" x2="{width - right}" y1="{top + plot_height}" y2="{top + plot_height}"/>')
    bar_width = plot_width / max(len(values), 1) * 0.68
    slot = plot_width / max(len(values), 1)
    for index, (label, value) in enumerate(values):
        x = left + slot * index + (slot - bar_width) / 2
        bar_height = plot_height * value / maximum
        y = top + plot_height - bar_height
        lines.append(f'<rect class="bar" x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}"/>')
        lines.append(
            f'<text x="{x + bar_width / 2:.1f}" y="{y - 6:.1f}" text-anchor="middle" font-size="11">'
            f'{value:.2f}{_svg_text(value_suffix)}</text>'
        )
        lines.append(
            f'<text x="{x + bar_width / 2:.1f}" y="{top + plot_height + 18:.1f}" '
            f'text-anchor="end" transform="rotate(-45 {x + bar_width / 2:.1f} {top + plot_height + 18:.1f})" '
            f'font-size="11">{_svg_text(label)}</text>'
        )
    missing = len(rows) - len(values)
    if missing:
        lines.append(
            f'<text class="note" x="{left}" y="{height - 12}">{missing} row(s) with missing values excluded; no zero imputation.</text>'
        )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_finish_svg(lines), encoding="utf-8")
    return output


def _resource_svg(rows: Sequence[Mapping[str, str]], output: Path) -> Path:
    if not rows:
        raise PlotUnavailable("resource-cost plot cannot be generated: resource table is empty")
    metrics = (
        ("mean_cpu_percent", "Mean CPU (%)"),
        ("mean_resident_memory_kb", "Mean resident memory (KiB)"),
        ("mean_read_bytes_delta", "Mean read bytes/sample"),
        ("mean_write_bytes_delta", "Mean write bytes/sample"),
    )
    width, height = 1100, 760
    lines = _svg_header("Resource cost by detector and phase", width, height)
    panel_width, panel_height = 500, 320
    for index, (field, title) in enumerate(metrics):
        panel_x = 35 + (index % 2) * 530
        panel_y = 55 + (index // 2) * 350
        values = [
            (_label(row, ("detector", "phase")), _number(row.get(field)))
            for row in rows
        ]
        values = [(label, value) for label, value in values if value is not None]
        if not values:
            lines.append(
                f'<text class="note" x="{panel_x}" y="{panel_y + 30}">'
                f'{_svg_text(title)}: no valid values</text>'
            )
            continue
        left, right, top, bottom = panel_x + 50, panel_x + 15, panel_y + 45, panel_y + 100
        plot_width = panel_width - 65
        plot_height = panel_height - 145
        maximum = max(value for _, value in values) or 1.0
        lines.append(f'<text x="{panel_x + panel_width / 2:.1f}" y="{panel_y + 25}" text-anchor="middle" font-size="14" font-weight="bold">{_svg_text(title)}</text>')
        lines.append(f'<line class="axis" x1="{left}" x2="{left}" y1="{top}" y2="{top + plot_height}"/>')
        lines.append(f'<line class="axis" x1="{left}" x2="{left + plot_width}" y1="{top + plot_height}" y2="{top + plot_height}"/>')
        slot = plot_width / len(values)
        bar_width = slot * 0.65
        for bar_index, (label, value) in enumerate(values):
            x = left + bar_index * slot + (slot - bar_width) / 2
            bar_height = plot_height * value / maximum
            y = top + plot_height - bar_height
            lines.append(f'<rect class="bar" x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}"/>')
            lines.append(f'<text x="{x + bar_width / 2:.1f}" y="{y - 5:.1f}" text-anchor="middle" font-size="10">{value:.2f}</text>')
            lines.append(f'<text x="{x + bar_width / 2:.1f}" y="{top + plot_height + 16:.1f}" text-anchor="end" transform="rotate(-45 {x + bar_width / 2:.1f} {top + plot_height + 16:.1f})" font-size="10">{_svg_text(label)}</text>')
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(_finish_svg(lines), encoding="utf-8")
    return output


def generate_plots(table_dir: str | Path, output_dir: str | Path) -> tuple[list[Path], list[str]]:
    """Generate available plots and return paths plus explicit skip messages."""

    tables = Path(table_dir)
    output = Path(output_dir)
    generated: list[Path] = []
    messages: list[str] = []
    requests = (
        ("detection_rate.csv", "detection-rate.svg", "Detection rate", "detection_rate", ("detector", "technique"), 1.0, ""),
        ("latency.csv", "latency.svg", "Alert latency", "mean_latency_ms", ("detector", "technique"), None, " ms"),
        ("false_positives.csv", "false-positive.svg", "False-positive count", "false_positive_count", ("detector", "technique"), None, ""),
    )
    for table_name, plot_name, title, field, labels, maximum, suffix in requests:
        try:
            rows = _read_table(tables / table_name)
            generated.append(
                _bar_chart_svg(
                    rows,
                    title=title,
                    value_field=field,
                    label_fields=labels,
                    output=output / plot_name,
                    y_max=maximum,
                    value_suffix=suffix,
                )
            )
        except PlotUnavailable as exc:
            messages.append(str(exc))
    try:
        generated.append(_resource_svg(_read_table(tables / "resource_summary.csv"), output / "resource-cost.svg"))
    except PlotUnavailable as exc:
        messages.append(str(exc))

    try:
        evasion_path = tables / "evasion.csv"
        if not evasion_path.exists():
            raise PlotUnavailable(
                "evasion plot cannot be generated: no evasion labels/data were supplied"
            )
        evasion_rows = _read_table(evasion_path)
        if not evasion_rows:
            raise PlotUnavailable(
                "evasion plot cannot be generated: no evasion labels/data were supplied"
            )
        generated.append(
            _bar_chart_svg(
                evasion_rows,
                title="Evasion detection rate",
                value_field="evasion_detection_rate",
                label_fields=("detector", "technique", "evasion_label"),
                output=output / "evasion.svg",
                y_max=1.0,
            )
        )
    except PlotUnavailable as exc:
        messages.append(str(exc))
    return generated, messages


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tables-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        generated, messages = generate_plots(args.tables_dir, args.output_dir)
    except OSError as exc:
        print(f"[plots] error: {exc}", file=sys.stderr)
        return 2
    for path in generated:
        print(path)
    for message in messages:
        print(f"[plots] {message}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
