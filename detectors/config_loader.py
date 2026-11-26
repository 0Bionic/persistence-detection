"""Loader and resolver for the shared detector path configuration."""

from __future__ import annotations

import json
import os
import string
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:  # Works both as ``detectors.config_loader`` and as a direct script import.
    from .alert_schema import SCHEMA_VERSION, TECHNIQUE_SLUGS
except ImportError:  # pragma: no cover - direct script execution fallback
    from alert_schema import SCHEMA_VERSION, TECHNIQUE_SLUGS


class ConfigError(ValueError):
    """Raised when detectors/config.json is malformed or incomplete."""


@dataclass(frozen=True)
class TechniqueConfig:
    slug: str
    path_templates: tuple[str, ...]
    path_kind: str
    source: str


@dataclass(frozen=True)
class DetectorConfig:
    schema_version: str
    techniques: dict[str, TechniqueConfig]


def _validate_template(template: Any, *, slug: str) -> str:
    if not isinstance(template, str) or not template.strip():
        raise ConfigError(f"{slug}: path templates must be non-empty strings")
    if not template.startswith("/") and not template.startswith("{home}/"):
        raise ConfigError(f"{slug}: path template must be absolute or start with {{home}}/")

    formatter = string.Formatter()
    try:
        fields = [field_name for _, field_name, _, _ in formatter.parse(template) if field_name]
    except ValueError as exc:
        raise ConfigError(f"{slug}: invalid path template {template!r}") from exc
    unknown = set(fields).difference({"home", "user"})
    if unknown:
        raise ConfigError(f"{slug}: unsupported placeholders {sorted(unknown)}")
    return template


def _validate_config(data: Any) -> DetectorConfig:
    if not isinstance(data, dict):
        raise ConfigError("configuration root must be an object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ConfigError(f"configuration schema_version must be {SCHEMA_VERSION!r}")

    entries = data.get("techniques")
    if not isinstance(entries, dict):
        raise ConfigError("techniques must be an object")
    if set(entries) != set(TECHNIQUE_SLUGS):
        raise ConfigError(
            "techniques must contain exactly: " + ", ".join(TECHNIQUE_SLUGS)
        )

    techniques: dict[str, TechniqueConfig] = {}
    for slug in TECHNIQUE_SLUGS:
        entry = entries[slug]
        if not isinstance(entry, dict):
            raise ConfigError(f"{slug}: entry must be an object")
        templates = entry.get("path_templates")
        if not isinstance(templates, list) or not templates:
            raise ConfigError(f"{slug}: path_templates must be a non-empty list")
        validated_templates = tuple(
            _validate_template(template, slug=slug) for template in templates
        )
        path_kind = entry.get("path_kind")
        if path_kind not in {"file", "directory"}:
            raise ConfigError(f"{slug}: path_kind must be 'file' or 'directory'")
        source = entry.get("source")
        if not isinstance(source, str) or not source.strip():
            raise ConfigError(f"{slug}: source must be a non-empty string")
        techniques[slug] = TechniqueConfig(
            slug=slug,
            path_templates=validated_templates,
            path_kind=path_kind,
            source=source,
        )
    return DetectorConfig(schema_version=SCHEMA_VERSION, techniques=techniques)


def load_config(path: str | os.PathLike[str] | None = None) -> DetectorConfig:
    """Read and validate config.json without external packages."""

    config_path = Path(path) if path is not None else Path(__file__).with_name("config.json")
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read configuration {config_path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ConfigError(f"invalid JSON in {config_path}: {exc}") from exc
    return _validate_config(data)


def resolve_paths(
    config: DetectorConfig,
    technique: str,
    *,
    home: str | os.PathLike[str] | None = None,
    user: str | None = None,
) -> tuple[Path, ...]:
    """Resolve one technique's ``{home}`` and ``{user}`` placeholders."""

    if technique not in config.techniques:
        raise ConfigError(f"unknown technique: {technique}")
    home_value = Path(home).expanduser() if home is not None else Path.home()
    home_value = home_value.absolute()
    user_value = user or os.environ.get("USER") or os.environ.get("USERNAME")
    if not user_value:
        raise ConfigError("cannot resolve {user}; pass user explicitly")

    entry = config.techniques[technique]
    return tuple(
        Path(template.format(home=str(home_value), user=user_value)).absolute()
        for template in entry.path_templates
    )


def resolve_all_paths(
    config: DetectorConfig,
    *,
    home: str | os.PathLike[str] | None = None,
    user: str | None = None,
) -> dict[str, tuple[Path, ...]]:
    return {
        slug: resolve_paths(config, slug, home=home, user=user)
        for slug in TECHNIQUE_SLUGS
    }
