from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import ValidationError
from ruamel.yaml import YAML

from vulnwatch.models import ProductRegistry, SourceRegistry

_MACHINE_READABLE_FORMATS = {
    "api",
    "atom",
    "csaf",
    "csv",
    "cvrf",
    "dataset",
    "graphql",
    "json",
    "jvnjs",
    "osv",
    "oval",
    "rss",
    "vex",
    "xml",
}


class ConfigError(ValueError):
    """Raised when a configuration file is invalid."""


def _load_yaml(path: Path) -> dict[str, Any]:
    yaml = YAML(typ="safe")
    yaml.allow_duplicate_keys = False
    try:
        payload = yaml.load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigError(f"failed to load {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ConfigError(f"{path} must contain a mapping")
    return payload


def load_sources(path: Path = Path("config/sources.yaml")) -> SourceRegistry:
    payload = _load_yaml(path)
    payload.pop("feed_status_values", None)
    payload.pop("collection_priority", None)
    payload.pop("monitoring_requirements", None)
    for source in payload.get("sources", []):
        feed = source.pop("feed", {}) or {}
        formats = feed.get("formats", [])
        machine_formats = [item for item in formats if item in _MACHINE_READABLE_FORMATS]
        alternative_channels = [
            *feed.get("alternative_channels", []),
            *[item for item in formats if item not in _MACHINE_READABLE_FORMATS],
        ]
        source.setdefault("feed_status", feed.get("status"))
        source.setdefault("feed_formats", machine_formats)
        source.setdefault("feed_urls", feed.get("urls", []))
        source.setdefault("alternative_channels", alternative_channels)
        source.setdefault("note", feed.get("note"))
    try:
        return SourceRegistry.model_validate(payload)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc


def load_products(path: Path = Path("config/products.yaml")) -> ProductRegistry:
    try:
        return ProductRegistry.model_validate(_load_yaml(path))
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
