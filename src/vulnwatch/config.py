from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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

_CATALOG_RUNTIME_KEYS = {
    "enabled",
    "collector",
    "parser",
    "content_types",
    "max_items",
    "max_detail_fetches",
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
    catalog_runtime = payload.pop("catalog_runtime", {}) or {}
    if not isinstance(catalog_runtime, dict):
        raise ConfigError("catalog_runtime must contain a mapping")
    unknown_runtime_keys = set(catalog_runtime) - _CATALOG_RUNTIME_KEYS
    if unknown_runtime_keys:
        raise ConfigError(
            f"catalog_runtime contains unsupported keys: {sorted(unknown_runtime_keys)}"
        )
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
        if catalog_runtime.get("enabled") and "enabled" not in source:
            _apply_catalog_runtime(source, catalog_runtime)
    try:
        return SourceRegistry.model_validate(payload)
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc


def _apply_catalog_runtime(source: dict[str, Any], defaults: dict[str, Any]) -> None:
    """Turn a catalog-only source into a bounded official-web collection source."""

    source["enabled"] = True
    source.setdefault("collector", defaults.get("collector", "html"))
    source.setdefault("url", source["advisory_url"])
    source.setdefault("parser", defaults.get("parser", "generic"))
    source.setdefault(
        "content_types",
        defaults.get(
            "content_types",
            [
                "text/html",
                "application/xhtml+xml",
                "application/json",
                "application/xml",
                "application/rss+xml",
                "application/atom+xml",
                "text/xml",
            ],
        ),
    )
    source.setdefault("max_items", defaults.get("max_items", 500))
    source.setdefault("max_detail_fetches", defaults.get("max_detail_fetches", 10))
    if not source.get("allowed_hosts"):
        candidates = [
            source.get("advisory_url"),
            source.get("url"),
            *source.get("feed_urls", []),
        ]
        source["allowed_hosts"] = sorted(
            {
                hostname.casefold()
                for candidate in candidates
                if candidate and (hostname := urlsplit(str(candidate)).hostname)
            }
        )


def load_products(path: Path = Path("config/products.yaml")) -> ProductRegistry:
    try:
        return ProductRegistry.model_validate(_load_yaml(path))
    except ValidationError as exc:
        raise ConfigError(str(exc)) from exc
