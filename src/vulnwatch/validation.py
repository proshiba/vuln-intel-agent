from __future__ import annotations

from pathlib import Path

from vulnwatch.config import load_products, load_sources
from vulnwatch.models import Advisory, RunManifest


def validate_config(
    sources_path: Path = Path("config/sources.yaml"),
    products_path: Path = Path("config/products.yaml"),
) -> tuple[int, int]:
    sources = load_sources(sources_path)
    load_products(products_path)
    enabled = sum(source.enabled for source in sources.sources)
    return len(sources.sources), enabled


def validate_tree(root: Path) -> tuple[int, int]:
    advisories = 0
    for path in (root / "data" / "vendors").glob("*/advisories/*/*/advisory.json"):
        Advisory.model_validate_json(path.read_text(encoding="utf-8"))
        advisories += 1
    manifest_path = root / "run-manifest.json"
    changes = 0
    if manifest_path.exists():
        manifest = RunManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        changes = len(manifest.changes)
    return advisories, changes
