from __future__ import annotations

from pathlib import Path

from vulnwatch.models import Advisory, ProductRegistry, SourceRegistry
from vulnwatch.storage.filesystem import write_json


def export_schemas(root: Path = Path("schemas")) -> None:
    root.mkdir(parents=True, exist_ok=True)
    write_json(root / "advisory.schema.json", Advisory.model_json_schema())
    write_json(root / "sources.schema.json", SourceRegistry.model_json_schema())
    write_json(root / "products.schema.json", ProductRegistry.model_json_schema())
