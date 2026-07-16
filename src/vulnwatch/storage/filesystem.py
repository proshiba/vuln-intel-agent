from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from vulnwatch.identity import slugify
from vulnwatch.models import Advisory, SourceState


def atomic_write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        delete=False,
    ) as handle:
        handle.write(content)
        handle.flush()
        os.fsync(handle.fileno())
        temporary = Path(handle.name)
    os.replace(temporary, path)


def write_json(path: Path, payload: Any) -> None:
    atomic_write_text(
        path,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    )


class FileSystemStorage:
    def __init__(self, root: Path) -> None:
        self.root = root

    @staticmethod
    def prepare_staging(repository_root: Path, output_root: Path) -> None:
        repository_root = repository_root.resolve()
        output_root = output_root.resolve()
        if output_root == repository_root:
            raise ValueError("output root must not be the repository root")
        output_root.mkdir(parents=True, exist_ok=True)
        for name in ("data", "state", "reports", "quarantine"):
            target = output_root / name
            if target.exists():
                shutil.rmtree(target)
            source = repository_root / name
            if source.exists():
                shutil.copytree(source, target)
        for filename in ("run-manifest.json", "run-summary.md"):
            path = output_root / filename
            if path.exists():
                path.unlink()

    def advisory_path(self, advisory: Advisory) -> Path:
        vendor = slugify(advisory.vendor)
        local_id = advisory.canonical_id.split(":", 1)[-1]
        year_source = advisory.published_at or advisory.updated_at or advisory.first_seen_at
        return (
            self.root
            / "data"
            / "vendors"
            / vendor
            / "advisories"
            / str(year_source.year)
            / slugify(local_id)
            / "advisory.json"
        )

    def write(self, advisory: Advisory) -> Path:
        path = self.advisory_path(advisory)
        write_json(path, advisory.model_dump(mode="json", exclude_none=True))
        return path

    def load(self, path: Path) -> Advisory | None:
        if not path.exists():
            return None
        return Advisory.model_validate_json(path.read_text(encoding="utf-8"))

    def find(self, canonical_id: str) -> tuple[Path, Advisory] | None:
        for path in (self.root / "data" / "vendors").glob("*/advisories/*/*/advisory.json"):
            advisory = self.load(path)
            if advisory and advisory.canonical_id == canonical_id:
                return path, advisory
        return None

    def state_path(self, source_id: str) -> Path:
        return self.root / "state" / "sources" / f"{source_id}.json"

    def load_state(self, source_id: str) -> SourceState:
        path = self.state_path(source_id)
        if not path.exists():
            return SourceState(source_id=source_id)
        return SourceState.model_validate_json(path.read_text(encoding="utf-8"))

    def write_state(self, state: SourceState) -> None:
        write_json(self.state_path(state.source_id), state.model_dump(mode="json"))

    def write_quarantine(self, source_id: str, payload: dict[str, Any]) -> Path:
        path = self.root / "quarantine" / source_id / "latest.json"
        write_json(path, payload)
        return path

    def rebuild_indexes(self) -> None:
        base = self.root / "data" / "vendors"
        if not base.exists():
            return
        for vendor_dir in base.iterdir():
            if not vendor_dir.is_dir():
                continue
            entries: list[dict[str, Any]] = []
            for path in vendor_dir.glob("advisories/*/*/advisory.json"):
                advisory = self.load(path)
                if advisory:
                    entries.append(
                        {
                            "canonical_id": advisory.canonical_id,
                            "title": advisory.title,
                            "priority": advisory.decision.priority,
                            "published_at": (
                                advisory.published_at.isoformat() if advisory.published_at else None
                            ),
                            "updated_at": (
                                advisory.updated_at.isoformat() if advisory.updated_at else None
                            ),
                            "path": str(path.relative_to(vendor_dir)),
                        }
                    )
            entries.sort(
                key=lambda item: str(item.get("updated_at") or item.get("published_at") or ""),
                reverse=True,
            )
            write_json(vendor_dir / "index.json", {"schema_version": 1, "advisories": entries})
