from __future__ import annotations

import json
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

from vulnwatch.identity import slugify
from vulnwatch.models import Advisory, SourceState

PUBLISHED_DIRECTORIES = ("data", "reports", "state", "quarantine")
PUBLISHED_FILES = ("run-manifest.json", "run-summary.md")
REQUIRED_PUBLISHED_DIRECTORIES = ("data/vendors", "reports/daily", "state/sources")


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


def _remove_path(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def publish_tree(source_root: Path, repository_root: Path) -> int:
    """Mirror a validated staging tree into the Git-managed artifact paths."""

    source_root = source_root.resolve()
    repository_root = repository_root.resolve()
    if source_root == repository_root:
        raise ValueError("publish source must not be the repository root")

    destinations = [repository_root / name for name in PUBLISHED_DIRECTORIES]
    if any(
        source_root == path or source_root.is_relative_to(path) or path.is_relative_to(source_root)
        for path in destinations
    ):
        raise ValueError("publish source and destination artifact directories must not overlap")

    missing = [name for name in REQUIRED_PUBLISHED_DIRECTORIES if not (source_root / name).is_dir()]
    missing.extend(name for name in PUBLISHED_FILES if not (source_root / name).is_file())
    if (source_root / "quarantine").exists() and not (source_root / "quarantine").is_dir():
        missing.append("quarantine/")
    if missing:
        raise FileNotFoundError(f"publish tree is incomplete: {', '.join(missing)}")

    source_paths = [source_root / name for name in (*PUBLISHED_DIRECTORIES, *PUBLISHED_FILES)]
    if any(
        path.is_symlink()
        for source in source_paths
        if source.exists()
        for path in [source, *source.rglob("*")]
    ):
        raise ValueError("publish tree must not contain symbolic links")

    published_files = sum(
        path.is_file()
        for source in source_paths
        if source.exists()
        for path in ([source] if source.is_file() else source.rglob("*"))
    )

    transaction_root = Path(tempfile.mkdtemp(prefix=".vulnwatch-publish-", dir=repository_root))
    prepared_root = transaction_root / "prepared"
    backup_root = transaction_root / "backup"
    published_names: list[str] = []
    backed_up_names: set[str] = set()
    try:
        for name in PUBLISHED_DIRECTORIES:
            source = source_root / name
            prepared = prepared_root / name
            if source.exists():
                shutil.copytree(source, prepared)
            elif name == "quarantine":
                prepared.mkdir(parents=True)
                (prepared / ".gitkeep").touch()
        for name in PUBLISHED_FILES:
            prepared = prepared_root / name
            prepared.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source_root / name, prepared)

        backup_root.mkdir()
        for name in (*PUBLISHED_DIRECTORIES, *PUBLISHED_FILES):
            destination = repository_root / name
            backup = backup_root / name
            prepared = prepared_root / name
            backup.parent.mkdir(parents=True, exist_ok=True)
            if destination.exists() or destination.is_symlink():
                os.replace(destination, backup)
                backed_up_names.add(name)
            try:
                os.replace(prepared, destination)
            except Exception:
                if name in backed_up_names:
                    os.replace(backup, destination)
                    backed_up_names.remove(name)
                raise
            published_names.append(name)
    except Exception:
        for name in reversed(published_names):
            destination = repository_root / name
            _remove_path(destination)
            if name in backed_up_names:
                os.replace(backup_root / name, destination)
        raise
    finally:
        shutil.rmtree(transaction_root, ignore_errors=True)

    return published_files


class FileSystemStorage:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._advisory_cache: dict[str, tuple[Path, Advisory]] | None = None

    def reset_advisory_cache(self) -> None:
        self._advisory_cache = None

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
        if self._advisory_cache is not None:
            self._advisory_cache[advisory.canonical_id] = (path, advisory)
        return path

    def load(self, path: Path) -> Advisory | None:
        if not path.exists():
            return None
        return Advisory.model_validate_json(path.read_text(encoding="utf-8"))

    def find(self, canonical_id: str) -> tuple[Path, Advisory] | None:
        if self._advisory_cache is None:
            self._advisory_cache = {}
            for path in (self.root / "data" / "vendors").glob("*/advisories/*/*/advisory.json"):
                advisory = self.load(path)
                if advisory:
                    self._advisory_cache[advisory.canonical_id] = (path, advisory)
        return self._advisory_cache.get(canonical_id)

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
