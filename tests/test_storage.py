import json
from pathlib import Path

from vulnwatch.storage.filesystem import FileSystemStorage, atomic_write_text


def test_storage_writes_canonical_layout_and_index(tmp_path: Path, advisory_factory) -> None:
    storage = FileSystemStorage(tmp_path)
    advisory = advisory_factory()

    path = storage.write(advisory)
    storage.rebuild_indexes()

    assert path == (tmp_path / "data/vendors/example/advisories/2026/adv-1/advisory.json")
    assert storage.load(path) == advisory
    index = json.loads((tmp_path / "data/vendors/example/index.json").read_text())
    assert index["advisories"][0]["canonical_id"] == advisory.canonical_id


def test_atomic_write_replaces_existing_file(tmp_path: Path) -> None:
    path = tmp_path / "nested/value.txt"
    atomic_write_text(path, "first")
    atomic_write_text(path, "second")

    assert path.read_text() == "second"
    assert list(path.parent.glob(f".{path.name}.*")) == []
