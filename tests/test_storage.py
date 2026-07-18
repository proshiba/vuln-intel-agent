import json
import os
import shutil
from pathlib import Path

import pytest

from vulnwatch.storage.filesystem import FileSystemStorage, atomic_write_text, publish_tree


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


def test_storage_find_reuses_index_and_tracks_new_writes(tmp_path: Path, advisory_factory) -> None:
    storage = FileSystemStorage(tmp_path)
    first = advisory_factory(canonical_id="example:first")
    second = advisory_factory(canonical_id="example:second")
    storage.write(first)

    assert storage.find(first.canonical_id) is not None

    def fail_if_reloaded(path: Path):
        raise AssertionError(f"cache miss unexpectedly reloaded {path}")

    storage.load = fail_if_reloaded  # type: ignore[method-assign]
    assert storage.find(first.canonical_id) is not None
    storage.write(second)
    assert storage.find(second.canonical_id) is not None


def test_publish_tree_mirrors_every_generated_artifact(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    staging = repository / "staging"
    generated = {
        "data/vendors/example/advisories/2026/adv-1/advisory.json": "{}\n",
        "data/vendors/example/advisories/2026/adv-1/summary.ja.md": "要約\n",
        "data/vendors/example/index.json": "{}\n",
        "reports/daily/2026/07/2026-07-18.md": "# report\n",
        "state/sources/example.json": "{}\n",
        "quarantine/example/latest.json": "{}\n",
        "run-manifest.json": "{}\n",
        "run-summary.md": "# summary\n",
    }
    for relative, content in generated.items():
        path = staging / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    stale = repository / "data/vendors/stale/index.json"
    stale.parent.mkdir(parents=True)
    stale.write_text("stale", encoding="utf-8")
    unrelated = repository / "config/sources.yaml"
    unrelated.parent.mkdir(parents=True)
    unrelated.write_text("keep", encoding="utf-8")
    local_history = staging / "history/private-note.md"
    local_history.parent.mkdir()
    local_history.write_text("not an artifact", encoding="utf-8")

    count = publish_tree(staging, repository)

    assert count == len(generated)
    for relative, content in generated.items():
        assert (repository / relative).read_text(encoding="utf-8") == content
    assert not stale.exists()
    assert unrelated.read_text(encoding="utf-8") == "keep"
    assert not (repository / "history").exists()
    assert local_history.exists()


def test_publish_tree_rejects_incomplete_or_overlapping_source(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="must not be the repository root"):
        publish_tree(tmp_path, tmp_path)

    staging = tmp_path / "data/staging"
    staging.mkdir(parents=True)
    with pytest.raises(ValueError, match="must not overlap"):
        publish_tree(staging, tmp_path)

    nested_repository = tmp_path / "source/repository"
    (tmp_path / "source").mkdir(exist_ok=True)
    with pytest.raises(ValueError, match="must not overlap"):
        publish_tree(tmp_path / "source", nested_repository)

    incomplete = tmp_path / "staging"
    incomplete.mkdir()
    with pytest.raises(FileNotFoundError, match="publish tree is incomplete"):
        publish_tree(incomplete, tmp_path)


def test_publish_tree_rejects_symbolic_links(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    staging = repository / "staging"
    for directory in ("data/vendors", "reports/daily", "state/sources"):
        (staging / directory).mkdir(parents=True)
    (staging / "run-manifest.json").write_text("{}", encoding="utf-8")
    (staging / "run-summary.md").write_text("summary", encoding="utf-8")
    target = staging / "outside.txt"
    target.write_text("outside", encoding="utf-8")
    (staging / "data/vendors/link").symlink_to(target)

    with pytest.raises(ValueError, match="symbolic links"):
        publish_tree(staging, repository)


def test_publish_tree_keeps_empty_quarantine_git_visible(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    staging = repository / "staging"
    for directory in ("data/vendors", "reports/daily", "state/sources"):
        (staging / directory).mkdir(parents=True)
    (staging / "run-manifest.json").write_text("{}", encoding="utf-8")
    (staging / "run-summary.md").write_text("summary", encoding="utf-8")

    publish_tree(staging, repository)

    assert (repository / "quarantine/.gitkeep").is_file()


def test_publish_tree_does_not_remove_existing_data_when_preparation_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    staging = repository / "staging"
    generated = {
        "data/vendors/example/index.json": "new data",
        "reports/daily/2026/07/report.md": "new report",
        "state/sources/example.json": "new state",
        "run-manifest.json": "{}",
        "run-summary.md": "new summary",
    }
    for relative, content in generated.items():
        path = staging / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    existing = repository / "data/vendors/example/index.json"
    existing.parent.mkdir(parents=True)
    existing.write_text("existing data", encoding="utf-8")

    def fail_on_copy(source: Path, destination: Path) -> Path:
        raise OSError("simulated copy failure")

    monkeypatch.setattr(shutil, "copytree", fail_on_copy)

    with pytest.raises(OSError, match="simulated copy failure"):
        publish_tree(staging, repository)

    assert existing.read_text(encoding="utf-8") == "existing data"
    assert list(repository.glob(".vulnwatch-publish-*")) == []


def test_publish_tree_restores_every_artifact_when_swap_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "repository"
    staging = repository / "staging"
    generated = {
        "data/vendors/example/index.json": "new data",
        "reports/daily/2026/07/report.md": "new report",
        "state/sources/example.json": "new state",
        "quarantine/example/latest.json": "new quarantine",
        "run-manifest.json": "new manifest",
        "run-summary.md": "new summary",
    }
    existing = {
        "data/vendors/example/index.json": "existing data",
        "reports/daily/2026/07/report.md": "existing report",
        "state/sources/example.json": "existing state",
        "quarantine/example/latest.json": "existing quarantine",
        "run-manifest.json": "existing manifest",
        "run-summary.md": "existing summary",
    }
    for relative, content in generated.items():
        path = staging / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    for relative, content in existing.items():
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    replace = os.replace
    failure_injected = False

    def fail_installing_reports(source: Path, destination: Path) -> None:
        nonlocal failure_injected
        source_path = Path(source)
        destination_path = Path(destination)
        if (
            not failure_injected
            and source_path.name == "reports"
            and source_path.parent.name == "prepared"
            and destination_path == repository / "reports"
        ):
            failure_injected = True
            raise OSError("simulated swap failure")
        replace(source, destination)

    monkeypatch.setattr(os, "replace", fail_installing_reports)

    with pytest.raises(OSError, match="simulated swap failure"):
        publish_tree(staging, repository)

    assert failure_injected
    for relative, content in existing.items():
        assert (repository / relative).read_text(encoding="utf-8") == content
    assert list(repository.glob(".vulnwatch-publish-*")) == []
