from __future__ import annotations

import asyncio
import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from vulnwatch.collectors.base import CollectorError
from vulnwatch.models import (
    ChangeStatus,
    CollectionResult,
    Priority,
    RawRecord,
    SourceDefinition,
    SourceState,
    Tier,
)
from vulnwatch.pipeline import Pipeline


def _write_config(root: Path) -> tuple[Path, Path]:
    sources = root / "sources.yaml"
    products = root / "products.yaml"
    sources.write_text(
        """
schema_version: 1
as_of: "2026-07-16"
categories:
  - id: test
    name: Test
sources:
  - id: example
    category: test
    vendor: Example
    products: [Example OS]
    advisory_url: https://security.example.com/advisories
    enabled: true
    role: advisory
    collector: json_api
    url: https://security.example.com/feed.json
    allowed_hosts: [security.example.com]
    tier: daily
    parser: json
    content_types: [application/json]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    products.write_text("schema_version: 1\nproducts: []\n", encoding="utf-8")
    return sources, products


def _publish(repository: Path, staging: Path) -> None:
    for name in ("data", "state", "reports", "quarantine"):
        source = staging / name
        target = repository / name
        if target.exists():
            shutil.rmtree(target)
        if source.exists():
            shutil.copytree(source, target)


@pytest.mark.asyncio
async def test_pipeline_new_unchanged_updated_and_quarantined(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, products = _write_config(tmp_path)
    current = {
        "item": {
            "id": "ADV-1",
            "title": "First title",
            "url": "https://security.example.com/ADV-1",
            "published": "2026-07-01T00:00:00Z",
            "description": "CVE-2026-12345",
        },
        "error": None,
    }

    class FakeCollector:
        async def collect(
            self,
            source: SourceDefinition,
            state: SourceState,
            since: datetime,
        ) -> CollectionResult:
            if current["error"]:
                raise CollectorError(str(current["error"]))
            item = current["item"]
            assert isinstance(item, dict)
            return CollectionResult(
                source_id=source.id,
                records=[
                    RawRecord(
                        source_id=source.id,
                        url=str(item["url"]),
                        content=json.dumps(item),
                        metadata=item,
                    )
                ],
            )

    monkeypatch.setattr("vulnwatch.pipeline.create_collector", lambda kind: FakeCollector())
    since = datetime(2026, 1, 1, tzinfo=UTC)

    first_root = tmp_path / "staging-1"
    first = Pipeline(tmp_path, first_root, sources, products)
    first_manifest = await first.run(Tier.DAILY, since)
    assert [change.status for change in first_manifest.changes] == [ChangeStatus.NEW]
    assert first_manifest.changes[0].priority == Priority.INFO
    _publish(tmp_path, first_root)

    second_root = tmp_path / "staging-2"
    second = Pipeline(tmp_path, second_root, sources, products)
    second_manifest = await second.run(Tier.DAILY, since)
    assert [change.status for change in second_manifest.changes] == [ChangeStatus.UNCHANGED]
    _publish(tmp_path, second_root)

    item = current["item"]
    assert isinstance(item, dict)
    item["title"] = "Updated title"
    third_root = tmp_path / "staging-3"
    third = Pipeline(tmp_path, third_root, sources, products)
    third_manifest = await third.run(Tier.DAILY, since)
    assert [change.status for change in third_manifest.changes] == [ChangeStatus.UPDATED]

    current["error"] = "upstream failed"
    failed_root = tmp_path / "staging-failed"
    failed = Pipeline(tmp_path, failed_root, sources, products)
    failed_manifest = await failed.run(Tier.DAILY, since)
    assert failed_manifest.changes[0].status == ChangeStatus.QUARANTINED
    assert (failed_root / "quarantine/example/latest.json").exists()


@pytest.mark.asyncio
async def test_pipeline_partial_snapshot_preserves_known_ids_and_accepts_empty_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, products = _write_config(tmp_path)
    current: dict[str, object] = {"id": "ADV-1", "complete": True}

    class FakeCollector:
        async def collect(
            self,
            source: SourceDefinition,
            state: SourceState,
            since: datetime,
        ) -> CollectionResult:
            item_id = current["id"]
            records: list[RawRecord] = []
            if item_id is not None:
                item = {
                    "id": item_id,
                    "title": str(item_id),
                    "url": f"https://security.example.com/{item_id}",
                    "published": "2026-07-01T00:00:00Z",
                }
                records.append(
                    RawRecord(
                        source_id=source.id,
                        url=str(item["url"]),
                        content=json.dumps(item),
                        metadata=item,
                    )
                )
            return CollectionResult(
                source_id=source.id,
                records=records,
                complete_snapshot=bool(current["complete"]),
            )

    monkeypatch.setattr("vulnwatch.pipeline.create_collector", lambda kind: FakeCollector())
    since = datetime(2026, 1, 1, tzinfo=UTC)

    first_root = tmp_path / "staging-partial-1"
    first_manifest = await Pipeline(tmp_path, first_root, sources, products).run(Tier.DAILY, since)
    first_id = first_manifest.changes[0].canonical_id
    _publish(tmp_path, first_root)

    current.update(id="ADV-2", complete=False)
    second_root = tmp_path / "staging-partial-2"
    second = Pipeline(tmp_path, second_root, sources, products)
    second_manifest = await second.run(Tier.DAILY, since)
    second_id = second_manifest.changes[0].canonical_id
    second_state = second.storage.load_state("example")

    assert second_id != first_id
    assert second_state.known_ids == sorted([first_id, second_id])
    assert all(change.status != ChangeStatus.WITHDRAWN for change in second_manifest.changes)
    _publish(tmp_path, second_root)

    current.update(id=None, complete=False)
    empty_root = tmp_path / "staging-partial-empty"
    empty = Pipeline(tmp_path, empty_root, sources, products)
    empty_manifest = await empty.run(Tier.DAILY, since)

    assert empty_manifest.changes == []
    assert empty.storage.load_state("example").known_ids == sorted([first_id, second_id])
    assert not (empty_root / "quarantine/example/latest.json").exists()


@pytest.mark.asyncio
async def test_pipeline_collects_independent_sources_concurrently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sources, products = _write_config(tmp_path)
    pipeline = Pipeline(tmp_path, tmp_path / "staging-concurrent", sources, products)
    original = pipeline.sources.sources[0]
    pipeline.sources.sources.append(
        original.model_copy(update={"id": "example_two", "vendor": "Example Two"})
    )
    started: set[str] = set()
    both_started = asyncio.Event()

    class FakeCollector:
        async def collect(
            self,
            source: SourceDefinition,
            state: SourceState,
            since: datetime,
        ) -> CollectionResult:
            started.add(source.id)
            if len(started) == 2:
                both_started.set()
            await both_started.wait()
            item = {
                "id": f"ADV-{source.id}",
                "title": source.id,
                "url": f"https://security.example.com/{source.id}",
                "published": "2026-07-01T00:00:00Z",
            }
            return CollectionResult(
                source_id=source.id,
                records=[
                    RawRecord(
                        source_id=source.id,
                        url=str(item["url"]),
                        content=json.dumps(item),
                        metadata=item,
                    )
                ],
            )

    monkeypatch.setattr("vulnwatch.pipeline.create_collector", lambda kind: FakeCollector())

    manifest = await asyncio.wait_for(
        pipeline.run(Tier.DAILY, datetime(2026, 1, 1, tzinfo=UTC)),
        timeout=2,
    )

    assert started == {"example", "example_two"}
    assert len(manifest.changes) == 2


def test_withdrawal_requires_three_misses_and_24_hours(tmp_path: Path, advisory_factory) -> None:
    sources, products = _write_config(tmp_path)
    pipeline = Pipeline(tmp_path, tmp_path / "staging", sources, products)
    advisory = advisory_factory(canonical_id="example:adv-1", source_id="example", vendor="Example")
    pipeline.storage.write(advisory)
    source = pipeline.sources.sources[0]
    state = SourceState(
        source_id="example",
        known_ids=[advisory.canonical_id],
        missing_counts={advisory.canonical_id: 2},
        first_missing_at={advisory.canonical_id: datetime.now(UTC) - timedelta(hours=25)},
    )
    manifest = __import__("vulnwatch.models", fromlist=["RunManifest"]).RunManifest(
        started_at=datetime.now(UTC), profile=Tier.DAILY, since=datetime.now(UTC)
    )

    pipeline._handle_missing(source, state, [], manifest)

    assert manifest.changes[0].status == ChangeStatus.WITHDRAWN
    stored = pipeline.storage.find(advisory.canonical_id)
    assert stored is not None and stored[1].status == "withdrawn"
