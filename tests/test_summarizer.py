from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnwatch.models import AiStatus, ChangeRecord, ChangeStatus, Priority, RunManifest, Tier
from vulnwatch.storage.filesystem import FileSystemStorage, write_json
from vulnwatch.summarizers.openai import summarize_tree
from vulnwatch.summarizers.schema import AiSummary


async def test_summarizer_is_optional_without_credentials(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advisory_factory
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    storage = FileSystemStorage(tmp_path)
    advisory = advisory_factory()
    path = storage.write(advisory)
    manifest = RunManifest(
        started_at=datetime.now(UTC),
        completed_at=datetime.now(UTC),
        profile=Tier.DAILY,
        since=datetime(2026, 4, 1, tzinfo=UTC),
        changes=[
            ChangeRecord(
                canonical_id=advisory.canonical_id,
                source_id=advisory.source_id,
                status=ChangeStatus.NEW,
                priority=Priority.INFO,
                path=str(path.relative_to(tmp_path)),
            )
        ],
    )
    write_json(tmp_path / "run-manifest.json", manifest.model_dump(mode="json"))

    success, skipped = await summarize_tree(tmp_path)

    updated = storage.load(path)
    assert success == 0 and skipped == 1
    assert updated is not None
    assert updated.ai.status == "skipped"
    assert "not configured" in (updated.ai.error or "")


@pytest.mark.parametrize(
    ("failure", "expected_status"),
    [
        (PermissionError("refused"), AiStatus.REFUSED),
        (ValueError("schema violation"), AiStatus.FAILED),
        (TimeoutError("timed out"), AiStatus.FAILED),
    ],
)
async def test_summarizer_records_failure_states(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    advisory_factory,
    failure: Exception,
    expected_status: AiStatus,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "test-model")

    class FakeSummarizer:
        def __init__(self, model: str) -> None:
            self.model = model

        async def summarize(self, advisory):
            raise failure

    monkeypatch.setattr("vulnwatch.summarizers.openai.OpenAiSummarizer", FakeSummarizer)
    storage = FileSystemStorage(tmp_path)
    advisory = advisory_factory()
    path = storage.write(advisory)
    _write_manifest(tmp_path, advisory, path)

    await summarize_tree(tmp_path)

    updated = storage.load(path)
    assert updated is not None and updated.ai.status == expected_status


async def test_successful_summary_is_idempotent_by_input_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advisory_factory
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    calls = 0

    class FakeSummarizer:
        def __init__(self, model: str) -> None:
            self.model = model

        async def summarize(self, advisory):
            nonlocal calls
            calls += 1
            return AiSummary(summary_ja="検証済み要約", evidence_urls=[advisory.source_url])

    monkeypatch.setattr("vulnwatch.summarizers.openai.OpenAiSummarizer", FakeSummarizer)
    storage = FileSystemStorage(tmp_path)
    advisory = advisory_factory()
    path = storage.write(advisory)
    _write_manifest(tmp_path, advisory, path)

    assert await summarize_tree(tmp_path) == (1, 0)
    assert await summarize_tree(tmp_path) == (0, 1)
    assert calls == 1
    assert path.with_name("summary.ja.md").exists()


def _write_manifest(tmp_path: Path, advisory, path: Path) -> None:
    manifest = RunManifest(
        started_at=datetime.now(UTC),
        profile=Tier.DAILY,
        since=datetime(2026, 4, 1, tzinfo=UTC),
        changes=[
            ChangeRecord(
                canonical_id=advisory.canonical_id,
                source_id=advisory.source_id,
                status=ChangeStatus.NEW,
                priority=Priority.INFO,
                path=str(path.relative_to(tmp_path)),
            )
        ],
    )
    write_json(tmp_path / "run-manifest.json", manifest.model_dump(mode="json"))
