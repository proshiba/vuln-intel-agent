from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnwatch.models import AiStatus, ChangeRecord, ChangeStatus, Priority, RunManifest, Tier
from vulnwatch.report import (
    AGENT_SUMMARY_MODEL,
    ReportSummaryArtifact,
    report_summary_path,
    write_agent_report_summary,
)
from vulnwatch.storage.filesystem import FileSystemStorage, write_json
from vulnwatch.summarizers.openai import summarize_tree
from vulnwatch.summarizers.schema import AiSummary, ReportSectionSummary


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
    artifact = ReportSummaryArtifact.model_validate_json(
        report_summary_path(tmp_path, manifest).read_text(encoding="utf-8")
    )
    assert artifact.status == AiStatus.SKIPPED


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

        async def summarize_report(self, payload):
            raise failure

    monkeypatch.setattr("vulnwatch.summarizers.openai.OpenAiSummarizer", FakeSummarizer)
    storage = FileSystemStorage(tmp_path)
    advisory = advisory_factory()
    path = storage.write(advisory)
    manifest = _write_manifest(tmp_path, advisory, path)

    await summarize_tree(tmp_path)

    updated = storage.load(path)
    assert updated is not None and updated.ai.status == expected_status
    artifact = ReportSummaryArtifact.model_validate_json(
        report_summary_path(tmp_path, manifest).read_text(encoding="utf-8")
    )
    assert artifact.status == expected_status


async def test_successful_summary_is_idempotent_by_input_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advisory_factory
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    advisory_calls = 0
    report_calls = 0

    class FakeSummarizer:
        def __init__(self, model: str) -> None:
            self.model = model

        async def summarize(self, advisory):
            nonlocal advisory_calls
            advisory_calls += 1
            return AiSummary(summary_ja="検証済み要約", evidence_urls=[advisory.source_url])

        async def summarize_report(self, payload):
            nonlocal report_calls
            report_calls += 1
            return ReportSectionSummary(
                critical_summary_ja="CriticalのAIサマリです。全件を確認しています。",
                exploitation_summary_ja="悪用・PoCのAIサマリです。重複も確認しています。",
            )

    monkeypatch.setattr("vulnwatch.summarizers.openai.OpenAiSummarizer", FakeSummarizer)
    storage = FileSystemStorage(tmp_path)
    advisory = advisory_factory()
    path = storage.write(advisory)
    manifest = _write_manifest(tmp_path, advisory, path)

    assert await summarize_tree(tmp_path) == (1, 0)
    assert await summarize_tree(tmp_path) == (0, 1)
    assert advisory_calls == 1
    assert report_calls == 1
    assert path.with_name("summary.ja.md").exists()
    artifact = ReportSummaryArtifact.model_validate_json(
        report_summary_path(tmp_path, manifest).read_text(encoding="utf-8")
    )
    assert artifact.status == AiStatus.SUCCESS
    assert artifact.critical_summary_ja == "CriticalのAIサマリです。全件を確認しています。"


async def test_agent_report_summary_is_not_overwritten_by_automatic_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advisory_factory
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("LLM_MODEL", "test-model")
    report_calls = 0

    class FakeSummarizer:
        def __init__(self, model: str) -> None:
            self.model = model

        async def summarize(self, advisory):
            return AiSummary(summary_ja="検証済み要約", evidence_urls=[advisory.source_url])

        async def summarize_report(self, payload):
            nonlocal report_calls
            report_calls += 1
            raise AssertionError("agent summary must take precedence")

    monkeypatch.setattr("vulnwatch.summarizers.openai.OpenAiSummarizer", FakeSummarizer)
    storage = FileSystemStorage(tmp_path)
    advisory = advisory_factory()
    path = storage.write(advisory)
    manifest = _write_manifest(tmp_path, advisory, path)
    write_agent_report_summary(
        tmp_path,
        "Criticalの手動AIサマリです。全件を確認しています。",
        "悪用・PoCの手動AIサマリです。重複も確認しています。",
    )

    await summarize_tree(tmp_path)

    artifact = ReportSummaryArtifact.model_validate_json(
        report_summary_path(tmp_path, manifest).read_text(encoding="utf-8")
    )
    assert report_calls == 0
    assert artifact.model == AGENT_SUMMARY_MODEL


def test_report_section_summary_rejects_non_japanese_or_markdown() -> None:
    invalid_values = (
        "only English. still English.",
        "一文だけです。",
        "<script>は禁止です。二文目もあります。",
    )
    for value in invalid_values:
        with pytest.raises(ValueError, match="2-4 non-placeholder Japanese sentences"):
            ReportSectionSummary(
                critical_summary_ja=value,
                exploitation_summary_ja="悪用状況のサマリです。重複も確認しています。",
            )


async def test_summarizer_rejects_advisory_path_outside_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, advisory_factory
) -> None:
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("LLM_MODEL", raising=False)
    storage = FileSystemStorage(tmp_path)
    advisory = advisory_factory()
    path = storage.write(advisory)
    manifest = _write_manifest(tmp_path, advisory, path)
    manifest.changes[0].path = "../outside/advisory.json"
    write_json(tmp_path / "run-manifest.json", manifest.model_dump(mode="json"))

    with pytest.raises(ValueError, match="invalid report advisory path"):
        await summarize_tree(tmp_path)


def _write_manifest(tmp_path: Path, advisory, path: Path) -> RunManifest:
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
    return manifest
