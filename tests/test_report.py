from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from vulnwatch.models import (
    Advisory,
    AdvisoryFacts,
    ChangeRecord,
    ChangeStatus,
    Priority,
    RunManifest,
    Tier,
)
from vulnwatch.report import generate_report


def _write_report_input(tmp_path: Path, advisories: list[Advisory]) -> None:
    changes: list[ChangeRecord] = []
    for index, advisory in enumerate(advisories):
        advisory_path = Path(
            f"data/vendors/example/advisories/2026/example-{index}/advisory.json"
        )
        output_path = tmp_path / advisory_path
        output_path.parent.mkdir(parents=True)
        output_path.write_text(advisory.model_dump_json(), encoding="utf-8")
        changes.append(
            ChangeRecord(
                canonical_id=advisory.canonical_id,
                source_id=advisory.source_id,
                status=ChangeStatus.NEW,
                priority=Priority.INFO,
                path=str(advisory_path),
            )
        )
    manifest = RunManifest(
        started_at=datetime(2026, 7, 17, tzinfo=UTC),
        profile=Tier.DAILY,
        since=datetime(2026, 4, 18, tzinfo=UTC),
        changes=changes,
    )
    (tmp_path / "run-manifest.json").write_text(manifest.model_dump_json(), encoding="utf-8")


def test_generate_report_adds_matrix_and_orders_by_severity(
    tmp_path: Path, advisory_factory
) -> None:
    advisories = [
        advisory_factory(
            canonical_id="example:moderate",
            title="Moderate advisory",
            facts=AdvisoryFacts(cves=["CVE-2026-10003"], cvss_score=5.5),
        ),
        advisory_factory(
            canonical_id="example:other",
            title="Other advisory",
            facts=AdvisoryFacts(),
        ),
        advisory_factory(
            canonical_id="example:critical",
            title="Critical advisory",
            facts=AdvisoryFacts(
                cves=["CVE-2026-10001"],
                cvss_score=9.8,
                known_exploited=True,
                poc_public=True,
            ),
        ),
        advisory_factory(
            canonical_id="example:high",
            title="High advisory",
            facts=AdvisoryFacts(cves=["CVE-2026-10002"], cvss_score=8.1),
        ),
    ]
    _write_report_input(tmp_path, advisories)

    report = generate_report(tmp_path).read_text(encoding="utf-8")

    assert "## サマリ" in report
    assert "`総数(悪用済み, PoC公開済み)`" in report
    assert "| Example | 1(1,1) | 1(0,0) | 1(0,0) | 1(0,0) | 4(1,1) |" in report
    assert "| 危険度 | 優先度 | 状態 | ベンダー | CVE | CVSS（最大） | 悪用状況 |" in report
    assert "悪用済み<br>PoC公開済み" in report
    assert report.index("| Critical | INFO |") < report.index("| High | INFO |")
    assert report.index("| High | INFO |") < report.index("| Moderate | INFO |")
    assert report.index("| Moderate | INFO |") < report.index("| その他 | INFO |")


def test_generate_report_marks_missing_values_as_unconfirmed(
    tmp_path: Path, advisory_factory
) -> None:
    advisory = advisory_factory(facts=AdvisoryFacts())
    _write_report_input(tmp_path, [advisory])

    report = generate_report(tmp_path).read_text(encoding="utf-8")

    assert "| その他 | INFO | new | Example | - | - | 確認なし |" in report
