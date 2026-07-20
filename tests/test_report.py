from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnwatch.models import (
    Advisory,
    AdvisoryFacts,
    ChangeRecord,
    ChangeStatus,
    Priority,
    RunManifest,
    Tier,
)
from vulnwatch.report import generate_report, write_agent_report_summary
from vulnwatch.validation import validate_tree


def _write_report_input(tmp_path: Path, advisories: list[Advisory]) -> None:
    changes: list[ChangeRecord] = []
    for index, advisory in enumerate(advisories):
        advisory_path = Path(f"data/vendors/example/advisories/2026/example-{index}/advisory.json")
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
    # Report-focused tests intentionally exercise the legacy manifest path. Source
    # outcome validation has dedicated coverage below.
    (tmp_path / "run-manifest.json").write_text(
        manifest.model_dump_json(exclude={"source_outcomes"}), encoding="utf-8"
    )


def test_generate_report_adds_matrix_and_orders_by_risk(tmp_path: Path, advisory_factory) -> None:
    advisories = [
        advisory_factory(
            canonical_id="example:moderate",
            title="Moderate advisory",
            facts=AdvisoryFacts(cves=["CVE-2026-10003"], cvss_score=5.5, known_exploited=True),
        ),
        advisory_factory(
            canonical_id="example:other",
            title="Other advisory",
            facts=AdvisoryFacts(poc_public=True),
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
    write_agent_report_summary(
        tmp_path,
        "Critical節の検証済みAIサマリです。対象件数を確認しています。",
        "悪用済み・PoC公開済み節の検証済みAIサマリです。重複も確認しています。",
    )

    report = generate_report(tmp_path).read_text(encoding="utf-8")

    assert "## サマリ" in report
    assert "リスク評価: 緊急 1件 / 高 1件 / 中 2件 / 低 0件" in report
    assert (
        "| ベンダー | Critical | High | Moderate | その他 | 合計 | 悪用済み | PoC公開済み |"
        in report
    )
    assert "| Example | 1 | 1 | 1 | 1 | 4 | 2 | 2 |" in report
    assert "| 合計 | 1 | 1 | 1 | 1 | 4 | 2 | 2 |" in report
    matrix = report.split("## 要対応", 1)[0]
    assert "(" not in matrix
    attention = report.split("## 要対応", 1)[1].split("## Critical", 1)[0]
    assert "[Critical advisory](<https://security.example.com/ADV-1>)" in attention
    assert "[Moderate advisory](<https://security.example.com/ADV-1>)" in attention
    assert "[High advisory]" not in attention
    assert "| 緊急 | 85 |" in attention
    assert "悪用確認済み<br>PoC公開済み<br>修正版未提供" in attention
    assert (
        "| リスク | 危険度 | 優先度 | 状態 | ベンダー | CVE | CVSS（最大） | 悪用状況 |" in report
    )
    assert "悪用済み<br>PoC公開済み" in report
    assert report.index("## 要対応") < report.index("## Critical")
    assert report.index("## Critical") < report.index("## 悪用済み・PoC公開済み")
    assert report.index("## 悪用済み・PoC公開済み") < report.index("## 詳細")
    critical_table = report.split("## Critical", 1)[1].split("## 悪用済み・PoC公開済み", 1)[0]
    assert "Critical節の検証済みAIサマリです。対象件数を確認しています。" in critical_table
    assert critical_table.index(
        "Critical節の検証済みAIサマリです。対象件数を確認しています。"
    ) < critical_table.index("| 優先度 |")
    assert "[Critical advisory](<https://security.example.com/ADV-1>)" in critical_table
    assert "[High advisory]" not in critical_table
    assert "## 悪用済み・PoC公開済み" in report
    exploitation_table = report.split("## 悪用済み・PoC公開済み", 1)[1].split("## 詳細", 1)[0]
    assert (
        "悪用済み・PoC公開済み節の検証済みAIサマリです。重複も確認しています。"
        in exploitation_table
    )
    assert "[Critical advisory](<https://security.example.com/ADV-1>)" in exploitation_table
    assert "[Moderate advisory](<https://security.example.com/ADV-1>)" in exploitation_table
    assert "[Other advisory](<https://security.example.com/ADV-1>)" in exploitation_table
    assert "[High advisory]" not in exploitation_table
    assert exploitation_table.count("[Critical advisory]") == 1
    assert "| 緊急 | Critical | INFO | new | Example | CVE-2026-10001 | 9.8 | ○ | ○ |" in report
    details = report.split("## 詳細", 1)[1]
    assert details.index("| 緊急 | Critical |") < details.index("| 高 | Moderate |")
    assert details.index("| 高 | Moderate |") < details.index("| 中 | High |")
    assert details.index("| 中 | High |") < details.index("| 中 | その他 |")
    assert validate_tree(tmp_path) == (4, 4)


def test_attention_table_truncates_long_cve_lists(tmp_path: Path, advisory_factory) -> None:
    advisory = advisory_factory(
        facts=AdvisoryFacts(
            cves=[f"CVE-2026-1000{index}" for index in range(7)],
            cvss_score=9.8,
            known_exploited=True,
        ),
    )
    _write_report_input(tmp_path, [advisory])

    report = generate_report(tmp_path).read_text(encoding="utf-8")

    attention = report.split("## 要対応", 1)[1].split("## Critical", 1)[0]
    assert "CVE-2026-10004<br>他2件" in attention
    assert "CVE-2026-10005" not in attention
    details = report.split("## 詳細", 1)[1]
    assert "CVE-2026-10005" in details


def test_generate_report_marks_missing_values_as_unconfirmed(
    tmp_path: Path, advisory_factory
) -> None:
    advisory = advisory_factory(facts=AdvisoryFacts())
    _write_report_input(tmp_path, [advisory])

    report = generate_report(tmp_path).read_text(encoding="utf-8")

    assert "## 悪用済み・PoC公開済み" in report
    assert "該当するアドバイザリはありません。" in report
    assert "| その他 | INFO | new | Example | - | - | 確認なし |" in report
    with pytest.raises(ValueError, match="AI report summary"):
        validate_tree(tmp_path)


def test_generate_report_includes_all_critical_and_escapes_untrusted_cells(
    tmp_path: Path, advisory_factory
) -> None:
    critical = advisory_factory(
        canonical_id="example:critical-unexploited",
        vendor="Example | Vendor",
        title="[Critical] <noscript> advisory\ncontinued",
        facts=AdvisoryFacts(vendor_severity="Critical"),
    )
    high_poc = advisory_factory(
        canonical_id="example:high-poc",
        title="High PoC advisory",
        facts=AdvisoryFacts(cvss_score=8.0, poc_public=True),
    )
    _write_report_input(tmp_path, [critical, high_poc])
    write_agent_report_summary(
        tmp_path,
        "Criticalの日本語AIサマリです。全件を確認しています。",
        "悪用・PoCの日本語AIサマリです。和集合を確認しています。",
    )

    report = generate_report(tmp_path).read_text(encoding="utf-8")

    critical_section = report.split("## Critical", 1)[1].split("## 悪用済み・PoC公開済み", 1)[0]
    exploitation_section = report.split("## 悪用済み・PoC公開済み", 1)[1].split("## 詳細", 1)[0]
    assert r"\[Critical\] &lt;noscript&gt; advisory continued" in critical_section
    assert "Example &#124; Vendor" in critical_section
    assert "High PoC advisory" not in critical_section
    assert "High PoC advisory" in exploitation_section
    assert "[Critical]" not in exploitation_section


def test_validation_rejects_stale_report_content(tmp_path: Path, advisory_factory) -> None:
    _write_report_input(tmp_path, [advisory_factory()])
    write_agent_report_summary(
        tmp_path,
        "Critical対象はありません。現在の変更分を確認しています。",
        "悪用・PoC対象はありません。現在の変更分を確認しています。",
    )
    path = generate_report(tmp_path)
    path.write_text(path.read_text(encoding="utf-8") + "手動追記\n", encoding="utf-8")

    with pytest.raises(ValueError, match="stale or has unvalidated content"):
        validate_tree(tmp_path)


def test_report_rejects_missing_manifest_advisory_path(tmp_path: Path, advisory_factory) -> None:
    _write_report_input(tmp_path, [advisory_factory()])
    manifest_path = tmp_path / "run-manifest.json"
    manifest = RunManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
    manifest.changes[0].path = None
    manifest_path.write_text(manifest.model_dump_json(), encoding="utf-8")

    with pytest.raises(ValueError, match="has no advisory path"):
        generate_report(tmp_path)


def test_no_change_report_removes_stale_summary_and_is_valid(tmp_path: Path) -> None:
    _write_report_input(tmp_path, [])
    summary_path = write_agent_report_summary(
        tmp_path,
        "Critical対象はありません。現在の変更分を確認しています。",
        "悪用・PoC対象はありません。現在の変更分を確認しています。",
    )
    assert summary_path.exists()

    path = generate_report(tmp_path)

    assert not summary_path.exists()
    assert "新規・更新・取り下げアドバイザリはありません。" in path.read_text(encoding="utf-8")
    assert validate_tree(tmp_path) == (0, 0)
