from __future__ import annotations

import hashlib
import html
import json
import re
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal
from zoneinfo import ZoneInfo

from pydantic import Field, model_validator

from vulnwatch.exploitation import infer_exploitation_status
from vulnwatch.models import (
    Advisory,
    AiStatus,
    ChangeRecord,
    ChangeStatus,
    RunManifest,
    StrictModel,
)
from vulnwatch.storage.filesystem import atomic_write_text, write_json

SEVERITY_ORDER = ("Critical", "High", "Moderate", "その他")
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITY_ORDER)}
REPORT_SUMMARY_SCHEMA_VERSION: Literal[1] = 1
AGENT_SUMMARY_MODEL = "codex-agent"
AGENT_SUMMARY_PROMPT_VERSION = "AGENTS.md-v1"
_MISSING_AI_SUMMARY = (
    "AIサマリは未生成です。`vulnwatch summarize`で生成するか、"
    "`vulnwatch report`のサマリオプションを指定してください。"
)
_JAPANESE_TEXT = re.compile(r"[\u3040-\u30ff\u3400-\u9fff]")
_INLINE_MARKDOWN = re.compile(r"[<>{}\[\]`*_|]")


def _normalize_report_summary(value: str) -> str:
    normalized = " ".join(value.split())
    sentence_count = len([sentence for sentence in normalized.split("。") if sentence])
    if (
        not _JAPANESE_TEXT.search(normalized)
        or not normalized.endswith("。")
        or not 2 <= sentence_count <= 4
        or "AIサマリは未生成" in normalized
        or _INLINE_MARKDOWN.search(normalized)
        or normalized.startswith(("#", "-", ">"))
    ):
        raise ValueError("report summary must be 2-4 non-placeholder Japanese sentences")
    return normalized


@dataclass(frozen=True)
class ReportEntry:
    advisory: Advisory
    status: ChangeStatus
    severity: str
    exploited: bool
    poc_public: bool


class ReportSummaryArtifact(StrictModel):
    schema_version: Literal[1] = REPORT_SUMMARY_SCHEMA_VERSION
    report_date: date
    manifest_started_at: datetime
    generated_at: datetime
    status: AiStatus
    model: str | None = None
    prompt_version: str | None = None
    source_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    critical_summary_ja: str | None = Field(default=None, max_length=2000)
    exploitation_summary_ja: str | None = Field(default=None, max_length=2000)
    error: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_success_content(self) -> ReportSummaryArtifact:
        if self.status == AiStatus.SUCCESS:
            critical = _normalize_report_summary(self.critical_summary_ja or "")
            exploitation = _normalize_report_summary(self.exploitation_summary_ja or "")
            object.__setattr__(self, "critical_summary_ja", critical)
            object.__setattr__(self, "exploitation_summary_ja", exploitation)
        return self


def _severity(advisory: Advisory) -> str:
    score = advisory.facts.cvss_score
    if score is not None:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 4.0:
            return "Moderate"
        return "その他"

    vendor_severity = (advisory.facts.vendor_severity or "").strip().casefold()
    if vendor_severity == "critical":
        return "Critical"
    if vendor_severity in {"high", "important"}:
        return "High"
    if vendor_severity in {"medium", "moderate"}:
        return "Moderate"
    return "その他"


def resolve_advisory_path(root: Path, change: ChangeRecord) -> Path:
    if not change.path:
        raise ValueError(f"reportable change has no advisory path: {change.canonical_id}")
    resolved_root = root.resolve()
    advisory_path = (root / change.path).resolve()
    if (
        not advisory_path.is_relative_to(resolved_root)
        or advisory_path.name != "advisory.json"
        or not advisory_path.is_file()
    ):
        raise ValueError(f"invalid report advisory path: {change.path}")
    return advisory_path


def _exploitation_flags(advisory: Advisory) -> tuple[bool, bool]:
    inferred_exploited, inferred_poc = infer_exploitation_status(advisory.body_excerpt)
    exploited = (
        advisory.enrichment.cisa_kev
        or advisory.facts.known_exploited is True
        or inferred_exploited is True
    )
    poc_public = advisory.facts.poc_public is True or inferred_poc is True
    return exploited, poc_public


def load_report_entries(root: Path, manifest: RunManifest) -> list[ReportEntry]:
    entries: list[ReportEntry] = []
    for change in manifest.changes:
        if change.status in {ChangeStatus.UNCHANGED, ChangeStatus.QUARANTINED}:
            continue
        advisory_path = resolve_advisory_path(root, change)
        advisory = Advisory.model_validate_json(advisory_path.read_text(encoding="utf-8"))
        exploited, poc_public = _exploitation_flags(advisory)
        entries.append(
            ReportEntry(
                advisory=advisory,
                status=change.status,
                severity=_severity(advisory),
                exploited=exploited,
                poc_public=poc_public,
            )
        )
    return sorted(
        entries,
        key=lambda entry: (
            _SEVERITY_RANK[entry.severity],
            -(
                entry.advisory.facts.cvss_score
                if entry.advisory.facts.cvss_score is not None
                else -1
            ),
            entry.advisory.vendor.casefold(),
            entry.advisory.title.casefold(),
        ),
    )


def report_datetime(manifest: RunManifest) -> datetime:
    timestamp = manifest.completed_at or manifest.started_at
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(ZoneInfo("Asia/Tokyo"))


def report_path(root: Path, manifest: RunManifest) -> Path:
    timestamp = report_datetime(manifest)
    return (
        root
        / "reports"
        / "daily"
        / f"{timestamp:%Y}"
        / f"{timestamp:%m}"
        / f"{timestamp:%Y-%m-%d}.md"
    )


def report_summary_path(root: Path, manifest: RunManifest) -> Path:
    return report_path(root, manifest).with_suffix(".summary.json")


def report_summary_payload(entries: list[ReportEntry], manifest: RunManifest) -> dict[str, Any]:
    def compact(entry: ReportEntry) -> dict[str, Any]:
        advisory = entry.advisory
        return {
            "canonical_id": advisory.canonical_id,
            "vendor": advisory.vendor,
            "title": advisory.title,
            "source_url": advisory.source_url,
            "cves": advisory.facts.cves,
            "products": advisory.facts.products,
            "cvss_score": advisory.facts.cvss_score,
            "vendor_severity": advisory.facts.vendor_severity,
            "priority": advisory.decision.priority,
            "change_status": entry.status,
            "severity": entry.severity,
            "exploited": entry.exploited,
            "poc_public": entry.poc_public,
            "cisa_kev": advisory.enrichment.cisa_kev,
        }

    critical = [compact(entry) for entry in entries if entry.severity == "Critical"]
    exploitation = [compact(entry) for entry in entries if entry.exploited or entry.poc_public]
    return {
        "report_date": report_datetime(manifest).date().isoformat(),
        "total_advisory_count": len(entries),
        "critical_advisory_count": len(critical),
        "exploited_advisory_count": sum(entry.exploited for entry in entries),
        "poc_public_advisory_count": sum(entry.poc_public for entry in entries),
        "critical_advisories": critical,
        "exploited_or_poc_public_advisories": exploitation,
    }


def report_summary_source_hash(entries: list[ReportEntry], manifest: RunManifest) -> str:
    payload = json.dumps(
        report_summary_payload(entries, manifest),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def read_current_report_summary(
    root: Path,
    manifest: RunManifest,
    entries: list[ReportEntry],
) -> ReportSummaryArtifact | None:
    path = report_summary_path(root, manifest)
    if not path.exists():
        return None
    try:
        artifact = ReportSummaryArtifact.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        artifact.status != AiStatus.SUCCESS
        or artifact.report_date != report_datetime(manifest).date()
        or artifact.source_hash != report_summary_source_hash(entries, manifest)
    ):
        return None
    return artifact


def write_agent_report_summary(
    root: Path,
    critical_summary_ja: str,
    exploitation_summary_ja: str,
) -> Path:
    manifest = RunManifest.model_validate_json(
        (root / "run-manifest.json").read_text(encoding="utf-8")
    )
    entries = load_report_entries(root, manifest)
    artifact = ReportSummaryArtifact(
        report_date=report_datetime(manifest).date(),
        manifest_started_at=manifest.started_at,
        generated_at=datetime.now(UTC),
        status=AiStatus.SUCCESS,
        model=AGENT_SUMMARY_MODEL,
        prompt_version=AGENT_SUMMARY_PROMPT_VERSION,
        source_hash=report_summary_source_hash(entries, manifest),
        critical_summary_ja=critical_summary_ja,
        exploitation_summary_ja=exploitation_summary_ja,
    )
    path = report_summary_path(root, manifest)
    write_json(path, artifact.model_dump(mode="json", exclude_none=True))
    return path


def _matrix_lines(entries: list[ReportEntry]) -> list[str]:
    lines = [
        "深刻度別と合計はアドバイザリ件数です。悪用済み・PoC公開済みは、深刻度に関係なく集計します。",
        "",
        "| ベンダー | Critical | High | Moderate | その他 | 合計 | 悪用済み | PoC公開済み |",
        "|---|---:|---:|---:|---:|---:|---:|---:|",
    ]
    vendors = sorted({entry.advisory.vendor for entry in entries}, key=str.casefold)
    for vendor in vendors:
        vendor_entries = [entry for entry in entries if entry.advisory.vendor == vendor]
        cells = [
            str(sum(entry.severity == severity for entry in vendor_entries))
            for severity in SEVERITY_ORDER
        ]
        exploited = sum(entry.exploited for entry in vendor_entries)
        poc_public = sum(entry.poc_public for entry in vendor_entries)
        lines.append(
            f"| {_escape_table_cell(vendor)} | {' | '.join(cells)} | "
            f"{len(vendor_entries)} | {exploited} | {poc_public} |"
        )
    totals = [
        str(sum(entry.severity == severity for entry in entries)) for severity in SEVERITY_ORDER
    ]
    lines.append(
        f"| 合計 | {' | '.join(totals)} | {len(entries)} | "
        f"{sum(entry.exploited for entry in entries)} | "
        f"{sum(entry.poc_public for entry in entries)} |"
    )
    return lines


def _exploitation_label(entry: ReportEntry) -> str:
    labels: list[str] = []
    if entry.exploited:
        labels.append("悪用済み（CISA KEV）" if entry.advisory.enrichment.cisa_kev else "悪用済み")
    if entry.poc_public:
        labels.append("PoC公開済み")
    return "<br>".join(labels) or "確認なし"


def _escape_table_cell(value: str, *, link_label: bool = False) -> str:
    escaped = html.escape(" ".join(value.split()), quote=False).replace("|", "&#124;")
    if link_label:
        escaped = escaped.replace("\\", "\\\\").replace("[", r"\[").replace("]", r"\]")
    return escaped


def _summary_paragraph(value: str) -> str:
    return f"<p>{html.escape(value, quote=False)}</p>"


def _focused_table_lines(entries: list[ReportEntry], *, include_severity: bool) -> list[str]:
    if include_severity:
        header = (
            "| 危険度 | 優先度 | 状態 | ベンダー | CVE | CVSS（最大） | "
            "悪用済み | PoC公開済み | アドバイザリ |"
        )
        divider = "|---|---|---|---|---|---:|---|---|---|"
    else:
        header = (
            "| 優先度 | 状態 | ベンダー | CVE | CVSS（最大） | "
            "悪用済み | PoC公開済み | アドバイザリ |"
        )
        divider = "|---|---|---|---|---:|---|---|---|"

    lines = [header, divider]
    for entry in entries:
        advisory = entry.advisory
        title = _escape_table_cell(advisory.title, link_label=True)
        vendor = _escape_table_cell(advisory.vendor)
        cves = "<br>".join(_escape_table_cell(cve) for cve in advisory.facts.cves) or "-"
        cvss = f"{advisory.facts.cvss_score:.1f}" if advisory.facts.cvss_score is not None else "-"
        exploited = (
            "CISA KEV" if advisory.enrichment.cisa_kev else ("○" if entry.exploited else "-")
        )
        poc_public = "○" if entry.poc_public else "-"
        severity = f"{entry.severity} | " if include_severity else ""
        lines.append(
            f"| {severity}{advisory.decision.priority} | {entry.status} | "
            f"{vendor} | {cves} | {cvss} | {exploited} | {poc_public} | "
            f"[{title}](<{advisory.source_url}>) |"
        )
    return lines


def _critical_table_lines(entries: list[ReportEntry], summary: str) -> list[str]:
    critical = [entry for entry in entries if entry.severity == "Critical"]
    lines = ["", "## Critical", "", "### AIサマリ", "", _summary_paragraph(summary), ""]
    if not critical:
        return [*lines, "Criticalに該当する新規・更新・取り下げアドバイザリはありません。"]
    return [*lines, *_focused_table_lines(critical, include_severity=False)]


def _exploitation_table_lines(entries: list[ReportEntry], summary: str) -> list[str]:
    relevant = [entry for entry in entries if entry.exploited or entry.poc_public]
    lines = [
        "",
        "## 悪用済み・PoC公開済み",
        "",
        "### AIサマリ",
        "",
        _summary_paragraph(summary),
        "",
    ]
    if not relevant:
        return [*lines, "該当するアドバイザリはありません。"]
    lines.append(
        "この表は悪用済みまたはPoC公開済みのアドバイザリの和集合で、両方に該当する行も1件として掲載します。"
    )
    lines.append("")
    lines.extend(_focused_table_lines(relevant, include_severity=True))
    return lines


def render_report(root: Path, manifest: RunManifest, entries: list[ReportEntry]) -> str:
    timestamp = report_datetime(manifest)
    lines = [f"# 脆弱性情報 日次レポート {timestamp:%Y-%m-%d}", "", "## サマリ", ""]
    if not entries:
        lines.append("新規・更新・取り下げアドバイザリはありません。")
        return "\n".join(lines) + "\n"

    lines.extend(_matrix_lines(entries))
    summary = read_current_report_summary(root, manifest, entries)
    critical_summary = (
        summary.critical_summary_ja
        if summary and summary.critical_summary_ja
        else _MISSING_AI_SUMMARY
    )
    exploitation_summary = (
        summary.exploitation_summary_ja
        if summary and summary.exploitation_summary_ja
        else _MISSING_AI_SUMMARY
    )
    lines.extend(_critical_table_lines(entries, critical_summary))
    lines.extend(_exploitation_table_lines(entries, exploitation_summary))
    lines.extend(
        [
            "",
            "## 詳細",
            "",
            "| 危険度 | 優先度 | 状態 | ベンダー | CVE | CVSS（最大） | 悪用状況 | アドバイザリ |",
            "|---|---|---|---|---|---:|---|---|",
        ]
    )
    for entry in entries:
        advisory = entry.advisory
        title = _escape_table_cell(advisory.title, link_label=True)
        vendor = _escape_table_cell(advisory.vendor)
        cves = "<br>".join(_escape_table_cell(cve) for cve in advisory.facts.cves) or "-"
        cvss = f"{advisory.facts.cvss_score:.1f}" if advisory.facts.cvss_score is not None else "-"
        lines.append(
            f"| {entry.severity} | {advisory.decision.priority} | {entry.status} | "
            f"{vendor} | {cves} | {cvss} | {_exploitation_label(entry)} | "
            f"[{title}](<{advisory.source_url}>) |"
        )
    return "\n".join(lines) + "\n"


def generate_report(root: Path) -> Path:
    manifest = RunManifest.model_validate_json(
        (root / "run-manifest.json").read_text(encoding="utf-8")
    )
    path = report_path(root, manifest)
    entries = load_report_entries(root, manifest)
    if not entries:
        report_summary_path(root, manifest).unlink(missing_ok=True)
    atomic_write_text(path, render_report(root, manifest, entries))
    return path
