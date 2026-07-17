from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from vulnwatch.exploitation import infer_exploitation_status
from vulnwatch.models import Advisory, ChangeStatus, RunManifest
from vulnwatch.storage.filesystem import atomic_write_text

SEVERITY_ORDER = ("Critical", "High", "Moderate", "その他")
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITY_ORDER)}


@dataclass(frozen=True)
class ReportEntry:
    advisory: Advisory
    status: ChangeStatus
    severity: str
    exploited: bool
    poc_public: bool


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


def _exploitation_flags(advisory: Advisory) -> tuple[bool, bool]:
    inferred_exploited, inferred_poc = infer_exploitation_status(advisory.body_excerpt)
    exploited = (
        advisory.enrichment.cisa_kev
        or advisory.facts.known_exploited is True
        or inferred_exploited is True
    )
    poc_public = advisory.facts.poc_public is True or inferred_poc is True
    return exploited, poc_public


def _load_entries(root: Path, manifest: RunManifest) -> list[ReportEntry]:
    entries: list[ReportEntry] = []
    for change in manifest.changes:
        if change.status == ChangeStatus.UNCHANGED or not change.path:
            continue
        advisory_path = root / change.path
        if advisory_path.name != "advisory.json" or not advisory_path.exists():
            continue
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


def _matrix_cell(entries: list[ReportEntry]) -> str:
    exploited = sum(entry.exploited for entry in entries)
    poc_public = sum(entry.poc_public for entry in entries)
    return f"{len(entries)}({exploited},{poc_public})"


def _matrix_lines(entries: list[ReportEntry]) -> list[str]:
    lines = [
        "各セルは `総数(悪用済み, PoC公開済み)` のアドバイザリ件数です。",
        "",
        "| ベンダー | Critical | High | Moderate | その他 | 合計 |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    vendors = sorted({entry.advisory.vendor for entry in entries}, key=str.casefold)
    for vendor in vendors:
        vendor_entries = [entry for entry in entries if entry.advisory.vendor == vendor]
        cells = [
            _matrix_cell([entry for entry in vendor_entries if entry.severity == severity])
            for severity in SEVERITY_ORDER
        ]
        lines.append(
            f"| {vendor.replace('|', r'\|')} | {' | '.join(cells)} | "
            f"{_matrix_cell(vendor_entries)} |"
        )
    totals = [
        _matrix_cell([entry for entry in entries if entry.severity == severity])
        for severity in SEVERITY_ORDER
    ]
    lines.append(f"| 合計 | {' | '.join(totals)} | {_matrix_cell(entries)} |")
    return lines


def _exploitation_label(entry: ReportEntry) -> str:
    labels: list[str] = []
    if entry.exploited:
        labels.append("悪用済み（CISA KEV）" if entry.advisory.enrichment.cisa_kev else "悪用済み")
    if entry.poc_public:
        labels.append("PoC公開済み")
    return "<br>".join(labels) or "確認なし"


def generate_report(root: Path) -> Path:
    manifest = RunManifest.model_validate_json(
        (root / "run-manifest.json").read_text(encoding="utf-8")
    )
    now = datetime.now(ZoneInfo("Asia/Tokyo"))
    path = root / "reports" / "daily" / f"{now:%Y}" / f"{now:%m}" / f"{now:%Y-%m-%d}.md"
    entries = _load_entries(root, manifest)
    lines = [f"# 脆弱性情報 日次レポート {now:%Y-%m-%d}", "", "## サマリ", ""]
    if not entries:
        lines.append("新規・更新アドバイザリはありません。")
        atomic_write_text(path, "\n".join(lines) + "\n")
        return path

    lines.extend(_matrix_lines(entries))
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
        title = advisory.title.replace("|", "\\|")
        vendor = advisory.vendor.replace("|", "\\|")
        cves = "<br>".join(advisory.facts.cves) or "-"
        cvss = f"{advisory.facts.cvss_score:.1f}" if advisory.facts.cvss_score is not None else "-"
        lines.append(
            f"| {entry.severity} | {advisory.decision.priority} | {entry.status} | "
            f"{vendor} | {cves} | {cvss} | {_exploitation_label(entry)} | "
            f"[{title}]({advisory.source_url}) |"
        )
    atomic_write_text(path, "\n".join(lines) + "\n")
    return path
