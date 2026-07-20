from __future__ import annotations

from pathlib import Path

from vulnwatch.config import load_products, load_sources
from vulnwatch.models import Advisory, RunManifest, SourceOutcomeStatus, Tier
from vulnwatch.report import (
    load_report_entries,
    read_current_report_summary,
    render_report,
    report_path,
    report_summary_path,
)
from vulnwatch.vulndb import validate_vulndb


def validate_config(
    sources_path: Path = Path("config/sources.yaml"),
    products_path: Path = Path("config/products.yaml"),
) -> tuple[int, int]:
    sources = load_sources(sources_path)
    load_products(products_path)
    enabled = sum(source.enabled for source in sources.sources)
    return len(sources.sources), enabled


def validate_tree(root: Path) -> tuple[int, int]:
    advisories = 0
    for path in (root / "data" / "vendors").glob("*/advisories/*/*/advisory.json"):
        Advisory.model_validate_json(path.read_text(encoding="utf-8"))
        advisories += 1
    validate_vulndb(root)
    manifest_path = root / "run-manifest.json"
    changes = 0
    if manifest_path.exists():
        manifest = RunManifest.model_validate_json(manifest_path.read_text(encoding="utf-8"))
        _validate_source_outcomes(manifest)
        changes = len(manifest.changes)
        entries = load_report_entries(root, manifest)
        daily_report = report_path(root, manifest)
        if not daily_report.exists():
            raise ValueError(f"current daily report is missing: {daily_report}")
        report_text = daily_report.read_text(encoding="utf-8")
        if not entries:
            if report_summary_path(root, manifest).exists():
                raise ValueError("no-change daily report must not retain an AI summary sidecar")
            if report_text != render_report(root, manifest, entries):
                raise ValueError("current no-change daily report is stale")
            return advisories, changes
        if entries:
            report_summary = read_current_report_summary(root, manifest, entries)
            if report_summary is None:
                raise ValueError(
                    "current AI report summary is missing, unsuccessful, or stale: "
                    f"{report_summary_path(root, manifest)}"
                )
            if report_text != render_report(root, manifest, entries):
                raise ValueError("current daily report is stale or has unvalidated content")
    return advisories, changes


def _validate_source_outcomes(manifest: RunManifest) -> None:
    # Manifests created before source-level outcome tracking did not contain this key.
    # Keep those historical trees readable while requiring complete outcomes whenever
    # a producer opts in by writing the field (including an explicitly empty list).
    if "source_outcomes" not in manifest.model_fields_set:
        return

    registry = load_sources()
    expected_ids = {
        source.id
        for source in registry.sources
        if source.enabled and (manifest.profile == Tier.DAILY or source.tier == Tier.EDGE)
    }
    actual_ids = {outcome.source_id for outcome in manifest.source_outcomes}
    if actual_ids != expected_ids:
        missing = sorted(expected_ids - actual_ids)
        unexpected = sorted(actual_ids - expected_ids)
        details: list[str] = []
        if missing:
            details.append(f"missing: {', '.join(missing)}")
        if unexpected:
            details.append(f"unexpected: {', '.join(unexpected)}")
        raise ValueError(
            f"source outcomes do not match the {manifest.profile} profile "
            f"({'; '.join(details)})"
        )

    unsuccessful = [
        outcome
        for outcome in manifest.source_outcomes
        if outcome.status in {SourceOutcomeStatus.FAILED, SourceOutcomeStatus.PARTIAL}
    ]
    if unsuccessful:
        unsuccessful_details = ", ".join(
            f"{outcome.source_id}={outcome.status}" for outcome in unsuccessful
        )
        raise ValueError(
            "source outcomes include unsuccessful collection results: "
            f"{unsuccessful_details}"
        )
