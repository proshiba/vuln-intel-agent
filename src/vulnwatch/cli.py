from __future__ import annotations

import asyncio
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Annotated

import feedparser
import typer

from vulnwatch.collectors.json_api import _items
from vulnwatch.config import load_sources
from vulnwatch.models import Priority, RawRecord, Tier
from vulnwatch.parsers import parse_record
from vulnwatch.pipeline import Pipeline
from vulnwatch.report import generate_report, write_agent_report_summary
from vulnwatch.schemas import export_schemas
from vulnwatch.storage import publish_tree
from vulnwatch.summarizers import summarize_tree
from vulnwatch.threatintel import (
    ThreatIntelStore,
    VulnThreatActivity,
    export_csv,
    export_misp,
    export_stix,
)
from vulnwatch.validation import validate_config, validate_tree

app = typer.Typer(no_args_is_help=True)
config_app = typer.Typer(no_args_is_help=True)
source_app = typer.Typer(no_args_is_help=True)
app.add_typer(config_app, name="config")
app.add_typer(source_app, name="source")


def _since(value: str) -> datetime:
    match = re.fullmatch(r"(\d+)d", value)
    if not match:
        raise typer.BadParameter("since must use the form 90d")
    return datetime.now(UTC) - timedelta(days=int(match.group(1)))


@config_app.command("validate")
def config_validate(
    sources: Annotated[Path, typer.Option()] = Path("config/sources.yaml"),
    products: Annotated[Path, typer.Option()] = Path("config/products.yaml"),
    attack_surface: Annotated[Path, typer.Option()] = Path("config/attack_surface.yaml"),
) -> None:
    total, enabled, surface_classes = validate_config(sources, products, attack_surface)
    export_schemas()
    typer.echo(
        f"configuration valid: {total} sources, {enabled} enabled, "
        f"{surface_classes} attack-surface classes"
    )


@app.command()
def collect(
    profile: Annotated[Tier, typer.Option()] = Tier.DAILY,
    since: Annotated[str, typer.Option()] = "90d",
    output: Annotated[Path, typer.Option()] = Path("staging"),
) -> None:
    pipeline = Pipeline(Path.cwd(), output)
    manifest = asyncio.run(pipeline.run(profile, _since(since)))
    typer.echo(f"collection complete: {len(manifest.changes)} change records")


@app.command()
def summarize(
    root: Annotated[Path, typer.Option()] = Path("staging"),
    priority: Annotated[str | None, typer.Option()] = None,
) -> None:
    priorities = {Priority(item.strip()) for item in priority.split(",")} if priority else None
    success, skipped = asyncio.run(summarize_tree(root, priorities))
    typer.echo(f"summaries: {success} successful, {skipped} skipped")


@app.command()
def validate(root: Annotated[Path, typer.Option()] = Path("staging")) -> None:
    advisories, changes = validate_tree(root)
    typer.echo(f"tree valid: {advisories} advisories, {changes} change records")


@app.command()
def report(
    root: Annotated[Path, typer.Option()] = Path("staging"),
    critical_summary: Annotated[
        str | None, typer.Option(help="AI-authored Japanese summary for the Critical table")
    ] = None,
    exploitation_summary: Annotated[
        str | None,
        typer.Option(help="AI-authored Japanese summary for the exploited/PoC table"),
    ] = None,
) -> None:
    if (critical_summary is None) != (exploitation_summary is None):
        raise typer.BadParameter(
            "--critical-summary and --exploitation-summary must be supplied together"
        )
    if critical_summary is not None and exploitation_summary is not None:
        write_agent_report_summary(root, critical_summary, exploitation_summary)
    typer.echo(str(generate_report(root)))


@app.command()
def publish(
    root: Annotated[Path, typer.Option()] = Path("staging"),
    repository: Annotated[Path, typer.Option()] = Path("."),
) -> None:
    validate_tree(root)
    published = publish_tree(root, repository)
    typer.echo(f"published {published} generated files to {repository.resolve()}")


@source_app.command("test")
def source_test(
    source_id: str,
    fixture: Annotated[Path, typer.Option(exists=True, dir_okay=False)],
) -> None:
    registry = load_sources()
    source = next((item for item in registry.sources if item.id == source_id), None)
    if source is None:
        raise typer.BadParameter(f"unknown source: {source_id}")
    content = fixture.read_text(encoding="utf-8")
    records: list[RawRecord] = []
    if fixture.suffix == ".json":
        payload = json.loads(content)
        fixture_items = [payload] if source.parser == "csaf" else _items(payload)
        records = [
            RawRecord(
                source_id=source.id,
                url=str(item.get("url") or source.advisory_url),
                content=json.dumps(item, ensure_ascii=False),
                metadata=item,
            )
            for item in fixture_items
        ]
    elif fixture.suffix in {".xml", ".rss"}:
        parsed = feedparser.parse(content)
        records = [
            RawRecord(
                source_id=source.id,
                url=str(entry.get("link") or source.advisory_url),
                content=str(entry.get("summary", "")),
                metadata=dict(entry),
            )
            for entry in parsed.entries
        ]
    else:
        records = [
            RawRecord(
                source_id=source.id,
                url=source.advisory_url,
                content=content,
                metadata={"title": source.vendor},
            )
        ]
    advisories = [parse_record(source, record) for record in records]
    typer.echo(
        json.dumps(
            [item.model_dump(mode="json") for item in advisories],
            ensure_ascii=False,
            indent=2,
        )
    )


threat_app = typer.Typer(no_args_is_help=True)
app.add_typer(threat_app, name="threat")


@threat_app.command("apply")
def threat_apply(
    findings: Annotated[Path, typer.Argument(help="調査結果のJSONファイル")],
    repository: Annotated[Path, typer.Option()] = Path("."),
) -> None:
    """調査で得た攻撃活動（キャンペーン・マルウェア・IOC）を台帳へ反映します。

    JSON は VulnThreatActivity の配列です。保存時に出典URLの有無、値の正規化、
    非公開アドレスの排除が検証され、条件を満たさない指標は取り込まれません。
    """

    payload = json.loads(findings.read_text(encoding="utf-8"))
    if isinstance(payload, dict):
        payload = [payload]
    store = ThreatIntelStore(repository)
    applied = 0
    indicators = 0
    for item in payload:
        activity = VulnThreatActivity.model_validate(item)
        merged = store.apply(activity)
        applied += 1
        indicators += len(merged.indicators)
    typer.echo(f"applied {applied} vulnerabilities, {indicators} indicators")


@threat_app.command("export")
def threat_export(
    repository: Annotated[Path, typer.Option()] = Path("."),
) -> None:
    """台帳の攻撃活動を CSV / STIX / MISP へ書き出します。"""

    store = ThreatIntelStore(repository)
    activities = list(store.iter_activities())
    store.exports_root.mkdir(parents=True, exist_ok=True)
    (store.exports_root / "iocs.csv").write_text(export_csv(activities), encoding="utf-8")
    (store.exports_root / "iocs.stix.json").write_text(
        json.dumps(export_stix(activities), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    (store.exports_root / "iocs.misp.json").write_text(
        json.dumps(export_misp(activities), ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    total = sum(len(activity.indicators) for activity in activities)
    typer.echo(f"exported {total} indicators from {len(activities)} vulnerabilities")


if __name__ == "__main__":
    app()
