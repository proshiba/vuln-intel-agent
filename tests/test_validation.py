from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from vulnwatch import validation
from vulnwatch.models import (
    Category,
    CollectorKind,
    RunManifest,
    SourceDefinition,
    SourceOutcome,
    SourceOutcomeStatus,
    SourceRegistry,
    Tier,
)
from vulnwatch.report import generate_report


def _source(source_id: str, *, tier: Tier, enabled: bool = True) -> SourceDefinition:
    return SourceDefinition(
        id=source_id,
        category="example",
        vendor="Example",
        advisory_url=f"https://{source_id}.example.com/advisories",
        enabled=enabled,
        collector=CollectorKind.FEED if enabled else None,
        url=f"https://{source_id}.example.com/feed" if enabled else None,
        allowed_hosts=[f"{source_id}.example.com"] if enabled else [],
        tier=tier,
        parser="feed" if enabled else None,
    )


def _registry() -> SourceRegistry:
    return SourceRegistry(
        as_of="2026-07-19",
        categories=[Category(id="example", name="Example")],
        sources=[
            _source("edge_source", tier=Tier.EDGE),
            _source("daily_source", tier=Tier.DAILY),
            _source("disabled_source", tier=Tier.EDGE, enabled=False),
        ],
    )


def _outcome(
    source_id: str, status: SourceOutcomeStatus = SourceOutcomeStatus.SUCCESS
) -> SourceOutcome:
    return SourceOutcome(
        source_id=source_id,
        status=status,
        collector=CollectorKind.FEED,
        endpoint_url=f"https://{source_id}.example.com/feed",
    )


def _write_manifest(
    root: Path,
    *,
    profile: Tier,
    outcomes: list[SourceOutcome],
    include_outcomes: bool = True,
) -> None:
    manifest = RunManifest(
        started_at=datetime(2026, 7, 19, tzinfo=UTC),
        profile=profile,
        since=datetime(2026, 7, 18, tzinfo=UTC),
        source_outcomes=outcomes,
    )
    exclude = set() if include_outcomes else {"source_outcomes"}
    (root / "run-manifest.json").write_text(
        manifest.model_dump_json(exclude=exclude), encoding="utf-8"
    )
    generate_report(root)


@pytest.fixture(autouse=True)
def source_registry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(validation, "load_sources", _registry)


def test_validate_tree_accepts_complete_daily_source_outcomes(tmp_path: Path) -> None:
    _write_manifest(
        tmp_path,
        profile=Tier.DAILY,
        outcomes=[
            _outcome("edge_source"),
            _outcome("daily_source", SourceOutcomeStatus.NOT_MODIFIED),
        ],
    )

    assert validation.validate_tree(tmp_path) == (0, 0)


def test_validate_tree_applies_edge_profile_and_excludes_disabled_sources(
    tmp_path: Path,
) -> None:
    _write_manifest(
        tmp_path,
        profile=Tier.EDGE,
        outcomes=[_outcome("edge_source")],
    )

    assert validation.validate_tree(tmp_path) == (0, 0)


@pytest.mark.parametrize(
    ("outcomes", "message"),
    [
        ([_outcome("edge_source")], "missing: daily_source"),
        (
            [
                _outcome("edge_source"),
                _outcome("daily_source"),
                _outcome("unexpected_source"),
            ],
            "unexpected: unexpected_source",
        ),
        ([], "missing: daily_source, edge_source"),
    ],
)
def test_validate_tree_rejects_incomplete_or_unexpected_source_outcomes(
    tmp_path: Path,
    outcomes: list[SourceOutcome],
    message: str,
) -> None:
    _write_manifest(tmp_path, profile=Tier.DAILY, outcomes=outcomes)

    with pytest.raises(ValueError, match=message):
        validation.validate_tree(tmp_path)


@pytest.mark.parametrize("status", [SourceOutcomeStatus.FAILED, SourceOutcomeStatus.PARTIAL])
def test_validate_tree_rejects_unsuccessful_source_outcomes(
    tmp_path: Path, status: SourceOutcomeStatus
) -> None:
    _write_manifest(
        tmp_path,
        profile=Tier.DAILY,
        outcomes=[_outcome("edge_source", status), _outcome("daily_source")],
    )

    with pytest.raises(ValueError, match=rf"edge_source={status}"):
        validation.validate_tree(tmp_path)


def test_validate_tree_accepts_legacy_manifest_without_source_outcomes(
    tmp_path: Path,
) -> None:
    _write_manifest(
        tmp_path,
        profile=Tier.DAILY,
        outcomes=[],
        include_outcomes=False,
    )

    assert validation.validate_tree(tmp_path) == (0, 0)
