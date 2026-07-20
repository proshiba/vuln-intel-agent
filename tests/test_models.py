from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vulnwatch.models import (
    AdvisoryDraft,
    CollectorKind,
    Priority,
    RunManifest,
    SourceDefinition,
    SourceOutcome,
    SourceOutcomeStatus,
    Tier,
)


def test_draft_normalizes_cves_and_validates_cvss() -> None:
    draft = AdvisoryDraft(
        source_id="example",
        vendor="Example",
        title="Example",
        source_url="https://security.example.com/1",
        published_at=datetime(2026, 7, 1, tzinfo=UTC),
        cves=["cve-2026-12345", "CVE-2026-12345"],
        cvss_score=9.8,
        raw_sha256="a" * 64,
    )
    assert draft.cves == ["CVE-2026-12345"]
    assert Priority("P1") == Priority.P1

    with pytest.raises(ValidationError):
        AdvisoryDraft(
            source_id="example",
            vendor="Example",
            title="Example",
            source_url="https://security.example.com/1",
            cvss_score=10.1,
            raw_sha256="a" * 64,
        )

    with pytest.raises(ValidationError):
        AdvisoryDraft(
            source_id="example",
            vendor="Example",
            title="Example",
            source_url="http://security.example.com/1",
            cves=["not-a-cve"],
            raw_sha256="short",
        )

    for unsafe_url in (
        "https://security.example.com/>malformed",
        "https://security.example.com/bad|column",
        "https://security.example.com/trailing\\",
    ):
        with pytest.raises(ValidationError):
            AdvisoryDraft(
                source_id="example",
                vendor="Example",
                title="Example",
                source_url=unsafe_url,
                raw_sha256="a" * 64,
            )


def test_run_manifest_accepts_legacy_payload_without_source_outcomes() -> None:
    manifest = RunManifest.model_validate(
        {
            "schema_version": 1,
            "started_at": "2026-07-19T00:00:00Z",
            "profile": Tier.DAILY,
            "since": "2026-07-18T00:00:00Z",
            "changes": [],
        }
    )

    assert manifest.source_outcomes == []


def test_run_manifest_rejects_duplicate_source_outcome_ids() -> None:
    outcome = SourceOutcome(
        source_id="example",
        status=SourceOutcomeStatus.SUCCESS,
        collector=CollectorKind.FEED,
        endpoint_url="https://security.example.com/feed",
    )

    with pytest.raises(ValidationError, match="source outcome IDs must be unique"):
        RunManifest(
            started_at=datetime(2026, 7, 19, tzinfo=UTC),
            profile=Tier.DAILY,
            since=datetime(2026, 7, 18, tzinfo=UTC),
            source_outcomes=[outcome, outcome],
        )


def test_source_definition_rejects_bootstrap_window_for_other_collectors() -> None:
    with pytest.raises(ValidationError, match="only supported by osv_global"):
        SourceDefinition.model_validate(
            {
                "id": "example",
                "category": "test",
                "vendor": "Example",
                "advisory_url": "https://example.com/security",
                "enabled": True,
                "collector": "html",
                "url": "https://example.com/security",
                "allowed_hosts": ["example.com"],
                "bootstrap_window_hours": 1,
            }
        )


def test_source_definition_rejects_osv_prefix_filter_for_other_collectors() -> None:
    with pytest.raises(ValidationError, match="only supported by osv_global"):
        SourceDefinition.model_validate(
            {
                "id": "example",
                "category": "test",
                "vendor": "Example",
                "advisory_url": "https://example.com/security",
                "enabled": True,
                "collector": "html",
                "url": "https://example.com/security",
                "allowed_hosts": ["example.com"],
                "osv_id_prefixes": ["GHSA-"],
            }
        )


@pytest.mark.parametrize("prefix", ["", "GHSA/", "ＧＨＳＡ-"])
def test_source_definition_rejects_unsafe_osv_prefix(prefix: str) -> None:
    with pytest.raises(ValidationError, match="bounded safe identifier prefixes"):
        SourceDefinition.model_validate(
            {
                "id": "example",
                "category": "test",
                "vendor": "Example",
                "advisory_url": "https://example.com/security",
                "enabled": True,
                "collector": "osv_global",
                "url": "https://example.com/security",
                "allowed_hosts": ["example.com"],
                "osv_id_prefixes": [prefix],
            }
        )
