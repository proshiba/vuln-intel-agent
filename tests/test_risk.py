from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from vulnwatch.models import AdvisoryEnrichment, AdvisoryFacts, Tier
from vulnwatch.risk import assess_risk, load_source_catalog

REPORT_TIME = datetime(2026, 7, 18, 9, 0, tzinfo=UTC)


def _assess(advisory, **overrides):
    parameters = {
        "severity": "その他",
        "exploited": False,
        "poc_public": False,
        "report_time": REPORT_TIME,
        "category": None,
        "tier": None,
    }
    parameters.update(overrides)
    return assess_risk(advisory, **parameters)


def test_unremarkable_advisory_is_low_risk(advisory_factory) -> None:
    advisory = advisory_factory(facts=AdvisoryFacts(fixed_versions=["1.2.3"]))
    result = _assess(advisory)
    assert result.level == "低"
    assert result.reasons == ()


def test_exploited_unfixed_critical_on_edge_device_is_urgent(advisory_factory) -> None:
    advisory = advisory_factory(
        facts=AdvisoryFacts(
            cvss_score=9.8,
            remote=True,
            authentication_required=False,
        ),
        enrichment=AdvisoryEnrichment(cisa_kev=True),
    )
    result = _assess(
        advisory,
        severity="Critical",
        exploited=True,
        poc_public=True,
        category="network_security",
        tier=Tier.EDGE,
    )
    assert result.score == 100
    assert result.level == "緊急"
    assert result.reasons == (
        "悪用確認済み（CISA KEV）",
        "PoC公開済み",
        "修正版未提供",
        "認証不要でリモート攻撃可能",
        "境界機器（侵入起点になりやすい）",
    )


def test_recent_fix_scores_higher_than_old_fix(advisory_factory) -> None:
    recent = advisory_factory(
        updated_at=datetime(2026, 7, 10, tzinfo=UTC),
        facts=AdvisoryFacts(cvss_score=8.0, fixed_versions=["2.0"]),
    )
    old = advisory_factory(
        updated_at=datetime(2026, 1, 10, tzinfo=UTC),
        facts=AdvisoryFacts(cvss_score=8.0, fixed_versions=["2.0"]),
    )
    recent_risk = _assess(recent, severity="High")
    old_risk = _assess(old, severity="High")
    assert recent_risk.score == old_risk.score + 8
    assert "修正公開から日が浅く未適用の組織が多い可能性" in recent_risk.reasons
    assert old_risk.reasons == ()


def test_widely_used_middleware_and_own_assets_add_risk(advisory_factory) -> None:
    advisory = advisory_factory(
        facts=AdvisoryFacts(cvss_score=7.5, fixed_versions=["3.1"], remote=True),
        updated_at=datetime(2026, 1, 1, tzinfo=UTC),
        enrichment=AdvisoryEnrichment(asset_match=True, internet_exposed=True),
    )
    result = _assess(advisory, severity="High", category="os_middleware_application")
    assert result.score == 22 + 8 + 5 + 10 + 10
    assert result.level == "高"
    assert result.reasons == (
        "リモート攻撃可能",
        "広く利用されるOS・ミドルウェア",
        "自組織資産と一致",
        "インターネット公開資産",
    )


def test_load_source_catalog_returns_empty_for_missing_file(tmp_path: Path) -> None:
    assert load_source_catalog(tmp_path / "missing.yaml") == {}


def test_load_source_catalog_maps_real_sources() -> None:
    catalog = load_source_catalog()
    category, tier = catalog["cisco"]
    assert category == "network_security"
    assert tier == Tier.EDGE
