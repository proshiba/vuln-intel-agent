from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnwatch.models import AdvisoryEnrichment, AdvisoryFacts, Tier
from vulnwatch.risk import assess_risk, load_source_catalog

REPORT_TIME = datetime(2026, 7, 18, 9, 0, tzinfo=UTC)
# advisory_factory の既定の公開日(2026-07-01)は REPORT_TIME から17日前で、
# 新しさの加点が付く。加点を避けたいテストではこの日付を明示的に上書きする。
LONG_AGO = datetime(2025, 1, 1, tzinfo=UTC)


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
    advisory = advisory_factory(
        facts=AdvisoryFacts(fixed_versions=["1.2.3"]), published_at=LONG_AGO
    )
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
        "公開・修正から30日以内（17日）",
        "認証不要でリモート攻撃可能",
        "境界機器（侵入起点になりやすい）",
    )


def test_freshly_published_outranks_the_same_flaw_from_last_year(advisory_factory) -> None:
    # 攻撃側は公開直後に飛びつき、防御側はまだ適用が済んでいない。同じ深刻度でも
    # 新しいほうを上に出さないと、日次レポートで見るべきものが埋もれる。
    facts = AdvisoryFacts(cvss_score=8.0, fixed_versions=["2.0"])
    fresh = advisory_factory(published_at=datetime(2026, 7, 10, tzinfo=UTC), facts=facts)
    stale = advisory_factory(published_at=LONG_AGO, facts=facts)

    fresh_risk = _assess(fresh, severity="High")
    stale_risk = _assess(stale, severity="High")

    assert fresh_risk.score == stale_risk.score + 15
    assert "公開・修正から30日以内（8日）" in fresh_risk.reasons
    assert stale_risk.reasons == ()


def test_recency_falls_off_in_two_steps(advisory_factory) -> None:
    facts = AdvisoryFacts(cvss_score=8.0, fixed_versions=["2.0"])

    def score_for(published: datetime) -> int:
        return _assess(advisory_factory(published_at=published, facts=facts), severity="High").score

    within_30 = score_for(REPORT_TIME - timedelta(days=29))
    within_90 = score_for(REPORT_TIME - timedelta(days=89))
    older = score_for(REPORT_TIME - timedelta(days=91))

    assert within_30 == within_90 + 8
    assert within_90 == older + 7


def test_a_revised_advisory_counts_as_recent_even_if_first_published_long_ago(
    advisory_factory,
) -> None:
    # ベンダーが古い CVE のアドバイザリを改訂するのは、修正版の提供や影響範囲の
    # 変更を伴うことが多い。公開日だけを見ると、その動きを取り逃がす。
    advisory = advisory_factory(
        published_at=LONG_AGO,
        updated_at=datetime(2026, 7, 10, tzinfo=UTC),
        facts=AdvisoryFacts(cvss_score=8.0, fixed_versions=["2.0"]),
    )

    assert "公開・修正から30日以内（8日）" in _assess(advisory, severity="High").reasons


def test_missing_dates_earn_no_recency_points(advisory_factory) -> None:
    # 日付が欠けているだけの脆弱性を、新しいものとして扱う根拠はない。
    advisory = advisory_factory(
        published_at=None, facts=AdvisoryFacts(cvss_score=8.0, fixed_versions=["2.0"])
    )

    assert _assess(advisory, severity="High").reasons == ()


def test_a_future_publication_date_does_not_produce_a_negative_age(advisory_factory) -> None:
    # 収集元が未来の日付を返すことがある。経過日数が負になっても壊れないこと。
    advisory = advisory_factory(
        published_at=REPORT_TIME + timedelta(days=3),
        facts=AdvisoryFacts(cvss_score=8.0, fixed_versions=["2.0"]),
    )

    assert "公開・修正から30日以内（0日）" in _assess(advisory, severity="High").reasons


def test_widely_used_middleware_and_own_assets_add_risk(advisory_factory) -> None:
    advisory = advisory_factory(
        facts=AdvisoryFacts(cvss_score=7.5, fixed_versions=["3.1"], remote=True),
        published_at=LONG_AGO,
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
