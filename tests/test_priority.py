from vulnwatch.models import (
    AdvisoryEnrichment,
    AdvisoryFacts,
    Exposure,
    Priority,
    ProductAsset,
    ProductRegistry,
)
from vulnwatch.priority import decide_priority, enrich_assets


def test_asset_matching_uses_vendor_and_exact_normalized_alias() -> None:
    registry = ProductRegistry(
        products=[
            ProductAsset(
                id="edge-fw",
                vendor="Palo Alto Networks",
                names=["PAN-OS"],
                aliases=["PAN OS"],
                exposure=Exposure.INTERNET,
                owner="network",
            )
        ]
    )

    enrichment = enrich_assets("Palo Alto Networks", ["PAN_OS"], registry)

    assert enrichment.asset_match
    assert enrichment.internet_exposed
    assert enrichment.matched_asset_ids == ["edge-fw"]


def test_priority_rules() -> None:
    matched = AdvisoryEnrichment(asset_match=True)
    assert decide_priority(AdvisoryFacts(known_exploited=True), matched).priority == Priority.P1
    assert (
        decide_priority(
            AdvisoryFacts(remote=True, authentication_required=False),
            AdvisoryEnrichment(asset_match=True, internet_exposed=True),
        ).priority
        == Priority.P1
    )
    assert (
        decide_priority(
            AdvisoryFacts(vendor_severity="Critical", fixed_versions=["2.0"]), matched
        ).priority
        == Priority.P2
    )
    assert decide_priority(AdvisoryFacts(), matched).priority == Priority.P3
    assert decide_priority(AdvisoryFacts(), AdvisoryEnrichment()).priority == Priority.INFO


def test_asset_matching_ignores_disabled_assets_and_wrong_vendors() -> None:
    registry = ProductRegistry(
        products=[
            ProductAsset(
                id="disabled",
                vendor="Example",
                names=["Product"],
                exposure=Exposure.INTERNET,
                owner="team",
                enabled=False,
            ),
            ProductAsset(
                id="wrong-vendor",
                vendor="Other",
                names=["Product"],
                exposure=Exposure.INTERNET,
                owner="team",
            ),
        ]
    )

    enrichment = enrich_assets("Example", ["Product"], registry)

    assert not enrichment.asset_match
    assert not enrichment.internet_exposed
    assert enrichment.matched_asset_ids == []


def test_cisa_kev_promotes_matched_asset_to_p1() -> None:
    decision = decide_priority(AdvisoryFacts(), AdvisoryEnrichment(asset_match=True, cisa_kev=True))

    assert decision.priority == Priority.P1
    assert decision.reasons == ["資産一致かつ悪用確認済み"]


def test_high_severity_requires_fixed_version_for_p2() -> None:
    decision = decide_priority(
        AdvisoryFacts(vendor_severity="High"), AdvisoryEnrichment(asset_match=True)
    )

    assert decision.priority == Priority.P3
