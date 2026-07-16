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
