from vulnwatch.models import (
    AdvisoryEnrichment,
    AdvisoryFacts,
    Exposure,
    Priority,
    ProductAsset,
    ProductRegistry,
    SurfaceReach,
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


# --- 初期アクセス面による引き上げ -------------------------------------------


def _facts(**over: object) -> AdvisoryFacts:
    base: dict[str, object] = {"products": ["Connect Secure"]}
    base.update(over)
    return AdvisoryFacts(**base)  # type: ignore[arg-type]


def _surface(class_id: str, reach: SurfaceReach) -> AdvisoryEnrichment:
    return AdvisoryEnrichment(attack_surface_class=class_id, attack_surface_reach=reach)


def test_exploited_edge_device_is_p1_without_an_asset_match() -> None:
    # config/products.yaml が空でも、悪用済みの境界機器を INFO に沈めてはいけない。
    enrichment = _surface("vpn_gateway", SurfaceReach.NETWORK_PIVOT)
    enrichment.cisa_kev = True

    decision = decide_priority(_facts(), enrichment)

    assert decision.priority is Priority.P1
    assert not enrichment.asset_match


def test_edge_devices_outrank_ordinary_services_at_the_same_severity() -> None:
    # 「広範なネットワークへ到達しうるか」が、同じ深刻度での差になる。
    facts = _facts(vendor_severity="High")
    pivot = decide_priority(facts, _surface("vpn_gateway", SurfaceReach.NETWORK_PIVOT))
    service = decide_priority(facts, _surface("file_transfer", SurfaceReach.SERVICE))

    assert pivot.priority is Priority.P2
    assert service.priority is Priority.INFO


def test_unauthenticated_remote_flaw_on_an_edge_device_is_p1() -> None:
    decision = decide_priority(
        _facts(remote=True, authentication_required=False),
        _surface("edge_network", SurfaceReach.NETWORK_PIVOT),
    )

    assert decision.priority is Priority.P1


def test_unclassified_products_stay_info() -> None:
    # 分類に無い製品まで引き上げると、45,000件の台帳がすべて P3 になって意味を失う。
    decision = decide_priority(_facts(vendor_severity="Critical"), AdvisoryEnrichment())

    assert decision.priority is Priority.INFO


def test_asset_match_still_wins_over_the_surface_heuristic() -> None:
    # 自組織の資産台帳は依然として最優先の根拠。
    enrichment = _surface("file_transfer", SurfaceReach.SERVICE)
    enrichment.asset_match = True
    enrichment.cisa_kev = True

    decision = decide_priority(_facts(), enrichment)

    assert decision.priority is Priority.P1
    assert decision.reasons == ["資産一致かつ悪用確認済み"]
