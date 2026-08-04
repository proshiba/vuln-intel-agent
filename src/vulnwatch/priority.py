from __future__ import annotations

import re
import unicodedata

from vulnwatch.models import (
    AdvisoryDecision,
    AdvisoryEnrichment,
    AdvisoryFacts,
    Exposure,
    Priority,
    ProductAsset,
    ProductRegistry,
    SurfaceReach,
)


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[^a-z0-9]+", "", normalized)


def match_assets(vendor: str, products: list[str], registry: ProductRegistry) -> list[ProductAsset]:
    vendor_key = _normalize(vendor)
    product_keys = {_normalize(product) for product in products}
    matches: list[ProductAsset] = []
    for asset in registry.products:
        if not asset.enabled or _normalize(asset.vendor) != vendor_key:
            continue
        aliases = {_normalize(name) for name in [*asset.names, *asset.aliases]}
        if aliases & product_keys:
            matches.append(asset)
    return matches


def enrich_assets(
    vendor: str, products: list[str], registry: ProductRegistry
) -> AdvisoryEnrichment:
    matches = match_assets(vendor, products, registry)
    return AdvisoryEnrichment(
        asset_match=bool(matches),
        matched_asset_ids=sorted(asset.id for asset in matches),
        internet_exposed=any(asset.exposure == Exposure.INTERNET for asset in matches),
    )


def decide_priority(facts: AdvisoryFacts, enrichment: AdvisoryEnrichment) -> AdvisoryDecision:
    if enrichment.asset_match and (enrichment.cisa_kev or facts.known_exploited is True):
        return AdvisoryDecision(priority=Priority.P1, reasons=["資産一致かつ悪用確認済み"])
    if (
        enrichment.asset_match
        and enrichment.internet_exposed
        and facts.remote is True
        and facts.authentication_required is False
    ):
        return AdvisoryDecision(
            priority=Priority.P1,
            reasons=["インターネット公開資産で認証不要のリモート攻撃が可能"],
        )
    severity = (facts.vendor_severity or "").casefold()
    if (
        enrichment.asset_match
        and severity in {"critical", "high", "important"}
        and facts.fixed_versions
    ):
        return AdvisoryDecision(priority=Priority.P2, reasons=["資産一致、高深刻度、修正版あり"])
    if enrichment.asset_match:
        return AdvisoryDecision(
            priority=Priority.P3, reasons=["資産一致、攻撃条件または修正版を要確認"]
        )
    return _decide_by_attack_surface(facts, enrichment)


def _decide_by_attack_surface(
    facts: AdvisoryFacts, enrichment: AdvisoryEnrichment
) -> AdvisoryDecision:
    """資産台帳に載っていない製品を、初期アクセス面としての重みで評価する。

    `config/products.yaml` に自組織の資産を登録していなくても、外部公開されやすく
    悪用の実績がある製品は放置できない。とくに VPN 装置・境界機器・リモート管理基盤は、
    1台の侵害が内部ネットワーク全体への足がかりになるため、その他のサービスより高く扱う。
    """

    surface = enrichment.attack_surface_class
    if surface is None:
        return AdvisoryDecision(priority=Priority.INFO, reasons=["資産不一致または判定情報不足"])

    pivot = enrichment.attack_surface_reach is SurfaceReach.NETWORK_PIVOT
    label = "境界・リモートアクセス機器" if pivot else "初期アクセス面の製品"

    if enrichment.cisa_kev or facts.known_exploited is True:
        return AdvisoryDecision(priority=Priority.P1, reasons=[f"{label}で悪用確認済み"])
    if pivot and facts.remote is True and facts.authentication_required is False:
        return AdvisoryDecision(
            priority=Priority.P1, reasons=[f"{label}に認証不要のリモート攻撃が可能"]
        )

    severity = (facts.vendor_severity or "").casefold()
    if pivot:
        # 境界機器は、侵害時に内部ネットワークへ広く到達しうる点だけで一段高く扱う。
        if severity in {"critical", "high", "important"}:
            return AdvisoryDecision(priority=Priority.P2, reasons=[f"{label}の高深刻度"])
        return AdvisoryDecision(priority=Priority.P3, reasons=[label])
    if severity == "critical":
        return AdvisoryDecision(priority=Priority.P3, reasons=[f"{label}のCritical"])
    return AdvisoryDecision(priority=Priority.INFO, reasons=[f"{label}（深刻度は低〜中）"])
