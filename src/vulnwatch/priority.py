from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass

from vulnwatch.models import (
    AdvisoryDecision,
    AdvisoryEnrichment,
    AdvisoryFacts,
    Exposure,
    Priority,
    ProductAsset,
    ProductRegistry,
)

_HIGH_SEVERITIES = frozenset({"critical", "high", "important"})


def _normalize(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    return re.sub(r"[^a-z0-9]+", "", normalized)


def _asset_alias_keys(asset: ProductAsset) -> set[str]:
    return {_normalize(name) for name in (*asset.names, *asset.aliases)}


def _is_enabled_vendor_asset(asset: ProductAsset, vendor_key: str) -> bool:
    return asset.enabled and _normalize(asset.vendor) == vendor_key


def match_assets(vendor: str, products: list[str], registry: ProductRegistry) -> list[ProductAsset]:
    vendor_key = _normalize(vendor)
    product_keys = {_normalize(product) for product in products}
    return [
        asset
        for asset in registry.products
        if _is_enabled_vendor_asset(asset, vendor_key) and _asset_alias_keys(asset) & product_keys
    ]


def enrich_assets(
    vendor: str, products: list[str], registry: ProductRegistry
) -> AdvisoryEnrichment:
    matches = match_assets(vendor, products, registry)
    return AdvisoryEnrichment(
        asset_match=bool(matches),
        matched_asset_ids=sorted(asset.id for asset in matches),
        internet_exposed=any(asset.exposure == Exposure.INTERNET for asset in matches),
    )


@dataclass(frozen=True)
class _PriorityRule:
    priority: Priority
    reason: str
    applies: Callable[[AdvisoryFacts, AdvisoryEnrichment], bool]


def _asset_exploited(facts: AdvisoryFacts, enrichment: AdvisoryEnrichment) -> bool:
    return enrichment.asset_match and (enrichment.cisa_kev or facts.known_exploited is True)


def _remote_unauthenticated_internet_asset(
    facts: AdvisoryFacts, enrichment: AdvisoryEnrichment
) -> bool:
    return (
        enrichment.asset_match
        and enrichment.internet_exposed
        and facts.remote is True
        and facts.authentication_required is False
    )


def _high_severity_with_fix(facts: AdvisoryFacts, enrichment: AdvisoryEnrichment) -> bool:
    severity = (facts.vendor_severity or "").casefold()
    return enrichment.asset_match and severity in _HIGH_SEVERITIES and bool(facts.fixed_versions)


def _any_asset_match(_facts: AdvisoryFacts, enrichment: AdvisoryEnrichment) -> bool:
    return enrichment.asset_match


_PRIORITY_RULES = (
    _PriorityRule(Priority.P1, "資産一致かつ悪用確認済み", _asset_exploited),
    _PriorityRule(
        Priority.P1,
        "インターネット公開資産で認証不要のリモート攻撃が可能",
        _remote_unauthenticated_internet_asset,
    ),
    _PriorityRule(Priority.P2, "資産一致、高深刻度、修正版あり", _high_severity_with_fix),
    _PriorityRule(Priority.P3, "資産一致、攻撃条件または修正版を要確認", _any_asset_match),
)


def decide_priority(facts: AdvisoryFacts, enrichment: AdvisoryEnrichment) -> AdvisoryDecision:
    for rule in _PRIORITY_RULES:
        if rule.applies(facts, enrichment):
            return AdvisoryDecision(priority=rule.priority, reasons=[rule.reason])
    return AdvisoryDecision(priority=Priority.INFO, reasons=["資産不一致または判定情報不足"])
