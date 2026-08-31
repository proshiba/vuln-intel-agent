from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vulnwatch.config import ConfigError, load_sources
from vulnwatch.models import Advisory, SurfaceReach, Tier

RISK_LEVELS = ("緊急", "高", "中", "低")
_BASE_POINTS = {"Critical": 30, "High": 22, "Moderate": 12, "その他": 5}
# 公開または修正からの経過日数による加点。新しい脆弱性ほど、攻撃側が飛びつきやすく
# 防御側の適用が済んでいないため重く扱う。(日数上限, 加点, 表示ラベル) を新しい順に並べる。
_RECENCY_TIERS: tuple[tuple[int, int, str], ...] = (
    (30, 15, "公開・修正から30日以内"),
    (90, 7, "公開・修正から90日以内"),
)
_CATEGORY_FACTORS = {
    "network_security": (10, "境界機器（侵入起点になりやすい）"),
    "server_virtualization": (6, "サーバー・仮想化基盤（機密情報が集中）"),
    "os_middleware_application": (5, "広く利用されるOS・ミドルウェア"),
    "ot_iot_camera": (5, "OT・IoT機器"),
}


@dataclass(frozen=True)
class RiskAssessment:
    score: int
    level: str
    reasons: tuple[str, ...]


def load_source_catalog(path: Path = Path("config/sources.yaml")) -> dict[str, tuple[str, Tier]]:
    """ソースID→（カテゴリ、tier）の対応表。設定が無い環境では空を返す。"""

    if not path.is_file():
        return {}
    try:
        registry = load_sources(path)
    except ConfigError:
        return {}
    return {source.id: (source.category, source.tier) for source in registry.sources}


def assess_risk(
    advisory: Advisory,
    *,
    severity: str,
    exploited: bool,
    poc_public: bool,
    report_time: datetime,
    category: str | None,
    tier: Tier | None,
) -> RiskAssessment:
    """レポート掲載アドバイザリの複合リスクを決定論的に採点する。

    CVSS・ベンダー深刻度、悪用確認とPoC公開の有無、修正提供状況、公開・修正からの
    経過日数、攻撃経路、対象機器の利用され方（侵入起点・機密集中・普及度）、
    自組織資産との一致を加点し、レポート基準時刻に対して再現可能な値を返す。
    """

    score = _BASE_POINTS.get(severity, _BASE_POINTS["その他"])
    reasons: list[str] = []

    if advisory.enrichment.cisa_kev:
        score += 30
        reasons.append("悪用確認済み（CISA KEV）")
    elif exploited:
        score += 25
        reasons.append("悪用確認済み")
    if poc_public:
        score += 15
        reasons.append("PoC公開済み")

    if not advisory.facts.fixed_versions:
        score += 15
        reasons.append("修正版未提供")

    recency = _recency_points(advisory, report_time)
    if recency is not None:
        points, label = recency
        score += points
        reasons.append(label)

    if advisory.facts.remote is True and advisory.facts.authentication_required is False:
        score += 15
        reasons.append("認証不要でリモート攻撃可能")
    elif advisory.facts.remote is True:
        score += 8
        reasons.append("リモート攻撃可能")

    factor = _CATEGORY_FACTORS.get(category or "")
    if tier == Tier.EDGE and category != "network_security":
        score += 10
        reasons.append("境界機器（侵入起点になりやすい）")
    elif factor is not None:
        points, label = factor
        score += points
        reasons.append(label)

    if advisory.enrichment.attack_surface_reach is SurfaceReach.NETWORK_PIVOT:
        # 1台の侵害が内部ネットワーク全体への足がかりになるため、他の面より重く見る。
        score += 12
        reasons.append("侵害されると内部ネットワークへ広く到達しうる機器")
    elif advisory.enrichment.attack_surface_class is not None:
        score += 6
        reasons.append("初期アクセスに悪用されやすい製品")

    if advisory.enrichment.asset_match:
        score += 10
        reasons.append("自組織資産と一致")
    if advisory.enrichment.internet_exposed:
        score += 10
        reasons.append("インターネット公開資産")

    score = min(score, 100)
    return RiskAssessment(score=score, level=_level(score), reasons=tuple(reasons))


def _recency_points(advisory: Advisory, report_time: datetime) -> tuple[int, str] | None:
    """公開または修正からの経過日数による加点を返す。該当しなければ None。

    公開日と更新日のうち新しいほうを基準にする。ベンダーがアドバイザリを更新するのは
    修正版の提供や影響範囲の改訂を伴うことが多く、その時点から改めて注目が集まるため。

    どちらの日付も無いエントリは加点しない。日付が欠けているだけの脆弱性を、
    古いものとして減点するのも新しいものとして加点するのも根拠がないため。
    """

    dates = [value for value in (advisory.published_at, advisory.updated_at) if value is not None]
    if not dates:
        return None
    # 収集元が未来の日付を返すことがある。負の経過日数で最上位の区分に落ちるのは
    # 意図した挙動なので、0 に丸めたうえで通常どおり判定する。
    elapsed = max((report_time - _aware(max(dates))).days, 0)
    for limit, points, label in _RECENCY_TIERS:
        if elapsed <= limit:
            return points, f"{label}（{elapsed}日）"
    return None


def _level(score: int) -> str:
    if score >= 70:
        return "緊急"
    if score >= 50:
        return "高"
    if score >= 30:
        return "中"
    return "低"


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
