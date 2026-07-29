"""脆弱性ごとの攻撃活動（キャンペーン・マルウェア・IOC）の台帳。

`vulndb/` が「その脆弱性が存在し、修正され、悪用されたか」を追うのに対し、ここでは
「誰が、何を使って、どのインフラから悪用しているか」を追う。出所は Claude routine による
公開情報の調査で、結果をこのモジュールが検証してから保存する。

調査は言語モデルが行うため、**出典に実在しない値が混入する危険**が本質的にある。そのため
保存側で次を強制する。

- すべての指標に出典 URL を要求する。
- 値を正規化する（defang 解除・小文字化）。ポータルは正規化済みの値でソースを横断して
  束ねるため、表記揺れがあると横串が切れる。
- プライベート/予約アドレスを拒否する。攻撃者インフラの台帳に自組織の内部アドレスが
  紛れ込むことを、仕組みとして防ぐ。

保存先は `vulndb/iocs/<vuln_id>.yaml`、エクスポートは `vulndb/exports/`。
"""

from __future__ import annotations

import csv
import io
import ipaddress
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path

from pydantic import Field, field_validator
from ruamel.yaml import YAML

from vulnwatch.models import StrictModel
from vulnwatch.storage.filesystem import atomic_write_text

IOCS_DIRECTORY = "iocs"
EXPORTS_DIRECTORY = "exports"

_HASH_LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}
_HEX = re.compile(r"^[0-9a-f]+$")


class IndicatorType(StrEnum):
    """ポータル連携仕様の `ioc.*` 語彙に対応する。"""

    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"


class IndicatorRole(StrEnum):
    """その指標が攻撃のどこに現れたか。"""

    SCANNER = "scanner"
    C2 = "c2"
    PAYLOAD = "payload"
    PHISHING = "phishing"
    INFRASTRUCTURE = "infrastructure"


def refang(value: str) -> str:
    """`1.2.3[.]4` や `hxxp://` のような防御的表記を元に戻す。"""

    text = value.strip()
    for marker, replacement in (
        ("[.]", "."),
        ("(.)", "."),
        ("[:]", ":"),
        ("[at]", "@"),
        ("[@]", "@"),
    ):
        text = text.replace(marker, replacement)
    return re.sub(r"^h(?:xx|XX)p", "http", text)


def normalize_indicator(indicator_type: IndicatorType, value: str) -> str:
    """種別ごとの正規化。ポータルはこの形の値で横串を作る。"""

    text = refang(value)
    if indicator_type in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}:
        return text.lower()
    if indicator_type is IndicatorType.DOMAIN:
        return text.lower().rstrip(".")
    if indicator_type is IndicatorType.URL:
        # スキームとホストだけ小文字化する。パスは大文字小文字を区別しうるため触らない。
        match = re.match(r"^([A-Za-z][A-Za-z0-9+.-]*://)([^/?#]+)(.*)$", text)
        if match:
            return f"{match.group(1).lower()}{match.group(2).lower()}{match.group(3)}"
        return text
    return text.lower()


def _reject_non_public_address(indicator_type: IndicatorType, value: str) -> None:
    """自組織側のアドレスが攻撃者インフラとして保存されるのを防ぐ。"""

    if indicator_type not in {IndicatorType.IPV4, IndicatorType.IPV6}:
        return
    address = ipaddress.ip_address(value)
    if not address.is_global:
        raise ValueError(
            f"indicator must be a public address; refusing non-routable value: {value}"
        )


class ThreatIndicator(StrictModel):
    """攻撃者インフラの指標。出典 URL を必ず伴う。"""

    type: IndicatorType
    value: str
    role: IndicatorRole = IndicatorRole.INFRASTRUCTURE
    source_id: str
    # 出典。ここに実在しない値は保存しない、という前提を型で示す。
    url: str
    first_seen: datetime | None = None

    @field_validator("value")
    @classmethod
    def normalize_value(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        indicator_type = info.data.get("type")
        if indicator_type is None:
            return value.strip()
        normalized = normalize_indicator(indicator_type, value)
        if not normalized:
            raise ValueError("indicator value must not be empty")
        _validate_shape(indicator_type, normalized)
        _reject_non_public_address(indicator_type, normalized)
        return normalized

    @field_validator("url")
    @classmethod
    def require_https_source(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("indicator source URL must be an HTTPS URL")
        return value


def _validate_shape(indicator_type: IndicatorType, value: str) -> None:
    if indicator_type in _HASH_LENGTHS:
        expected = _HASH_LENGTHS[indicator_type]
        if len(value) != expected or not _HEX.match(value):
            raise ValueError(f"{indicator_type} must be {expected} hex characters: {value}")
    elif indicator_type is IndicatorType.IPV4:
        if ipaddress.ip_address(value).version != 4:
            raise ValueError(f"not an IPv4 address: {value}")
    elif indicator_type is IndicatorType.IPV6:
        if ipaddress.ip_address(value).version != 6:
            raise ValueError(f"not an IPv6 address: {value}")
    elif indicator_type is IndicatorType.DOMAIN:
        if "/" in value or " " in value or "." not in value:
            raise ValueError(f"not a bare domain: {value}")
    elif indicator_type is IndicatorType.URL and "://" not in value:
        raise ValueError(f"not an absolute URL: {value}")


class ThreatCampaign(StrictModel):
    """脆弱性を悪用している攻撃活動。名称・攻撃者・マルウェアを出典つきで持つ。"""

    name: str
    actors: list[str] = Field(default_factory=list)
    malware: list[str] = Field(default_factory=list)
    first_reported: datetime | None = None
    references: list[str] = Field(default_factory=list)
    summary: str = ""


class VulnThreatActivity(StrictModel):
    """1 脆弱性ぶんの攻撃活動。"""

    schema_version: int = 1
    vuln_id: str
    cve: str | None = None
    campaigns: list[ThreatCampaign] = Field(default_factory=list)
    indicators: list[ThreatIndicator] = Field(default_factory=list)
    updated_at: datetime

    def merge(self, other: VulnThreatActivity) -> VulnThreatActivity:
        """調査結果を取り込む。既存の観測は消さず、重複だけを畳む。"""

        campaigns = {campaign.name.casefold(): campaign for campaign in self.campaigns}
        for campaign in other.campaigns:
            key = campaign.name.casefold()
            existing = campaigns.get(key)
            if existing is None:
                campaigns[key] = campaign
                continue
            campaigns[key] = existing.model_copy(
                update={
                    "actors": sorted(set(existing.actors) | set(campaign.actors)),
                    "malware": sorted(set(existing.malware) | set(campaign.malware)),
                    "references": sorted(set(existing.references) | set(campaign.references)),
                    # 最初に報じられた日付は最も古いものを残す。
                    "first_reported": min(
                        [
                            value
                            for value in (existing.first_reported, campaign.first_reported)
                            if value is not None
                        ],
                        default=None,
                    ),
                    "summary": existing.summary or campaign.summary,
                }
            )
        indicators = {(item.type, item.value): item for item in self.indicators}
        for indicator in other.indicators:
            indicators.setdefault((indicator.type, indicator.value), indicator)
        return self.model_copy(
            update={
                "campaigns": sorted(campaigns.values(), key=lambda item: item.name),
                "indicators": sorted(indicators.values(), key=lambda item: (item.type, item.value)),
                "cve": self.cve or other.cve,
                "updated_at": max(self.updated_at, other.updated_at),
            }
        )

    @property
    def malware_names(self) -> list[str]:
        return sorted({name for campaign in self.campaigns for name in campaign.malware})

    @property
    def actor_names(self) -> list[str]:
        return sorted({name for campaign in self.campaigns for name in campaign.actors})


class ThreatIntelStore:
    """`vulndb/iocs/` に置く攻撃活動の読み書き。"""

    def __init__(self, root: Path) -> None:
        self.root = root / "vulndb" / IOCS_DIRECTORY
        self.exports_root = root / "vulndb" / EXPORTS_DIRECTORY

    def path_for(self, vuln_id: str) -> Path:
        return self.root / f"{vuln_id}.yaml"

    def load(self, vuln_id: str) -> VulnThreatActivity | None:
        path = self.path_for(vuln_id)
        if not path.exists():
            return None
        yaml = YAML(typ="safe")
        return VulnThreatActivity.model_validate(yaml.load(path.read_text(encoding="utf-8")))

    def save(self, activity: VulnThreatActivity) -> Path:
        yaml = YAML(typ="safe")
        yaml.default_flow_style = False
        buffer = io.StringIO()
        yaml.dump(activity.model_dump(mode="json", exclude_none=True), buffer)
        path = self.path_for(activity.vuln_id)
        atomic_write_text(path, buffer.getvalue())
        return path

    def apply(self, activity: VulnThreatActivity) -> VulnThreatActivity:
        """既存があれば統合してから保存する。"""

        existing = self.load(activity.vuln_id)
        merged = existing.merge(activity) if existing else activity
        self.save(merged)
        return merged

    def iter_activities(self) -> Iterator[VulnThreatActivity]:
        if not self.root.exists():
            return
        yaml = YAML(typ="safe")
        for path in sorted(self.root.glob("*.yaml")):
            yield VulnThreatActivity.model_validate(yaml.load(path.read_text(encoding="utf-8")))


EXPORT_COLUMNS = (
    "type",
    "value",
    "role",
    "vuln_id",
    "cve",
    "campaigns",
    "malware",
    "actors",
    "source_id",
    "reference",
    "first_seen",
)


def export_csv(activities: list[VulnThreatActivity]) -> str:
    """他ツールへ渡すための平坦な一覧。"""

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(EXPORT_COLUMNS)
    for activity in activities:
        campaigns = ";".join(campaign.name for campaign in activity.campaigns)
        malware = ";".join(activity.malware_names)
        actors = ";".join(activity.actor_names)
        for indicator in activity.indicators:
            writer.writerow(
                [
                    indicator.type,
                    indicator.value,
                    indicator.role,
                    activity.vuln_id,
                    activity.cve or "",
                    campaigns,
                    malware,
                    actors,
                    indicator.source_id,
                    indicator.url,
                    indicator.first_seen.date().isoformat() if indicator.first_seen else "",
                ]
            )
    return buffer.getvalue()


_STIX_PATTERN = {
    IndicatorType.IPV4: "[ipv4-addr:value = '{value}']",
    IndicatorType.IPV6: "[ipv6-addr:value = '{value}']",
    IndicatorType.DOMAIN: "[domain-name:value = '{value}']",
    IndicatorType.URL: "[url:value = '{value}']",
    IndicatorType.MD5: "[file:hashes.'MD5' = '{value}']",
    IndicatorType.SHA1: "[file:hashes.'SHA-1' = '{value}']",
    IndicatorType.SHA256: "[file:hashes.'SHA-256' = '{value}']",
}


def export_stix(activities: list[VulnThreatActivity]) -> dict[str, object]:
    """STIX 2.1 バンドル。

    出力は入力データだけから決まります。実行時刻を引数に取らないのは、内容が
    変わっていないのに毎回差分が出ると、本当の更新が埋もれてしまうためです。
    """

    objects: list[dict[str, object]] = []
    for activity in activities:
        # 生成時刻ではなくデータ側の更新時刻を使う。実行のたびに created/modified が
        # 動くと、内容が変わっていなくても毎回差分が出てしまうため。
        stamp = _stix_time(activity.updated_at)
        for indicator in activity.indicators:
            labels = [indicator.role.value]
            if activity.cve:
                labels.append(activity.cve)
            objects.append(
                {
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": f"indicator--{_deterministic_uuid(indicator.type, indicator.value)}",
                    "created": stamp,
                    "modified": stamp,
                    "name": f"{indicator.type}: {indicator.value}",
                    "description": (
                        f"{activity.cve or activity.vuln_id} の悪用に関連して "
                        f"{indicator.source_id} が報告した攻撃者インフラ。出典: {indicator.url}"
                    ),
                    "pattern": _STIX_PATTERN[indicator.type].format(value=indicator.value),
                    "pattern_type": "stix",
                    "valid_from": _stix_time(indicator.first_seen or activity.updated_at),
                    "labels": labels,
                    "external_references": [
                        {"source_name": indicator.source_id, "url": indicator.url}
                    ],
                }
            )
    # バンドル ID も内容から導く。生成時刻に依存させると毎回変わってしまう。
    fingerprint = "|".join(str(item["id"]) for item in objects)
    return {
        "type": "bundle",
        "id": f"bundle--{_deterministic_uuid('bundle', fingerprint)}",
        "objects": objects,
    }


def _stix_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


_MISP_TYPES = {
    IndicatorType.IPV4: "ip-dst",
    IndicatorType.IPV6: "ip-dst",
    IndicatorType.DOMAIN: "domain",
    IndicatorType.URL: "url",
    IndicatorType.MD5: "md5",
    IndicatorType.SHA1: "sha1",
    IndicatorType.SHA256: "sha256",
}


def export_misp(activities: list[VulnThreatActivity]) -> dict[str, object]:
    """MISP イベント形式。脆弱性 1 件を 1 イベントとして表す。

    STIX と同様、出力は入力データだけから決まります。
    """

    events: list[dict[str, object]] = []
    for activity in activities:
        if not activity.indicators:
            continue
        events.append(
            {
                "Event": {
                    "uuid": _deterministic_uuid("event", activity.vuln_id),
                    "info": (f"{activity.cve or activity.vuln_id} の悪用に関連する攻撃者インフラ"),
                    "date": activity.updated_at.date().isoformat(),
                    "threat_level_id": "2",
                    "analysis": "1",
                    "Attribute": [
                        {
                            "type": _MISP_TYPES[indicator.type],
                            "category": "Network activity"
                            if indicator.type
                            not in {IndicatorType.MD5, IndicatorType.SHA1, IndicatorType.SHA256}
                            else "Payload delivery",
                            "value": indicator.value,
                            "to_ids": True,
                            "comment": (
                                f"{indicator.role} / {indicator.source_id} / {indicator.url}"
                            ),
                        }
                        for indicator in activity.indicators
                    ],
                    "Tag": [
                        {"name": f'misp-galaxy:malware="{name}"'} for name in activity.malware_names
                    ]
                    + ([{"name": activity.cve}] if activity.cve else []),
                }
            }
        )
    return {"response": events}


def _deterministic_uuid(*parts: str) -> str:
    """同じ入力からは同じ ID を作る。再生成のたびに差分が出るのを避ける。"""

    import hashlib
    import uuid

    digest = hashlib.sha256("|".join(parts).encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest[:16], version=4))
