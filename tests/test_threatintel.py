from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from vulnwatch.threatintel import (
    IndicatorRole,
    IndicatorType,
    ThreatCampaign,
    ThreatIndicator,
    ThreatIntelStore,
    VulnThreatActivity,
    export_csv,
    export_misp,
    export_stix,
    normalize_indicator,
    refang,
)

NOW = datetime(2026, 7, 27, tzinfo=UTC)
EARLIER = datetime(2026, 7, 20, tzinfo=UTC)
SOURCE = "https://unit42.paloaltonetworks.com/example"


def _indicator(**over: object) -> ThreatIndicator:
    base: dict[str, object] = {
        "type": IndicatorType.IPV4,
        "value": "45.61.136.14",
        "role": IndicatorRole.C2,
        "source_id": "unit42",
        "url": SOURCE,
    }
    base.update(over)
    return ThreatIndicator(**base)  # type: ignore[arg-type]


def _activity(**over: object) -> VulnThreatActivity:
    base: dict[str, object] = {
        "vuln_id": "VW-2026-0001",
        "cve": "CVE-2026-1281",
        "campaigns": [ThreatCampaign(name="Example Campaign", malware=["ValleyRAT"])],
        "indicators": [_indicator()],
        "updated_at": NOW,
    }
    base.update(over)
    return VulnThreatActivity(**base)  # type: ignore[arg-type]


# --- 正規化 -----------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1.2.3[.]4", "1.2.3.4"),
        ("1.2.3(.)4", "1.2.3.4"),
        ("hxxp://evil.test/a", "http://evil.test/a"),
        ("hxxps://evil.test", "https://evil.test"),
    ],
)
def test_defanged_values_are_restored(raw: str, expected: str) -> None:
    assert refang(raw) == expected


def test_values_are_normalised_for_cross_source_joining() -> None:
    # The portal joins sources on these values, so casing and defanging must not differ.
    assert normalize_indicator(IndicatorType.DOMAIN, "Evil[.]TEST.") == "evil.test"
    assert normalize_indicator(IndicatorType.SHA256, "AB" * 32) == "ab" * 32
    assert (
        normalize_indicator(IndicatorType.URL, "hxxps://Evil.TEST/PathCase")
        == "https://evil.test/PathCase"
    )


def test_indicator_stores_the_normalised_value() -> None:
    assert _indicator(type=IndicatorType.DOMAIN, value="Evil[.]Test").value == "evil.test"


# --- 捏造・取り違えへの防御 ---------------------------------------------------


def test_indicator_requires_an_https_source_url() -> None:
    # An indicator with no verifiable source is exactly what a hallucination looks like.
    with pytest.raises(ValidationError):
        _indicator(url="http://insecure.example/report")


@pytest.mark.parametrize("value", ["10.0.0.5", "192.168.1.1", "127.0.0.1", "169.254.1.1"])
def test_private_addresses_are_refused_as_attacker_infrastructure(value: str) -> None:
    # These would be our own assets, not the attacker's. Keep them out of the ledger.
    with pytest.raises(ValidationError):
        _indicator(value=value)


@pytest.mark.parametrize("value", ["203.0.113.10", "192.0.2.1", "198.51.100.7"])
def test_documentation_addresses_are_refused(value: str) -> None:
    # RFC 5737 ranges cannot be real attacker infrastructure, and they are precisely what
    # a language model invents when it has no real indicator to report, so rejecting them
    # doubles as a fabrication check.
    with pytest.raises(ValidationError):
        _indicator(value=value)


@pytest.mark.parametrize(
    ("indicator_type", "value"),
    [
        (IndicatorType.SHA256, "abc123"),
        (IndicatorType.MD5, "not-a-hash-value-at-all-nope-1234"),
        (IndicatorType.IPV4, "2001:db8::1"),
        (IndicatorType.DOMAIN, "https://evil.test/path"),
        (IndicatorType.URL, "evil.test"),
    ],
)
def test_malformed_indicators_are_refused(indicator_type: IndicatorType, value: str) -> None:
    with pytest.raises(ValidationError):
        _indicator(type=indicator_type, value=value)


def test_public_addresses_are_accepted() -> None:
    assert _indicator(value="45.61.136.14").value == "45.61.136.14"
    assert _indicator(type=IndicatorType.IPV6, value="2001:500:200::b").value == "2001:500:200::b"


# --- 統合 -------------------------------------------------------------------


def test_merge_keeps_earlier_observations_and_folds_duplicates() -> None:
    first = _activity()
    second = _activity(
        campaigns=[
            ThreatCampaign(
                name="example campaign",  # 大文字小文字違いは同じキャンペーン
                actors=["APT-Example"],
                malware=["Cobalt Strike"],
                first_reported=EARLIER,
            )
        ],
        indicators=[_indicator(), _indicator(type=IndicatorType.DOMAIN, value="c2.example.test")],
        updated_at=NOW,
    )

    merged = first.merge(second)

    assert len(merged.campaigns) == 1
    campaign = merged.campaigns[0]
    assert campaign.actors == ["APT-Example"]
    assert campaign.malware == ["Cobalt Strike", "ValleyRAT"]
    assert campaign.first_reported == EARLIER
    # The duplicate indicator is folded; the new one is kept.
    assert [item.value for item in merged.indicators] == ["c2.example.test", "45.61.136.14"]


def test_store_merges_into_an_existing_entry(tmp_path: Path) -> None:
    store = ThreatIntelStore(tmp_path)
    store.apply(_activity())
    store.apply(
        _activity(indicators=[_indicator(type=IndicatorType.SHA256, value="cd" * 32)])
    )

    loaded = store.load("VW-2026-0001")
    assert loaded is not None
    assert len(loaded.indicators) == 2
    assert [activity.vuln_id for activity in store.iter_activities()] == ["VW-2026-0001"]


def test_store_returns_none_for_unknown_entries(tmp_path: Path) -> None:
    assert ThreatIntelStore(tmp_path).load("VW-2026-9999") is None


# --- エクスポート -------------------------------------------------------------


def test_csv_export_flattens_indicators_with_their_context() -> None:
    rows = export_csv([_activity()]).splitlines()

    assert rows[0].startswith("type,value,role,vuln_id,cve")
    assert "ipv4,45.61.136.14,c2,VW-2026-0001,CVE-2026-1281,Example Campaign,ValleyRAT" in rows[1]
    assert SOURCE in rows[1]


def test_stix_export_is_a_valid_bundle_with_stable_ids() -> None:
    first = export_stix([_activity()], generated_at=NOW)
    second = export_stix([_activity()], generated_at=NOW)

    assert first["type"] == "bundle"
    objects = first["objects"]
    assert isinstance(objects, list)
    indicator = objects[0]
    assert indicator["pattern"] == "[ipv4-addr:value = '45.61.136.14']"
    assert indicator["external_references"][0]["url"] == SOURCE
    # Regenerating must not churn IDs, otherwise every run looks like a change.
    assert first == second
    json.dumps(first)  # serialisable


def test_misp_export_emits_one_event_per_vulnerability() -> None:
    events = export_misp([_activity()], generated_at=NOW)["response"]

    assert isinstance(events, list)
    event = events[0]["Event"]
    assert event["Attribute"][0]["type"] == "ip-dst"
    assert event["Attribute"][0]["value"] == "45.61.136.14"
    assert {"name": "CVE-2026-1281"} in event["Tag"]
    json.dumps(events)


def test_exports_skip_vulnerabilities_without_indicators() -> None:
    empty = _activity(indicators=[])

    assert export_csv([empty]).strip().count("\n") == 0  # header only
    assert export_misp([empty], generated_at=NOW)["response"] == []
