from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from vulnwatch.webapi import (
    build_entities,
    build_meta,
    build_search_document,
    build_threat_entities,
    encode_prefixes,
    expand_flags,
    scan_entry_prefixes,
)


def _entry(root: Path, prefix: str, vuln_id: str) -> None:
    path = root / prefix / f"{vuln_id}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"vuln_id: {vuln_id}\n", encoding="utf-8")


def test_scan_maps_entries_to_their_vendor_year_month(tmp_path: Path) -> None:
    _entry(tmp_path, "ivanti/2026/07", "VW-2026-0001")
    _entry(tmp_path, "microsoft/2025/12", "VW-2025-0009")

    assert scan_entry_prefixes(tmp_path) == {
        "VW-2026-0001": "ivanti/2026/07",
        "VW-2025-0009": "microsoft/2025/12",
    }


def test_scan_skips_flat_legacy_entries(tmp_path: Path) -> None:
    # A pre-migration entry sitting directly under vulns/ has no vendor/year/month to
    # build a detail URL from, so it must not appear with a bogus prefix.
    (tmp_path / "VW-2020-0001.yaml").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "VW-2020-0001.yaml").write_text("vuln_id: VW-2020-0001\n", encoding="utf-8")
    _entry(tmp_path, "ivanti/2026/07", "VW-2026-0001")

    assert scan_entry_prefixes(tmp_path) == {"VW-2026-0001": "ivanti/2026/07"}


def test_scan_returns_empty_when_ledger_absent(tmp_path: Path) -> None:
    assert scan_entry_prefixes(tmp_path / "missing") == {}


def test_prefixes_are_dictionary_encoded_and_reusable() -> None:
    prefixes = {
        "VW-2026-0001": "ivanti/2026/07",
        "VW-2026-0002": "ivanti/2026/07",
        "VW-2026-0003": "cisco/2026/07",
    }

    dictionary, encoded = encode_prefixes(
        ["VW-2026-0001", "VW-2026-0002", "VW-2026-0003"], prefixes
    )

    # The repeated prefix is stored once and referenced by index.
    assert dictionary == ["ivanti/2026/07", "cisco/2026/07"]
    assert encoded == [0, 0, 1]


def test_unknown_entries_encode_to_a_sentinel() -> None:
    dictionary, encoded = encode_prefixes(["VW-2026-0001"], {})

    assert dictionary == []
    assert encoded == [-1]


def test_meta_exposes_a_usable_detail_url_template() -> None:
    meta = build_meta(
        generated_at="2026-07-26T00:00:00+00:00",
        repository="proshiba/vuln-intel-agent",
        site_url="https://proshiba.github.io/vuln-intel-agent/",
        ref="main",
        stats={"total": 3},
        fields=["id", "cve"],
        flags={"kev": 8},
        attack_surfaces={"vpn_gateway": "VPN/リモートアクセス"},
    )

    template = meta["endpoints"]["detail_url_template"]
    resolved = template.format(prefix="ivanti/2026/07", vuln_id="VW-2026-0001")
    assert resolved == (
        "https://raw.githubusercontent.com/proshiba/vuln-intel-agent/main/"
        "vulndb/vulns/ivanti/2026/07/VW-2026-0001.yaml"
    )
    assert meta["endpoints"]["search"] == "api/v1/search.json"
    # Integrators (including agents) must be able to find the guide from meta alone.
    assert meta["endpoints"]["documentation"] == "INTEGRATION.md"
    assert meta["endpoints"]["openapi"] == "openapi.yaml"
    assert meta["cors"] is True
    assert meta["stats"]["total"] == 3


# --- ポータル連携仕様 v1 への準拠 -------------------------------------------
# research_bench の docs/portal-spec.md に対応する。仕様側にバリデータが用意されて
# いないため、準拠条件をここで検証する。

FIELDS = [
    "id",
    "cve",
    "vendors",
    "products",
    "title",
    "cvss",
    "sev",
    "prio",
    "flags",
    "pub",
    "upd",
    "asc",
    "lag",
    "prefix",
]
FLAGS = {"fixed": 1, "poc": 2, "exploited": 4, "kev": 8, "ransomware": 16}


def _row(**over: object) -> list[object]:
    base: dict[str, object] = {
        "id": "VW-2026-0001",
        "cve": "CVE-2026-1281",
        "vendors": "Ivanti",
        "products": "Connect Secure",
        "title": "RCE",
        "cvss": 9.8,
        "sev": "critical",
        "prio": "P1",
        "flags": 12,
        "pub": "2026-07-20",
        "upd": "2026-07-25",
        "asc": "vpn_gateway",
        "lag": 6,
        "prefix": 0,
    }
    base.update(over)
    return [base[name] for name in FIELDS]


def test_flags_bitmask_expands_to_names() -> None:
    assert sorted(expand_flags(12, FLAGS)) == ["exploited", "kev"]
    assert expand_flags(0, FLAGS) == []
    assert expand_flags("", FLAGS) == []


def test_entity_matches_the_portal_contract() -> None:
    entities = build_entities([_row()], FIELDS, FLAGS, ["ivanti/2026/07"])

    assert len(entities) == 1
    entity = entities[0]
    assert entity["type"] == "cve"
    assert entity["id"] == "vuln:VW-2026-0001"
    assert entity["label"] == "CVE-2026-1281"
    # value is the join key the portal uses to link sources; it must be the upper-case CVE.
    assert entity["value"] == "CVE-2026-1281"
    # detail is substituted into deep_links, which route by internal ID.
    assert entity["detail"] == "VW-2026-0001"
    attrs = entity["attrs"]
    assert attrs["題名"] == "RCE"
    assert attrs["優先度"] == "P1"
    assert attrs["攻撃面"] == "vpn_gateway"
    assert sorted(attrs["flags"]) == ["exploited", "kev"]
    # The portal builds the raw YAML URL from this, so it must be the string, not an index.
    assert attrs["prefix"] == "ivanti/2026/07"


def test_cve_value_is_upper_cased_for_joining() -> None:
    entities = build_entities([_row(cve="cve-2026-1281")], FIELDS, FLAGS, [])

    assert entities[0]["value"] == "CVE-2026-1281"


def test_entry_without_a_cve_becomes_a_report_keyed_by_internal_id() -> None:
    entities = build_entities([_row(cve="")], FIELDS, FLAGS, [])

    entity = entities[0]
    assert entity["type"] == "report"
    assert entity["label"] == entity["value"] == "VW-2026-0001"


def test_empty_attrs_are_omitted() -> None:
    entities = build_entities(
        [_row(cvss="", sev="", asc="", lag="", flags=0, prefix=-1)], FIELDS, FLAGS, []
    )

    attrs = entities[0]["attrs"]
    for absent in ("CVSS", "深刻度", "攻撃面", "KEVラグ", "flags", "prefix"):
        assert absent not in attrs
    assert attrs["題名"] == "RCE"


def test_attrs_use_no_portal_reserved_keys() -> None:
    entities = build_entities([_row()], FIELDS, FLAGS, ["ivanti/2026/07"])

    # Keys beginning with "_" are reserved for the portal's own bookkeeping.
    assert not [key for key in entities[0]["attrs"] if key.startswith("_")]


def test_search_document_carries_the_spec_envelope() -> None:
    document = build_search_document(
        generated_at="2026-07-26T00:00:00+00:00",
        entities=build_entities([_row()], FIELDS, FLAGS, ["ivanti/2026/07"]),
    )

    assert document["spec_version"] == "1.0"
    assert document["app_id"] == "vuln-intel-agent"
    assert document["generated_at"] == "2026-07-26T00:00:00+00:00"
    assert len(document["entities"]) == 1


def test_meta_carries_the_spec_v1_fields() -> None:
    meta = build_meta(
        generated_at="2026-07-26T00:00:00+00:00",
        repository="proshiba/vuln-intel-agent",
        site_url="https://proshiba.github.io/vuln-intel-agent",
        ref="main",
        stats={"total": 1},
        fields=FIELDS,
        flags=FLAGS,
        attack_surfaces={"vpn_gateway": "VPN/リモートアクセス"},
    )

    assert meta["spec_version"] == "1.0"
    assert meta["app_id"] == "vuln-intel-agent"
    assert meta["name"] == "脆弱性インテル"
    # The portal resolves relative endpoints against site_url, so it must end in a slash.
    assert meta["site_url"].endswith("/")
    assert meta["endpoints"]["search"] == "api/v1/search.json"
    assert meta["endpoints"]["viewer_index"] == "api/v1/viewer.json"
    # Vulnerability entities open in the bundled viewer. Malware/actor/IOC entities are
    # emitted purely so the portal can join them across sources; this app has no page for
    # them, so it deliberately declares no deep link rather than one that lands nowhere.
    assert set(meta["deep_links"]) == {"cve", "report"}
    assert meta["deep_links"]["cve"] == "#/vuln/{detail}"
    assert "iframe" in meta["capabilities"]


# --- 攻撃活動エンティティ（ポータルの横串用） --------------------------------


def _activity(**over: object):
    from vulnwatch.threatintel import (
        IndicatorRole,
        IndicatorType,
        ThreatCampaign,
        ThreatIndicator,
        VulnThreatActivity,
    )

    base: dict[str, object] = {
        "vuln_id": "VW-2026-0001",
        "cve": "CVE-2026-1281",
        "campaigns": [
            ThreatCampaign(name="Example", actors=["APT Example"], malware=["ValleyRAT"])
        ],
        "indicators": [
            ThreatIndicator(
                type=IndicatorType.DOMAIN,
                value="c2.example.test",
                role=IndicatorRole.C2,
                source_id="unit42",
                url="https://unit42.paloaltonetworks.com/example",
            )
        ],
        "updated_at": datetime(2026, 7, 27, tzinfo=UTC),
    }
    base.update(over)
    return VulnThreatActivity(**base)  # type: ignore[arg-type]


def test_threat_activity_becomes_joinable_entities() -> None:
    entities = {e["type"]: e for e in build_threat_entities([_activity()])}

    assert set(entities) == {"malware", "actor", "ioc.domain"}
    # The portal folds actor/malware names to lower-case alphanumerics before joining,
    # so the value must already be in that form to match other sources.
    assert entities["malware"]["value"] == "valleyrat"
    assert entities["malware"]["label"] == "ValleyRAT"
    assert entities["actor"]["value"] == "aptexample"
    assert entities["ioc.domain"]["value"] == "c2.example.test"
    assert entities["ioc.domain"]["attrs"]["出典"].startswith("https://")
    assert entities["ioc.domain"]["attrs"]["関連CVE"] == ["CVE-2026-1281"]


def test_the_same_indicator_across_vulnerabilities_is_one_entity() -> None:
    entities = build_threat_entities(
        [_activity(), _activity(vuln_id="VW-2026-0002", cve="CVE-2026-9999")]
    )

    domains = [e for e in entities if e["type"] == "ioc.domain"]
    assert len(domains) == 1
    # Both vulnerabilities are recorded on the shared entity.
    assert domains[0]["attrs"]["関連CVE"] == ["CVE-2026-1281", "CVE-2026-9999"]


def test_no_threat_entities_without_activity() -> None:
    assert build_threat_entities([]) == []
