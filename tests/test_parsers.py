from __future__ import annotations

import json
from pathlib import Path

import feedparser
import pytest
from bs4 import BeautifulSoup

from vulnwatch.collectors.json_api import _items
from vulnwatch.config import load_sources
from vulnwatch.models import CollectorKind, RawRecord, SourceDefinition
from vulnwatch.parsers import parse_cisa_kev, parse_record

FIXTURES = Path("tests/fixtures")
VENDOR_FIXTURES = {
    "cisco": "cisco.json",
    "microsoft": "microsoft.json",
    "red_hat": "red_hat.json",
    "suse": "suse.json",
    "palo_alto_networks": "palo_alto_networks.json",
    "kubernetes": "kubernetes.json",
    "fortinet": "fortinet.xml",
    "sonicwall": "sonicwall.xml",
    "veeam": "veeam.xml",
    "juniper_networks": "juniper_networks.xml",
    "canonical": "canonical.xml",
    "debian": "debian.xml",
    "jenkins": "jenkins.xml",
    "gitlab": "gitlab.xml",
    "jvn": "jvn.xml",
    "grafana_github": "github_advisory.json",
}


def _record(source_id: str, filename: str) -> RawRecord:
    registry = load_sources()
    source = next(item for item in registry.sources if item.id == source_id)
    path = FIXTURES / "vendors" / filename
    content = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        payload = json.loads(content)
        item = payload if source.parser == "csaf" else _items(payload)[0]
        return RawRecord(
            source_id=source_id,
            url=str(item.get("url") or source.advisory_url),
            content=json.dumps(item, ensure_ascii=False),
            metadata=item,
        )
    if path.suffix == ".xml":
        entry = feedparser.parse(content).entries[0]
        return RawRecord(
            source_id=source_id,
            url=str(entry.link),
            content=str(entry.get("summary") or entry.get("title") or ""),
            metadata=dict(entry),
        )
    soup = BeautifulSoup(content, "lxml")
    item_node = soup.select_one(source.selectors["item"])
    assert item_node is not None
    title_node = item_node.select_one(source.selectors["title"])
    link_node = item_node.select_one(source.selectors["link"])
    time_node = item_node.select_one(source.selectors["published_at"])
    assert title_node is not None and link_node is not None
    return RawRecord(
        source_id=source_id,
        url=source.advisory_url,
        content=item_node.get_text("\n", strip=True),
        metadata={
            "title": title_node.get_text(" ", strip=True),
            "published": time_node.get("datetime") if time_node else None,
        },
    )


@pytest.mark.parametrize(("source_id", "filename"), VENDOR_FIXTURES.items())
def test_initial_vendor_fixtures(source_id: str, filename: str) -> None:
    registry = load_sources()
    source = next(item for item in registry.sources if item.id == source_id)
    expected = json.loads((FIXTURES / "expected.json").read_text(encoding="utf-8"))[source_id]

    draft = parse_record(source, _record(source_id, filename))

    assert draft.title == expected["title"]
    assert expected["cve"] in draft.cves
    assert draft.vendor_advisory_id == expected["vendor_id"]


def test_cisa_kev_fixture_is_enrichment_only() -> None:
    payload = json.loads((FIXTURES / "cisa-kev.json").read_text(encoding="utf-8"))
    records = [
        RawRecord(
            source_id="cisa_kev",
            url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            content=json.dumps(item),
            metadata=item,
        )
        for item in payload["vulnerabilities"]
    ]

    assert parse_cisa_kev(records) == {"CVE-2026-10001"}


def test_github_advisory_normalizes_nested_vulnerability_fields() -> None:
    registry = load_sources()
    source = next(item for item in registry.sources if item.id == "grafana_github")

    draft = parse_record(source, _record("grafana_github", "github_advisory.json"))

    assert draft.products == ["github.com/grafana/grafana"]
    assert draft.affected_versions == ["github.com/grafana/grafana: >= 11.0.0, < 11.1.2"]
    assert draft.fixed_versions == ["github.com/grafana/grafana: 11.1.2"]
    assert draft.cvss_score == 9.8
    assert draft.remote is True
    assert draft.authentication_required is False
    assert draft.poc_public is True


def test_json_parser_uses_collector_validated_source_url() -> None:
    source = SourceDefinition(
        id="example_json",
        category="test",
        vendor="Example",
        advisory_url="https://security.example.com/advisories",
        enabled=True,
        collector=CollectorKind.JSON_API,
        url="https://security.example.com/api",
        allowed_hosts=["security.example.com"],
        parser="json",
    )
    raw = RawRecord(
        source_id=source.id,
        url=source.advisory_url,
        content='{"id":"ADV-1"}',
        metadata={"id": "ADV-1", "url": "http://legacy.example.com/ADV-1"},
    )

    assert parse_record(source, raw).source_url == source.advisory_url


@pytest.mark.parametrize(
    "payload, expected",
    [
        (
            {
                "CVE_data_meta": {
                    "ID": "CVE-2021-9999",
                    "TITLE": "Legacy httpd issue",
                    "DATE_PUBLIC": "2021-06-01",
                    "STATE": "PUBLIC",
                },
                "description": {
                    "description_data": [{"lang": "eng", "value": "Legacy description"}]
                },
                "impact": [{"other": "important"}],
                "affects": {
                    "vendor": {
                        "vendor_data": [
                            {
                                "product": {
                                    "product_data": [
                                        {
                                            "product_name": "Apache HTTP Server",
                                            "version": {
                                                "version_data": [
                                                    {
                                                        "version_affected": "=",
                                                        "version_value": "2.4.46",
                                                    }
                                                ]
                                            },
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                },
            },
            ("Legacy httpd issue", "IMPORTANT", "Apache HTTP Server: = 2.4.46"),
        ),
        (
            {
                "cveMetadata": {"cveId": "CVE-2026-9999", "state": "PUBLISHED"},
                "containers": {
                    "cna": {
                        "title": "Current httpd issue",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Users are recommended to upgrade to version 2.4.67.",
                            }
                        ],
                        "affected": [
                            {
                                "product": "Apache HTTP Server",
                                "versions": [
                                    {
                                        "status": "affected",
                                        "version": "2.4.30",
                                        "lessThanOrEqual": "2.4.66",
                                    }
                                ],
                            }
                        ],
                        "metrics": [
                            {
                                "other": {
                                    "content": {"text": "critical"},
                                    "type": "Textual description of severity",
                                }
                            }
                        ],
                        "timeline": [
                            {"time": "2026-05-04", "value": "2.4.67 released"}
                        ],
                    }
                },
            },
            ("Current httpd issue", "CRITICAL", "Apache HTTP Server: >= 2.4.30, <= 2.4.66"),
        ),
    ],
)
def test_apache_httpd_parser_supports_mixed_cve_formats(
    payload: dict[str, object], expected: tuple[str, str, str]
) -> None:
    source = next(item for item in load_sources().sources if item.id == "apache_http_server")
    raw = RawRecord(
        source_id=source.id,
        url=source.advisory_url,
        content=json.dumps(payload),
        metadata=payload,
    )

    draft = parse_record(source, raw)

    assert draft.title == expected[0]
    assert draft.vendor_severity == expected[1]
    assert expected[2] in draft.affected_versions
    assert draft.vendor_advisory_id in draft.cves
    if draft.vendor_advisory_id == "CVE-2026-9999":
        assert draft.fixed_versions == ["2.4.67"]


def test_nvd_parser_maps_description_cvss_and_cpe_bounds() -> None:
    source = next(item for item in load_sources().sources if item.id == "nist_nvd")
    payload = {
        "id": "CVE-2026-12345",
        "published": "2026-07-01T00:00:00.000Z",
        "lastModified": "2026-07-02T00:00:00.000Z",
        "descriptions": [{"lang": "en", "value": "Example vulnerability"}],
        "metrics": {
            "cvssMetricV31": [
                {
                    "cvssData": {
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    }
                }
            ]
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "criteria": "cpe:2.3:a:example:server:*:*:*:*:*:*:*:*",
                                "versionEndExcluding": "2.0",
                            }
                        ]
                    }
                ]
            }
        ],
    }
    raw = RawRecord(
        source_id=source.id,
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        content=json.dumps(payload),
        metadata=payload,
    )

    draft = parse_record(source, raw)

    assert draft.vendor_advisory_id == "CVE-2026-12345"
    assert draft.title == "Example vulnerability"
    assert draft.cves == ["CVE-2026-12345"]
    assert draft.cvss_score == 9.8
    assert draft.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert draft.remote is True
    assert draft.authentication_required is False
    assert draft.vendor_severity == "CRITICAL"
    assert draft.products == ["example server"]
    assert draft.affected_versions == ["example server: versionEndExcluding=2.0"]
    assert draft.fixed_versions == ["example server: 2.0"]


def test_netapp_parser_maps_official_api_fields() -> None:
    source = SourceDefinition(
        id="netapp",
        category="test",
        vendor="NetApp",
        products=["ONTAP"],
        advisory_url="https://security.netapp.com/advisory",
        enabled=True,
        collector=CollectorKind.JSON_API,
        url="https://security.netapp.com/adv_api/advisory/?limit=100",
        allowed_hosts=["security.netapp.com"],
        parser="netapp",
        content_types=["application/json"],
    )
    payload = {
        "ntap_advisory_id": "NTAP-20260719-0001",
        "kb_title": "Example Vulnerability in NetApp Products",
        "published_date": "2026-07-18T00:00:00",
        "updated_date": "2026-07-19T00:00:00",
        "kb_cve": ["CVE-2026-12345"],
        "kb_scoring": {
            "CVE-2026-12345": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        },
        "kb_affected_list": ["ONTAP 9"],
        "kb_fixes": [
            {
                "product": "ONTAP 9",
                "fixes": ["9.16.1P9"],
                "instructions": "Upgrade to a fixed release.",
            }
        ],
        "kb_exploitation": "NetApp is not aware of active exploitation or a public PoC.",
        "kb_status": "Final",
    }
    raw = RawRecord(
        source_id=source.id,
        url="https://security.netapp.com/advisory/NTAP-20260719-0001",
        content=json.dumps(payload),
        metadata=payload,
    )

    draft = parse_record(source, raw)

    assert draft.vendor_advisory_id == "NTAP-20260719-0001"
    assert draft.title == "Example Vulnerability in NetApp Products"
    assert draft.cves == ["CVE-2026-12345"]
    assert draft.products == ["ONTAP 9"]
    assert draft.fixed_versions == ["ONTAP 9: 9.16.1P9"]
    assert draft.mitigations == ["Upgrade to a fixed release."]
    assert draft.cvss_score == 9.8
    assert draft.vendor_severity == "CRITICAL"
    assert draft.remote is True
    assert draft.authentication_required is False
    assert draft.known_exploited is False
    assert draft.poc_public is False
