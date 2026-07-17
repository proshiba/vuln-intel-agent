from __future__ import annotations

import json
from pathlib import Path

import feedparser
import pytest
from bs4 import BeautifulSoup

from vulnwatch.collectors.json_api import _items
from vulnwatch.config import load_sources
from vulnwatch.models import RawRecord
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
    "juniper_networks": "juniper_networks.html",
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
            content=str(entry.summary),
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
