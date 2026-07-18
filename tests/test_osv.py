from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest
import respx

from vulnwatch.collectors.base import ParserChangedError
from vulnwatch.collectors.osv import OSV_QUERY_URL, OsvCollector
from vulnwatch.models import (
    AdvisoryStatus,
    CollectorKind,
    RawRecord,
    SourceDefinition,
    SourceState,
)
from vulnwatch.parsers import parse_record
from vulnwatch.pipeline import apply_backend, resolve_github_backend

FIXTURE = Path(__file__).parent / "fixtures" / "vendors" / "osv_aiohttp.json"


def _osv_source() -> SourceDefinition:
    return SourceDefinition(
        id="aiohttp_github",
        category="os_middleware_application",
        vendor="aiohttp",
        products=["aiohttp"],
        advisory_url="https://github.com/aio-libs/aiohttp/security/advisories",
        enabled=True,
        collector=CollectorKind.JSON_API,
        url="https://api.github.com/repos/aio-libs/aiohttp/security-advisories",
        allowed_hosts=["api.github.com", "github.com"],
        parser="github_advisory",
        osv_ecosystem="PyPI",
        osv_packages=["aiohttp"],
        content_types=["application/json"],
    )


def test_parse_osv_maps_cve_cvss_fix_and_source_url() -> None:
    payload = json.loads(FIXTURE.read_text(encoding="utf-8"))
    source = apply_backend(_osv_source(), "osv")
    raw = RawRecord(
        source_id=source.id,
        url="https://osv.dev/vulnerability/GHSA-4fvr-rgm6-gqmc",
        content=json.dumps(payload),
        metadata=payload,
    )

    draft = parse_record(source, raw)

    assert draft.vendor_advisory_id == "GHSA-4fvr-rgm6-gqmc"
    assert draft.cves == ["CVE-2026-54273"]
    assert draft.status == AdvisoryStatus.ACTIVE
    assert draft.cvss_score is not None and 0 <= draft.cvss_score <= 10
    assert draft.cvss_vector is not None and draft.cvss_vector.startswith("CVSS:4")
    assert draft.vendor_severity == "MODERATE"
    assert draft.fixed_versions == ["aiohttp: 3.14.1"]
    assert draft.source_url == (
        "https://github.com/aio-libs/aiohttp/security/advisories/GHSA-4fvr-rgm6-gqmc"
    )
    assert draft.products == ["aiohttp"]


def test_parse_osv_handles_withdrawn_and_missing_severity() -> None:
    source = apply_backend(_osv_source(), "osv")
    payload = {
        "id": "GHSA-zero-zero-zero",
        "summary": "example",
        "withdrawn": "2026-07-01T00:00:00Z",
        "aliases": ["CVE-2026-99999"],
        "affected": [{"package": {"ecosystem": "PyPI", "name": "aiohttp"}}],
        "references": [],
    }
    raw = RawRecord(source_id=source.id, url="https://osv.dev/x", content="{}", metadata=payload)

    draft = parse_record(source, raw)

    assert draft.status == AdvisoryStatus.WITHDRAWN
    assert draft.cves == ["CVE-2026-99999"]
    assert draft.cvss_score is None
    assert draft.source_url == "https://osv.dev/x"


@respx.mock
async def test_osv_collector_paginates_and_dedupes() -> None:
    source = apply_backend(_osv_source(), "osv")
    page1 = {
        "vulns": [{"id": "GHSA-a", "summary": "a"}, {"id": "GHSA-b", "summary": "b"}],
        "next_page_token": "tok",
    }
    page2 = {"vulns": [{"id": "GHSA-b", "summary": "b"}, {"id": "GHSA-c", "summary": "c"}]}
    route = respx.post(OSV_QUERY_URL).mock(
        side_effect=[
            httpx.Response(200, json=page1, headers={"content-type": "application/json"}),
            httpx.Response(200, json=page2, headers={"content-type": "application/json"}),
        ]
    )

    result = await OsvCollector().collect(
        source, SourceState(source_id=source.id), datetime(2026, 1, 1, tzinfo=UTC)
    )

    assert route.call_count == 2
    assert [record.metadata["id"] for record in result.records] == ["GHSA-a", "GHSA-b", "GHSA-c"]
    assert result.complete_snapshot is False
    assert json.loads(route.calls[1].request.content)["page_token"] == "tok"


@respx.mock
async def test_osv_collector_raises_when_empty() -> None:
    source = apply_backend(_osv_source(), "osv")
    respx.post(OSV_QUERY_URL).mock(
        return_value=httpx.Response(
            200, json={"vulns": []}, headers={"content-type": "application/json"}
        )
    )

    with pytest.raises(ParserChangedError):
        await OsvCollector().collect(
            source, SourceState(source_id=source.id), datetime(2026, 1, 1, tzinfo=UTC)
        )


def test_apply_backend_switches_only_github_sources_with_coordinates() -> None:
    github_source = _osv_source()

    osv_variant = apply_backend(github_source, "osv")
    assert osv_variant.collector == CollectorKind.OSV
    assert osv_variant.parser == "osv"
    assert osv_variant.url == OSV_QUERY_URL
    assert "api.osv.dev" in osv_variant.allowed_hosts

    assert apply_backend(github_source, "github") is github_source

    no_coordinates = github_source.model_copy(update={"osv_ecosystem": None, "osv_packages": []})
    assert apply_backend(no_coordinates, "osv") is no_coordinates

    csaf_source = SourceDefinition(
        id="cisco",
        category="network_security",
        vendor="Cisco",
        advisory_url="https://sec.cloudapps.cisco.com/security/center/publicationListing.x",
        enabled=True,
        collector=CollectorKind.CSAF,
        url="https://sec.cloudapps.cisco.com/security/center/csaf_20.xml",
        allowed_hosts=["sec.cloudapps.cisco.com"],
        parser="csaf",
    )
    assert apply_backend(csaf_source, "osv") is csaf_source


def test_resolve_github_backend_defaults_and_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VULNWATCH_GITHUB_BACKEND", raising=False)
    assert resolve_github_backend() == "github"
    monkeypatch.setenv("VULNWATCH_GITHUB_BACKEND", "osv")
    assert resolve_github_backend() == "osv"
    monkeypatch.setenv("VULNWATCH_GITHUB_BACKEND", "nonsense")
    assert resolve_github_backend() == "github"
