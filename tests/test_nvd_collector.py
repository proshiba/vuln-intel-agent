import re
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, ParserChangedError
from vulnwatch.collectors.nvd import (
    FORTRA_SOURCE_IDENTIFIER,
    NVD_API_HOST,
    NVD_API_PATH,
    NvdCollector,
)
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState

NVD_API_URL = f"https://{NVD_API_HOST}{NVD_API_PATH}"
FORTRA_API_URL = f"{NVD_API_URL}?sourceIdentifier={FORTRA_SOURCE_IDENTIFIER}"


def _source(**overrides: object) -> SourceDefinition:
    values: dict[str, object] = {
        "id": "nist_nvd",
        "category": "cross_vendor",
        "vendor": "NIST",
        "products": ["NVD"],
        "advisory_url": "https://nvd.nist.gov/",
        "enabled": True,
        "collector": CollectorKind.JSON_API,
        "url": NVD_API_URL,
        "allowed_hosts": [NVD_API_HOST, "nvd.nist.gov"],
        "content_types": ["application/json"],
        "max_items": 10,
        "max_index_items": 20,
        "rate_limit_per_second": 20,
    }
    values.update(overrides)
    return SourceDefinition.model_validate(values)


def _response(
    *,
    start_index: int,
    results_per_page: int,
    total_results: int,
    ids: list[str],
) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
            "totalResults": total_results,
            "format": "NVD_CVE",
            "version": "2.0",
            "vulnerabilities": [
                {"cve": {"id": identifier, "published": "2026-07-01T00:00:00.000"}}
                for identifier in ids
            ],
        },
        headers={"content-type": "application/json"},
    )


def _fortra_source(**overrides: object) -> SourceDefinition:
    values: dict[str, object] = {
        "id": "fortra",
        "vendor": "Fortra",
        "products": ["GoAnywhere MFT", "FileCatalyst", "BoKS"],
        "advisory_url": "https://www.fortra.com/security/advisories/product-security",
        "url": FORTRA_API_URL,
        "allowed_hosts": [NVD_API_HOST, "www.fortra.com"],
        "parser": "nvd",
        "max_items": 200,
        "max_index_items": 200,
    }
    values.update(overrides)
    return _source(**values)


def _fortra_item(
    identifier: str,
    reference: str,
    *,
    source_identifier: str = FORTRA_SOURCE_IDENTIFIER,
) -> dict[str, object]:
    return {
        "cve": {
            "id": identifier,
            "sourceIdentifier": source_identifier,
            "published": "2026-06-01T00:00:00.000",
            "lastModified": "2026-07-01T00:00:00.000",
            "references": [{"url": reference, "source": source_identifier}],
        }
    }


@respx.mock
async def test_fortra_uses_modified_window_and_keeps_only_product_advisories(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed_now = datetime(2026, 7, 19, 12, tzinfo=UTC)
    monkeypatch.setattr("vulnwatch.collectors.nvd._utc_now", lambda: fixed_now)
    route = respx.get(re.compile(rf"{re.escape(NVD_API_URL)}\?.+")).mock(
        return_value=httpx.Response(
            200,
            json={
                "resultsPerPage": 3,
                "startIndex": 0,
                "totalResults": 3,
                "vulnerabilities": [
                    _fortra_item(
                        "CVE-2026-12164",
                        "https://www.fortra.com/security/advisories/"
                        "product-security/fi-2026-010?tracking=ignored",
                    ),
                    _fortra_item(
                        "CVE-2026-11111",
                        "https://www.fortra.com/security/advisories/research/fr-2026-001",
                    ),
                    _fortra_item(
                        "CVE-2026-9863",
                        "https://www.fortra.com/security/advisories/product-security/fi-2026-008/",
                    ),
                ],
            },
            headers={"content-type": "application/json"},
        )
    )

    result = await NvdCollector().collect(
        _fortra_source(),
        SourceState(source_id="fortra"),
        datetime(2026, 4, 20, 8, tzinfo=UTC),
    )

    assert [record.metadata["id"] for record in result.records] == [
        "CVE-2026-12164",
        "CVE-2026-9863",
    ]
    assert [record.url for record in result.records] == [
        "https://www.fortra.com/security/advisories/product-security/fi-2026-010",
        "https://www.fortra.com/security/advisories/product-security/fi-2026-008",
    ]
    params = route.calls[0].request.url.params
    assert params["sourceIdentifier"] == FORTRA_SOURCE_IDENTIFIER
    assert params["lastModStartDate"] == "2026-04-20T08:00:00.000Z"
    assert params["lastModEndDate"] == "2026-07-19T12:00:00.000Z"
    assert "pubStartDate" not in params
    assert "pubEndDate" not in params


@respx.mock
async def test_fortra_rejects_an_item_from_an_unexpected_cna(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vulnwatch.collectors.nvd._utc_now",
        lambda: datetime(2026, 7, 19, tzinfo=UTC),
    )
    respx.get(re.compile(rf"{re.escape(NVD_API_URL)}\?.+")).mock(
        return_value=httpx.Response(
            200,
            json={
                "resultsPerPage": 1,
                "startIndex": 0,
                "totalResults": 1,
                "vulnerabilities": [
                    _fortra_item(
                        "CVE-2026-12164",
                        "https://www.fortra.com/security/advisories/product-security/fi-2026-010",
                        source_identifier="unexpected-cna",
                    )
                ],
            },
            headers={"content-type": "application/json"},
        )
    )

    with pytest.raises(ParserChangedError, match="unexpected sourceIdentifier"):
        await NvdCollector().collect(
            _fortra_source(),
            SourceState(source_id="fortra"),
            datetime(2026, 4, 20, tzinfo=UTC),
        )


@pytest.mark.parametrize(
    "url",
    [
        NVD_API_URL,
        f"{NVD_API_URL}?sourceIdentifier=wrong",
        f"{FORTRA_API_URL}&keywordSearch=Fortra",
    ],
)
async def test_fortra_rejects_an_unbounded_nvd_endpoint(url: str) -> None:
    with pytest.raises(CollectorError, match="configured Fortra sourceIdentifier"):
        await NvdCollector().collect(
            _fortra_source(url=url),
            SourceState(source_id="fortra"),
            datetime(2026, 4, 20, tzinfo=UTC),
        )


@respx.mock
async def test_nvd_paginates_maps_cves_and_deduplicates_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed_now = datetime(2026, 7, 19, 12, 34, 56, 789000, tzinfo=UTC)
    monkeypatch.setattr("vulnwatch.collectors.nvd._utc_now", lambda: fixed_now)
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    route = respx.get(re.compile(rf"{re.escape(NVD_API_URL)}\?.+")).mock(
        side_effect=[
            _response(
                start_index=0,
                results_per_page=2,
                total_results=4,
                ids=["CVE-2026-1001", "CVE-2026-1002"],
            ),
            _response(
                start_index=2,
                results_per_page=2,
                total_results=4,
                ids=["CVE-2026-1002", "CVE-2026-1003"],
            ),
        ]
    )

    result = await NvdCollector().collect(
        _source(max_items=4),
        SourceState(source_id="nist_nvd"),
        datetime(2026, 7, 1, tzinfo=UTC),
    )

    assert result.complete_snapshot is False
    assert [record.metadata["id"] for record in result.records] == [
        "CVE-2026-1001",
        "CVE-2026-1002",
        "CVE-2026-1003",
    ]
    first = result.records[0]
    assert first.url == "https://nvd.nist.gov/vuln/detail/CVE-2026-1001"
    assert first.metadata == {
        "id": "CVE-2026-1001",
        "published": "2026-07-01T00:00:00.000",
    }
    assert first.content == ('{"id": "CVE-2026-1001", "published": "2026-07-01T00:00:00.000"}')
    assert first.fetched_at == fixed_now

    assert route.call_count == 2
    first_params = route.calls[0].request.url.params
    second_params = route.calls[1].request.url.params
    assert first_params["pubStartDate"] == "2026-07-01T00:00:00.000Z"
    assert first_params["pubEndDate"] == "2026-07-19T12:34:56.789Z"
    assert first_params["startIndex"] == "0"
    assert first_params["resultsPerPage"] == "4"
    assert second_params["startIndex"] == "2"


@respx.mock
async def test_nvd_uses_last_modified_window_after_a_successful_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixed_now = datetime(2026, 7, 19, 12, tzinfo=UTC)
    monkeypatch.setattr("vulnwatch.collectors.nvd._utc_now", lambda: fixed_now)
    route = respx.get(re.compile(rf"{re.escape(NVD_API_URL)}\?.+")).mock(
        return_value=_response(
            start_index=0,
            results_per_page=10,
            total_results=0,
            ids=[],
        )
    )

    result = await NvdCollector().collect(
        _source(),
        SourceState(
            source_id="nist_nvd",
            last_success_at=datetime(2026, 7, 15, 8, 30, tzinfo=UTC),
        ),
        datetime(2026, 7, 1, tzinfo=UTC),
    )

    assert result.records == []
    assert result.complete_snapshot is False
    params = route.calls[0].request.url.params
    assert params["lastModStartDate"] == "2026-07-15T08:30:00.000Z"
    assert params["lastModEndDate"] == "2026-07-19T12:00:00.000Z"
    assert "pubStartDate" not in params
    assert "pubEndDate" not in params


@respx.mock
@pytest.mark.parametrize(
    ("source_overrides", "message"),
    [
        ({"max_index_items": 2, "max_items": 10}, "NVD index exceeds configured limit"),
        ({"max_index_items": 10, "max_items": 2}, "NVD window exceeds configured limit"),
    ],
)
async def test_nvd_rejects_results_over_configured_limits(
    monkeypatch: pytest.MonkeyPatch,
    source_overrides: dict[str, int],
    message: str,
) -> None:
    monkeypatch.setattr(
        "vulnwatch.collectors.nvd._utc_now",
        lambda: datetime(2026, 7, 19, tzinfo=UTC),
    )
    respx.get(re.compile(rf"{re.escape(NVD_API_URL)}\?.+")).mock(
        return_value=_response(
            start_index=0,
            results_per_page=2,
            total_results=3,
            ids=["CVE-2026-1001", "CVE-2026-1002"],
        )
    )

    with pytest.raises(CollectorError, match=message):
        await NvdCollector().collect(
            _source(**source_overrides),
            SourceState(source_id="nist_nvd"),
            datetime(2026, 7, 1, tzinfo=UTC),
        )


@respx.mock
@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (
            httpx.Response(200, content=b"not-json", headers={"content-type": "application/json"}),
            CollectorError,
            "invalid NVD JSON",
        ),
        (
            httpx.Response(
                200,
                json={"startIndex": 0, "resultsPerPage": 10, "totalResults": 1},
                headers={"content-type": "application/json"},
            ),
            ParserChangedError,
            "no vulnerabilities array",
        ),
    ],
)
async def test_nvd_rejects_invalid_responses(
    monkeypatch: pytest.MonkeyPatch,
    response: httpx.Response,
    error: type[Exception],
    message: str,
) -> None:
    monkeypatch.setattr(
        "vulnwatch.collectors.nvd._utc_now",
        lambda: datetime(2026, 7, 19, tzinfo=UTC),
    )
    respx.get(re.compile(rf"{re.escape(NVD_API_URL)}\?.+")).mock(return_value=response)

    with pytest.raises(error, match=message):
        await NvdCollector().collect(
            _source(),
            SourceState(source_id="nist_nvd"),
            datetime(2026, 7, 1, tzinfo=UTC),
        )
