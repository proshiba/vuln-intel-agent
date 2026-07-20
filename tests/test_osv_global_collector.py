from __future__ import annotations

import re
from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, ParserChangedError
from vulnwatch.collectors.osv_global import (
    OSV_DETAIL_BASE_URL,
    OSV_MODIFIED_INDEX_URL,
    OsvGlobalCollector,
)
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState


def _source(**overrides: object) -> SourceDefinition:
    values: dict[str, object] = {
        "id": "osv",
        "category": "cross_vendor",
        "vendor": "OSV",
        "products": ["OSV"],
        "advisory_url": OSV_MODIFIED_INDEX_URL,
        "enabled": True,
        "collector": CollectorKind.OSV_GLOBAL,
        "url": OSV_MODIFIED_INDEX_URL,
        "allowed_hosts": ["storage.googleapis.com"],
        "content_types": ["text/csv", "application/json"],
        "max_items": 10,
        "max_index_items": 20,
        "max_detail_fetches": 10,
        "rate_limit_per_second": 20,
    }
    values.update(overrides)
    return SourceDefinition.model_validate(values)


def _index_response(rows: list[tuple[str, str]]) -> httpx.Response:
    text = "".join(f"{modified},{path}\n" for modified, path in rows)
    return httpx.Response(200, text=text, headers={"content-type": "text/csv"})


def _detail_url(path: str) -> str:
    return f"{OSV_DETAIL_BASE_URL}{path}.json"


@respx.mock
async def test_osv_global_filters_on_newest_state_boundary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=httpx.Response(
            200,
            text=(
                "2026-07-10T00:00:00.123456789Z,PyPI/GHSA-new\n"
                "2026-07-08T00:00:00Z,Go/GO-middle\n"
                "2026-07-07T00:00:00Z,npm/GHSA-boundary\n"
                "2026-07-06T00:00:00Z,Maven/OLD\n"
            ),
            headers={
                "content-type": "text/csv",
                "etag": '"index-etag"',
                "last-modified": "Sun, 19 Jul 2026 08:00:00 GMT",
            },
        )
    )
    for path, identifier in (("PyPI/GHSA-new", "GHSA-new"), ("Go/GO-middle", "GO-middle")):
        respx.get(_detail_url(path)).mock(
            return_value=httpx.Response(
                200,
                json={"id": identifier, "summary": identifier},
                headers={"content-type": "application/json"},
            )
        )
    boundary = respx.get(_detail_url("npm/GHSA-boundary")).mock(return_value=httpx.Response(500))

    result = await OsvGlobalCollector().collect(
        _source(),
        SourceState(
            source_id="osv",
            last_success_at=datetime(2026, 7, 7, tzinfo=UTC),
        ),
        datetime(2026, 7, 1, tzinfo=UTC),
    )

    assert result.complete_snapshot is False
    assert result.etag == '"index-etag"'
    assert result.last_modified == "Sun, 19 Jul 2026 08:00:00 GMT"
    assert [record.metadata["id"] for record in result.records] == [
        "GHSA-new",
        "GO-middle",
    ]
    assert result.records[0].url == "https://osv.dev/vulnerability/GHSA-new"
    assert boundary.called is False


@respx.mock
async def test_osv_global_uses_explicit_bootstrap_window_without_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "vulnwatch.collectors.osv_global._utc_now",
        lambda: datetime(2026, 7, 10, 4, tzinfo=UTC),
    )
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=_index_response(
            [
                ("2026-07-10T03:30:00Z", "PyPI/NEW"),
                ("2026-07-10T03:00:00Z", "PyPI/BOUNDARY"),
                ("2026-07-10T02:00:00Z", "PyPI/OLD"),
            ]
        )
    )
    respx.get(_detail_url("PyPI/NEW")).mock(
        return_value=httpx.Response(
            200,
            json={"id": "NEW"},
            headers={"content-type": "application/json"},
        )
    )

    result = await OsvGlobalCollector().collect(
        _source(bootstrap_window_hours=1),
        SourceState(source_id="osv"),
        datetime(2026, 7, 1, tzinfo=UTC),
    )

    assert [record.metadata["id"] for record in result.records] == ["NEW"]


@respx.mock
async def test_osv_global_deduplicates_paths_and_payload_ids(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=_index_response(
            [
                ("2026-07-10T03:00:00Z", "GIT/CVE-2026-1000"),
                ("2026-07-10T02:00:00Z", "GIT/CVE-2026-1000"),
                ("2026-07-10T01:00:00Z", "Linux/CVE-2026-1000"),
                ("2026-07-01T00:00:00Z", "PyPI/OLD"),
            ]
        )
    )
    routes = []
    for path in ("GIT/CVE-2026-1000", "Linux/CVE-2026-1000"):
        routes.append(
            respx.get(_detail_url(path)).mock(
                return_value=httpx.Response(
                    200,
                    json={"id": "CVE-2026-1000", "summary": path},
                    headers={"content-type": "application/json"},
                )
            )
        )

    result = await OsvGlobalCollector().collect(
        _source(max_items=1, max_detail_fetches=2),
        SourceState(source_id="osv"),
        datetime(2026, 7, 1, tzinfo=UTC),
    )

    assert [record.metadata["id"] for record in result.records] == ["CVE-2026-1000"]
    assert [route.call_count for route in routes] == [1, 1]


@respx.mock
async def test_osv_global_filters_object_identifiers_before_detail_fetch() -> None:
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=_index_response(
            [
                ("2026-07-10T03:00:00Z", "Go/GO-2026-1"),
                ("2026-07-10T02:00:00Z", "Go/GHSA-new"),
                ("2026-07-01T00:00:00Z", "PyPI/OLD"),
            ]
        )
    )
    skipped = respx.get(_detail_url("Go/GO-2026-1")).mock(return_value=httpx.Response(500))
    respx.get(_detail_url("Go/GHSA-new")).mock(
        return_value=httpx.Response(
            200,
            json={"id": "GHSA-new"},
            headers={"content-type": "application/json"},
        )
    )

    result = await OsvGlobalCollector().collect(
        _source(osv_id_prefixes=["GHSA-"]),
        SourceState(source_id="osv"),
        datetime(2026, 7, 1, tzinfo=UTC),
    )

    assert [record.metadata["id"] for record in result.records] == ["GHSA-new"]
    assert skipped.called is False


@respx.mock
@pytest.mark.parametrize(
    "path",
    [
        "../secret",
        "PyPI/../secret",
        "/absolute",
        "https://evil.example/id",
        r"PyPI\id",
        "PyPI/%2e%2e",
        "PyPI/id?alt=media",
        "PyPI/id#fragment",
        "PyPI/id/extra",
    ],
)
async def test_osv_global_rejects_unsafe_object_paths(path: str) -> None:
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=_index_response([("2026-07-10T00:00:00Z", path)])
    )

    with pytest.raises(CollectorError, match="invalid OSV object path"):
        await OsvGlobalCollector().collect(
            _source(),
            SourceState(source_id="osv"),
            datetime(2026, 7, 1, tzinfo=UTC),
        )


@respx.mock
async def test_osv_global_rejects_index_scan_over_limit() -> None:
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=_index_response(
            [
                ("2026-07-10T03:00:00Z", "PyPI/ONE"),
                ("2026-07-10T02:00:00Z", "PyPI/TWO"),
                ("2026-07-10T01:00:00Z", "PyPI/THREE"),
            ]
        )
    )

    with pytest.raises(CollectorError, match="OSV index scan exceeds configured limit"):
        await OsvGlobalCollector().collect(
            _source(max_index_items=2),
            SourceState(source_id="osv"),
            datetime(2026, 7, 1, tzinfo=UTC),
        )


@respx.mock
async def test_osv_global_rejects_detail_fetches_over_limit() -> None:
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=_index_response(
            [
                ("2026-07-10T02:00:00Z", "PyPI/ONE"),
                ("2026-07-10T01:00:00Z", "PyPI/TWO"),
            ]
        )
    )
    detail_route = respx.get(re.compile(rf"{re.escape(OSV_DETAIL_BASE_URL)}.+\.json")).mock(
        return_value=httpx.Response(500)
    )

    with pytest.raises(CollectorError, match="OSV delta exceeds configured detail fetch limit"):
        await OsvGlobalCollector().collect(
            _source(max_detail_fetches=1),
            SourceState(source_id="osv"),
            datetime(2026, 7, 1, tzinfo=UTC),
        )
    assert detail_route.called is False


@respx.mock
async def test_osv_global_rejects_unique_records_over_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=_index_response(
            [
                ("2026-07-10T02:00:00Z", "PyPI/ONE"),
                ("2026-07-10T01:00:00Z", "PyPI/TWO"),
            ]
        )
    )
    for identifier in ("ONE", "TWO"):
        respx.get(_detail_url(f"PyPI/{identifier}")).mock(
            return_value=httpx.Response(
                200,
                json={"id": identifier},
                headers={"content-type": "application/json"},
            )
        )

    with pytest.raises(CollectorError, match="OSV delta exceeds configured record limit"):
        await OsvGlobalCollector().collect(
            _source(max_items=1, max_detail_fetches=2),
            SourceState(source_id="osv"),
            datetime(2026, 7, 1, tzinfo=UTC),
        )


@respx.mock
@pytest.mark.parametrize(
    ("response", "error", "message"),
    [
        (
            httpx.Response(
                200,
                content=b"not-json",
                headers={"content-type": "application/json"},
            ),
            CollectorError,
            "invalid OSV JSON",
        ),
        (
            httpx.Response(200, json=[], headers={"content-type": "application/json"}),
            ParserChangedError,
            "OSV detail is not an object",
        ),
        (
            httpx.Response(
                200,
                json={"summary": "missing id"},
                headers={"content-type": "application/json"},
            ),
            ParserChangedError,
            "OSV detail has no valid id",
        ),
    ],
)
async def test_osv_global_rejects_invalid_detail_json(
    response: httpx.Response,
    error: type[Exception],
    message: str,
) -> None:
    respx.get(OSV_MODIFIED_INDEX_URL).mock(
        return_value=_index_response([("2026-07-10T00:00:00Z", "PyPI/ONE")])
    )
    respx.get(_detail_url("PyPI/ONE")).mock(return_value=response)

    with pytest.raises(error, match=message):
        await OsvGlobalCollector().collect(
            _source(),
            SourceState(source_id="osv"),
            datetime(2026, 7, 1, tzinfo=UTC),
        )
