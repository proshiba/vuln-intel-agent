from datetime import UTC, datetime

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, ParserChangedError
from vulnwatch.collectors.ubiquiti import UbiquitiCollector
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState
from vulnwatch.parsers.advisory import parse_record

API_URL = "https://community.svc.ui.com"


def _source(**overrides: object) -> SourceDefinition:
    values: dict[str, object] = {
        "id": "ubiquiti",
        "category": "network_security",
        "vendor": "Ubiquiti",
        "products": ["UniFi OS"],
        "advisory_url": "https://community.ui.com/releases",
        "enabled": True,
        "collector": CollectorKind.UBIQUITI,
        "url": API_URL,
        "allowed_hosts": ["community.svc.ui.com", "community.ui.com"],
        "parser": "generic",
        "max_items": 100,
        "max_index_items": 1000,
        "max_detail_fetches": 100,
        "content_types": ["application/json"],
    }
    values.update(overrides)
    return SourceDefinition.model_validate(values)


def _index(items: list[dict[str, object]]) -> dict[str, object]:
    return {
        "data": {
            "releases": {
                "items": items,
                "pageInfo": {"limit": 100, "offset": 0},
                "totalCount": len(items),
            }
        }
    }


def _item(
    *,
    identifier: str = "bulletin-066",
    title: str = "Security Advisory Bulletin 066",
    created: str = "2026-07-02T05:26:20Z",
) -> dict[str, object]:
    return {
        "id": identifier,
        "slug": title.replace(" ", "-"),
        "title": title,
        "createdAt": created,
        "updatedAt": None,
    }


def _detail(item: dict[str, object]) -> dict[str, object]:
    return {
        "data": {
            "release": {
                **item,
                "content": None,
                "newFeatures": [],
                "improvements": [],
                "bugfixes": [],
                "knownIssues": [],
                "importantNotes": [
                    {
                        "type": "TEXT",
                        "content": (
                            "<p>Affected Products: UniFi OS</p>"
                            "<p>CVE-2026-50746</p>"
                        ),
                    }
                ],
                "instructions": [],
                "rollingReleaseNotes": [],
            }
        }
    }


@respx.mock
async def test_ubiquiti_collects_recent_bulletin_body_and_parses_it() -> None:
    bulletin = _item()
    unrelated = _item(
        identifier="release-1",
        title="UniFi OS - Dream Machines",
    )
    route = respx.post(API_URL).mock(
        side_effect=[
            httpx.Response(200, json=_index([bulletin, unrelated])),
            httpx.Response(200, json=_detail(bulletin)),
        ]
    )

    source = _source()
    result = await UbiquitiCollector().collect(
        source,
        SourceState(source_id=source.id),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert route.call_count == 2
    assert result.complete_snapshot is False
    assert len(result.records) == 1
    record = result.records[0]
    assert record.url.endswith("/Security-Advisory-Bulletin-066/bulletin-066")
    assert "CVE-2026-50746" in record.content
    assert parse_record(source, record).cves == ["CVE-2026-50746"]


@respx.mock
async def test_ubiquiti_verifies_index_but_allows_no_new_bulletins() -> None:
    route = respx.post(API_URL).mock(
        return_value=httpx.Response(200, json=_index([_item()]))
    )

    result = await UbiquitiCollector().collect(
        _source(),
        SourceState(source_id="ubiquiti"),
        datetime(2026, 7, 10, tzinfo=UTC),
    )

    assert route.call_count == 1
    assert result.records == []


@respx.mock
async def test_ubiquiti_fails_closed_when_search_shape_no_longer_contains_bulletins() -> None:
    route = respx.post(API_URL).mock(
        return_value=httpx.Response(
            200,
            json=_index([_item(identifier="release-1", title="UniFi OS 6.0")]),
        )
    )

    with pytest.raises(ParserChangedError, match="zero Security Advisory Bulletins"):
        await UbiquitiCollector().collect(
            _source(),
            SourceState(source_id="ubiquiti"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )
    assert route.call_count == 1


@respx.mock
async def test_ubiquiti_enforces_detail_limit_before_fetching_details() -> None:
    route = respx.post(API_URL).mock(
        return_value=httpx.Response(
            200,
            json=_index(
                [
                    _item(identifier="bulletin-065", title="Security Advisory Bulletin 065"),
                    _item(identifier="bulletin-066", title="Security Advisory Bulletin 066"),
                ]
            ),
        )
    )

    with pytest.raises(CollectorError, match="detail count exceeds"):
        await UbiquitiCollector().collect(
            _source(max_detail_fetches=1),
            SourceState(source_id="ubiquiti"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )
    assert route.call_count == 1


@respx.mock
async def test_ubiquiti_rejects_graphql_errors() -> None:
    respx.post(API_URL).mock(
        return_value=httpx.Response(200, json={"errors": [{"message": "changed"}]})
    )

    with pytest.raises(ParserChangedError, match="GraphQL response contains errors"):
        await UbiquitiCollector().collect(
            _source(),
            SourceState(source_id="ubiquiti"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )
