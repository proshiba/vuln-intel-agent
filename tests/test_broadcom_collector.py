from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, ParserChangedError
from vulnwatch.collectors.broadcom import BroadcomCollector
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState
from vulnwatch.parsers import parse_record

ENDPOINT = (
    "https://support.broadcom.com/web/ecx/security-advisory/-/"
    "securityadvisory/getSecurityAdvisoryList"
)


def _source(**overrides: object) -> SourceDefinition:
    values: dict[str, object] = {
        "id": "broadcom_vmware",
        "category": "server_virtualization",
        "vendor": "Broadcom / VMware",
        "products": ["ESXi", "vCenter"],
        "advisory_url": "https://www.broadcom.com/support/vmware-security-advisories",
        "enabled": True,
        "collector": CollectorKind.BROADCOM,
        "url": ENDPOINT,
        "allowed_hosts": ["www.broadcom.com", "support.broadcom.com"],
        "parser": "json",
        "content_types": ["application/json", "text/html"],
        "max_items": 10,
        "max_index_items": 20,
        "rate_limit_per_second": 20,
    }
    values.update(overrides)
    return SourceDefinition.model_validate(values)


def _response(
    items: list[object],
    *,
    current: int = 0,
    last: int = 0,
    total: int | None = None,
    next_page: int = 0,
) -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "success": True,
            "data": {
                "list": items,
                "pageInfo": {
                    "totalCount": len(items) if total is None else total,
                    "currentPage": current,
                    "pageSize": len(items),
                    "nextPage": next_page,
                    "lastPage": last,
                    "firstPage": 0,
                },
            },
        },
        # The public endpoint currently labels its JSON response as text/html.
        headers={"content-type": "text/html;charset=UTF-8"},
    )


def _item(identifier: str, notification_id: int) -> dict[str, object]:
    return {
        "documentId": identifier,
        "notificationId": notification_id,
        "notificationUrl": (
            "https://support.broadcom.com/web/ecx/support-content-notification/-/"
            f"external/content/SecurityAdvisories/0/{notification_id}"
        ),
        "published": "08 June 2026",
        "updated": "2026-06-08T07:26:38.058026",
        "title": f"{identifier}: update for CVE-2026-{notification_id}",
        "affectedCve": f"CVE-2026-{notification_id}",
        "severity": "HIGH",
        "supportProducts": "ESXi,vCenter",
    }


@respx.mock
async def test_broadcom_collector_posts_pages_deduplicates_and_is_partial() -> None:
    route = respx.post(ENDPOINT).mock(
        side_effect=[
            _response(
                [_item("VMSA-1", 10001), _item("VMSA-2", 10002)],
                current=0,
                last=1,
                total=3,
                next_page=1,
            ),
            _response(
                [_item("VMSA-2", 10002), _item("VMSA-3", 10003)],
                current=1,
                last=1,
                total=3,
                next_page=1,
            ),
        ]
    )

    result = await BroadcomCollector().collect(
        _source(),
        SourceState(source_id="broadcom_vmware"),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert [record.metadata["documentId"] for record in result.records] == [
        "VMSA-1",
        "VMSA-2",
        "VMSA-3",
    ]
    assert result.complete_snapshot is False
    assert route.call_count == 2
    first_request = json.loads(route.calls[0].request.content)
    second_request = json.loads(route.calls[1].request.content)
    assert first_request == {
        "pageNumber": 0,
        "pageSize": 100,
        "searchVal": "",
        "segment": "VC",
        "sortInfo": {"column": "", "order": ""},
    }
    assert second_request["pageNumber"] == 1


@respx.mock
async def test_broadcom_record_maps_public_api_fields() -> None:
    item = _item("VMSA-2026-0001", 12345)
    respx.post(ENDPOINT).mock(return_value=_response([item]))

    result = await BroadcomCollector().collect(
        _source(),
        SourceState(source_id="broadcom_vmware"),
        datetime(2026, 4, 1, tzinfo=UTC),
    )
    draft = parse_record(_source(), result.records[0])

    assert draft.vendor_advisory_id == "VMSA-2026-0001"
    assert draft.cves == ["CVE-2026-12345"]
    assert draft.products == ["ESXi,vCenter"]
    assert draft.vendor_severity == "HIGH"
    assert draft.source_url.endswith("/SecurityAdvisories/0/12345")
    assert draft.published_at is not None
    assert draft.updated_at is not None


@respx.mock
@pytest.mark.parametrize(
    "notification_url",
    [
        "http://support.broadcom.com/advisory/1",
        "https://evil.example/advisory/1",
        "https://user@support.broadcom.com/advisory/1",
    ],
)
async def test_broadcom_collector_rejects_unsafe_item_urls(
    notification_url: str,
) -> None:
    item = _item("VMSA-1", 10001)
    item["notificationUrl"] = notification_url
    respx.post(ENDPOINT).mock(return_value=_response([item]))

    with pytest.raises(CollectorError, match="unsafe Broadcom advisory URL"):
        await BroadcomCollector().collect(
            _source(),
            SourceState(source_id="broadcom_vmware"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )


@respx.mock
@pytest.mark.parametrize(
    ("source_overrides", "message"),
    [
        ({"max_index_items": 1}, "index exceeds configured limit"),
        ({"max_items": 1}, "advisories exceed configured limit"),
    ],
)
async def test_broadcom_collector_enforces_item_limits(
    source_overrides: dict[str, int], message: str
) -> None:
    respx.post(ENDPOINT).mock(
        return_value=_response(
            [_item("VMSA-1", 10001), _item("VMSA-2", 10002)], total=2
        )
    )

    with pytest.raises(CollectorError, match=message):
        await BroadcomCollector().collect(
            _source(**source_overrides),
            SourceState(source_id="broadcom_vmware"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )


@respx.mock
@pytest.mark.parametrize(
    "payload",
    [
        {"success": False, "data": {}},
        {"success": True, "data": {"list": [], "pageInfo": None}},
        {
            "success": True,
            "data": {
                "list": ["not-an-object"],
                "pageInfo": {
                    "totalCount": 1,
                    "currentPage": 0,
                    "lastPage": 0,
                },
            },
        },
    ],
)
async def test_broadcom_collector_fails_closed_on_schema_changes(
    payload: dict[str, object],
) -> None:
    respx.post(ENDPOINT).mock(
        return_value=httpx.Response(
            200,
            json=payload,
            headers={"content-type": "text/html;charset=UTF-8"},
        )
    )

    with pytest.raises(ParserChangedError):
        await BroadcomCollector().collect(
            _source(),
            SourceState(source_id="broadcom_vmware"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )
