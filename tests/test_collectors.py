import re
from datetime import UTC, datetime, timedelta, timezone
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, SafeHttpClient
from vulnwatch.collectors.json_api import JsonApiCollector
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState


def _source(**overrides: object) -> SourceDefinition:
    values: dict[str, object] = {
        "id": "example",
        "category": "test",
        "vendor": "Example",
        "products": [],
        "advisory_url": "https://security.example.com/advisories",
        "enabled": True,
        "collector": CollectorKind.JSON_API,
        "url": "https://security.example.com/feed.json",
        "allowed_hosts": ["security.example.com"],
        "content_types": ["application/json"],
        "timeout_seconds": 1,
    }
    values.update(overrides)
    return SourceDefinition.model_validate(values)


@respx.mock
async def test_conditional_request_and_304() -> None:
    route = respx.get("https://security.example.com/feed.json").mock(
        return_value=httpx.Response(304, headers={"etag": '"new"'})
    )
    state = SourceState(source_id="example", etag='"old"')

    result = await SafeHttpClient(_source()).fetch(
        "https://security.example.com/feed.json", state, conditional=True
    )

    assert result.not_modified
    assert route.calls[0].request.headers["if-none-match"] == '"old"'
    assert route.calls[0].request.headers["user-agent"].startswith("Mozilla/5.0")
    assert "vulnwatch/0.1" in route.calls[0].request.headers["user-agent"]


@respx.mock
async def test_schneider_landing_page_uses_transparent_compatible_user_agent() -> None:
    url = "https://www.se.com/ww/en/work/support/cybersecurity/security-notifications/"
    route = respx.get(url).mock(
        return_value=httpx.Response(
            200,
            text="<html></html>",
            headers={"content-type": "text/html"},
        )
    )
    source = _source(
        id="schneider_electric",
        advisory_url=url,
        url=url,
        allowed_hosts=["www.se.com"],
        content_types=["text/html"],
    )

    await SafeHttpClient(source).fetch(url)

    assert route.calls[0].request.headers["user-agent"] == (
        "vulnwatch/0.1 (+public vulnerability intelligence collection)"
    )


@respx.mock
async def test_redirect_to_unapproved_host_is_rejected() -> None:
    respx.get("https://security.example.com/feed.json").mock(
        return_value=httpx.Response(302, headers={"location": "https://evil.example/feed"})
    )

    with pytest.raises(CollectorError, match="host is not allowed"):
        await SafeHttpClient(_source()).fetch("https://security.example.com/feed.json")


@respx.mock
async def test_retry_only_transient_statuses(monkeypatch: pytest.MonkeyPatch) -> None:
    sleep = AsyncMock()
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", sleep)
    route = respx.get("https://security.example.com/feed.json").mock(
        side_effect=[
            httpx.Response(500),
            httpx.Response(429, headers={"retry-after": "1"}),
            httpx.Response(200, json={"items": []}),
        ]
    )

    result = await SafeHttpClient(_source()).fetch("https://security.example.com/feed.json")

    assert result.body == b'{"items":[]}'
    assert route.call_count == 3
    assert sleep.await_count >= 2


@respx.mock
async def test_content_type_and_size_limits() -> None:
    respx.get("https://security.example.com/feed.json").mock(
        return_value=httpx.Response(200, text="html", headers={"content-type": "text/html"})
    )
    with pytest.raises(CollectorError, match="unexpected Content-Type"):
        await SafeHttpClient(_source()).fetch("https://security.example.com/feed.json")

    respx.get("https://security.example.com/feed.json").mock(
        return_value=httpx.Response(
            200,
            content=b"12345",
            headers={"content-type": "application/json"},
        )
    )
    with pytest.raises(CollectorError, match="response exceeds"):
        await SafeHttpClient(_source(max_response_bytes=4)).fetch(
            "https://security.example.com/feed.json"
        )


@respx.mock
async def test_github_token_is_scoped_to_api_host_and_gh_token_has_precedence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GH_TOKEN", "preferred-token")
    monkeypatch.setenv("GITHUB_TOKEN", "fallback-token")
    api_url = "https://api.github.com/repos/example/project/security-advisories"
    source = _source(
        advisory_url="https://github.com/example/project/security/advisories",
        url=api_url,
        allowed_hosts=["api.github.com", "github.com"],
    )
    api_route = respx.get(api_url).mock(
        return_value=httpx.Response(200, json=[], headers={"content-type": "application/json"})
    )
    vendor_route = respx.get("https://security.example.com/feed.json").mock(
        return_value=httpx.Response(200, json={}, headers={"content-type": "application/json"})
    )

    await SafeHttpClient(source).fetch(api_url)
    await SafeHttpClient(_source()).fetch("https://security.example.com/feed.json")

    assert api_route.calls[0].request.headers["authorization"] == "Bearer preferred-token"
    assert "authorization" not in vendor_route.calls[0].request.headers


@respx.mock
async def test_github_token_falls_back_and_is_removed_on_redirect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GH_TOKEN", "   ")
    monkeypatch.setenv("GITHUB_TOKEN", "workflow-token")
    api_url = "https://api.github.com/repos/example/project/security-advisories"
    redirected_url = "https://github.com/example/project/security/advisories.json"
    source = _source(
        advisory_url="https://github.com/example/project/security/advisories",
        url=api_url,
        allowed_hosts=["api.github.com", "github.com"],
    )
    api_route = respx.get(api_url).mock(
        return_value=httpx.Response(302, headers={"location": redirected_url})
    )
    redirected_route = respx.get(redirected_url).mock(
        return_value=httpx.Response(200, json=[], headers={"content-type": "application/json"})
    )

    await SafeHttpClient(source).fetch(api_url)

    assert api_route.calls[0].request.headers["authorization"] == "Bearer workflow-token"
    assert "authorization" not in redirected_route.calls[0].request.headers


@respx.mock
async def test_github_rate_limit_error_does_not_expose_token(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "secret-value-that-must-not-leak"
    monkeypatch.setenv("GH_TOKEN", token)
    api_url = "https://api.github.com/repos/example/project/security-advisories"
    source = _source(
        advisory_url="https://github.com/example/project/security/advisories",
        url=api_url,
        allowed_hosts=["api.github.com", "github.com"],
    )
    respx.get(api_url).mock(
        return_value=httpx.Response(
            403,
            headers={"x-ratelimit-remaining": "0", "x-ratelimit-reset": "0"},
        )
    )

    with pytest.raises(CollectorError, match="set GH_TOKEN or GITHUB_TOKEN") as caught:
        await SafeHttpClient(source).fetch(api_url)

    assert token not in str(caught.value)


@respx.mock
async def test_json_api_follows_next_links_without_reusing_conditionals_and_deduplicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    first_url = "https://security.example.com/feed.json"
    second_url = "https://security.example.com/feed.json?page=2"
    first = respx.get(re.compile(rf"{re.escape(first_url)}$")).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"id": "ADV-1", "url": "https://security.example.com/advisories/1"},
                {
                    "ghsa_id": "GHSA-2",
                    "url": "https://security.example.com/advisories/2",
                },
            ],
            headers={
                "content-type": "application/json",
                "etag": '"first-page"',
                "last-modified": "Sat, 18 Jul 2026 00:00:00 GMT",
                "link": '<?page=2>; rel="prev next"',
            },
        )
    )
    second = respx.get(re.compile(rf"{re.escape(second_url)}$")).mock(
        return_value=httpx.Response(
            200,
            json=[
                {"ghsa_id": "adv-1", "url": "https://security.example.com/duplicate"},
                {"url": "https://security.example.com/advisories/2"},
                {"id": "ADV-3", "url": "https://security.example.com/advisories/3"},
            ],
            headers={"content-type": "application/json", "etag": '"second-page"'},
        )
    )
    state = SourceState(
        source_id="example",
        etag='"old"',
        last_modified="Fri, 17 Jul 2026 00:00:00 GMT",
    )

    result = await JsonApiCollector().collect(
        _source(max_items=3, max_index_items=5, rate_limit_per_second=20),
        state,
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    identifiers = [
        record.metadata.get("id") or record.metadata.get("ghsa_id")
        for record in result.records
    ]
    assert identifiers == [
        "ADV-1",
        "GHSA-2",
        "ADV-3",
    ]
    assert result.etag == '"first-page"'
    assert result.last_modified == "Sat, 18 Jul 2026 00:00:00 GMT"
    assert result.complete_snapshot is False
    assert first.calls[0].request.headers["if-none-match"] == '"old"'
    assert first.calls[0].request.headers["if-modified-since"] == state.last_modified
    assert "if-none-match" not in second.calls[0].request.headers
    assert "if-modified-since" not in second.calls[0].request.headers


@respx.mock
async def test_json_api_not_modified_result_is_not_a_complete_snapshot() -> None:
    respx.get("https://security.example.com/feed.json").mock(
        return_value=httpx.Response(304, headers={"etag": '"current"'})
    )

    result = await JsonApiCollector().collect(
        _source(),
        SourceState(source_id="example", etag='"old"'),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert result.not_modified is True
    assert result.complete_snapshot is False


@respx.mock
async def test_github_global_advisories_adds_since_filter_and_uses_item_link() -> None:
    global_url = (
        "https://api.github.com/advisories?type=reviewed&sort=updated&"
        "updated=%3E%3D2020-01-01T00%3A00%3A00Z"
    )
    route = respx.get(re.compile(r"https://api\.github\.com/advisories\?.+")).mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "ghsa_id": "GHSA-TEST-0001",
                    "item_link": "https://github.com/advisories/GHSA-TEST-0001",
                }
            ],
            headers={"content-type": "application/json"},
        )
    )
    since = datetime(2026, 7, 19, 9, 30, tzinfo=timezone(timedelta(hours=9)))

    result = await JsonApiCollector().collect(
        _source(
            advisory_url="https://github.com/advisories",
            url=global_url,
            allowed_hosts=["api.github.com", "github.com"],
        ),
        SourceState(source_id="example"),
        since,
    )

    params = route.calls[0].request.url.params
    assert params.get_list("updated") == [">=2026-07-19T00:30:00Z"]
    assert params["type"] == "reviewed"
    assert params["sort"] == "updated"
    assert result.records[0].url == "https://github.com/advisories/GHSA-TEST-0001"
    repository_url = "https://api.github.com/repos/example/project/security-advisories"
    assert JsonApiCollector._collection_url(repository_url, since) == repository_url


@respx.mock
async def test_ibm_security_api_reads_nested_records_and_builds_node_urls() -> None:
    api_url = "https://www.ibm.com/support/pages/securityapp/api/site/datalist?limit=1000"
    respx.get(api_url).mock(
        return_value=httpx.Response(
            200,
            json={
                "results": {
                    "top_records": [
                        {
                            "nid": "7280476",
                            "title": "Multiple vulnerabilities affect IBM Example",
                            "field_cve_id": "CVE-2026-12345",
                            "field_pub_date": "2026-07-18",
                        }
                    ]
                }
            },
            headers={"content-type": "application/json"},
        )
    )

    result = await JsonApiCollector().collect(
        _source(
            id="ibm",
            advisory_url="https://www.ibm.com/support/pages/bulletin/",
            url=api_url,
            allowed_hosts=["www.ibm.com"],
        ),
        SourceState(source_id="ibm"),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert len(result.records) == 1
    assert result.records[0].metadata["nid"] == "7280476"
    assert result.records[0].url == "https://www.ibm.com/support/pages/node/7280476"


@respx.mock
async def test_manageengine_public_api_uses_required_origin_and_paginates() -> None:
    api_url = (
        "https://securitycontact.manageengine.com/publiccve?host=me&from=1&"
        "limit=2&criteria=%28For_product_search%3D%3D0%29"
    )
    route = respx.get(
        re.compile(r"https://securitycontact\.manageengine\.com/publiccve\?.+")
    ).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "ID": "1",
                            "CVE_ID": "CVE-2026-10001",
                            "ADVISORY": "First issue",
                            "CVE_Details_Link": {
                                "url": "https://www.manageengine.com/advisory/CVE-2026-10001.html"
                            },
                        },
                        {
                            "ID": "2",
                            "CVE_ID": "CVE-2026-10002",
                            "ADVISORY": "Second issue",
                            "CVE_Details_Link": {
                                "value": "https://www.manageengine.com/advisory/CVE-2026-10002.html"
                            },
                        },
                    ]
                },
                headers={"content-type": "application/json"},
            ),
            httpx.Response(
                200,
                json={
                    "data": [
                        {
                            "ID": "3",
                            "CVE_ID": "CVE-2026-10003",
                            "ADVISORY": "Third issue",
                            "CVE_Details_Link": {
                                "url": "https://www.manageengine.com/advisory/CVE-2026-10003.html"
                            },
                        }
                    ]
                },
                headers={"content-type": "application/json"},
            ),
        ]
    )
    source = _source(
        id="manageengine",
        advisory_url="https://www.manageengine.com/security/advisory/",
        url=api_url,
        allowed_hosts=["securitycontact.manageengine.com", "www.manageengine.com"],
        max_items=10,
        max_index_items=10,
    )

    result = await JsonApiCollector().collect(
        source,
        SourceState(source_id="manageengine"),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert route.call_count == 2
    assert route.calls[1].request.url.params["from"] == "3"
    assert all(
        call.request.headers["origin"] == "https://www.manageengine.com"
        and call.request.headers["referer"]
        == "https://www.manageengine.com/security/advisory/"
        for call in route.calls
    )
    assert [record.url for record in result.records] == [
        "https://www.manageengine.com/advisory/CVE-2026-10001.html",
        "https://www.manageengine.com/advisory/CVE-2026-10002.html",
        "https://www.manageengine.com/advisory/CVE-2026-10003.html",
    ]


@respx.mock
@pytest.mark.parametrize(
    ("source_overrides", "message"),
    [
        ({"max_index_items": 1, "max_items": 3}, "JSON index exceeds configured limit"),
        ({"max_index_items": 3, "max_items": 1}, "JSON exceeds configured limit"),
    ],
)
async def test_json_api_enforces_index_and_record_limits(
    source_overrides: dict[str, int],
    message: str,
) -> None:
    respx.get("https://security.example.com/feed.json").mock(
        return_value=httpx.Response(
            200,
            json=[{"id": "ADV-1"}, {"id": "ADV-2"}],
            headers={"content-type": "application/json"},
        )
    )

    with pytest.raises(CollectorError, match=message):
        await JsonApiCollector().collect(
            _source(**source_overrides),
            SourceState(source_id="example"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )


@respx.mock
@pytest.mark.parametrize(
    ("next_url", "message"),
    [
        ("https://evil.example/feed.json?page=2", "host is not allowed"),
        ("http://security.example.com/feed.json?page=2", "non-HTTPS URL rejected"),
    ],
)
async def test_json_api_rejects_unsafe_next_links(next_url: str, message: str) -> None:
    respx.get("https://security.example.com/feed.json").mock(
        return_value=httpx.Response(
            200,
            json=[{"id": "ADV-1"}],
            headers={
                "content-type": "application/json",
                "link": f'<{next_url}>; rel="next"',
            },
        )
    )

    with pytest.raises(CollectorError, match=message):
        await JsonApiCollector().collect(
            _source(),
            SourceState(source_id="example"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )


@respx.mock
async def test_json_api_rejects_pagination_loops() -> None:
    url = "https://security.example.com/feed.json"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            json=[{"id": "ADV-1"}],
            headers={"content-type": "application/json", "link": f'<{url}>; rel="next"'},
        )
    )

    with pytest.raises(CollectorError, match="pagination loop"):
        await JsonApiCollector().collect(
            _source(),
            SourceState(source_id="example"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )


@respx.mock
async def test_json_api_rejects_page_chains_over_the_page_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    monkeypatch.setattr("vulnwatch.collectors.json_api._MAX_PAGES", 2)
    first_url = "https://security.example.com/feed.json"
    second_url = "https://security.example.com/feed.json?page=2"
    for page_url, item_id, next_page in (
        (first_url, "ADV-1", second_url),
        (second_url, "ADV-2", "https://security.example.com/feed.json?page=3"),
    ):
        respx.get(re.compile(rf"{re.escape(page_url)}$")).mock(
            return_value=httpx.Response(
                200,
                json=[{"id": item_id}],
                headers={
                    "content-type": "application/json",
                    "link": f'<{next_page}>; rel="next"',
                },
            )
        )

    with pytest.raises(CollectorError, match="limit of 2 pages"):
        await JsonApiCollector().collect(
            _source(max_items=3),
            SourceState(source_id="example"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )


@respx.mock
async def test_netapp_api_adds_since_filter_and_uses_bounded_offset_pagination(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    route = respx.get(re.compile(r"https://security\.netapp\.com/adv_api/advisory/\?.+")).mock(
        side_effect=[
            httpx.Response(
                200,
                json={
                    "status": "success",
                    "total_count": 3,
                    "advisories": [
                        {"ntap_advisory_id": "NTAP-20260719-0001"},
                        {"ntap_advisory_id": "NTAP-20260718-0002"},
                    ],
                },
                headers={"content-type": "application/json"},
            ),
            httpx.Response(
                200,
                json={
                    "status": "success",
                    "total_count": 3,
                    "advisories": [
                        {"ntap_advisory_id": "NTAP-20260717-0003"},
                    ],
                },
                headers={"content-type": "application/json"},
            ),
        ]
    )
    source = _source(
        id="netapp",
        advisory_url="https://security.netapp.com/advisory",
        url="https://security.netapp.com/adv_api/advisory/?limit=2",
        allowed_hosts=["security.netapp.com"],
        parser="netapp",
        max_items=3,
        max_index_items=3,
        rate_limit_per_second=20,
    )

    result = await JsonApiCollector().collect(
        source,
        SourceState(source_id="netapp"),
        datetime(2026, 7, 1, 15, 0, tzinfo=timezone(timedelta(hours=-4))),
    )

    assert route.call_count == 2
    assert route.calls[0].request.url.params["updated_start_date"] == "2026-07-01"
    assert route.calls[0].request.url.params["skip"] == "0"
    assert route.calls[0].request.url.params["sort_by"] == "ntap_advisory_id"
    assert route.calls[1].request.url.params["skip"] == "2"
    assert [record.url for record in result.records] == [
        "https://security.netapp.com/advisory/NTAP-20260719-0001",
        "https://security.netapp.com/advisory/NTAP-20260718-0002",
        "https://security.netapp.com/advisory/NTAP-20260717-0003",
    ]


@respx.mock
async def test_netapp_api_rejects_reported_total_over_index_limit() -> None:
    respx.get(re.compile(r"https://security\.netapp\.com/adv_api/advisory/\?.+")).mock(
        return_value=httpx.Response(
            200,
            json={
                "status": "success",
                "total_count": 11,
                "advisories": [{"ntap_advisory_id": "NTAP-20260719-0001"}],
            },
            headers={"content-type": "application/json"},
        )
    )
    source = _source(
        id="netapp",
        advisory_url="https://security.netapp.com/advisory",
        url="https://security.netapp.com/adv_api/advisory/?limit=10",
        allowed_hosts=["security.netapp.com"],
        max_items=10,
        max_index_items=10,
    )

    with pytest.raises(CollectorError, match="JSON index exceeds configured limit"):
        await JsonApiCollector().collect(
            source,
            SourceState(source_id="netapp"),
            datetime(2026, 7, 1, tzinfo=UTC),
        )
