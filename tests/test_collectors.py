from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, SafeHttpClient
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
