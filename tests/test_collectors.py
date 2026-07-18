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
