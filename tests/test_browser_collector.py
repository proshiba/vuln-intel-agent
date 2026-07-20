from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import ModuleType
from typing import Any

import pytest

from vulnwatch.collectors.base import CollectorError, ParserChangedError
from vulnwatch.collectors.browser import BrowserCollector
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState


class FakePlaywrightError(Exception):
    pass


@dataclass
class FakeRequest:
    url: str
    resource_type: str = "document"


@dataclass
class FakeRoute:
    request: FakeRequest
    action: str | None = None

    async def abort(self) -> None:
        self.action = "abort"

    async def continue_(self) -> None:
        self.action = "continue"


@dataclass
class FakeResponse:
    url: str
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body_bytes: bytes = b""

    async def body(self) -> bytes:
        return self.body_bytes


@dataclass
class FakePage:
    html: str
    response: FakeResponse | None
    final_url: str
    requests: list[FakeRequest] = field(default_factory=list)
    url_after_content: str | None = None
    url: str = "about:blank"
    default_timeout: int | None = None
    goto_arguments: dict[str, object] = field(default_factory=dict)
    waited_for: tuple[str, str, int] | None = None
    routed: list[FakeRoute] = field(default_factory=list)
    context: FakeContext | None = None

    def set_default_timeout(self, timeout: int) -> None:
        self.default_timeout = timeout

    async def goto(self, url: str, **kwargs: object) -> FakeResponse | None:
        self.goto_arguments = {"url": url, **kwargs}
        if self.context is None or self.context.route_handler is None:
            raise AssertionError("context routing must be installed before navigation")
        for request in self.requests:
            route = FakeRoute(request)
            await self.context.route_handler(route)
            self.routed.append(route)
        self.url = self.final_url
        return self.response

    async def wait_for_selector(self, selector: str, *, state: str, timeout: int) -> None:
        self.waited_for = (selector, state, timeout)

    async def content(self) -> str:
        if self.url_after_content is not None:
            self.url = self.url_after_content
        return self.html


@dataclass
class FakeContext:
    page: FakePage
    route_handler: Any = None
    route_pattern: str | None = None
    closed: bool = False

    async def route(self, pattern: str, handler: Any) -> None:
        self.route_pattern = pattern
        self.route_handler = handler

    async def new_page(self) -> FakePage:
        self.page.context = self
        return self.page

    async def close(self) -> None:
        self.closed = True


@dataclass
class FakeBrowser:
    context: FakeContext
    context_options: dict[str, object] = field(default_factory=dict)
    closed: bool = False

    async def new_context(self, **kwargs: object) -> FakeContext:
        self.context_options = kwargs
        return self.context

    async def close(self) -> None:
        self.closed = True


@dataclass
class FakeChromium:
    browser: FakeBrowser

    async def launch(self) -> FakeBrowser:
        return self.browser


@dataclass
class FakePlaywright:
    chromium: FakeChromium


@dataclass
class FakePlaywrightManager:
    playwright: FakePlaywright

    async def __aenter__(self) -> FakePlaywright:
        return self.playwright

    async def __aexit__(self, *args: object) -> None:
        return None


@dataclass
class FakeEnvironment:
    page: FakePage
    context: FakeContext
    browser: FakeBrowser


@pytest.fixture
def install_playwright(monkeypatch: pytest.MonkeyPatch) -> Any:
    def install(page: FakePage) -> FakeEnvironment:
        context = FakeContext(page)
        browser = FakeBrowser(context)
        playwright = FakePlaywright(FakeChromium(browser))
        manager = FakePlaywrightManager(playwright)

        package = ModuleType("playwright")
        package.__path__ = []  # type: ignore[attr-defined]
        async_api = ModuleType("playwright.async_api")
        async_api.Error = FakePlaywrightError  # type: ignore[attr-defined]
        async_api.async_playwright = lambda: manager  # type: ignore[attr-defined]
        monkeypatch.setitem(sys.modules, "playwright", package)
        monkeypatch.setitem(sys.modules, "playwright.async_api", async_api)
        return FakeEnvironment(page, context, browser)

    return install


def _source(**overrides: object) -> SourceDefinition:
    values: dict[str, object] = {
        "id": "browser_example",
        "category": "test",
        "vendor": "Example",
        "products": ["Example Product"],
        "advisory_url": "https://security.example.com/advisories",
        "enabled": True,
        "collector": CollectorKind.BROWSER,
        "url": "https://security.example.com/advisories",
        "allowed_hosts": ["security.example.com"],
        "timeout_seconds": 5,
        "max_response_bytes": 100_000,
        "max_detail_fetches": 0,
    }
    values.update(overrides)
    return SourceDefinition.model_validate(values)


async def _collect(source: SourceDefinition) -> Any:
    return await BrowserCollector().collect(
        source,
        SourceState(source_id=source.id),
        datetime(2026, 1, 1, tzinfo=UTC),
    )


async def test_browser_routes_only_https_allowed_hosts_and_blocks_assets(
    install_playwright: Any,
) -> None:
    url = "https://security.example.com/advisories"
    page = FakePage(
        html="<html><body>No advisories</body></html>",
        response=FakeResponse(url),
        final_url=url,
        requests=[
            FakeRequest("https://SECURITY.example.com/app.js", "script"),
            FakeRequest("https://security.example.com/app.css", "stylesheet"),
            FakeRequest("https://outside.example/api", "xhr"),
            FakeRequest("http://security.example.com/plain", "document"),
            FakeRequest("https://security.example.com/logo.png", "image"),
        ],
    )
    environment = install_playwright(page)

    await _collect(_source())

    assert environment.context.route_pattern == "**/*"
    assert [route.action for route in page.routed] == [
        "continue",
        "continue",
        "abort",
        "abort",
        "abort",
    ]
    assert environment.browser.context_options == {
        "java_script_enabled": True,
        "accept_downloads": False,
        "service_workers": "block",
        "user_agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
        ),
        "locale": "en-US",
    }
    assert environment.context.closed is True
    assert environment.browser.closed is True


async def test_browser_rejects_navigation_outside_allowed_hosts(
    install_playwright: Any,
) -> None:
    page = FakePage(
        html="<html></html>",
        response=FakeResponse("https://outside.example/advisories"),
        final_url="https://outside.example/advisories",
    )
    environment = install_playwright(page)

    with pytest.raises(CollectorError, match="navigation left allowed hosts"):
        await _collect(_source())

    assert environment.context.closed is True
    assert environment.browser.closed is True


async def test_browser_rechecks_navigation_after_rendering(
    install_playwright: Any,
) -> None:
    url = "https://security.example.com/advisories"
    page = FakePage(
        html="<html></html>",
        response=FakeResponse(url),
        final_url=url,
        url_after_content="data:text/html,untrusted",
    )
    install_playwright(page)

    with pytest.raises(CollectorError, match="navigation left allowed hosts"):
        await _collect(_source(wait_for="body"))


async def test_browser_rejects_http_error_response(install_playwright: Any) -> None:
    url = "https://security.example.com/advisories"
    page = FakePage(
        html="<html></html>",
        response=FakeResponse(url, status=503),
        final_url=url,
    )
    install_playwright(page)

    with pytest.raises(CollectorError, match="browser HTTP 503"):
        await _collect(_source())


async def test_browser_rejects_declared_response_over_size_limit(
    install_playwright: Any,
) -> None:
    url = "https://security.example.com/advisories"
    page = FakePage(
        html="<html></html>",
        response=FakeResponse(url, headers={"content-length": "101"}),
        final_url=url,
    )
    install_playwright(page)

    with pytest.raises(CollectorError, match="response exceeds 100 bytes"):
        await _collect(_source(max_response_bytes=100))


async def test_browser_rejects_rendered_dom_over_size_limit(
    install_playwright: Any,
) -> None:
    url = "https://security.example.com/advisories"
    page = FakePage(
        html="脆" * 40,
        response=FakeResponse(url),
        final_url=url,
    )
    install_playwright(page)

    with pytest.raises(CollectorError, match="response exceeds 100 bytes"):
        await _collect(_source(max_response_bytes=100))


async def test_browser_extracts_configured_selector_records_from_final_url(
    install_playwright: Any,
) -> None:
    initial_url = "https://security.example.com/advisories"
    final_url = "https://security.example.com/security/index"
    page = FakePage(
        html=(
            "<html><body><article class='advisory'>"
            "<a class='detail' href='ADV-2026-001'>"
            "<span class='title'>Security advisory CVE-2026-12345</span></a>"
            "<time datetime='2026-07-01T00:00:00Z'></time>"
            "</article></body></html>"
        ),
        response=FakeResponse(final_url),
        final_url=final_url,
    )
    install_playwright(page)

    result = await _collect(
        _source(
            url=initial_url,
            wait_for=".advisory",
            selectors={
                "item": ".advisory",
                "link": ".detail",
                "title": ".title",
                "published_at": "time",
            },
        )
    )

    assert result.complete_snapshot is False
    assert len(result.records) == 1
    assert result.records[0].url == "https://security.example.com/security/ADV-2026-001"
    assert result.records[0].metadata["title"] == "Security advisory CVE-2026-12345"
    assert result.records[0].metadata["published"] == "2026-07-01T00:00:00Z"
    assert page.waited_for == (".advisory", "attached", 5000)
    assert page.default_timeout == 5000
    assert page.goto_arguments == {
        "url": initial_url,
        "wait_until": "domcontentloaded",
        "timeout": 5000,
    }


async def test_browser_uses_generic_link_extraction(install_playwright: Any) -> None:
    url = "https://security.example.com/advisories"
    page = FakePage(
        html=(
            "<html><body><ul>"
            "<li><a href='/security/ADV-2'>Security advisory CVE-2026-23456</a></li>"
            "<li><a href='https://outside.example/CVE-2026-99999'>External advisory</a></li>"
            "</ul></body></html>"
        ),
        response=FakeResponse(url),
        final_url=url,
    )
    install_playwright(page)

    result = await _collect(_source())

    assert [record.url for record in result.records] == [
        "https://security.example.com/security/ADV-2"
    ]


async def test_browser_accepts_empty_page_as_partial_success(
    install_playwright: Any,
) -> None:
    url = "https://security.example.com/advisories"
    page = FakePage(
        html="<html><body><h1>No current advisories</h1></body></html>",
        response=FakeResponse(url),
        final_url=url,
    )
    install_playwright(page)

    result = await _collect(_source())

    assert result.records == []
    assert result.complete_snapshot is False


async def test_browser_fails_closed_when_configured_selector_matches_nothing(
    install_playwright: Any,
) -> None:
    url = "https://security.example.com/advisories"
    page = FakePage(
        html="<html><body><a href='/security'>Security home</a></body></html>",
        response=FakeResponse(url),
        final_url=url,
    )
    install_playwright(page)

    with pytest.raises(ParserChangedError, match="selector matched zero advisory records"):
        await _collect(_source(selectors={"item": "article.advisory"}))


async def test_browser_parses_raw_machine_readable_response(
    install_playwright: Any,
) -> None:
    url = "https://security.example.com/advisories.xml"
    rss = b"""<?xml version="1.0"?>
    <rss version="2.0"><channel><title>Advisories</title><item>
      <title>Security advisory CVE-2026-12345</title>
      <link>https://security.example.com/ADV-1</link>
      <pubDate>Wed, 01 Jul 2026 00:00:00 GMT</pubDate>
    </item></channel></rss>"""
    page = FakePage(
        html="<html></html>",
        response=FakeResponse(
            url,
            headers={"content-type": "application/rss+xml"},
            body_bytes=rss,
        ),
        final_url=url,
    )
    install_playwright(page)

    result = await _collect(
        _source(
            url=url,
            advisory_url="https://security.example.com/advisories",
            content_types=["application/rss+xml"],
        )
    )

    assert len(result.records) == 1
    assert result.records[0].url == "https://security.example.com/ADV-1"
