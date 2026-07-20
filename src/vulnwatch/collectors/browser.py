from __future__ import annotations

import asyncio
from datetime import datetime
from urllib.parse import urlsplit

from bs4 import BeautifulSoup

from vulnwatch.collectors.base import (
    CollectorError,
    OptionalDependencyError,
    ParserChangedError,
)
from vulnwatch.collectors.web import WebCollector
from vulnwatch.models import CollectionResult, SourceDefinition, SourceState

_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36"
)


class BrowserCollector:
    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        del state
        try:
            from playwright.async_api import Error as PlaywrightError
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise OptionalDependencyError(
                "browser collector requires pip install -e .[browser]"
            ) from exc
        assert source.url is not None
        allowed_hosts = {host.casefold() for host in source.allowed_hosts}
        timeout_ms = int(source.timeout_seconds * 1000)
        final_url = source.url
        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch()
                try:
                    context = await browser.new_context(
                        java_script_enabled=True,
                        accept_downloads=False,
                        service_workers="block",
                        user_agent=_BROWSER_USER_AGENT,
                        locale="en-US",
                    )
                    try:

                        async def route_handler(route: object) -> None:
                            request = route.request  # type: ignore[attr-defined]
                            parsed = urlsplit(str(request.url))
                            allowed = (
                                parsed.scheme == "https"
                                and (parsed.hostname or "").casefold() in allowed_hosts
                            )
                            if not allowed or request.resource_type in {
                                "image",
                                "font",
                                "media",
                            }:
                                await route.abort()  # type: ignore[attr-defined]
                            else:
                                await route.continue_()  # type: ignore[attr-defined]

                        # Context routing also covers popups created by page JavaScript.
                        await context.route("**/*", route_handler)
                        page = await context.new_page()
                        page.set_default_timeout(timeout_ms)
                        response = await page.goto(
                            source.url,
                            wait_until="domcontentloaded",
                            timeout=timeout_ms,
                        )
                        if response is None:
                            raise CollectorError(
                                f"{source.id}: browser navigation returned no HTTP response"
                            )
                        self._validate_page_url(
                            source.id,
                            str(response.url),
                            allowed_hosts,
                        )
                        if response.status >= 400:
                            raise CollectorError(
                                f"{source.id}: browser HTTP {response.status} from {response.url}"
                            )
                        declared_size = self._declared_content_length(response)
                        if declared_size is not None and declared_size > source.max_response_bytes:
                            raise CollectorError(
                                f"{source.id}: browser response exceeds "
                                f"{source.max_response_bytes} bytes"
                            )
                        response_content_type = str(
                            response.headers.get("content-type", "")
                        ).casefold()
                        if any(
                            marker in response_content_type
                            for marker in ("json", "xml", "rss", "atom")
                        ):
                            response_body = await response.body()
                            if len(response_body) > source.max_response_bytes:
                                raise CollectorError(
                                    f"{source.id}: browser response exceeds "
                                    f"{source.max_response_bytes} bytes"
                                )
                            structured = WebCollector._structured_records(
                                source,
                                str(response.url),
                                response_body,
                                response_content_type,
                                since,
                            )
                            if structured is not None:
                                return CollectionResult(
                                    source_id=source.id,
                                    records=structured,
                                    complete_snapshot=False,
                                )
                        self._validate_page_url(source.id, page.url, allowed_hosts)
                        if source.wait_for:
                            # Advisory tables are sometimes rendered inside a hidden tab.
                            # Presence in the DOM is sufficient for extraction; requiring
                            # CSS visibility would turn a populated official table into a
                            # timeout.
                            await page.wait_for_selector(
                                source.wait_for,
                                state="attached",
                                timeout=timeout_ms,
                            )
                        # Some SPA entry points perform a client-side navigation just
                        # after ``domcontentloaded``. Playwright refuses ``content()``
                        # while that navigation is in flight, so retry that narrow,
                        # transient condition rather than turning a healthy page into
                        # a source failure.
                        for attempt in range(5):
                            try:
                                html = await page.content()
                                break
                            except PlaywrightError as exc:
                                if "page is navigating" not in str(exc).casefold() or attempt == 4:
                                    raise
                                await asyncio.sleep(0.5)
                        final_url = page.url
                        self._validate_page_url(source.id, final_url, allowed_hosts)
                    finally:
                        await context.close()
                finally:
                    await browser.close()
        except CollectorError:
            raise
        except PlaywrightError as exc:
            raise CollectorError(f"{source.id}: browser navigation failed: {exc}") from exc
        encoded = html.encode("utf-8")
        if len(encoded) > source.max_response_bytes:
            raise CollectorError(
                f"{source.id}: browser response exceeds {source.max_response_bytes} bytes"
            )
        soup = BeautifulSoup(html, "lxml")
        records = WebCollector._explicit_html_records(source, final_url, soup)
        if source.selectors.get("item") and not records:
            raise ParserChangedError(
                f"{source.id}: configured browser selector matched zero advisory records"
            )
        if not records:
            records = WebCollector._generic_html_records(source, final_url, soup)
        if not records:
            records = WebCollector._inline_cve_records(source, final_url, soup)
        return CollectionResult(
            source_id=source.id,
            records=records,
            complete_snapshot=False,
        )

    @staticmethod
    def _validate_page_url(source_id: str, url: str, allowed_hosts: set[str]) -> None:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or (parsed.hostname or "").casefold() not in allowed_hosts:
            raise CollectorError(f"{source_id}: browser navigation left allowed hosts: {url}")

    @staticmethod
    def _declared_content_length(response: object) -> int | None:
        headers = response.headers  # type: ignore[attr-defined]
        value = str(headers.get("content-length", "")).strip()
        if not value.isdecimal():
            return None
        return int(value)
