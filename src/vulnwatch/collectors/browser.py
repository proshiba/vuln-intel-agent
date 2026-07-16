from __future__ import annotations

from datetime import UTC, datetime

from bs4 import BeautifulSoup

from vulnwatch.collectors.base import OptionalDependencyError, ParserChangedError
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState


class BrowserCollector:
    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise OptionalDependencyError(
                "browser collector requires pip install -e .[browser]"
            ) from exc
        assert source.url is not None
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch()
            context = await browser.new_context(
                java_script_enabled=True,
                accept_downloads=False,
                service_workers="block",
            )
            page = await context.new_page()

            async def route_handler(route: object) -> None:
                request = route.request  # type: ignore[attr-defined]
                if request.resource_type in {"image", "font", "media", "stylesheet"}:
                    await route.abort()  # type: ignore[attr-defined]
                else:
                    await route.continue_()  # type: ignore[attr-defined]

            await page.route("**/*", route_handler)
            try:
                await page.goto(source.url, wait_until="domcontentloaded", timeout=45_000)
                if source.wait_for:
                    await page.wait_for_selector(source.wait_for, timeout=20_000)
                html = await page.content()
            finally:
                await context.close()
                await browser.close()
        soup = BeautifulSoup(html, "lxml")
        records = [
            RawRecord(
                source_id=source.id,
                url=source.url,
                content=node.get_text("\n", strip=True),
                content_type="text/html",
                metadata={"title": node.get_text(" ", strip=True)[:500]},
                fetched_at=datetime.now(UTC),
            )
            for node in soup.select(source.selectors.get("item", "article"))
        ]
        if not records:
            raise ParserChangedError(f"{source.id}: browser selector matched zero items")
        return CollectionResult(source_id=source.id, records=records)
