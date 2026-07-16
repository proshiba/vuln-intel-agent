from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState


class HtmlCollector:
    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        assert source.url is not None
        fetched = await SafeHttpClient(source).fetch(source.url, state, conditional=True)
        if fetched.not_modified:
            return CollectionResult(
                source_id=source.id,
                etag=fetched.etag,
                last_modified=fetched.last_modified,
                not_modified=True,
            )
        soup = BeautifulSoup(fetched.body, "lxml")
        records: list[RawRecord] = []
        nodes = soup.select(source.selectors.get("item", "article"))
        if len(nodes) > source.max_items:
            raise CollectorError(
                f"{source.id}: HTML exceeds configured limit of {source.max_items} items"
            )
        for node in nodes:
            title_node = node.select_one(source.selectors.get("title", "h2, h3"))
            link_node = node.select_one(source.selectors.get("link", "a"))
            if not title_node or not link_node:
                continue
            time_node = node.select_one(source.selectors.get("published_at", "time"))
            records.append(
                RawRecord(
                    source_id=source.id,
                    url=urljoin(source.url, str(link_node.get("href", ""))),
                    content=node.get_text("\n", strip=True),
                    content_type=fetched.content_type,
                    metadata={
                        "title": title_node.get_text(" ", strip=True),
                        "published": time_node.get("datetime") if time_node else None,
                    },
                    fetched_at=datetime.now(UTC),
                )
            )
        if not records:
            raise ParserChangedError(f"{source.id}: selector matched zero items")
        return CollectionResult(
            source_id=source.id,
            records=records,
            etag=fetched.etag,
            last_modified=fetched.last_modified,
        )
