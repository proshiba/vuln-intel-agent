from __future__ import annotations

import re
import warnings
from datetime import UTC, datetime
from typing import Any

import feedparser
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from dateutil.parser import parse as parse_date

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import (
    CollectionResult,
    CollectorKind,
    RawRecord,
    SourceDefinition,
    SourceState,
)


class FeedCollector:
    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        assert source.url is not None
        client = SafeHttpClient(source)
        fetched = await client.fetch(source.url, state, conditional=True)
        if fetched.not_modified:
            return CollectionResult(
                source_id=source.id,
                etag=fetched.etag,
                last_modified=fetched.last_modified,
                not_modified=True,
            )
        parsed = feedparser.parse(fetched.body)
        entries = list(parsed.entries)
        link_contains = source.selectors.get("link_contains")
        if link_contains:
            entries = [
                entry
                for entry in entries
                if link_contains in str(entry.get("link") or "")
            ]
        title_pattern = source.selectors.get("title_pattern")
        if title_pattern:
            try:
                title_regex = re.compile(title_pattern, re.IGNORECASE)
            except re.error as exc:
                raise CollectorError(
                    f"{source.id}: invalid selectors.title_pattern: {exc}"
                ) from exc
            entries = [
                entry
                for entry in entries
                if title_regex.search(str(entry.get("title") or ""))
            ]
        if len(entries) > source.max_items:
            raise CollectorError(
                f"{source.id}: feed exceeds configured limit of {source.max_items} items"
            )
        records: list[RawRecord] = []
        for entry in entries:
            summary = str(entry.get("summary") or "")
            title = str(entry.get("title") or "")
            metadata: dict[str, Any] = {
                "id": entry.get("id"),
                "title": title,
                "published": entry.get("published"),
                "updated": entry.get("updated"),
                "summary": summary,
            }
            records.append(
                RawRecord(
                    source_id=source.id,
                    url=client.advisory_url(entry.get("link"), base_url=fetched.url),
                    content=summary or title,
                    content_type=fetched.content_type,
                    metadata=metadata,
                    fetched_at=datetime.now(UTC),
                )
            )
        if not records and not link_contains:
            raise ParserChangedError(f"{source.id}: feed contained zero entries")
        if source.detail_collector == CollectorKind.HTML and source.max_detail_fetches:
            await self._add_html_details(source, records, since)
        return CollectionResult(
            source_id=source.id,
            records=records,
            etag=fetched.etag,
            last_modified=fetched.last_modified,
            complete_snapshot=False,
        )

    @staticmethod
    async def _add_html_details(
        source: SourceDefinition,
        records: list[RawRecord],
        since: datetime,
    ) -> None:
        detail_source = source.model_copy(
            update={"content_types": ["text/html", "application/xhtml+xml"]}
        )
        client = SafeHttpClient(detail_source)
        fetched_count = 0
        detail_errors: list[str] = []
        for record in records:
            published = record.metadata.get("updated") or record.metadata.get("published")
            if published:
                try:
                    observed = parse_date(str(published))
                    if observed.tzinfo is None:
                        observed = observed.replace(tzinfo=UTC)
                    if observed.astimezone(UTC) < since.astimezone(UTC):
                        continue
                except (TypeError, ValueError, OverflowError):
                    pass
            if fetched_count >= source.max_detail_fetches:
                break
            fetched_count += 1
            try:
                detail = await client.fetch(record.url)
            except CollectorError as exc:
                record.metadata["detail_error"] = str(exc)[:500]
                detail_errors.append(str(exc))
                continue
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", XMLParsedAsHTMLWarning)
                soup = BeautifulSoup(detail.body, "lxml")
            body = soup.select_one("main, article, body")
            if body:
                record.content = body.get_text("\n", strip=True)[:100_000]
                record.metadata["detail_url"] = detail.url
        if detail_errors:
            raise CollectorError(
                f"{source.id}: {len(detail_errors)} advisory detail fetch(es) failed: "
                f"{detail_errors[0][:500]}"
            )
