from __future__ import annotations

import csv
import io
import json
from datetime import UTC, datetime
from urllib.parse import urljoin

import feedparser
from bs4 import BeautifulSoup
from dateutil.parser import parse as parse_date

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState


class CsafCollector:
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
        links: list[str] = []
        records: list[RawRecord] = []
        if "json" in fetched.content_type:
            payload = json.loads(fetched.body)
            if isinstance(payload, dict) and "document" in payload:
                records.append(self._record(source, fetched.url, payload, fetched.content_type))
            elif isinstance(payload, dict):
                for distribution in payload.get("distributions", []):
                    directory = distribution.get("directory_url")
                    if directory:
                        directory_content = await client.fetch(directory)
                        links.extend(self._html_links(directory, directory_content.body))
        elif "xml" in fetched.content_type or "rss" in fetched.content_type:
            feed = feedparser.parse(fetched.body)
            links.extend(str(entry.get("link")) for entry in feed.entries if entry.get("link"))
        elif "csv" in fetched.content_type:
            links.extend(self._csv_links(fetched.url, fetched.body, since))
        elif "html" in fetched.content_type:
            links.extend(self._html_links(source.url, fetched.body))
        else:
            raise CollectorError(f"{source.id}: unsupported CSAF index type")
        unique_links = sorted(set(links), reverse=True)
        if len(unique_links) > source.max_items:
            raise CollectorError(
                f"{source.id}: CSAF index exceeds configured limit of {source.max_items} items"
            )
        for link in unique_links:
            if link.startswith("http://"):
                link = "https://" + link.removeprefix("http://")
            try:
                detail = await client.fetch(link)
                payload = json.loads(detail.body)
            except (CollectorError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict) and "document" in payload:
                records.append(self._record(source, detail.url, payload, detail.content_type))
        if len(records) > source.max_items:
            raise CollectorError(
                f"{source.id}: CSAF exceeds configured limit of {source.max_items} documents"
            )
        if not records:
            raise ParserChangedError(f"{source.id}: CSAF index yielded zero documents")
        return CollectionResult(
            source_id=source.id,
            records=records,
            etag=fetched.etag,
            last_modified=fetched.last_modified,
        )

    @staticmethod
    def _html_links(base: str, body: bytes) -> list[str]:
        soup = BeautifulSoup(body, "lxml")
        return [
            urljoin(base, str(node.get("href")))
            for node in soup.select("a[href$='.json']")
            if node.get("href")
        ]

    @staticmethod
    def _csv_links(base: str, body: bytes, since: datetime) -> list[str]:
        links: list[str] = []
        text = body.decode("utf-8-sig")
        for row in csv.reader(io.StringIO(text)):
            if not row or not row[0].casefold().endswith(".json"):
                continue
            if len(row) > 1:
                try:
                    modified = parse_date(row[1])
                    if modified.tzinfo is None:
                        modified = modified.replace(tzinfo=UTC)
                    if modified.astimezone(UTC) < since.astimezone(UTC):
                        continue
                except (TypeError, ValueError, OverflowError):
                    pass
            links.append(urljoin(base, row[0]))
        return links

    @staticmethod
    def _record(
        source: SourceDefinition,
        url: str,
        payload: dict[str, object],
        content_type: str,
    ) -> RawRecord:
        content = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        return RawRecord(
            source_id=source.id,
            url=url,
            content=content,
            content_type=content_type,
            metadata=payload,
            fetched_at=datetime.now(UTC),
        )
