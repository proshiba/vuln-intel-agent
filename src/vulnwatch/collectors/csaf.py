from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit, urlunsplit

import feedparser
from bs4 import BeautifulSoup
from dateutil.parser import parse as parse_date

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState


@dataclass(frozen=True)
class _IndexLink:
    url: str
    modified: datetime | None = None


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
        links: list[_IndexLink] = []
        index_item_count = 0
        records: list[RawRecord] = []
        if "json" in fetched.content_type:
            payload = self._load_json(fetched.body)
            if isinstance(payload, dict) and "document" in payload:
                records.append(self._record(source, fetched.url, payload, fetched.content_type))
            elif isinstance(payload, dict):
                for distribution in payload.get("distributions", []):
                    directory = distribution.get("directory_url")
                    if directory:
                        directory_content = await client.fetch(directory)
                        discovered = self._html_links(directory, directory_content.body)
                        index_item_count += len(discovered)
                        links.extend(discovered)
        elif "xml" in fetched.content_type or "rss" in fetched.content_type:
            feed = feedparser.parse(fetched.body)
            links, index_item_count = self._feed_links(feed.entries, since)
        elif "csv" in fetched.content_type or urlsplit(fetched.url).path.endswith(".csv"):
            links, index_item_count = self._csv_links(fetched.url, fetched.body, since)
        elif "html" in fetched.content_type:
            links = self._html_links(source.url, fetched.body)
            index_item_count = len(links)
        else:
            raise CollectorError(f"{source.id}: unsupported CSAF index type")

        if records:
            return CollectionResult(
                source_id=source.id,
                records=records,
                etag=fetched.etag,
                last_modified=fetched.last_modified,
            )
        if index_item_count > source.max_index_items:
            raise CollectorError(
                f"{source.id}: CSAF index exceeds configured limit of "
                f"{source.max_index_items} items"
            )
        if index_item_count == 0:
            raise ParserChangedError(f"{source.id}: CSAF index contained no document links")
        unique_links = self._ordered_unique_links(links)
        if not unique_links:
            return CollectionResult(
                source_id=source.id,
                etag=fetched.etag,
                last_modified=fetched.last_modified,
                complete_snapshot=False,
            )
        selected_links = unique_links[: source.max_detail_fetches]
        if not selected_links:
            raise CollectorError(f"{source.id}: CSAF detail fetch budget is zero")
        failed_details = 0
        for link in selected_links:
            try:
                detail = await client.fetch(link)
                payload = self._load_json(detail.body)
            except (CollectorError, json.JSONDecodeError):
                failed_details += 1
                continue
            if isinstance(payload, dict) and "document" in payload:
                records.append(self._record(source, detail.url, payload, detail.content_type))
            else:
                failed_details += 1
        if failed_details:
            raise CollectorError(
                f"{source.id}: {failed_details} of {len(selected_links)} "
                "CSAF detail documents failed"
            )
        if not records:
            raise ParserChangedError(f"{source.id}: CSAF index yielded zero documents")
        return CollectionResult(
            source_id=source.id,
            records=records,
            etag=fetched.etag,
            last_modified=fetched.last_modified,
            complete_snapshot=False,
        )

    @staticmethod
    def _load_json(body: bytes) -> Any:
        try:
            return json.loads(body)
        except UnicodeDecodeError:
            return json.loads(body.decode("utf-8", errors="replace"))

    @staticmethod
    def _html_links(base: str, body: bytes) -> list[_IndexLink]:
        soup = BeautifulSoup(body, "lxml")
        return [
            _IndexLink(urljoin(base, str(node.get("href"))))
            for node in soup.select("a[href$='.json']")
            if node.get("href")
        ]

    @staticmethod
    def _csv_links(
        base: str,
        body: bytes,
        since: datetime,
    ) -> tuple[list[_IndexLink], int]:
        links: list[_IndexLink] = []
        item_count = 0
        since_utc = since.replace(tzinfo=UTC) if since.tzinfo is None else since.astimezone(UTC)
        text = body.decode("utf-8-sig")
        for row in csv.reader(io.StringIO(text)):
            if not row or not row[0].casefold().endswith(".json"):
                continue
            item_count += 1
            modified: datetime | None = None
            if len(row) > 1:
                try:
                    modified = parse_date(row[1])
                    if modified.tzinfo is None:
                        modified = modified.replace(tzinfo=UTC)
                    modified = modified.astimezone(UTC)
                    if modified < since_utc:
                        continue
                except (TypeError, ValueError, OverflowError):
                    modified = None
            links.append(_IndexLink(urljoin(base, row[0]), modified))
        return links, item_count

    @staticmethod
    def _feed_links(
        entries: list[object],
        since: datetime,
    ) -> tuple[list[_IndexLink], int]:
        links: list[_IndexLink] = []
        item_count = 0
        since_utc = since.replace(tzinfo=UTC) if since.tzinfo is None else since.astimezone(UTC)
        for entry in entries:
            link = entry.get("link")  # type: ignore[attr-defined]
            if not link:
                continue
            item_count += 1
            observed = entry.get("updated") or entry.get("published")  # type: ignore[attr-defined]
            modified: datetime | None = None
            if observed:
                try:
                    modified = parse_date(str(observed))
                    if modified.tzinfo is None:
                        modified = modified.replace(tzinfo=UTC)
                    modified = modified.astimezone(UTC)
                    if modified < since_utc:
                        continue
                except (TypeError, ValueError, OverflowError):
                    modified = None
            links.append(_IndexLink(str(link), modified))
        return links, item_count

    @classmethod
    def _ordered_unique_links(cls, links: list[_IndexLink]) -> list[str]:
        oldest = datetime.min.replace(tzinfo=UTC)
        ordered = sorted(
            links,
            key=lambda item: (item.modified is not None, item.modified or oldest),
            reverse=True,
        )
        unique: list[str] = []
        seen: set[str] = set()
        for item in ordered:
            url = cls._force_https(item.url)
            if url in seen:
                continue
            seen.add(url)
            unique.append(url)
        return unique

    @staticmethod
    def _force_https(url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme != "http":
            return url
        host = parsed.hostname or ""
        port = f":{parsed.port}" if parsed.port and parsed.port != 80 else ""
        return urlunsplit(("https", f"{host}{port}", parsed.path, parsed.query, ""))

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
