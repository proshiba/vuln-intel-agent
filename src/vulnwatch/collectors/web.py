from __future__ import annotations

import json
import re
import warnings
from datetime import UTC, datetime
from typing import cast
from urllib.parse import quote, urljoin, urlsplit

import feedparser
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning
from dateutil.parser import parse as parse_date

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.collectors.json_api import _items
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState

_CVE_PATTERN = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,}(?![A-Z0-9])", re.IGNORECASE)
_ADVISORY_PATTERN = re.compile(
    r"(?:"
    r"security[\s_-]*(?:advisory|advisories|alert|bulletin|notice|update)"
    r"|vulnerabilit(?:y|ies)"
    r"|\bpsirt\b"
    r"|\bcert(?:ificate)?[-_/ ]?(?:advisory|alert|notice)?\b"
    r"|セキュリティ(?:情報|更新|勧告|警告|アドバイザリ)?"
    r"|脆弱性|ぜい弱性|注意喚起"
    r")",
    re.IGNORECASE,
)
_ADVISORY_URL_PATTERN = re.compile(
    r"(?:cve[-_/]|security|advis|vuln|psirt|bulletin|alert|supportsec|trust[-_/]?center)",
    re.IGNORECASE,
)
_CONCRETE_ADVISORY_PATTERN = re.compile(
    r"(?:"
    r"\b(?:ADV|DSA|PSIRT|VMSA|APSB|RHSA|USN|SSA|ICSA|CERT|WDC|SA)"
    r"[-_ ]?\d{2,4}(?:[-_.]\d+)+\b"
    r"|\b(?:security\s+(?:advisory|bulletin|notice)|vulnerability\s+notice)"
    r"\s*(?:ID|No\.?|#|:|-)?\s*[A-Z]{0,12}[-_ ]?\d{2,4}(?:[-_.]\d+)+\b"
    r")",
    re.IGNORECASE,
)
_IGNORED_URL_PATTERN = re.compile(
    r"(?:privacy|terms|legal|cookie|login|sign[-_]?in|subscribe|contact|about(?:/|$))",
    re.IGNORECASE,
)
_MAX_HTML_PAGES = 100


class WebCollector:
    """Collect a public advisory entry point with safe content auto-detection.

    Catalog sources often expose only an official landing page. This collector first
    accepts JSON or RSS/Atom directly, then discovers an advertised feed, and finally
    extracts bounded advisory links from HTML. HTML and API indexes are deliberately
    treated as partial snapshots so a truncated page cannot withdraw older records.
    """

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
                complete_snapshot=False,
            )

        records = self._structured_records(
            source,
            fetched.url,
            fetched.body,
            fetched.content_type,
            since,
        )
        if records is None:
            records = await self._html_records(source, client, fetched.url, fetched.body, since)
        if not records:
            raise ParserChangedError(f"{source.id}: source returned zero concrete advisory records")

        return CollectionResult(
            source_id=source.id,
            records=records,
            etag=fetched.etag,
            last_modified=fetched.last_modified,
            complete_snapshot=False,
        )

    @classmethod
    def _structured_records(
        cls,
        source: SourceDefinition,
        url: str,
        body: bytes,
        content_type: str,
        since: datetime,
    ) -> list[RawRecord] | None:
        if cls._looks_like_json(content_type, body):
            try:
                payload = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None
            items = _items(payload)
            if len(items) > source.max_items:
                raise CollectorError(
                    f"{source.id}: JSON exceeds configured limit of {source.max_items} items"
                )
            return [
                RawRecord(
                    source_id=source.id,
                    url=cls._record_url(source, item, url),
                    content=json.dumps(item, ensure_ascii=False, sort_keys=True),
                    content_type=content_type,
                    metadata=item,
                    fetched_at=datetime.now(UTC),
                )
                for item in items
            ]

        parsed = feedparser.parse(body)
        feed_content = any(value in content_type for value in ("xml", "rss", "atom"))
        if parsed.entries and (not parsed.get("bozo") or feed_content):
            return cls._feed_records(source, parsed.entries, url, content_type, since)
        return None

    @staticmethod
    def _looks_like_json(content_type: str, body: bytes) -> bool:
        if "json" in content_type:
            return True
        stripped = body.lstrip()
        return stripped.startswith((b"{", b"["))

    @staticmethod
    def _entry_is_recent(entry: object, since: datetime) -> bool:
        observed = entry.get("updated") or entry.get("published")  # type: ignore[attr-defined]
        if not observed:
            return True
        try:
            value = cast(datetime, parse_date(str(observed)))
        except (TypeError, ValueError, OverflowError):
            return True
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        threshold = since if since.tzinfo is not None else since.replace(tzinfo=UTC)
        return value.astimezone(UTC) >= threshold.astimezone(UTC)

    @classmethod
    def _feed_records(
        cls,
        source: SourceDefinition,
        entries: list[object],
        feed_url: str,
        content_type: str,
        since: datetime,
    ) -> list[RawRecord]:
        recent_entries = [entry for entry in entries if cls._entry_is_recent(entry, since)]
        if len(recent_entries) > source.max_items:
            raise CollectorError(
                f"{source.id}: feed exceeds configured limit of {source.max_items} items"
            )
        records: list[RawRecord] = []
        client = SafeHttpClient(source)
        for entry in recent_entries:
            title = str(entry.get("title") or "")  # type: ignore[attr-defined]
            summary = str(entry.get("summary") or "")  # type: ignore[attr-defined]
            candidate_link = entry.get("link")  # type: ignore[attr-defined]
            link = client.advisory_url(
                candidate_link,
                base_url=feed_url,
            )
            records.append(
                RawRecord(
                    source_id=source.id,
                    url=link,
                    content=summary or title,
                    content_type=content_type,
                    metadata={
                        "id": entry.get("id"),  # type: ignore[attr-defined]
                        "title": title,
                        "published": entry.get("published"),  # type: ignore[attr-defined]
                        "updated": entry.get("updated"),  # type: ignore[attr-defined]
                        "summary": summary,
                    },
                    fetched_at=datetime.now(UTC),
                )
            )
        return records

    async def _html_records(
        self,
        source: SourceDefinition,
        client: SafeHttpClient,
        page_url: str,
        body: bytes,
        since: datetime,
    ) -> list[RawRecord]:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", XMLParsedAsHTMLWarning)
            soup = BeautifulSoup(body, "lxml")

        content_script_selector = source.selectors.get("content_script")
        if content_script_selector:
            script = soup.select_one(content_script_selector)
            script_url = (
                urljoin(page_url, str(script.get("src")))
                if script is not None and script.get("src")
                else ""
            )
            if not script_url or not self._allowed_url(source, script_url):
                raise ParserChangedError(f"{source.id}: configured content script was not found")
            fetched_script = await client.fetch(script_url)
            embedded_html = self._embedded_html(fetched_script.body)
            if embedded_html is None:
                raise ParserChangedError(f"{source.id}: configured content script format changed")
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", XMLParsedAsHTMLWarning)
                soup = BeautifulSoup(embedded_html, "lxml")
            page_url = fetched_script.url

        for feed_url in self._feed_candidates(source, page_url, soup):
            try:
                feed = await client.fetch(feed_url)
            except CollectorError:
                continue
            records = self._structured_records(
                source,
                feed.url,
                feed.body,
                feed.content_type,
                since,
            )
            if records:
                await self._add_details(source, client, records)
                return records

        records = self._explicit_html_records(source, page_url, soup)
        if source.selectors.get("item") and not records:
            raise ParserChangedError(
                f"{source.id}: configured HTML selector matched zero advisory records"
            )
        if records and source.selectors.get("next"):
            records = await self._paginate_explicit_html_records(
                source,
                client,
                page_url,
                soup,
                records,
                since,
            )
        if not records:
            records = self._generic_html_records(source, page_url, soup)
        if not records:
            records = self._inline_cve_records(source, page_url, soup)
        await self._add_details(source, client, records)
        return records

    @classmethod
    async def _paginate_explicit_html_records(
        cls,
        source: SourceDefinition,
        client: SafeHttpClient,
        first_page_url: str,
        first_soup: BeautifulSoup,
        records: list[RawRecord],
        since: datetime,
    ) -> list[RawRecord]:
        """Follow an explicitly configured same-path next link until the window ends."""

        selector = source.selectors["next"]
        expected_path = urlsplit(first_page_url).path
        page_url = first_page_url
        soup = first_soup
        seen_pages = {first_page_url}
        page_records = records
        for _ in range(_MAX_HTML_PAGES - 1):
            if cls._all_records_before(page_records, since):
                break
            next_node = soup.select_one(selector)
            if next_node is None or not next_node.get("href"):
                break
            next_url = urljoin(page_url, str(next_node.get("href")))
            parsed_next = urlsplit(next_url)
            if (
                not cls._allowed_url(source, next_url)
                or parsed_next.path != expected_path
                or next_url in seen_pages
            ):
                raise ParserChangedError(
                    f"{source.id}: configured pagination link is unsafe or cyclic"
                )
            seen_pages.add(next_url)
            fetched = await client.fetch(next_url)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", XMLParsedAsHTMLWarning)
                soup = BeautifulSoup(fetched.body, "lxml")
            page_url = fetched.url
            page_records = cls._explicit_html_records(source, page_url, soup)
            if not page_records:
                raise ParserChangedError(
                    f"{source.id}: configured pagination page matched zero advisory records"
                )
            if len(records) + len(page_records) > source.max_items:
                raise CollectorError(
                    f"{source.id}: HTML pagination exceeds configured limit of "
                    f"{source.max_items} items"
                )
            records.extend(page_records)
        else:
            if (
                not cls._all_records_before(page_records, since)
                and soup.select_one(selector) is not None
            ):
                raise CollectorError(
                    f"{source.id}: HTML pagination exceeds {_MAX_HTML_PAGES} pages"
                )
        return cls._dedupe_records(records)

    @staticmethod
    def _all_records_before(records: list[RawRecord], since: datetime) -> bool:
        if not records:
            return False
        threshold = since if since.tzinfo is not None else since.replace(tzinfo=UTC)
        observed: list[datetime] = []
        for record in records:
            value = record.metadata.get("published")
            if not value:
                return False
            try:
                parsed = cast(datetime, parse_date(str(value)))
            except (TypeError, ValueError, OverflowError):
                return False
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=UTC)
            observed.append(parsed.astimezone(UTC))
        return all(value < threshold.astimezone(UTC) for value in observed)

    @staticmethod
    def _embedded_html(body: bytes) -> str | None:
        """Extract a JSON-wrapped HTML body from an official content script."""

        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            return None
        marker = "Object.assign(window.cdnData,"
        marker_index = text.find(marker)
        if marker_index < 0:
            return None
        payload_text = text[marker_index + len(marker) :].strip()
        if not payload_text.endswith(")"):
            return None
        try:
            payload = json.loads(payload_text[:-1])
        except json.JSONDecodeError:
            return None
        embedded = payload.get("body") if isinstance(payload, dict) else None
        return embedded if isinstance(embedded, str) else None

    @classmethod
    def _feed_candidates(
        cls,
        source: SourceDefinition,
        page_url: str,
        soup: BeautifulSoup,
    ) -> list[str]:
        candidates: list[str] = []
        for node in soup.select("link[rel~='alternate'][href]"):
            media_type = str(node.get("type") or "").casefold()
            if not any(value in media_type for value in ("rss", "atom", "xml")):
                continue
            candidates.append(urljoin(page_url, str(node.get("href"))))
        candidates.extend(source.feed_urls)
        ranked = sorted(
            candidates,
            key=lambda value: (
                not bool(_ADVISORY_URL_PATTERN.search(value)),
                value,
            ),
        )
        return cls._allowed_unique_urls(source, ranked)

    @classmethod
    def _explicit_html_records(
        cls,
        source: SourceDefinition,
        page_url: str,
        soup: BeautifulSoup,
    ) -> list[RawRecord]:
        item_selector = source.selectors.get("item")
        if not item_selector:
            return []
        records: list[RawRecord] = []
        for node in soup.select(item_selector)[: source.max_items]:
            link_selector = source.selectors.get("link", "a[href]")
            link_node = (
                node if node.name == "a" and node.get("href") else node.select_one(link_selector)
            )
            if link_node is None or not link_node.get("href"):
                continue
            href = quote(
                str(link_node.get("href")).strip(),
                safe="/:?&=#%+@,;~.-_",
            )
            url = urljoin(page_url, href)
            if not cls._allowed_url(source, url):
                continue
            title_selector = source.selectors.get("title", "h1, h2, h3, h4, a")
            title_node = (
                node
                if node.name in {"h1", "h2", "h3", "h4", "a"}
                else node.select_one(title_selector)
            )
            title = (
                title_node.get_text(" ", strip=True)
                if title_node
                else node.get_text(" ", strip=True)
            )
            title_pattern = source.selectors.get("title_pattern")
            if title_pattern:
                try:
                    if not re.search(title_pattern, title, re.IGNORECASE):
                        continue
                except re.error as exc:
                    raise CollectorError(
                        f"{source.id}: invalid selectors.title_pattern: {exc}"
                    ) from exc
            time_node = node.select_one(source.selectors.get("published_at", "time"))
            published = None
            if time_node is not None:
                published = time_node.get("datetime") or time_node.get_text(" ", strip=True)
            products_node = None
            if products_selector := source.selectors.get("products"):
                products_node = node.select_one(products_selector)
            records.append(
                cls._html_record(
                    source,
                    url,
                    title,
                    node.get_text("\n", strip=True),
                    published,
                    products=(
                        products_node.get_text("\n", strip=True)
                        if products_node is not None
                        else None
                    ),
                )
            )
        return cls._dedupe_records(records)

    @classmethod
    def _generic_html_records(
        cls,
        source: SourceDefinition,
        page_url: str,
        soup: BeautifulSoup,
    ) -> list[RawRecord]:
        records: list[RawRecord] = []
        for anchor in soup.select("a[href]"):
            href = str(anchor.get("href") or "").strip()
            if not href or href.startswith(("#", "mailto:", "javascript:")):
                continue
            url = urljoin(page_url, href)
            if not cls._allowed_url(source, url) or cls._same_page(page_url, url):
                continue
            title = anchor.get_text(" ", strip=True)
            container = anchor.find_parent(["article", "li", "tr", "section", "div", "p"])
            context = container.get_text("\n", strip=True) if container else title
            # A broad navigation container can mention "security advisories" while
            # wrapping unrelated links. Generic discovery therefore requires the
            # candidate link itself to carry a CVE or concrete advisory identifier.
            # Sources without such identifiers must provide an explicit selector.
            candidate_evidence = f"{title}\n{url}"
            if _IGNORED_URL_PATTERN.search(url) and not _CVE_PATTERN.search(candidate_evidence):
                continue
            relevant = _CVE_PATTERN.search(candidate_evidence) or (
                _ADVISORY_PATTERN.search(candidate_evidence)
                and _CONCRETE_ADVISORY_PATTERN.search(candidate_evidence)
            )
            if not relevant:
                continue
            time_node = container.select_one("time") if container else None
            records.append(
                cls._html_record(
                    source,
                    url,
                    title or context[:500],
                    context,
                    time_node.get("datetime") if time_node else None,
                )
            )
            if len(records) >= source.max_items:
                break
        return cls._dedupe_records(records)

    @classmethod
    def _inline_cve_records(
        cls,
        source: SourceDefinition,
        page_url: str,
        soup: BeautifulSoup,
    ) -> list[RawRecord]:
        text = soup.get_text("\n", strip=True)
        records: list[RawRecord] = []
        for cve in dict.fromkeys(match.upper() for match in _CVE_PATTERN.findall(text)):
            index = text.upper().find(cve)
            excerpt = text[max(0, index - 1000) : index + 3000]
            records.append(
                RawRecord(
                    source_id=source.id,
                    url=page_url,
                    content=excerpt,
                    content_type="text/html",
                    metadata={"id": cve, "title": cve},
                    fetched_at=datetime.now(UTC),
                )
            )
            if len(records) >= source.max_items:
                break
        return records

    @classmethod
    async def _add_details(
        cls,
        source: SourceDefinition,
        client: SafeHttpClient,
        records: list[RawRecord],
    ) -> None:
        if source.max_detail_fetches <= 0:
            return
        detail_errors: list[str] = []
        for record in records[: source.max_detail_fetches]:
            if not cls._allowed_url(source, record.url):
                continue
            try:
                detail = await client.fetch(record.url)
            except CollectorError as exc:
                record.metadata["detail_error"] = str(exc)[:500]
                detail_errors.append(str(exc))
                continue
            if cls._looks_like_json(detail.content_type, detail.body):
                try:
                    record.content = json.dumps(
                        json.loads(detail.body), ensure_ascii=False, sort_keys=True
                    )[:100_000]
                    continue
                except (json.JSONDecodeError, UnicodeDecodeError):
                    pass
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", XMLParsedAsHTMLWarning)
                detail_soup = BeautifulSoup(detail.body, "lxml")
            content_node = detail_soup.select_one("main, article, [role='main'], body")
            if content_node:
                record.content = content_node.get_text("\n", strip=True)[:100_000]
                record.metadata["detail_url"] = detail.url
        if detail_errors:
            raise CollectorError(
                f"{source.id}: {len(detail_errors)} advisory detail fetch(es) failed: "
                f"{detail_errors[0][:500]}"
            )

    @staticmethod
    def _html_record(
        source: SourceDefinition,
        url: str,
        title: str,
        content: str,
        published: object,
        *,
        products: str | None = None,
    ) -> RawRecord:
        metadata: dict[str, object] = {
            "title": title[:500] or source.vendor,
            "published": published,
        }
        if products:
            metadata["products"] = products
        return RawRecord(
            source_id=source.id,
            url=url,
            content=content[:100_000],
            content_type="text/html",
            metadata=metadata,
            fetched_at=datetime.now(UTC),
        )

    @staticmethod
    def _record_url(source: SourceDefinition, item: dict[str, object], fallback: str) -> str:
        candidate = str(
            item.get("url") or item.get("external_url") or item.get("html_url") or fallback
        )
        return candidate if WebCollector._is_output_url(candidate) else source.advisory_url

    @staticmethod
    def _is_output_url(url: str) -> bool:
        parsed = urlsplit(url)
        return parsed.scheme == "https" and bool(parsed.hostname)

    @classmethod
    def _allowed_url(cls, source: SourceDefinition, url: str) -> bool:
        parsed = urlsplit(url)
        return parsed.scheme == "https" and (parsed.hostname or "").casefold() in {
            host.casefold() for host in source.allowed_hosts
        }

    @classmethod
    def _allowed_unique_urls(
        cls,
        source: SourceDefinition,
        urls: list[str],
    ) -> list[str]:
        unique: list[str] = []
        seen: set[str] = set()
        for url in urls:
            if url in seen or not cls._allowed_url(source, url):
                continue
            seen.add(url)
            unique.append(url)
        return unique

    @staticmethod
    def _same_page(left: str, right: str) -> bool:
        left_parts = urlsplit(left)
        right_parts = urlsplit(right)
        return (
            left_parts.scheme.casefold(),
            left_parts.netloc.casefold(),
            left_parts.path.rstrip("/"),
        ) == (
            right_parts.scheme.casefold(),
            right_parts.netloc.casefold(),
            right_parts.path.rstrip("/"),
        )

    @staticmethod
    def _dedupe_records(records: list[RawRecord]) -> list[RawRecord]:
        unique: list[RawRecord] = []
        seen: set[str] = set()
        for record in records:
            if record.url in seen:
                continue
            seen.add(record.url)
            unique.append(record)
        return unique
