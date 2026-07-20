from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any, cast

from bs4 import BeautifulSoup
from dateutil.parser import parse as parse_date

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState

_PAGE_SIZE = 100
_MAX_PAGES = 100
_BULLETIN_TITLE = re.compile(r"^Security Advisory Bulletin \d+$", re.IGNORECASE)
_INDEX_QUERY = """
query GetReleases($limit: Int, $offset: Int, $searchTerm: String) {
  releases(
    limit: $limit
    offset: $offset
    searchTerm: $searchTerm
    sortBy: LATEST
  ) {
    items { id slug title createdAt updatedAt }
    pageInfo { limit offset }
    totalCount
  }
}
"""
_DETAIL_QUERY = """
query GetRelease($id: ID!) {
  release(id: $id) {
    id
    slug
    title
    createdAt
    updatedAt
    content { type ... on TextContent { content } }
    newFeatures { type ... on TextContent { content } }
    improvements { type ... on TextContent { content } }
    bugfixes { type ... on TextContent { content } }
    knownIssues { type ... on TextContent { content } }
    importantNotes { type ... on TextContent { content } }
    instructions { type ... on TextContent { content } }
    rollingReleaseNotes { type ... on TextContent { content } }
  }
}
"""
_CONTENT_FIELDS = (
    "content",
    "newFeatures",
    "improvements",
    "bugfixes",
    "knownIssues",
    "importantNotes",
    "instructions",
    "rollingReleaseNotes",
)


class UbiquitiCollector:
    """Collect Ubiquiti's public Security Advisory Bulletins via its community API."""

    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        assert source.url is not None
        client = SafeHttpClient(source)
        candidates = await self._index(source, client)
        threshold = self._threshold(since, state.last_success_at)
        recent = [item for item in candidates if self._observed_at(source.id, item) >= threshold]
        if len(recent) > source.max_detail_fetches:
            raise CollectorError(
                f"{source.id}: Ubiquiti detail count exceeds configured limit of "
                f"{source.max_detail_fetches} items"
            )
        if len(recent) > source.max_items:
            raise CollectorError(
                f"{source.id}: Ubiquiti advisories exceed configured limit of "
                f"{source.max_items} items"
            )

        records: list[RawRecord] = []
        for item in recent:
            detail = await self._detail(source, client, item)
            identifier = cast(str, detail["id"])
            slug = cast(str, detail["slug"])
            title = cast(str, detail["title"])
            content = self._detail_text(source.id, detail)
            records.append(
                RawRecord(
                    source_id=source.id,
                    url=f"https://community.ui.com/releases/{slug}/{identifier}",
                    content=content[:100_000],
                    content_type="text/html",
                    metadata={
                        "id": identifier,
                        "title": title,
                        "published": detail.get("createdAt"),
                        "updated": detail.get("updatedAt"),
                    },
                    fetched_at=datetime.now(UTC),
                )
            )
        return CollectionResult(
            source_id=source.id,
            records=records,
            complete_snapshot=False,
        )

    async def _index(
        self,
        source: SourceDefinition,
        client: SafeHttpClient,
    ) -> list[dict[str, Any]]:
        candidates: dict[str, dict[str, Any]] = {}
        offset = 0
        expected_total: int | None = None
        indexed = 0
        for _ in range(_MAX_PAGES):
            fetched = await client.post_json(
                cast(str, source.url),
                {
                    "query": _INDEX_QUERY,
                    "operationName": "GetReleases",
                    "variables": {
                        "limit": _PAGE_SIZE,
                        "offset": offset,
                        "searchTerm": "Security Advisory Bulletin",
                    },
                },
            )
            payload = self._json(source.id, fetched.body)
            releases = self._graphql_data(source.id, payload, "releases")
            items = releases.get("items")
            total = releases.get("totalCount")
            page_info = releases.get("pageInfo")
            if (
                not isinstance(items, list)
                or isinstance(total, bool)
                or not isinstance(total, int)
                or total < 0
                or not isinstance(page_info, dict)
            ):
                raise ParserChangedError(f"{source.id}: invalid Ubiquiti release index")
            if expected_total is None:
                expected_total = total
                if total > source.max_index_items:
                    raise CollectorError(
                        f"{source.id}: Ubiquiti index exceeds configured limit of "
                        f"{source.max_index_items} items"
                    )
            elif total != expected_total:
                raise CollectorError(
                    f"{source.id}: Ubiquiti result count changed during pagination"
                )
            if page_info.get("offset") != offset:
                raise ParserChangedError(
                    f"{source.id}: Ubiquiti response returned an unexpected offset"
                )
            if not items and indexed < total:
                raise ParserChangedError(
                    f"{source.id}: Ubiquiti returned an empty page before the last page"
                )
            indexed += len(items)
            if indexed > source.max_index_items:
                raise CollectorError(
                    f"{source.id}: Ubiquiti index exceeds configured limit of "
                    f"{source.max_index_items} items"
                )
            for value in items:
                item = self._release(source.id, value)
                if _BULLETIN_TITLE.fullmatch(cast(str, item["title"])):
                    candidates[cast(str, item["id"])] = item
            if indexed >= total:
                break
            offset += len(items)
        else:
            raise CollectorError(
                f"{source.id}: Ubiquiti pagination exceeds configured limit of "
                f"{_MAX_PAGES} pages"
            )
        if not candidates:
            raise ParserChangedError(
                f"{source.id}: Ubiquiti index contained zero Security Advisory Bulletins"
            )
        return list(candidates.values())

    async def _detail(
        self,
        source: SourceDefinition,
        client: SafeHttpClient,
        item: dict[str, Any],
    ) -> dict[str, Any]:
        fetched = await client.post_json(
            cast(str, source.url),
            {
                "query": _DETAIL_QUERY,
                "operationName": "GetRelease",
                "variables": {"id": item["id"]},
            },
        )
        payload = self._json(source.id, fetched.body)
        detail = self._graphql_data(source.id, payload, "release")
        normalized = self._release(source.id, detail)
        if normalized["id"] != item["id"]:
            raise ParserChangedError(
                f"{source.id}: Ubiquiti detail returned an unexpected advisory"
            )
        return detail

    @staticmethod
    def _json(source_id: str, body: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CollectorError(f"{source_id}: invalid Ubiquiti JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ParserChangedError(f"{source_id}: invalid Ubiquiti response envelope")
        if payload.get("errors"):
            raise ParserChangedError(f"{source_id}: Ubiquiti GraphQL response contains errors")
        return payload

    @staticmethod
    def _graphql_data(
        source_id: str,
        payload: dict[str, Any],
        field: str,
    ) -> dict[str, Any]:
        data = payload.get("data")
        value = data.get(field) if isinstance(data, dict) else None
        if not isinstance(value, dict):
            raise ParserChangedError(f"{source_id}: Ubiquiti response is missing {field}")
        return value

    @staticmethod
    def _release(source_id: str, value: object) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ParserChangedError(f"{source_id}: invalid Ubiquiti release item")
        for field in ("id", "slug", "title", "createdAt"):
            field_value = value.get(field)
            if not isinstance(field_value, str) or not field_value.strip():
                raise ParserChangedError(
                    f"{source_id}: Ubiquiti release is missing {field}"
                )
        return value

    @staticmethod
    def _observed_at(source_id: str, item: dict[str, Any]) -> datetime:
        value = item.get("updatedAt") or item.get("createdAt")
        try:
            observed = cast(datetime, parse_date(cast(str, value)))
        except (TypeError, ValueError, OverflowError) as exc:
            raise ParserChangedError(
                f"{source_id}: Ubiquiti release contains an invalid date"
            ) from exc
        if observed.tzinfo is None:
            observed = observed.replace(tzinfo=UTC)
        return observed.astimezone(UTC)

    @staticmethod
    def _threshold(since: datetime, last_success_at: datetime | None) -> datetime:
        threshold = since if since.tzinfo is not None else since.replace(tzinfo=UTC)
        threshold = threshold.astimezone(UTC)
        if last_success_at is None:
            return threshold
        state_value = (
            last_success_at
            if last_success_at.tzinfo is not None
            else last_success_at.replace(tzinfo=UTC)
        )
        return max(threshold, state_value.astimezone(UTC))

    @staticmethod
    def _detail_text(source_id: str, detail: dict[str, Any]) -> str:
        fragments: list[str] = []
        for field in _CONTENT_FIELDS:
            value = detail.get(field)
            values = value if isinstance(value, list) else [value]
            for block in values:
                if not isinstance(block, dict) or block.get("type") != "TEXT":
                    continue
                content = block.get("content")
                if isinstance(content, str) and content.strip():
                    fragments.append(
                        BeautifulSoup(content, "lxml").get_text("\n", strip=True)
                    )
        text = "\n\n".join(fragment for fragment in fragments if fragment)
        if not text:
            raise ParserChangedError(
                f"{source_id}: Ubiquiti advisory detail contained no text"
            )
        return text
