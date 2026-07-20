from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState

_PAGE_SIZE = 100
_MAX_PAGES = 100


def _integer(value: object, field: str, source_id: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ParserChangedError(
            f"{source_id}: Broadcom response contains invalid {field}"
        )
    return value


class BroadcomCollector:
    """Collect VMware security advisories from Broadcom's public JSON endpoint."""

    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        del state, since  # The endpoint does not expose conditional or date-filter parameters.
        assert source.url is not None
        client = SafeHttpClient(source)
        records: list[RawRecord] = []
        identities: set[tuple[str, str]] = set()
        visited_pages: set[int] = set()
        expected_total: int | None = None
        indexed_items = 0
        page_number = 0

        for _ in range(_MAX_PAGES):
            if page_number in visited_pages:
                raise CollectorError(f"{source.id}: Broadcom pagination loop detected")
            visited_pages.add(page_number)
            fetched = await client.post_json(
                source.url,
                {
                    "pageNumber": page_number,
                    "pageSize": _PAGE_SIZE,
                    "searchVal": "",
                    "segment": "VC",
                    "sortInfo": {"column": "", "order": ""},
                },
            )
            items, page_info = self._parse_page(source.id, fetched.body)
            total_count = _integer(page_info.get("totalCount"), "totalCount", source.id)
            current_page = _integer(page_info.get("currentPage"), "currentPage", source.id)
            last_page = _integer(page_info.get("lastPage"), "lastPage", source.id)
            if current_page != page_number:
                raise ParserChangedError(
                    f"{source.id}: Broadcom response returned page {current_page}, "
                    f"expected {page_number}"
                )
            if last_page < current_page:
                raise ParserChangedError(
                    f"{source.id}: Broadcom response contains invalid lastPage"
                )
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                raise CollectorError(
                    f"{source.id}: Broadcom result count changed during pagination"
                )
            if total_count > source.max_index_items:
                raise CollectorError(
                    f"{source.id}: Broadcom index exceeds configured limit of "
                    f"{source.max_index_items} items"
                )

            indexed_items += len(items)
            if indexed_items > source.max_index_items:
                raise CollectorError(
                    f"{source.id}: Broadcom index exceeds configured limit of "
                    f"{source.max_index_items} items"
                )
            for item in items:
                identity = self._identity(item)
                if identity in identities:
                    continue
                identities.add(identity)
                item_url = self._item_url(source, item)
                records.append(
                    RawRecord(
                        source_id=source.id,
                        url=item_url,
                        content=json.dumps(item, ensure_ascii=False, sort_keys=True),
                        content_type=fetched.content_type,
                        metadata=item,
                        fetched_at=datetime.now(UTC),
                    )
                )
                if len(records) > source.max_items:
                    raise CollectorError(
                        f"{source.id}: Broadcom advisories exceed configured limit of "
                        f"{source.max_items} items"
                    )

            if current_page == last_page:
                if indexed_items < total_count:
                    raise CollectorError(
                        f"{source.id}: Broadcom returned {indexed_items} of "
                        f"{total_count} indexed items"
                    )
                break
            if not items:
                raise ParserChangedError(
                    f"{source.id}: Broadcom returned an empty page before the last page"
                )
            next_page = _integer(page_info.get("nextPage"), "nextPage", source.id)
            if next_page <= current_page or next_page > last_page:
                raise ParserChangedError(
                    f"{source.id}: Broadcom response contains invalid nextPage"
                )
            page_number = next_page
        else:
            raise CollectorError(
                f"{source.id}: Broadcom pagination exceeds configured limit of "
                f"{_MAX_PAGES} pages"
            )

        if not records:
            raise ParserChangedError(f"{source.id}: Broadcom returned zero advisories")
        return CollectionResult(
            source_id=source.id,
            records=records,
            complete_snapshot=False,
        )

    @staticmethod
    def _parse_page(
        source_id: str, body: bytes
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CollectorError(f"{source_id}: invalid Broadcom JSON: {exc}") from exc
        if not isinstance(payload, dict) or payload.get("success") is not True:
            raise ParserChangedError(f"{source_id}: unexpected Broadcom response envelope")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ParserChangedError(f"{source_id}: Broadcom response is missing data")
        items = data.get("list")
        page_info = data.get("pageInfo")
        if not isinstance(items, list) or not isinstance(page_info, dict):
            raise ParserChangedError(
                f"{source_id}: Broadcom response is missing list or pageInfo"
            )
        if not all(isinstance(item, dict) for item in items):
            raise ParserChangedError(f"{source_id}: Broadcom list contains an invalid item")
        return items, page_info

    @staticmethod
    def _identity(item: dict[str, Any]) -> tuple[str, str]:
        for key in ("documentId", "notificationId", "notificationUrl"):
            value = item.get(key)
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                continue
            normalized = str(value).strip().casefold()
            if normalized:
                return key, normalized
        return "content", json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)

    @staticmethod
    def _item_url(source: SourceDefinition, item: dict[str, Any]) -> str:
        candidate = item.get("notificationUrl")
        if candidate in (None, ""):
            return source.advisory_url
        if not isinstance(candidate, str):
            raise ParserChangedError(
                f"{source.id}: Broadcom advisory contains an invalid notificationUrl"
            )
        try:
            parsed = urlsplit(candidate)
            hostname = (parsed.hostname or "").casefold()
        except ValueError as exc:
            raise CollectorError(
                f"{source.id}: invalid Broadcom advisory URL"
            ) from exc
        allowed_hosts = {host.casefold() for host in source.allowed_hosts}
        if (
            parsed.scheme != "https"
            or hostname not in allowed_hosts
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise CollectorError(
                f"{source.id}: unsafe Broadcom advisory URL rejected: {candidate}"
            )
        return candidate
