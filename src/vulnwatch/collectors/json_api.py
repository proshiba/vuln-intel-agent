from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState

_MAX_PAGES = 100
_NETAPP_API_HOST = "security.netapp.com"
_NETAPP_API_PATH = "/adv_api/advisory"
_NETAPP_ADVISORY_ID = re.compile(r"^NTAP-\d{8}-\d{4}$", re.IGNORECASE)
_MANAGEENGINE_API_HOST = "securitycontact.manageengine.com"
_MANAGEENGINE_API_PATH = "/publiccve"


def _items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in (
        "vulnerabilities",
        "items",
        "itemdata",
        "articles",
        "list",
        "data",
        "content",
        "body",
        "top_records",
        "advisories",
        "results",
    ):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
        if isinstance(value, dict):
            nested = _items(value)
            if nested != [value]:
                return nested
    return [payload]


class JsonApiCollector:
    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        assert source.url is not None
        client = SafeHttpClient(source)
        first_page = await client.fetch(
            self._collection_url(source.url, since),
            state,
            conditional=True,
        )
        if first_page.not_modified:
            return CollectionResult(
                source_id=source.id,
                etag=first_page.etag,
                last_modified=first_page.last_modified,
                not_modified=True,
                complete_snapshot=False,
            )

        records: list[RawRecord] = []
        seen_items: set[tuple[str, str]] = set()
        seen_pages = {first_page.url}
        indexed_items = 0
        fetched = first_page
        page_count = 0
        while True:
            page_count += 1
            try:
                payload = json.loads(fetched.body)
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise CollectorError(f"{source.id}: invalid JSON: {exc}") from exc
            items = _items(payload)
            indexed_items += len(items)
            if indexed_items > source.max_index_items:
                raise CollectorError(
                    f"{source.id}: JSON index exceeds configured limit of "
                    f"{source.max_index_items} items"
                )
            for item in items:
                identity = self._identity(item)
                if not seen_items.isdisjoint(identity):
                    seen_items.update(identity)
                    continue
                seen_items.update(identity)
                records.append(
                    RawRecord(
                        source_id=source.id,
                        url=self._item_url(source, client, item),
                        content=json.dumps(item, ensure_ascii=False, sort_keys=True),
                        content_type=fetched.content_type,
                        metadata=item,
                        fetched_at=datetime.now(UTC),
                    )
                )
                if len(records) > source.max_items:
                    raise CollectorError(
                        f"{source.id}: JSON exceeds configured limit of "
                        f"{source.max_items} items"
                    )

            next_url = (
                fetched.next_url
                or self._netapp_next_url(source, fetched.url, payload, len(items))
                or self._manageengine_next_url(source, fetched.url, len(items))
            )
            if next_url is None:
                break
            if page_count >= _MAX_PAGES:
                raise CollectorError(
                    f"{source.id}: JSON pagination exceeds configured limit of "
                    f"{_MAX_PAGES} pages"
                )
            if next_url in seen_pages:
                raise CollectorError(f"{source.id}: JSON pagination loop detected")
            seen_pages.add(next_url)
            fetched = await client.fetch(next_url)
            if fetched.not_modified:
                raise CollectorError(f"{source.id}: unexpected 304 during JSON pagination")

        if not records:
            raise ParserChangedError(f"{source.id}: JSON contained zero items")
        return CollectionResult(
            source_id=source.id,
            records=records,
            etag=first_page.etag,
            last_modified=first_page.last_modified,
            complete_snapshot=False,
        )

    @staticmethod
    def _identity(item: dict[str, Any]) -> set[tuple[str, str]]:
        identity: set[tuple[str, str]] = set()
        nested_identifiers = []
        for parent, key in (("CVE_data_meta", "ID"), ("cveMetadata", "cveId")):
            nested = item.get(parent)
            if isinstance(nested, dict):
                nested_identifiers.append(nested.get(key))
        for value in [
            *(
                item.get(key)
                for key in (
                    "id",
                    "ID",
                    "nid",
                    "CVE_ID",
                    "ghsa_id",
                    "ntap_advisory_id",
                    "advisoryNumber",
                )
            ),
            *nested_identifiers,
        ]:
            if isinstance(value, bool) or not isinstance(value, (str, int)):
                continue
            normalized = str(value).strip().casefold()
            if normalized:
                identity.add(("identifier", normalized))
        url = item.get("url")
        if isinstance(url, str) and url.strip():
            identity.add(("url", url.strip()))
        if not identity:
            identity.add(
                ("content", json.dumps(item, ensure_ascii=False, sort_keys=True, default=str))
            )
        return identity

    @staticmethod
    def _collection_url(url: str, since: datetime) -> str:
        parsed = urlsplit(url)
        since_utc = since.replace(tzinfo=UTC) if since.tzinfo is None else since.astimezone(UTC)
        if (
            (parsed.hostname or "").casefold() == _NETAPP_API_HOST
            and parsed.path.rstrip("/") == _NETAPP_API_PATH
        ):
            netapp_query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            netapp_query["limit"] = netapp_query.get("limit", "100")
            netapp_query["skip"] = "0"
            netapp_query["order"] = "desc"
            # The update-date sort has many ties and produces duplicates across offset
            # pages. The advisory identifier is unique and makes pagination stable;
            # updated_start_date still limits the result set to the requested window.
            netapp_query["sort_by"] = "ntap_advisory_id"
            netapp_query["updated_start_date"] = since_utc.date().isoformat()
            return urlunsplit(
                (parsed.scheme, parsed.netloc, parsed.path, urlencode(netapp_query), "")
            )
        if (
            (parsed.hostname or "").casefold() != "api.github.com"
            or parsed.path.rstrip("/") != "/advisories"
        ):
            return url
        updated = f">={since_utc.isoformat(timespec='seconds').replace('+00:00', 'Z')}"
        query = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key != "updated"
        ]
        query.append(("updated", updated))
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")
        )

    @staticmethod
    def _item_url(
        source: SourceDefinition,
        client: SafeHttpClient,
        item: dict[str, Any],
    ) -> str:
        netapp_id = item.get("ntap_advisory_id")
        if isinstance(netapp_id, str) and _NETAPP_ADVISORY_ID.fullmatch(netapp_id):
            return client.advisory_url(
                netapp_id,
                base_url=f"{source.advisory_url.rstrip('/')}/",
            )
        ibm_node_id = item.get("nid")
        if source.id == "ibm" and isinstance(ibm_node_id, (str, int)):
            normalized_node_id = str(ibm_node_id).strip()
            if normalized_node_id.isdigit():
                return client.advisory_url(
                    f"https://www.ibm.com/support/pages/node/{normalized_node_id}",
                    base_url=source.advisory_url,
                )
        manageengine_link = item.get("CVE_Details_Link")
        if source.id == "manageengine" and isinstance(manageengine_link, dict):
            candidate = manageengine_link.get("url") or manageengine_link.get("value")
            return client.advisory_url(candidate, base_url=source.advisory_url)
        candidate = (
            item.get("url")
            or item.get("external_url")
            or item.get("html_url")
            or item.get("item_link")
            or item.get("href")
        )
        return client.advisory_url(candidate, base_url=source.url or source.advisory_url)

    @staticmethod
    def _netapp_next_url(
        source: SourceDefinition,
        current_url: str,
        payload: Any,
        page_item_count: int,
    ) -> str | None:
        parsed = urlsplit(current_url)
        if (
            (parsed.hostname or "").casefold() != _NETAPP_API_HOST
            or parsed.path.rstrip("/") != _NETAPP_API_PATH
        ):
            return None
        if not isinstance(payload, dict):
            raise ParserChangedError(f"{source.id}: invalid NetApp API response")
        total_count = payload.get("total_count")
        if (
            isinstance(total_count, bool)
            or not isinstance(total_count, int)
            or total_count < 0
        ):
            raise ParserChangedError(f"{source.id}: NetApp API omitted total_count")
        if total_count > source.max_index_items:
            raise CollectorError(
                f"{source.id}: JSON index exceeds configured limit of "
                f"{source.max_index_items} items"
            )
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        try:
            skip = int(query.get("skip", "0"))
            limit = int(query.get("limit", "100"))
        except ValueError as exc:
            raise CollectorError(f"{source.id}: invalid NetApp pagination parameters") from exc
        if skip < 0 or limit <= 0 or limit > source.max_items:
            raise CollectorError(f"{source.id}: invalid NetApp pagination parameters")
        consumed = skip + page_item_count
        if consumed >= total_count:
            return None
        if page_item_count == 0:
            raise ParserChangedError(
                f"{source.id}: NetApp API returned an empty page before total_count"
            )
        query["skip"] = str(consumed)
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")
        )

    @staticmethod
    def _manageengine_next_url(
        source: SourceDefinition,
        current_url: str,
        page_item_count: int,
    ) -> str | None:
        parsed = urlsplit(current_url)
        if (
            source.id != "manageengine"
            or (parsed.hostname or "").casefold() != _MANAGEENGINE_API_HOST
            or parsed.path.rstrip("/") != _MANAGEENGINE_API_PATH
        ):
            return None
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        try:
            start = int(query.get("from", "1"))
            limit = int(query.get("limit", "100"))
        except ValueError as exc:
            raise CollectorError(
                f"{source.id}: invalid ManageEngine pagination parameters"
            ) from exc
        if start < 1 or limit <= 0 or limit > 100:
            raise CollectorError(
                f"{source.id}: invalid ManageEngine pagination parameters"
            )
        if page_item_count < limit:
            return None
        query["from"] = str(start + page_item_count)
        return urlunsplit(
            (parsed.scheme, parsed.netloc, parsed.path, urlencode(query), "")
        )
