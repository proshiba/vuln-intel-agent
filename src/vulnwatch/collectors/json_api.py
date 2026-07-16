from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState


def _items(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("vulnerabilities", "items", "data", "advisories", "results"):
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]
    return [payload]


class JsonApiCollector:
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
        try:
            payload = json.loads(fetched.body)
        except json.JSONDecodeError as exc:
            raise CollectorError(f"{source.id}: invalid JSON: {exc}") from exc
        items = _items(payload)
        if len(items) > source.max_items:
            raise CollectorError(
                f"{source.id}: JSON exceeds configured limit of {source.max_items} items"
            )
        records = [
            RawRecord(
                source_id=source.id,
                url=str(
                    item.get("url")
                    or item.get("external_url")
                    or item.get("html_url")
                    or source.advisory_url
                ),
                content=json.dumps(item, ensure_ascii=False, sort_keys=True),
                content_type=fetched.content_type,
                metadata=item,
                fetched_at=datetime.now(UTC),
            )
            for item in items
        ]
        if not records:
            raise ParserChangedError(f"{source.id}: JSON contained zero items")
        return CollectionResult(
            source_id=source.id,
            records=records,
            etag=fetched.etag,
            last_modified=fetched.last_modified,
        )
