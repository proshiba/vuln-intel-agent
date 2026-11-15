from __future__ import annotations

import csv
import io
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import quote

from vulnwatch.collectors.base import (
    CollectorError,
    FetchedContent,
    ParserChangedError,
    SafeHttpClient,
)
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState

OSV_MODIFIED_INDEX_URL = "https://storage.googleapis.com/osv-vulnerabilities/modified_id.csv"
OSV_STORAGE_HOST = "storage.googleapis.com"
OSV_DETAIL_BASE_URL = "https://storage.googleapis.com/osv-vulnerabilities/"
OSV_ADVISORY_BASE_URL = "https://osv.dev/vulnerability/"
# 変更インデックスを読む単位。最新側だけ読めば足りるため、1回で収まる大きさにする。
_INDEX_CHUNK_BYTES = 4_194_304


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _modified_at(value: str, source_id: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ParserChangedError(
            f"{source_id}: OSV modified index has an invalid timestamp"
        ) from exc
    if parsed.tzinfo is None:
        raise ParserChangedError(f"{source_id}: OSV modified index timestamp has no timezone")
    return parsed.astimezone(UTC)


def _object_path(value: str, source_id: str) -> str:
    invalid_character = any(
        ord(character) < 32 or ord(character) == 127 or character in "\\%?#" for character in value
    )
    parts = value.split("/")
    if (
        not value
        or value != value.strip()
        or len(value) > 1_024
        or len(parts) != 2
        or any(part in {"", ".", ".."} for part in parts)
        or invalid_character
    ):
        raise CollectorError(f"{source_id}: invalid OSV object path: {value!r}")
    return value


def _load_detail(source_id: str, url: str, body: bytes) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant {value}")

    try:
        payload = json.loads(body, parse_constant=reject_constant)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
        raise CollectorError(f"{source_id}: invalid OSV JSON from {url}") from exc
    if not isinstance(payload, dict):
        raise ParserChangedError(f"{source_id}: OSV detail is not an object: {url}")
    identifier = payload.get("id")
    if (
        not isinstance(identifier, str)
        or not identifier
        or identifier != identifier.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in identifier)
    ):
        raise ParserChangedError(f"{source_id}: OSV detail has no valid id: {url}")
    return payload


class OsvGlobalCollector:
    """Collect OSV records changed after the last successful delta boundary."""

    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        self._validate_source(source)
        assert source.url is not None
        client = SafeHttpClient(source)
        threshold = self._threshold(source, state, since)
        fetched_index = await self._fetch_index_prefix(client, source, state, threshold)
        if fetched_index.not_modified:
            return CollectionResult(
                source_id=source.id,
                etag=fetched_index.etag,
                last_modified=fetched_index.last_modified,
                not_modified=True,
                complete_snapshot=False,
            )

        paths = self._recent_paths(source, fetched_index.body, threshold)
        if len(paths) > source.max_detail_fetches:
            # 長期間失敗したままになると境界が古くなり、差分が取得上限を超えて以後ずっと
            # 失敗し続ける。ブートストラップ窓を持つソースはそこから再活性化し、最新分の
            # 収集を再開する（間の期間は履歴カバレッジの既知の欠落として扱う）。
            reactivated = self._reactivation_threshold(source, threshold)
            if reactivated is None:
                raise CollectorError(
                    f"{source.id}: OSV delta exceeds configured detail fetch limit of "
                    f"{source.max_detail_fetches} items"
                )
            threshold = reactivated
            paths = self._recent_paths(source, fetched_index.body, threshold)
            if len(paths) > source.max_detail_fetches:
                raise CollectorError(
                    f"{source.id}: OSV delta exceeds configured detail fetch limit of "
                    f"{source.max_detail_fetches} items"
                )

        records: list[RawRecord] = []
        seen_ids: set[str] = set()
        for path in paths:
            detail_url = f"{OSV_DETAIL_BASE_URL}{quote(path, safe='/-._~')}.json"
            fetched_detail = await client.fetch(detail_url)
            payload = _load_detail(source.id, detail_url, fetched_detail.body)
            identifier = payload["id"]
            assert isinstance(identifier, str)
            if identifier in seen_ids:
                continue
            seen_ids.add(identifier)
            records.append(
                RawRecord(
                    source_id=source.id,
                    url=f"{OSV_ADVISORY_BASE_URL}{quote(identifier, safe='-._~')}",
                    content=json.dumps(payload, ensure_ascii=False, sort_keys=True),
                    content_type=fetched_detail.content_type,
                    metadata=payload,
                    fetched_at=datetime.now(UTC),
                )
            )
            if len(records) > source.max_items:
                raise CollectorError(
                    f"{source.id}: OSV delta exceeds configured record limit of "
                    f"{source.max_items} items"
                )

        return CollectionResult(
            source_id=source.id,
            records=records,
            etag=fetched_index.etag,
            last_modified=fetched_index.last_modified,
            complete_snapshot=False,
        )

    @staticmethod
    def _threshold(
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> datetime:
        threshold = _as_utc(since)
        if state.last_success_at is not None:
            threshold = max(threshold, _as_utc(state.last_success_at))
        elif source.bootstrap_window_hours is not None:
            # The global index can contain hundreds of thousands of changes for a
            # normal 90-day pipeline window. Activate it from a short, explicit
            # boundary; subsequent runs always continue from last_success_at.
            bootstrap_threshold = _utc_now() - timedelta(hours=source.bootstrap_window_hours)
            threshold = max(threshold, bootstrap_threshold)
        return threshold

    @staticmethod
    def _reactivation_threshold(
        source: SourceDefinition,
        threshold: datetime,
    ) -> datetime | None:
        if source.bootstrap_window_hours is None:
            return None
        candidate = _utc_now() - timedelta(hours=source.bootstrap_window_hours)
        return candidate if candidate > threshold else None

    @classmethod
    async def _fetch_index_prefix(
        cls,
        client: SafeHttpClient,
        source: SourceDefinition,
        state: SourceState,
        threshold: datetime,
    ) -> FetchedContent:
        """Read only the newest part of the modified index.

        The index lists every change OSV ever published, newest first, and is far
        larger than a single response may be. Rows older than the collection
        boundary are never used, so the read stops as soon as the boundary is
        reached -- or as soon as the delta is already bigger than the detail
        fetch budget, because reading further cannot change the outcome.
        """

        assert source.url is not None
        first: FetchedContent | None = None
        body = b""
        offset = 0
        while True:
            fetched = await client.fetch(
                source.url,
                state if offset == 0 else None,
                conditional=offset == 0,
                byte_range=(offset, _INDEX_CHUNK_BYTES),
            )
            if fetched.not_modified:
                return fetched
            if first is None:
                first = fetched
            if not fetched.body:
                break
            body += fetched.body
            offset += len(fetched.body)
            _, row_count, last_modified_value = cls._complete_rows(source, body)
            if fetched.total_bytes is None:
                # 範囲取得に応じず全体が返された場合は、このまま使う。
                break
            if offset >= fetched.total_bytes or offset >= source.max_response_bytes:
                break
            if row_count > source.max_detail_fetches:
                break
            if last_modified_value is not None and last_modified_value <= threshold:
                break
        if first is None:
            raise ParserChangedError(f"{source.id}: OSV modified index returned no content")
        rows, _, _ = cls._complete_rows(source, body)
        return replace(first, body=rows, not_modified=False)

    @staticmethod
    def _complete_rows(
        source: SourceDefinition,
        body: bytes,
    ) -> tuple[bytes, int, datetime | None]:
        """Trim a partial read to whole rows and report its size and oldest row."""

        boundary = body.rfind(b"\n")
        rows = body if boundary < 0 else body[: boundary + 1]
        if not rows:
            return b"", 0, None
        lines = rows.splitlines()
        row_count = len(lines)
        last_modified_value: datetime | None = None
        if lines:
            first_field = lines[-1].split(b",", 1)[0].decode("utf-8", errors="replace").strip()
            if first_field:
                last_modified_value = _modified_at(first_field, source.id)
        return rows, row_count, last_modified_value

    @staticmethod
    def _validate_source(source: SourceDefinition) -> None:
        if source.url != OSV_MODIFIED_INDEX_URL:
            raise CollectorError(f"{source.id}: invalid OSV modified index endpoint")
        if OSV_STORAGE_HOST.casefold() not in {host.casefold() for host in source.allowed_hosts}:
            raise CollectorError(f"{source.id}: OSV storage host is not allowed")

    @staticmethod
    def _recent_paths(
        source: SourceDefinition,
        body: bytes,
        threshold: datetime,
    ) -> list[str]:
        try:
            text = body.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise CollectorError(f"{source.id}: invalid OSV modified index encoding") from exc

        paths: list[str] = []
        seen_paths: set[str] = set()
        previous_modified: datetime | None = None
        row_count = 0
        try:
            rows = csv.reader(io.StringIO(text, newline=""), strict=True)
            for row in rows:
                if row_count >= source.max_index_items:
                    raise CollectorError(
                        f"{source.id}: OSV index scan exceeds configured limit of "
                        f"{source.max_index_items} items"
                    )
                row_count += 1
                if len(row) != 2:
                    raise ParserChangedError(
                        f"{source.id}: OSV modified index row must have two columns"
                    )
                modified = _modified_at(row[0], source.id)
                if previous_modified is not None and modified > previous_modified:
                    raise ParserChangedError(
                        f"{source.id}: OSV modified index is not sorted newest-first"
                    )
                previous_modified = modified
                if modified <= threshold:
                    break
                path = _object_path(row[1], source.id)
                identifier = path.rsplit("/", 1)[-1]
                if source.osv_id_prefixes and not any(
                    identifier.startswith(prefix) for prefix in source.osv_id_prefixes
                ):
                    continue
                if path not in seen_paths:
                    seen_paths.add(path)
                    paths.append(path)
        except csv.Error as exc:
            raise ParserChangedError(f"{source.id}: invalid OSV modified index CSV") from exc

        if row_count == 0:
            raise ParserChangedError(f"{source.id}: OSV modified index contained zero rows")
        return paths
