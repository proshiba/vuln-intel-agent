from __future__ import annotations

import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState

NVD_API_HOST = "services.nvd.nist.gov"
NVD_API_PATH = "/rest/json/cves/2.0"
NVD_DETAIL_BASE_URL = "https://nvd.nist.gov/vuln/detail/"
FORTRA_SOURCE_IDENTIFIER = "df4dee71-de3a-4139-9588-11b62fe6c0ff"
_FORTRA_ADVISORY_HOST = "www.fortra.com"
_FORTRA_ADVISORY_PATH = re.compile(
    r"^/security/advisories/product-security/fi-\d{4}-\d{3,}/?$",
    re.IGNORECASE,
)
_MAX_RESULTS_PER_PAGE = 2_000
_MAX_DATE_WINDOW = timedelta(days=120)
_DATE_RESOLUTION = timedelta(milliseconds=1)
_CONTROLLED_QUERY_PARAMETERS = {
    "lastModEndDate",
    "lastModStartDate",
    "pubEndDate",
    "pubStartDate",
    "resultsPerPage",
    "startIndex",
}


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _millisecond_precision(value: datetime) -> datetime:
    return value.replace(microsecond=(value.microsecond // 1_000) * 1_000)


def _nvd_datetime(value: datetime) -> str:
    return _millisecond_precision(_as_utc(value)).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _date_windows(start: datetime, end: datetime) -> Iterator[tuple[datetime, datetime]]:
    current = _millisecond_precision(start)
    final = _millisecond_precision(end)
    if current == final:
        yield current, final
        return
    while current < final:
        window_end = min(current + _MAX_DATE_WINDOW, final)
        yield current, window_end
        if window_end == final:
            return
        current = window_end + _DATE_RESOLUTION


def _integer(payload: dict[str, Any], key: str, source_id: str) -> int:
    value = payload.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ParserChangedError(f"{source_id}: NVD response has invalid {key}")
    return value


class NvdCollector:
    """Collect bounded CVE API 2.0 publication or modification windows from NVD."""

    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        assert source.url is not None
        self._validate_endpoint(source)

        now = _millisecond_precision(_utc_now())
        since_utc = _millisecond_precision(_as_utc(since))
        if since_utc > now:
            raise CollectorError(f"{source.id}: since date is later than the current time")

        # The Fortra source represents vendor advisories, including corrections to
        # previously published CVEs. Its initial 90-day run therefore uses the NVD
        # modification window as well as subsequent incremental runs.
        date_prefix = "lastMod" if source.id == "fortra" else "pub"
        range_start = since_utc
        if state.last_success_at is not None:
            date_prefix = "lastMod"
            range_start = max(since_utc, _millisecond_precision(_as_utc(state.last_success_at)))
            if range_start > now:
                raise CollectorError(
                    f"{source.id}: last successful collection is later than the current time"
                )

        client = SafeHttpClient(source)
        records: list[RawRecord] = []
        seen_ids: set[str] = set()
        indexed_items = 0
        for window_start, window_end in _date_windows(range_start, now):
            indexed_items += await self._collect_window(
                source=source,
                client=client,
                date_prefix=date_prefix,
                window_start=window_start,
                window_end=window_end,
                indexed_items=indexed_items,
                records=records,
                seen_ids=seen_ids,
                fetched_at=now,
            )

        return CollectionResult(
            source_id=source.id,
            records=records,
            complete_snapshot=False,
        )

    async def _collect_window(
        self,
        *,
        source: SourceDefinition,
        client: SafeHttpClient,
        date_prefix: str,
        window_start: datetime,
        window_end: datetime,
        indexed_items: int,
        records: list[RawRecord],
        seen_ids: set[str],
        fetched_at: datetime,
    ) -> int:
        assert source.url is not None
        base_url = source.url
        remaining_index_items = source.max_index_items - indexed_items
        remaining_records = source.max_items - len(records)
        if remaining_index_items <= 0 or remaining_records <= 0:
            raise CollectorError(f"{source.id}: NVD collection limit was exhausted")

        requested_page_size = min(
            _MAX_RESULTS_PER_PAGE,
            remaining_index_items,
            remaining_records,
        )
        records_before_window = len(records)
        start_index = 0
        declared_total: int | None = None
        while True:
            request_url = self._request_url(
                base_url,
                date_prefix=date_prefix,
                window_start=window_start,
                window_end=window_end,
                start_index=start_index,
                results_per_page=requested_page_size,
            )
            fetched = await client.fetch(request_url)
            payload = self._load_payload(source.id, fetched.body)
            vulnerabilities = payload.get("vulnerabilities")
            if not isinstance(vulnerabilities, list):
                raise ParserChangedError(
                    f"{source.id}: NVD response has no vulnerabilities array"
                )

            response_start = _integer(payload, "startIndex", source.id)
            response_page_size = _integer(payload, "resultsPerPage", source.id)
            total_results = _integer(payload, "totalResults", source.id)
            if response_start != start_index:
                raise ParserChangedError(f"{source.id}: NVD response startIndex did not match")
            if response_page_size <= 0 and total_results:
                raise ParserChangedError(f"{source.id}: NVD response has invalid resultsPerPage")
            if response_page_size > requested_page_size:
                raise CollectorError(
                    f"{source.id}: NVD response exceeded the requested page size"
                )
            if len(vulnerabilities) > response_page_size:
                raise ParserChangedError(
                    f"{source.id}: NVD vulnerabilities exceed resultsPerPage"
                )

            declared_total = max(declared_total or 0, total_results)
            if indexed_items + declared_total > source.max_index_items:
                raise CollectorError(
                    f"{source.id}: NVD index exceeds configured limit of "
                    f"{source.max_index_items} items"
                )
            if records_before_window + declared_total > source.max_items:
                raise CollectorError(
                    f"{source.id}: NVD window exceeds configured limit of "
                    f"{source.max_items} records"
                )
            if total_results == 0:
                if vulnerabilities:
                    raise ParserChangedError(
                        f"{source.id}: NVD returned records with totalResults zero"
                    )
                return declared_total
            if not vulnerabilities:
                raise ParserChangedError(
                    f"{source.id}: NVD pagination stopped before totalResults"
                )

            next_index = response_start + response_page_size
            if next_index < total_results and len(vulnerabilities) != response_page_size:
                raise ParserChangedError(f"{source.id}: NVD returned an incomplete page")

            for item in vulnerabilities:
                cve = item.get("cve") if isinstance(item, dict) else None
                identifier = cve.get("id") if isinstance(cve, dict) else None
                if not isinstance(identifier, str) or not identifier.strip():
                    raise ParserChangedError(f"{source.id}: NVD item has no CVE id")
                cve_metadata = cast(dict[str, Any], cve)
                record_url = f"{NVD_DETAIL_BASE_URL}{quote(identifier, safe='')}"
                if source.id == "fortra":
                    if cve_metadata.get("sourceIdentifier") != FORTRA_SOURCE_IDENTIFIER:
                        raise ParserChangedError(
                            f"{source.id}: NVD returned an unexpected sourceIdentifier"
                        )
                    fortra_url = self._fortra_product_advisory_url(cve_metadata)
                    if fortra_url is None:
                        # Fortra is also a CNA for vulnerabilities found in other
                        # vendors' products. Only its own FI product advisories are
                        # in scope for this source.
                        continue
                    record_url = fortra_url
                dedupe_key = identifier.casefold()
                if dedupe_key in seen_ids:
                    continue
                seen_ids.add(dedupe_key)
                records.append(
                    RawRecord(
                        source_id=source.id,
                        url=record_url,
                        content=json.dumps(cve_metadata, ensure_ascii=False, sort_keys=True),
                        content_type=fetched.content_type,
                        metadata=cve_metadata,
                        fetched_at=fetched_at,
                    )
                )
                if len(records) > source.max_items:
                    raise CollectorError(
                        f"{source.id}: NVD exceeds configured limit of "
                        f"{source.max_items} records"
                    )

            if next_index >= declared_total:
                return declared_total
            if next_index <= start_index:
                raise ParserChangedError(f"{source.id}: NVD pagination did not advance")
            start_index = next_index

    @staticmethod
    def _load_payload(source_id: str, body: bytes) -> dict[str, Any]:
        try:
            payload = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise CollectorError(f"{source_id}: invalid NVD JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise ParserChangedError(f"{source_id}: NVD response is not an object")
        return payload

    @staticmethod
    def _validate_endpoint(source: SourceDefinition) -> None:
        assert source.url is not None
        parsed = urlsplit(source.url)
        if parsed.hostname != NVD_API_HOST or parsed.path.rstrip("/") != NVD_API_PATH:
            raise CollectorError(f"{source.id}: invalid NVD CVE API 2.0 endpoint")
        if source.id == "fortra":
            query = parse_qsl(parsed.query, keep_blank_values=True)
            if query != [("sourceIdentifier", FORTRA_SOURCE_IDENTIFIER)]:
                raise CollectorError(
                    "fortra: NVD endpoint must contain only the configured "
                    "Fortra sourceIdentifier"
                )

    @staticmethod
    def _fortra_product_advisory_url(item: dict[str, Any]) -> str | None:
        references = item.get("references")
        if not isinstance(references, list):
            return None
        candidates: set[str] = set()
        for reference in references:
            candidate = reference.get("url") if isinstance(reference, dict) else None
            if not isinstance(candidate, str):
                continue
            try:
                parsed = urlsplit(candidate.strip())
                port = parsed.port
            except ValueError:
                continue
            if (
                parsed.scheme.casefold() != "https"
                or (parsed.hostname or "").casefold() != _FORTRA_ADVISORY_HOST
                or parsed.username is not None
                or parsed.password is not None
                or port not in (None, 443)
                or not _FORTRA_ADVISORY_PATH.fullmatch(parsed.path)
            ):
                continue
            candidates.add(
                urlunsplit(
                    (
                        "https",
                        _FORTRA_ADVISORY_HOST,
                        parsed.path.rstrip("/"),
                        "",
                        "",
                    )
                )
            )
        return min(candidates) if candidates else None

    @staticmethod
    def _request_url(
        base_url: str,
        *,
        date_prefix: str,
        window_start: datetime,
        window_end: datetime,
        start_index: int,
        results_per_page: int,
    ) -> str:
        parsed = urlsplit(base_url)
        query = [
            (key, value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
            if key not in _CONTROLLED_QUERY_PARAMETERS
        ]
        query.extend(
            [
                (f"{date_prefix}StartDate", _nvd_datetime(window_start)),
                (f"{date_prefix}EndDate", _nvd_datetime(window_end)),
                ("startIndex", str(start_index)),
                ("resultsPerPage", str(results_per_page)),
            ]
        )
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))
