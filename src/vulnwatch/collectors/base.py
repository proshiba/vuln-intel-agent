from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol
from urllib.parse import urljoin, urlsplit

import httpx

from vulnwatch.models import CollectionResult, SourceDefinition, SourceState


class CollectorError(RuntimeError):
    """A source could not be collected safely."""


class ParserChangedError(CollectorError):
    """The source responded successfully but expected content was absent."""


class OptionalDependencyError(CollectorError):
    """An optional collector dependency is not installed."""


class Collector(Protocol):
    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult: ...


@dataclass(frozen=True)
class FetchedContent:
    url: str
    body: bytes
    content_type: str
    etag: str | None
    last_modified: str | None
    not_modified: bool = False


class SafeHttpClient:
    def __init__(self, source: SourceDefinition) -> None:
        self.source = source
        self._last_request_at: float | None = None

    def _validate_url(self, url: str) -> None:
        parsed = urlsplit(url)
        if parsed.scheme != "https":
            raise CollectorError(f"{self.source.id}: non-HTTPS URL rejected: {url}")
        if (parsed.hostname or "").lower() not in {
            host.lower() for host in self.source.allowed_hosts
        }:
            raise CollectorError(f"{self.source.id}: host is not allowed: {parsed.hostname}")

    async def fetch(
        self,
        url: str,
        state: SourceState | None = None,
        *,
        conditional: bool = False,
    ) -> FetchedContent:
        self._validate_url(url)
        headers = {
            "User-Agent": "vulnwatch/0.1 (+https://github.com/proshiba/vuln-intel-agent)",
            "Accept": ", ".join(self.source.content_types) or "*/*",
        }
        if conditional and state:
            if state.etag:
                headers["If-None-Match"] = state.etag
            if state.last_modified:
                headers["If-Modified-Since"] = state.last_modified
        timeout = httpx.Timeout(self.source.timeout_seconds)
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            current = url
            for redirect_count in range(6):
                response = await self._request_with_retry(client, current, headers)
                if response.status_code == 304:
                    return FetchedContent(
                        url=current,
                        body=b"",
                        content_type=response.headers.get("content-type", ""),
                        etag=response.headers.get("etag") or (state.etag if state else None),
                        last_modified=response.headers.get("last-modified")
                        or (state.last_modified if state else None),
                        not_modified=True,
                    )
                if response.status_code in {301, 302, 303, 307, 308}:
                    if redirect_count == 5:
                        raise CollectorError(f"{self.source.id}: too many redirects")
                    location = response.headers.get("location")
                    if not location:
                        raise CollectorError(f"{self.source.id}: redirect without Location")
                    current = urljoin(current, location)
                    self._validate_url(current)
                    continue
                if response.status_code >= 400:
                    raise CollectorError(
                        f"{self.source.id}: HTTP {response.status_code} from {current}"
                    )
                body = await response.aread()
                if len(body) > self.source.max_response_bytes:
                    raise CollectorError(
                        f"{self.source.id}: response exceeds {self.source.max_response_bytes} bytes"
                    )
                content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
                if self.source.content_types and not any(
                    content_type == expected or content_type.startswith(f"{expected}+")
                    for expected in self.source.content_types
                ):
                    raise CollectorError(
                        f"{self.source.id}: unexpected Content-Type {content_type!r}"
                    )
                return FetchedContent(
                    url=str(response.url),
                    body=body,
                    content_type=content_type,
                    etag=response.headers.get("etag"),
                    last_modified=response.headers.get("last-modified"),
                )
        raise CollectorError(f"{self.source.id}: fetch failed")

    async def _request_with_retry(
        self,
        client: httpx.AsyncClient,
        url: str,
        headers: dict[str, str],
    ) -> httpx.Response:
        for attempt in range(3):
            await self._pace()
            try:
                response = await client.get(url, headers=headers)
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if attempt == 2:
                    raise CollectorError(f"{self.source.id}: network failure: {exc}") from exc
                await asyncio.sleep(2**attempt)
                continue
            if response.status_code == 429 or 500 <= response.status_code < 600:
                if attempt == 2:
                    return response
                retry_after = response.headers.get("retry-after")
                delay = (
                    min(float(retry_after), 30.0)
                    if retry_after and retry_after.isdigit()
                    else 2**attempt
                )
                await asyncio.sleep(delay)
                continue
            return response
        raise CollectorError(f"{self.source.id}: retries exhausted")

    async def _pace(self) -> None:
        loop = asyncio.get_running_loop()
        interval = 1.0 / self.source.rate_limit_per_second
        if self._last_request_at is not None:
            remaining = interval - (loop.time() - self._last_request_at)
            if remaining > 0:
                await asyncio.sleep(remaining)
        self._last_request_at = loop.time()
