from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, ParserChangedError
from vulnwatch.collectors.csaf import CsafCollector
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState


@respx.mock
async def test_csaf_changes_csv_filters_old_documents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    index_url = "https://api.example.com/csaf/advisories/changes.csv"
    recent_url = "https://api.example.com/csaf/advisories/2026/recent.json"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://api.example.com/csaf",
        enabled=True,
        collector=CollectorKind.CSAF,
        url=index_url,
        allowed_hosts=["api.example.com"],
        parser="csaf",
        content_types=["text/csv", "application/json"],
    )
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                '"2026/recent.json","2026-07-01T00:00:00Z"\n'
                '"2025/old.json","2025-01-01T00:00:00Z"\n'
            ),
            headers={"content-type": "text/csv"},
        )
    )
    recent = respx.get(recent_url).mock(
        return_value=httpx.Response(
            200,
            json={"document": {"title": "Recent", "tracking": {"id": "ADV-1"}}},
            headers={"content-type": "application/json"},
        )
    )

    result = await CsafCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert len(result.records) == 1
    assert result.complete_snapshot is False
    assert result.records[0].metadata["document"]["title"] == "Recent"
    assert recent.called


@respx.mock
async def test_csaf_changes_csv_limits_details_after_sorting_by_modified_date(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    index_url = "https://api.example.com/csaf/advisories/changes.csv"
    newest_url = "https://api.example.com/csaf/advisories/newest.json"
    middle_url = "https://api.example.com/csaf/advisories/middle.json"
    oldest_url = "https://api.example.com/csaf/advisories/oldest.json"
    undated_url = "https://api.example.com/csaf/advisories/undated.json"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://api.example.com/csaf",
        enabled=True,
        collector=CollectorKind.CSAF,
        url=index_url,
        allowed_hosts=["api.example.com"],
        parser="csaf",
        max_items=1,
        max_index_items=10,
        max_detail_fetches=2,
        content_types=["text/csv", "application/json"],
    )
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                '"oldest.json","2026-05-01T00:00:00Z"\n'
                '"newest.json","2026-07-03T00:00:00Z"\n'
                '"middle.json","2026-06-02T00:00:00Z"\n'
                '"undated.json","not-a-date"\n'
            ),
            headers={"content-type": "text/csv"},
        )
    )
    for url, title in ((newest_url, "Newest"), (middle_url, "Middle")):
        respx.get(url).mock(
            return_value=httpx.Response(
                200,
                json={"document": {"title": title, "tracking": {"id": title}}},
                headers={"content-type": "application/json"},
            )
        )
    oldest = respx.get(oldest_url).mock(return_value=httpx.Response(500))
    undated = respx.get(undated_url).mock(return_value=httpx.Response(500))

    result = await CsafCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert [record.url for record in result.records] == [newest_url, middle_url]
    assert result.complete_snapshot is False
    assert oldest.called is False
    assert undated.called is False


@respx.mock
async def test_csaf_index_limit_is_separate_from_detail_limit() -> None:
    index_url = "https://api.example.com/csaf/advisories/changes.csv"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://api.example.com/csaf",
        enabled=True,
        collector=CollectorKind.CSAF,
        url=index_url,
        allowed_hosts=["api.example.com"],
        parser="csaf",
        max_index_items=1,
        max_detail_fetches=1,
        content_types=["text/csv", "application/json"],
    )
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text=('"first.json","2026-07-03T00:00:00Z"\n"second.json","2026-07-02T00:00:00Z"\n'),
            headers={"content-type": "text/csv"},
        )
    )

    with pytest.raises(CollectorError, match="CSAF index exceeds configured limit"):
        await CsafCollector().collect(
            source,
            SourceState(source_id="example"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )


@respx.mock
async def test_csaf_old_index_rows_return_an_empty_partial_result() -> None:
    index_url = "https://api.example.com/csaf/advisories/changes.csv"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://api.example.com/csaf",
        enabled=True,
        collector=CollectorKind.CSAF,
        url=index_url,
        allowed_hosts=["api.example.com"],
        parser="csaf",
        content_types=["text/csv", "application/json"],
    )
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text='"old.json","2025-01-01T00:00:00Z"\n',
            headers={"content-type": "text/csv"},
        )
    )

    result = await CsafCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert result.records == []
    assert result.complete_snapshot is False


@respx.mock
async def test_csaf_index_without_document_links_is_rejected() -> None:
    index_url = "https://api.example.com/csaf/advisories/changes.csv"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://api.example.com/csaf",
        enabled=True,
        collector=CollectorKind.CSAF,
        url=index_url,
        allowed_hosts=["api.example.com"],
        parser="csaf",
        content_types=["text/csv", "application/json"],
    )
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text='"not-json.txt","2026-07-01T00:00:00Z"\n',
            headers={"content-type": "text/csv"},
        )
    )

    with pytest.raises(ParserChangedError, match="contained no document links"):
        await CsafCollector().collect(
            source,
            SourceState(source_id="example"),
            datetime(2026, 4, 1, tzinfo=UTC),
        )


@respx.mock
async def test_csaf_detail_tolerates_invalid_utf8_from_vendor() -> None:
    index_url = "https://api.example.com/csaf/advisories/changes.csv"
    detail_url = "https://api.example.com/csaf/advisories/detail.json"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://api.example.com/csaf",
        enabled=True,
        collector=CollectorKind.CSAF,
        url=index_url,
        allowed_hosts=["api.example.com"],
        parser="csaf",
        content_types=["text/csv", "application/json"],
    )
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text='"detail.json","2026-07-01T00:00:00Z"\n',
            headers={"content-type": "text/csv"},
        )
    )
    respx.get(detail_url).mock(
        return_value=httpx.Response(
            200,
            content=(b'{"document":{"title":"Invalid \x96 byte","tracking":{"id":"ADV-1"}}}'),
            headers={"content-type": "application/json"},
        )
    )

    result = await CsafCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 4, 1, tzinfo=UTC),
    )

    assert result.records[0].metadata["document"]["title"] == "Invalid � byte"


@respx.mock
async def test_csaf_rejects_partial_detail_batch_for_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("vulnwatch.collectors.base.asyncio.sleep", AsyncMock())
    index_url = "https://api.example.com/csaf/advisories/changes.csv"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://api.example.com/csaf",
        enabled=True,
        collector=CollectorKind.CSAF,
        url=index_url,
        allowed_hosts=["api.example.com"],
        parser="csaf",
        content_types=["text/csv", "application/json"],
    )
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text=('"success.json","2026-07-02T00:00:00Z"\n"failure.json","2026-07-01T00:00:00Z"\n'),
            headers={"content-type": "text/csv", "etag": '"new-index"'},
        )
    )
    respx.get("https://api.example.com/csaf/advisories/success.json").mock(
        return_value=httpx.Response(
            200,
            json={"document": {"title": "Success", "tracking": {"id": "ADV-1"}}},
            headers={"content-type": "application/json"},
        )
    )
    respx.get("https://api.example.com/csaf/advisories/failure.json").mock(
        return_value=httpx.Response(503)
    )

    with pytest.raises(CollectorError, match="1 of 2 CSAF detail documents failed"):
        await CsafCollector().collect(
            source,
            SourceState(source_id="example", etag='"old-index"'),
            datetime(2026, 4, 1, tzinfo=UTC),
        )
