from datetime import UTC, datetime
from unittest.mock import AsyncMock

import httpx
import pytest
import respx

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
    assert result.records[0].metadata["document"]["title"] == "Recent"
    assert recent.called
