from datetime import UTC, datetime

import httpx
import respx

from vulnwatch.collectors.feed import FeedCollector
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState


@respx.mock
async def test_feed_uses_title_when_description_is_empty() -> None:
    url = "https://support.example.com/knowledgerss?type=Security"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://support.example.com/security-advisories",
        enabled=True,
        collector=CollectorKind.FEED,
        url=url,
        allowed_hosts=["support.example.com"],
        parser="feed",
        content_types=["application/rss+xml"],
    )
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss version='2.0'><channel><title>Security</title><item>"
                "<guid>ADV-1</guid><title>Security Bulletin CVE-2026-10010</title>"
                "<link>https://support.example.com/s/article/ADV-1</link>"
                "<description></description></item></channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )

    result = await FeedCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert result.records[0].content == "Security Bulletin CVE-2026-10010"
    assert result.records[0].metadata["id"] == "ADV-1"
    assert result.complete_snapshot is False
