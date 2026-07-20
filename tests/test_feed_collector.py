from datetime import UTC, datetime

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, ParserChangedError
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


@respx.mock
async def test_feed_fails_closed_when_recent_advisory_detail_fetch_fails() -> None:
    feed_url = "https://support.example.com/advisories/feed.xml"
    detail_url = "https://support.example.com/advisories/ADV-1"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://support.example.com/advisories",
        enabled=True,
        collector=CollectorKind.FEED,
        url=feed_url,
        allowed_hosts=["support.example.com"],
        parser="feed",
        detail_collector=CollectorKind.HTML,
        max_detail_fetches=1,
        content_types=["application/rss+xml", "text/html"],
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss><channel><item><guid>ADV-1</guid><title>ADV-1</title>"
                f"<link>{detail_url}</link><pubDate>Sun, 19 Jul 2026 00:00:00 GMT</pubDate>"
                "</item></channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )
    respx.get(detail_url).mock(return_value=httpx.Response(404))

    with pytest.raises(CollectorError, match="advisory detail fetch.*failed"):
        await FeedCollector().collect(
            source,
            SourceState(source_id="example"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )


@respx.mock
async def test_feed_resolves_relative_links_against_the_feed_url() -> None:
    feed_url = "https://support.example.com/advisories/feed/"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://support.example.com/advisories/",
        enabled=True,
        collector=CollectorKind.FEED,
        url=feed_url,
        allowed_hosts=["support.example.com"],
        parser="feed",
        content_types=["application/rss+xml"],
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss version='2.0'><channel><item><title>ADV-2</title>"
                "<link>/advisories/ADV-2/</link></item></channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )

    result = await FeedCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert result.records[0].url == "https://support.example.com/advisories/ADV-2/"


@respx.mock
@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example/advisories/ADV-3",
        "http://support.example.com/advisories/ADV-3",
        "https://user:password@support.example.com/advisories/ADV-3",
    ],
)
async def test_feed_replaces_unsafe_links_with_the_official_landing_page(link: str) -> None:
    feed_url = "https://support.example.com/advisories/feed/"
    landing_url = "https://support.example.com/advisories/"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url=landing_url,
        enabled=True,
        collector=CollectorKind.FEED,
        url=feed_url,
        allowed_hosts=["support.example.com"],
        parser="feed",
        content_types=["application/rss+xml"],
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss version='2.0'><channel><item><title>ADV-3</title>"
                f"<link>{link}</link></item></channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )

    result = await FeedCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert result.records[0].url == landing_url


@respx.mock
async def test_feed_can_filter_a_vendor_news_feed_by_link_path() -> None:
    feed_url = "https://feeds.example.com/news"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://www.example.com/news/security/",
        enabled=True,
        collector=CollectorKind.FEED,
        url=feed_url,
        allowed_hosts=["feeds.example.com", "www.example.com"],
        parser="feed",
        selectors={"link_contains": "/news/security/"},
        content_types=["application/rss+xml"],
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss><channel>"
                "<item><title>Product launch</title>"
                "<link>https://www.example.com/news/release/1</link></item>"
                "<item><title>Security update CVE-2026-10010</title>"
                "<link>https://www.example.com/news/security/2</link></item>"
                "</channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )

    result = await FeedCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert [record.metadata["title"] for record in result.records] == [
        "Security update CVE-2026-10010"
    ]


@respx.mock
async def test_feed_can_filter_a_mixed_knowledge_feed_by_title_pattern() -> None:
    feed_url = "https://support.example.com/knowledge.rss"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://support.example.com/security-advisories",
        enabled=True,
        collector=CollectorKind.FEED,
        url=feed_url,
        allowed_hosts=["support.example.com"],
        parser="feed",
        selectors={"title_pattern": r"^SA-\d{4}-\d{3}\b"},
        content_types=["application/rss+xml"],
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss><channel>"
                "<item><title>New software release</title>"
                "<link>https://support.example.com/article/REL-1</link></item>"
                "<item><title>SA-2026-001 - Security update CVE-2026-10010</title>"
                "<link>https://support.example.com/article/SA-2026-001</link></item>"
                "</channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )

    result = await FeedCollector().collect(
        source,
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert [record.metadata["title"] for record in result.records] == [
        "SA-2026-001 - Security update CVE-2026-10010"
    ]


@respx.mock
async def test_feed_rejects_invalid_title_pattern() -> None:
    feed_url = "https://support.example.com/knowledge.rss"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://support.example.com/security-advisories",
        enabled=True,
        collector=CollectorKind.FEED,
        url=feed_url,
        allowed_hosts=["support.example.com"],
        parser="feed",
        selectors={"title_pattern": "["},
        content_types=["application/rss+xml"],
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss><channel><item><title>SA-2026-001</title>"
                "<link>https://support.example.com/article/SA-2026-001</link>"
                "</item></channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )

    with pytest.raises(CollectorError, match="invalid selectors.title_pattern"):
        await FeedCollector().collect(
            source,
            SourceState(source_id="example"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )


@respx.mock
async def test_feed_fails_closed_when_title_pattern_matches_nothing() -> None:
    feed_url = "https://support.example.com/knowledge.rss"
    source = SourceDefinition(
        id="example",
        category="test",
        vendor="Example",
        advisory_url="https://support.example.com/security-advisories",
        enabled=True,
        collector=CollectorKind.FEED,
        url=feed_url,
        allowed_hosts=["support.example.com"],
        parser="feed",
        selectors={"title_pattern": r"^SA-\d{4}-\d{3}\b"},
        content_types=["application/rss+xml"],
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss><channel><item><title>New software release</title>"
                "<link>https://support.example.com/article/REL-1</link>"
                "</item></channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )

    with pytest.raises(ParserChangedError, match="feed contained zero entries"):
        await FeedCollector().collect(
            source,
            SourceState(source_id="example"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )
