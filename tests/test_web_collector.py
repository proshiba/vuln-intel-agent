import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from vulnwatch.collectors.base import CollectorError, ParserChangedError
from vulnwatch.collectors.web import WebCollector
from vulnwatch.models import CollectorKind, SourceDefinition, SourceState
from vulnwatch.parsers.advisory import parse_record


def _source(**overrides: object) -> SourceDefinition:
    values: dict[str, object] = {
        "id": "example",
        "category": "test",
        "vendor": "Example",
        "products": ["Example Product"],
        "advisory_url": "https://security.example.com/advisories",
        "enabled": True,
        "collector": CollectorKind.HTML,
        "url": "https://security.example.com/advisories",
        "allowed_hosts": ["security.example.com"],
        "parser": "generic",
        "content_types": [
            "text/html",
            "application/json",
            "application/rss+xml",
            "application/atom+xml",
            "application/xml",
        ],
        "max_detail_fetches": 5,
    }
    values.update(overrides)
    return SourceDefinition.model_validate(values)


@respx.mock
async def test_web_collector_extracts_and_enriches_official_html_links() -> None:
    index_url = "https://security.example.com/advisories"
    detail_url = "https://security.example.com/advisories/ADV-2026-001"
    respx.get(url__eq=index_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<html><body><main><article>"
                "<h2><a href='/advisories/ADV-2026-001'>Security advisory ADV-2026-001</a></h2>"
                "<time datetime='2026-07-01T00:00:00Z'></time>"
                "</article><a href='https://elsewhere.example/CVE-2026-99999'>external</a>"
                "</main></body></html>"
            ),
            headers={"content-type": "text/html"},
        )
    )
    respx.get(detail_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><main>Example Product is affected by CVE-2026-12345.</main></html>",
            headers={"content-type": "text/html"},
        )
    )

    result = await WebCollector().collect(
        _source(),
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert result.complete_snapshot is False
    assert len(result.records) == 1
    assert result.records[0].url == detail_url
    assert "CVE-2026-12345" in result.records[0].content
    assert result.records[0].metadata["detail_url"] == detail_url


@respx.mock
async def test_web_collector_prefers_security_feed_discovered_from_html() -> None:
    index_url = "https://security.example.com/advisories"
    feed_url = "https://security.example.com/security/feed.xml"
    detail_url = "https://security.example.com/advisories/ADV-2"
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<html><head><link rel='alternate' type='application/rss+xml' "
                "href='/security/feed.xml'></head><body></body></html>"
            ),
            headers={"content-type": "text/html"},
        )
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss><channel><item><guid>ADV-2</guid><title>Security bulletin</title>"
                f"<link>{detail_url}</link><description>CVE-2026-23456</description>"
                "</item></channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )
    respx.get(detail_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><main>Detail CVE-2026-23456</main></html>",
            headers={"content-type": "text/html"},
        )
    )

    result = await WebCollector().collect(
        _source(),
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert [record.metadata["id"] for record in result.records] == ["ADV-2"]
    assert result.records[0].url == detail_url


@respx.mock
async def test_web_collector_uses_configured_feed_url_after_landing_page() -> None:
    index_url = "https://security.example.com/advisories"
    feed_url = "https://security.example.com/rss/security.xml"
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text="<html><body><h1>Advisories</h1></body></html>",
            headers={"content-type": "text/html"},
        )
    )
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss><channel><item><guid>ADV-3</guid><title>CVE-2026-34567</title>"
                "<link>https://security.example.com/advisories/ADV-3</link>"
                "</item></channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )
    respx.get("https://security.example.com/advisories/ADV-3").mock(
        return_value=httpx.Response(
            200,
            text="<html><main>CVE-2026-34567</main></html>",
            headers={"content-type": "text/html"},
        )
    )

    result = await WebCollector().collect(
        _source(feed_urls=[feed_url]),
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert [record.metadata["id"] for record in result.records] == ["ADV-3"]


@respx.mock
async def test_web_collector_fails_closed_on_empty_html() -> None:
    url = "https://security.example.com/advisories"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            text="<html><body><h1>No current advisories</h1></body></html>",
            headers={"content-type": "text/html"},
        )
    )

    with pytest.raises(ParserChangedError, match="zero concrete advisory records"):
        await WebCollector().collect(
            _source(max_detail_fetches=0),
            SourceState(source_id="example"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )


@respx.mock
async def test_web_collector_rejects_generic_navigation_candidates() -> None:
    url = "https://security.example.com/advisories"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<nav><a href='/security'>Security</a>"
                "<a href='/trust-center'>Trust Center</a>"
                "<a href='/policies'>Policies</a></nav>"
            ),
            headers={"content-type": "text/html"},
        )
    )

    with pytest.raises(ParserChangedError, match="zero concrete advisory records"):
        await WebCollector().collect(
            _source(max_detail_fetches=0),
            SourceState(source_id="example"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )


@respx.mock
async def test_web_collector_fails_closed_when_configured_selector_matches_nothing() -> None:
    url = "https://security.example.com/advisories"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            text="<html><body><nav><a href='/security'>Security</a></nav></body></html>",
            headers={"content-type": "text/html"},
        )
    )

    with pytest.raises(ParserChangedError, match="selector matched zero advisory records"):
        await WebCollector().collect(
            _source(selectors={"item": "article.advisory"}, max_detail_fetches=0),
            SourceState(source_id="example"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )


@respx.mock
async def test_web_collector_fails_closed_when_advisory_detail_fetch_fails() -> None:
    index_url = "https://security.example.com/advisories"
    detail_url = "https://security.example.com/advisories/ADV-2026-001"
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text=f"<a href='{detail_url}'>Security advisory ADV-2026-001</a>",
            headers={"content-type": "text/html"},
        )
    )
    respx.get(detail_url).mock(return_value=httpx.Response(404))

    with pytest.raises(CollectorError, match="advisory detail fetch.*failed"):
        await WebCollector().collect(
            _source(),
            SourceState(source_id="example"),
            datetime(2026, 1, 1, tzinfo=UTC),
        )


@respx.mock
async def test_web_collector_filters_explicit_items_and_reads_text_date() -> None:
    url = "https://security.example.com/advisories"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<table><tr><td><a href='/advisories/ADV-1'>Security advisory</a></td>"
                "<td class='date'>2026-07-10</td></tr>"
                "<tr><td><a href='/news/1'>Product news</a></td>"
                "<td class='date'>2026-07-11</td></tr></table>"
            ),
            headers={"content-type": "text/html"},
        )
    )

    result = await WebCollector().collect(
        _source(
            selectors={
                "item": "tr",
                "link": "a[href]",
                "title": "a[href]",
                "published_at": ".date",
                "title_pattern": "advisory",
            },
            max_detail_fetches=0,
        ),
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert [record.metadata["title"] for record in result.records] == ["Security advisory"]
    assert result.records[0].metadata["published"] == "2026-07-10"


@respx.mock
async def test_web_collector_extracts_schneider_security_notification_row() -> None:
    index_url = (
        "https://www.se.com/ww/en/work/support/cybersecurity/security-notifications/"
    )
    pdf_url = (
        "https://download.schneider-electric.com/files?p_Doc_Ref=SEVD-2026-195-01"
        "&p_enDocType=Security+and+Safety+Notice"
        "&p_File_Name=SEVD-2026-195-01%20notification.pdf"
    )
    raw_pdf_url = pdf_url.replace("%20", " ")
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<table><tr><th>Last updated</th><th>Title</th><th>CVE</th>"
                "<th>Description</th><th>Products and Versions affected</th>"
                "<th>PDF</th></tr><tr>"
                "<td>2026/07/14</td>"
                "<td>Out-of-Bounds Write vulnerability in IGSS</td>"
                "<td>CVE-2026-12927</td><td>CWE-787 Out-of-bounds write</td>"
                "<td>IGSS Definition (Version 18.0 and prior)</td>"
                f"<td><a href=' {raw_pdf_url} '>SEVD-2026-195-01 PDF</a></td>"
                "</tr></table>"
            ),
            headers={"content-type": "text/html"},
        )
    )
    source = _source(
        id="schneider_electric",
        vendor="Schneider Electric",
        products=["EcoStruxure", "Modicon", "APC", "PowerLogic", "Citect"],
        advisory_url=index_url,
        url=index_url,
        allowed_hosts=["www.se.com", "download.schneider-electric.com"],
        selectors={
            "item": "table tr:has(td)",
            "link": "td:nth-of-type(6) a[href]",
            "title": "td:nth-of-type(2)",
            "published_at": "td:nth-of-type(1)",
            "products": "td:nth-of-type(5)",
        },
        max_detail_fetches=0,
    )

    result = await WebCollector().collect(
        source,
        SourceState(source_id=source.id),
        datetime(2026, 4, 20, tzinfo=UTC),
    )

    assert len(result.records) == 1
    record = result.records[0]
    assert record.url == pdf_url
    assert record.metadata["title"] == "Out-of-Bounds Write vulnerability in IGSS"
    assert record.metadata["published"] == "2026/07/14"
    assert "IGSS Definition (Version 18.0 and prior)" in record.content
    draft = parse_record(source, record)
    assert draft.cves == ["CVE-2026-12927"]
    assert draft.products == ["IGSS Definition (Version 18.0 and prior)"]


@respx.mock
async def test_web_collector_paginates_explicit_items_until_window_ends() -> None:
    index_url = "https://security.example.com/advisories"
    page_two_url = "https://security.example.com/advisories?page=2"
    page_three_url = "https://security.example.com/advisories?page=3"
    respx.get(url__eq=index_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<article><a href='/advisories/ADV-NEW'>ADV-NEW</a>"
                "<time datetime='2026-07-10T00:00:00Z'></time></article>"
                "<a class='next' href='/advisories?page=2'>Next</a>"
            ),
            headers={"content-type": "text/html"},
        )
    )
    respx.get(url__eq=page_two_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<article><a href='/advisories/ADV-OLD'>ADV-OLD</a>"
                "<time datetime='2025-01-01T00:00:00Z'></time></article>"
                "<a class='next' href='/advisories?page=3'>Next</a>"
            ),
            headers={"content-type": "text/html"},
        )
    )
    page_three = respx.get(url__eq=page_three_url).mock(
        return_value=httpx.Response(500)
    )

    result = await WebCollector().collect(
        _source(
            selectors={
                "item": "article",
                "link": "a[href]",
                "title": "a[href]",
                "published_at": "time[datetime]",
                "next": "a.next[href]",
            },
            max_detail_fetches=0,
        ),
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert [record.metadata["title"] for record in result.records] == [
        "ADV-NEW",
        "ADV-OLD",
    ]
    assert page_three.called is False


@respx.mock
async def test_web_collector_reads_json_indexes_as_partial_results() -> None:
    url = "https://security.example.com/advisories"
    respx.get(url).mock(
        return_value=httpx.Response(
            200,
            json={
                "items": [
                    {
                        "id": "ADV-4",
                        "title": "CVE-2026-45678",
                        "url": "https://security.example.com/advisories/ADV-4",
                    }
                ]
            },
            headers={"content-type": "application/json"},
        )
    )

    result = await WebCollector().collect(
        _source(max_detail_fetches=0),
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert result.records[0].metadata["id"] == "ADV-4"
    assert result.complete_snapshot is False


@respx.mock
async def test_web_collector_safely_resolves_relative_feed_links() -> None:
    feed_url = "https://security.example.com/advisories/feed/"
    respx.get(feed_url).mock(
        return_value=httpx.Response(
            200,
            text=(
                "<rss><channel>"
                "<item><guid>ADV-5</guid><title>Relative</title>"
                "<link>../ADV-5</link></item>"
                "<item><guid>ADV-6</guid><title>External</title>"
                "<link>https://evil.example/ADV-6</link></item>"
                "</channel></rss>"
            ),
            headers={"content-type": "application/rss+xml"},
        )
    )

    result = await WebCollector().collect(
        _source(url=feed_url, max_detail_fetches=0),
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert [record.url for record in result.records] == [
        "https://security.example.com/advisories/ADV-5",
        "https://security.example.com/advisories",
    ]


@respx.mock
async def test_web_collector_follows_configured_embedded_content_script() -> None:
    index_url = "https://security.example.com/advisories"
    script_url = "https://security.example.com/api/contents/advisories_123.js"
    embedded = (
        "<table><tr><td><a href='https://security.example.com/advisories/ADV-7'>"
        "Security advisory CVE-2026-77777</a></td></tr></table>"
    )
    respx.get(index_url).mock(
        return_value=httpx.Response(
            200,
            text=f"<script src='{script_url}'></script>",
            headers={"content-type": "text/html"},
        )
    )
    payload = json.dumps({"body": embedded, "updated": "123"})
    respx.get(script_url).mock(
        return_value=httpx.Response(
            200,
            text=f"Object.assign(window.cdnData,{payload})",
            headers={"content-type": "application/javascript"},
        )
    )

    result = await WebCollector().collect(
        _source(
            selectors={"content_script": "script[src*='/api/contents/advisories_']"},
            content_types=["text/html", "application/javascript"],
            max_detail_fetches=0,
        ),
        SourceState(source_id="example"),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    assert len(result.records) == 1
    assert result.records[0].url == "https://security.example.com/advisories/ADV-7"
