from collections import Counter
from pathlib import Path

import pytest

from vulnwatch.config import ConfigError, load_products, load_sources


def test_registry_has_all_sources_enabled_for_collection() -> None:
    registry = load_sources()
    enabled = {source.id for source in registry.sources if source.enabled}

    assert len(registry.sources) == 160
    assert enabled == {source.id for source in registry.sources}
    assert all(source.allowed_hosts for source in registry.sources if source.enabled)
    assert all(isinstance(source.products, list) for source in registry.sources)

    ivanti = next(source for source in registry.sources if source.id == "ivanti")
    assert ivanti.collector == "feed"
    assert ivanti.url == "https://www.ivanti.com/blog/topics/security-advisory/rss"
    assert ivanti.parser == "feed"
    assert ivanti.max_detail_fetches == 20

    schneider = next(source for source in registry.sources if source.id == "schneider_electric")
    assert schneider.collector == "html"
    assert schneider.parser == "generic"
    assert schneider.url == schneider.advisory_url
    assert schneider.allowed_hosts == [
        "www.se.com",
        "download.schneider-electric.com",
    ]
    assert schneider.selectors == {
        "item": "table tr:has(td)",
        "link": "td:nth-of-type(6) a[href]",
        "title": "td:nth-of-type(2)",
        "published_at": "td:nth-of-type(1)",
        "products": "td:nth-of-type(5)",
    }
    assert schneider.max_detail_fetches == 0

    collector_counts = Counter(source.collector for source in registry.sources)
    assert collector_counts["html"] == 27
    assert collector_counts["csaf"] == 6


def test_alternative_channels_are_separate_from_machine_feeds() -> None:
    registry = load_sources()
    zyxel = next(source for source in registry.sources if source.id == "zyxel")

    assert "email" in zyxel.alternative_channels
    assert "email" not in zyxel.feed_formats


def test_runtime_sources_use_bounded_machine_readable_channels() -> None:
    registry = load_sources()
    by_id = {source.id: source for source in registry.sources}

    juniper = by_id["juniper_networks"]
    assert juniper.collector == "feed"
    assert juniper.url == "https://supportportal.juniper.net/knowledgerss?type=Security"
    assert juniper.fallback_collectors == []

    for source_id in ("microsoft", "red_hat", "suse"):
        source = by_id[source_id]
        assert source.max_index_items == 100_000
        assert source.max_detail_fetches == 100

    ibm = by_id["ibm"]
    assert ibm.url == (
        "https://www.ibm.com/support/pages/securityapp/api/site/datalist?offset=0&limit=1000"
    )
    assert ibm.allowed_hosts == ["www.ibm.com"]
    assert ibm.max_response_bytes == 60_000_000
    assert ibm.max_items == 1_000
    assert ibm.max_index_items == 1_000


def test_feed_only_sources_do_not_fetch_unsupported_html_details() -> None:
    registry = load_sources()
    by_id = {source.id: source for source in registry.sources}

    expected_hosts = {
        "arista_networks": ["www.arista.com"],
        "qnap": ["www.qnap.com"],
        "sophos": ["support.sophos.com", "www.sophos.com"],
        "xerox": ["security.business.xerox.com"],
    }
    for source_id, allowed_hosts in expected_hosts.items():
        source = by_id[source_id]
        assert source.collector == "feed"
        assert source.parser == "feed"
        assert source.max_detail_fetches == 0
        assert source.allowed_hosts == allowed_hosts


def test_products_registry_starts_empty_and_contains_no_sensitive_fields() -> None:
    registry = load_products()
    content = Path("config/products.yaml").read_text(encoding="utf-8").casefold()

    assert registry.products == []
    assert "hostname" not in content
    assert "ip_address" not in content
    assert "credential" not in content


def test_duplicate_yaml_keys_are_rejected(tmp_path: Path) -> None:
    path = tmp_path / "sources.yaml"
    path.write_text("schema_version: 1\nschema_version: 2\n", encoding="utf-8")

    with pytest.raises(ConfigError, match="duplicate key"):
        load_sources(path)
