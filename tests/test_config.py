from pathlib import Path

import pytest

from vulnwatch.config import ConfigError, load_products, load_sources


def test_registry_has_all_sources_and_expected_initial_set() -> None:
    registry = load_sources()
    enabled = {source.id for source in registry.sources if source.enabled}

    assert len(registry.sources) == 97
    assert enabled == {
        "cisco",
        "fortinet",
        "palo_alto_networks",
        "juniper_networks",
        "microsoft",
        "red_hat",
        "suse",
        "kubernetes",
        "sonicwall",
        "veeam",
        "cisa_kev",
    }
    assert all(source.allowed_hosts for source in registry.sources if source.enabled)
    assert all(isinstance(source.products, list) for source in registry.sources)


def test_alternative_channels_are_separate_from_machine_feeds() -> None:
    registry = load_sources()
    zyxel = next(source for source in registry.sources if source.id == "zyxel")

    assert "email" in zyxel.alternative_channels
    assert "email" not in zyxel.feed_formats


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
