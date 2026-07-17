from pathlib import Path

import pytest

from vulnwatch.config import ConfigError, load_products, load_sources


def test_registry_has_all_sources_and_expected_initial_set() -> None:
    registry = load_sources()
    enabled = {source.id for source in registry.sources if source.enabled}

    assert len(registry.sources) == 130
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
        "canonical",
        "debian",
        "jenkins",
        "gitlab",
        "jvn",
        "redis",
        "grafana_github",
        "matrix_synapse_github",
        "prometheus_github",
        "etcd_github",
        "gitea_github",
        "traefik_github",
        "minio_github",
        "jupyter_server_github",
        "helm_github",
        "argo_cd_github",
        "flux_github",
        "containerd_github",
        "moby_github",
        "docker_compose_github",
        "otel_collector_github",
        "immich_github",
        "jellyfin_github",
        "home_assistant_github",
        "deno_github",
        "caddy_github",
        "envoy_github",
        "alertmanager_github",
        "oauth2_proxy_github",
        "syncthing_github",
        "tailscale_github",
        "netbird_github",
        "keycloak_github",
        "grpc_go_github",
        "electron_github",
        "nextjs_github",
        "nuxt_github",
        "rails_github",
        "laravel_github",
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
