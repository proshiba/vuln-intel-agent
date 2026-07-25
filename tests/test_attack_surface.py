from __future__ import annotations

from pathlib import Path

from vulnwatch.attack_surface import (
    AttackSurfaceClassifier,
    classify,
    load_attack_surface,
)
from vulnwatch.models import (
    AttackSurfaceClass,
    AttackSurfaceProduct,
    AttackSurfaceRegistry,
)


def _registry() -> AttackSurfaceRegistry:
    return AttackSurfaceRegistry(
        classes={
            "vpn_gateway": AttackSurfaceClass(
                label="VPN/リモートアクセス",
                products=[
                    AttackSurfaceProduct(vendor="Ivanti", name="Connect Secure"),
                    AttackSurfaceProduct(vendor="Fortinet", name="FortiOS"),
                    AttackSurfaceProduct(vendor="Cisco", name="ASA"),
                ],
            ),
            "webmail_collab": AttackSurfaceClass(
                label="メール/コラボレーション",
                products=[AttackSurfaceProduct(vendor="Microsoft", name="Exchange Server")],
            ),
        }
    )


def test_classifies_when_vendor_and_product_both_match() -> None:
    classifier = AttackSurfaceClassifier(_registry())

    assert classifier.classify(["Ivanti"], ["Ivanti Connect Secure 22.6R2"]) == "vpn_gateway"
    assert classifier.classify(["Microsoft"], ["Exchange Server 2019"]) == "webmail_collab"


def test_requires_both_vendor_and_product_match() -> None:
    classifier = AttackSurfaceClassifier(_registry())

    # Vendor matches but product does not: no classification (precision over recall).
    assert classifier.classify(["Fortinet"], ["FortiManager"]) is None
    # Product string matches but vendor does not.
    assert classifier.classify(["Acme"], ["Connect Secure"]) is None
    # Missing products cannot be classified.
    assert classifier.classify(["Ivanti"], []) is None


def test_vendor_match_tolerates_naming_variants() -> None:
    classifier = AttackSurfaceClassifier(_registry())

    assert classifier.classify(["Ivanti, Inc."], ["connect secure gateway"]) == "vpn_gateway"


def test_short_product_tokens_match_on_boundaries_not_substrings() -> None:
    classifier = AttackSurfaceClassifier(_registry())

    # "ASA" must match the standalone product token, not appear inside another word.
    assert classifier.classify(["Cisco"], ["Cisco ASA 5500"]) == "vpn_gateway"
    assert classifier.classify(["Cisco"], ["Cisco Database Connector"]) is None


def test_labels_expose_class_titles() -> None:
    classifier = AttackSurfaceClassifier(_registry())

    assert classifier.labels()["vpn_gateway"] == "VPN/リモートアクセス"


def test_load_returns_empty_registry_when_file_missing(tmp_path: Path) -> None:
    registry = load_attack_surface(tmp_path / "does-not-exist.yaml")

    assert registry.classes == {}


def test_shipped_config_classifies_known_edge_products() -> None:
    # The committed config/attack_surface.yaml should classify canonical edge products.
    assert classify(["Ivanti"], ["Ivanti Connect Secure"]) == "vpn_gateway"
    assert classify(["Microsoft"], ["Microsoft SharePoint Server"]) == "webmail_collab"
    assert classify(["Example"], ["Example OS"]) is None
