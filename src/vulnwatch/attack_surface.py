"""初期アクセス面の分類。

`config/attack_surface.yaml` のキュレーション一覧に照らして、脆弱性のベンダー・製品を
初期アクセス面の分類（VPN機器、メール/コラボ基盤など）に対応づける。判定はベンダー名と
製品名の両方一致（英数字トークン境界での連続部分列一致）で行い、網羅より確度を優先する。
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from pathlib import Path

from ruamel.yaml import YAML

from vulnwatch.models import AttackSurfaceRegistry

DEFAULT_PATH = Path("config/attack_surface.yaml")


def _tokens(value: str) -> tuple[str, ...]:
    """英数字トークン列へ正規化する（大文字小文字を無視）。"""

    return tuple(re.findall(r"[a-z0-9]+", value.casefold()))


def _contains(haystack: tuple[str, ...], needle: tuple[str, ...]) -> bool:
    """needle が haystack の連続部分列なら True。"""

    count = len(needle)
    if count == 0 or count > len(haystack):
        return False
    return any(
        haystack[index : index + count] == needle for index in range(len(haystack) - count + 1)
    )


def load_attack_surface(path: Path = DEFAULT_PATH) -> AttackSurfaceRegistry:
    """分類定義を読み込む。ファイルが無い場合は空の定義を返す（分類なし）。"""

    if not path.exists():
        return AttackSurfaceRegistry()
    yaml = YAML(typ="safe")
    payload = yaml.load(path.read_text(encoding="utf-8"))
    return AttackSurfaceRegistry.model_validate(payload or {})


class AttackSurfaceClassifier:
    """正規化済みの製品一覧を保持し、ベンダー・製品から分類IDを判定する。"""

    def __init__(self, registry: AttackSurfaceRegistry) -> None:
        self._registry = registry
        # (class_id, vendor_tokens, name_tokens) を分類の定義順で保持する。
        self._specs: list[tuple[str, tuple[str, ...], tuple[str, ...]]] = [
            (class_id, _tokens(product.vendor), _tokens(product.name))
            for class_id, klass in registry.classes.items()
            for product in klass.products
        ]

    @property
    def registry(self) -> AttackSurfaceRegistry:
        return self._registry

    def labels(self) -> dict[str, str]:
        return {class_id: klass.label for class_id, klass in self._registry.classes.items()}

    def classify(self, vendors: Iterable[str], products: Iterable[str]) -> str | None:
        """一致した最初の分類IDを返す。一致なしは None。

        判定はベンダー・製品名をそれぞれ英数字トークン列に正規化し、連続部分列一致で
        行う。短い識別子（例: ASA）が無関係な語（例: database）の内部に部分一致する
        誤検出を避けるため、部分文字列ではなくトークン境界で照合する。
        """

        vendor_tokens = [_tokens(value) for value in vendors if value]
        product_tokens = [_tokens(value) for value in products if value]
        if not vendor_tokens or not product_tokens:
            return None
        for class_id, vendor_spec, name_spec in self._specs:
            vendor_ok = any(
                _contains(value, vendor_spec) or _contains(vendor_spec, value)
                for value in vendor_tokens
            )
            if vendor_ok and any(_contains(value, name_spec) for value in product_tokens):
                return class_id
        return None


_default_classifier: AttackSurfaceClassifier | None = None


def default_classifier() -> AttackSurfaceClassifier:
    """既定パスの分類器をプロセス内で一度だけ読み込んで再利用する。"""

    global _default_classifier
    if _default_classifier is None:
        _default_classifier = AttackSurfaceClassifier(load_attack_surface())
    return _default_classifier


def classify(vendors: Sequence[str], products: Sequence[str]) -> str | None:
    """既定の分類器でベンダー・製品を分類する簡易ヘルパー。"""

    return default_classifier().classify(vendors, products)
