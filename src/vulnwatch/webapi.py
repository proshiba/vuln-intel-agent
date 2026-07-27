"""GitHub Pages で配信する静的 JSON API の組み立て。

ポータルなど別オリジンのページから、この台帳を横断検索・相互参照できるようにするための
データを作る。GitHub Pages と raw.githubusercontent.com はどちらも
`Access-Control-Allow-Origin: *` を返すため、サーバを立てずにブラウザの JavaScript から
直接読める。

配信する2つの入口:

- `api/v1/meta.json`   … 何が提供されているかを示す discovery 文書。ポータルはまずこれを
                          読み、件数・スキーマ版・検索索引と詳細の URL を知る。
- `api/v1/search.json` … 全件の軽量索引。検索・絞り込み・集計はこれを読んだ側で行う。

個別の詳細は事前生成しない。台帳の YAML がリポジトリに存在し、raw.githubusercontent.com
から直接読めるため、その URL の組み立て方だけを meta で伝える。常に最新で、事前生成した
JSON より内容も厚い。
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

API_VERSION = "v1"
SCHEMA_VERSION = 1
# research_bench ポータル連携仕様のバージョン（docs/portal-spec.md）。
SPEC_VERSION = "1.0"
APP_ID = "vuln-intel-agent"
DISPLAY_NAME = "脆弱性インテル"
# ポータルはビューアを iframe で並べるため、二重のヘッダを隠す。
EMBED_CSS = "header.top { display: none !important; } main { padding-top: 12px; }"
RAW_BASE_TEMPLATE = "https://raw.githubusercontent.com/{repository}/{ref}/vulndb/vulns"
# ポータル側は prefix と vuln_id を差し込んで詳細 YAML の URL を組み立てる。
DETAIL_URL_TEMPLATE = "{base}/{prefix}/{vuln_id}.yaml"


def scan_entry_prefixes(vulns_root: Path) -> dict[str, str]:
    """台帳 YAML を走査し、vuln_id → "<vendor>/<year>/<month>" を返す。

    配置は台帳側が決めるため、CSV から導出せず実ファイルを正とする。
    """

    if not vulns_root.exists():
        return {}
    prefixes: dict[str, str] = {}
    for path in vulns_root.rglob("*.yaml"):
        relative = path.relative_to(vulns_root)
        if len(relative.parts) < 2:
            # 旧レイアウト（フラット配置）。prefix なしでは詳細 URL を作れないため除く。
            continue
        prefixes[path.stem] = "/".join(relative.parts[:-1])
    return prefixes


def encode_prefixes(vuln_ids: list[str], prefixes: dict[str, str]) -> tuple[list[str], list[int]]:
    """配置パターンを辞書化し、各エントリを辞書への添字で表す。

    ベンダー×年月の組み合わせは実データで 139 種類程度しかなく、辞書参照にすることで
    索引に配置情報を持たせてもサイズがほとんど増えない。未知の ID は -1 とする。
    """

    dictionary: list[str] = []
    lookup: dict[str, int] = {}
    encoded: list[int] = []
    for vuln_id in vuln_ids:
        prefix = prefixes.get(vuln_id)
        if prefix is None:
            encoded.append(-1)
            continue
        index = lookup.get(prefix)
        if index is None:
            index = len(dictionary)
            lookup[prefix] = index
            dictionary.append(prefix)
        encoded.append(index)
    return dictionary, encoded


def build_meta(
    *,
    generated_at: str,
    repository: str,
    site_url: str,
    ref: str,
    stats: dict[str, Any],
    fields: list[str],
    flags: dict[str, int],
    attack_surfaces: dict[str, str],
) -> dict[str, Any]:
    """ポータルが最初に読む discovery 文書を組み立てる。"""

    raw_base = RAW_BASE_TEMPLATE.format(repository=repository, ref=ref)
    return {
        # ポータル連携仕様 v1（research_bench docs/portal-spec.md）の必須フィールド。
        "spec_version": SPEC_VERSION,
        "app_id": APP_ID,
        "name": DISPLAY_NAME,
        "schema_version": SCHEMA_VERSION,
        "api_version": API_VERSION,
        "description": (
            "ベンダー公式・公的データベース・OSINT から収集した脆弱性台帳の静的 JSON API。"
        ),
        "generated_at": generated_at,
        "repository": f"https://github.com/{repository}",
        # 仕様上、相対パス解決の基点になるため末尾のスラッシュを必須とする。
        "site_url": site_url if site_url.endswith("/") else f"{site_url}/",
        "license": "収集元各社の原典に従う。二次利用時は各出典を確認すること。",
        "cors": True,
        "capabilities": ["iframe", "deep-link", "postmessage"],
        # ポータルが iframe に注入し、ヘッダの二重化を防ぐ。
        "embed_css": EMBED_CSS,
        # エンティティ種別ごとの詳細ページ。{detail} にエンティティの detail が入る。
        "deep_links": {
            "cve": "#/vuln/{detail}",
            "report": "#/vuln/{detail}",
        },
        "endpoints": {
            "meta": f"api/{API_VERSION}/meta.json",
            # 仕様 v1 のエンティティ配列。ポータルはこれを読む。
            "search": f"api/{API_VERSION}/search.json",
            # 同じデータの列指向版。ビューア専用の拡張であり仕様の一部ではない。
            "viewer_index": f"api/{API_VERSION}/viewer.json",
            # 連携する側（人・エージェントとも）が最初に読む文書。
            "documentation": "INTEGRATION.md",
            "openapi": "openapi.yaml",
            "detail_url_template": DETAIL_URL_TEMPLATE.format(
                base=raw_base, prefix="{prefix}", vuln_id="{vuln_id}"
            ),
        },
        "search_index": {
            # search.json の rows は配列の配列。fields が列名、flags がビットマスクの意味、
            # prefix_dictionary が配置パターンの辞書。
            "fields": fields,
            "flags": flags,
            "prefix_field": "prefix",
            "detail_format": "yaml",
        },
        "attack_surfaces": attack_surfaces,
        "stats": stats,
    }


def expand_flags(value: object, flag_map: dict[str, int]) -> list[str]:
    """ビットマスクを名前の配列へ展開する。ポータルはこれをバッジとして描画する。"""

    if not isinstance(value, int):
        return []
    return [name for name, bit in flag_map.items() if value & bit]


def _attrs(
    row: list[Any],
    column: dict[str, int],
    flag_map: dict[str, int],
    prefix_dictionary: list[str],
) -> dict[str, Any]:
    """ポータルが「キー: 値」として素直に表示できる補足情報を作る。

    値が無い項目は載せない。空欄が並ぶと画面が読みにくくなるため。
    """

    def cell(name: str) -> Any:
        index = column.get(name)
        return row[index] if index is not None else None

    attrs: dict[str, Any] = {}
    for label, name in (
        ("題名", "title"),
        ("ベンダー", "vendors"),
        ("製品", "products"),
        ("CVSS", "cvss"),
        ("深刻度", "sev"),
        ("優先度", "prio"),
        ("公開", "pub"),
        ("更新", "upd"),
        ("攻撃面", "asc"),
        ("KEVラグ", "lag"),
    ):
        value = cell(name)
        if value not in (None, "", []):
            attrs[label] = value
    flags = expand_flags(cell("flags"), flag_map)
    if flags:
        attrs["flags"] = flags
    prefix_index = cell("prefix")
    if isinstance(prefix_index, int) and 0 <= prefix_index < len(prefix_dictionary):
        # 生 YAML の URL を組み立てるために、番号ではなく実際の文字列を渡す。
        attrs["prefix"] = prefix_dictionary[prefix_index]
    return attrs


def build_entities(
    rows: list[list[Any]],
    fields: list[str],
    flag_map: dict[str, int],
    prefix_dictionary: list[str],
) -> list[dict[str, Any]]:
    """列指向の索引を、ポータル仕様のエンティティ配列へ変換する。

    CVE を持つ行は `cve` 型で、`value` を大文字の CVE ID にする。ポータルはこの値の
    一致だけでソースを横断して束ねるため、結合キーとして最も重要な項目になる。
    CVE 未採番の行は結合しようがないので `report` 型とし、内部 ID を値に使う。
    """

    column = {name: index for index, name in enumerate(fields)}
    entities: list[dict[str, Any]] = []
    for row in rows:
        vuln_id = str(row[column["id"]])
        cve = str(row[column["cve"]] or "").upper()
        entities.append(
            {
                "type": "cve" if cve else "report",
                "id": f"vuln:{vuln_id}",
                "label": cve or vuln_id,
                "value": cve or vuln_id,
                "detail": vuln_id,
                "attrs": _attrs(row, column, flag_map, prefix_dictionary),
            }
        )
    return entities


def build_search_document(*, generated_at: str, entities: list[dict[str, Any]]) -> dict[str, Any]:
    """ポータルが読む仕様 v1 の索引本体。"""

    return {
        "spec_version": SPEC_VERSION,
        "app_id": APP_ID,
        "generated_at": generated_at,
        "entities": entities,
    }


def build_threat_entities(activities: list[Any]) -> list[dict[str, Any]]:
    """攻撃活動を、ポータルが横串に使えるエンティティへ展開する。

    ポータルは `value` の一致だけでソースをまたいで束ねるため、マルウェア名・攻撃者名・
    IOC を個別のエンティティとして出す。仕様の正規化規則（actor/malware は小文字化して
    英数字以外を除去、ioc は refang 済みの小文字）に合わせた値を `value` に入れる。

    同じ値が複数の脆弱性に現れる場合は 1 エンティティにまとめ、関連 CVE を attrs に持たせる。
    """

    entities: dict[str, dict[str, Any]] = {}

    def upsert(entity_type: str, key: str, label: str, value: str, attrs: dict[str, Any]) -> None:
        entity = entities.get(key)
        if entity is None:
            entities[key] = {
                "type": entity_type,
                "id": key,
                "label": label,
                "value": value,
                "detail": label,
                "attrs": attrs,
            }
            return
        related = entity["attrs"].setdefault("関連CVE", [])
        for cve in attrs.get("関連CVE", []):
            if cve not in related:
                related.append(cve)

    for activity in activities:
        reference = activity.cve or activity.vuln_id
        for name in activity.malware_names:
            slug = _join_slug(name)
            upsert("malware", f"malware:{slug}", name, slug, {"関連CVE": [reference]})
        for name in activity.actor_names:
            slug = _join_slug(name)
            upsert("actor", f"actor:{slug}", name, slug, {"関連CVE": [reference]})
        for indicator in activity.indicators:
            upsert(
                f"ioc.{indicator.type}",
                f"ioc:{indicator.type}:{indicator.value}",
                indicator.value,
                indicator.value,
                {
                    "関連CVE": [reference],
                    "役割": str(indicator.role),
                    "出典": indicator.url,
                },
            )
    return list(entities.values())


def _join_slug(name: str) -> str:
    """アクター名・マルウェア名の結合キー。仕様どおり小文字化して英数字以外を除く。"""

    return re.sub(r"[^a-z0-9]", "", name.casefold())
