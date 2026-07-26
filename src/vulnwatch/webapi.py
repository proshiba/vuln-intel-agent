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

from pathlib import Path
from typing import Any

API_VERSION = "v1"
SCHEMA_VERSION = 1
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
        "schema_version": SCHEMA_VERSION,
        "api_version": API_VERSION,
        "name": "vulnwatch",
        "description": (
            "ベンダー公式・公的データベース・OSINT から収集した脆弱性台帳の静的 JSON API。"
        ),
        "generated_at": generated_at,
        "repository": f"https://github.com/{repository}",
        "site_url": site_url,
        "license": "収集元各社の原典に従う。二次利用時は各出典を確認すること。",
        "cors": True,
        "endpoints": {
            "meta": f"api/{API_VERSION}/meta.json",
            "search": f"api/{API_VERSION}/search.json",
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
