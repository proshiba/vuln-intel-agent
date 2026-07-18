from __future__ import annotations

import json
from datetime import UTC, datetime

from vulnwatch.collectors.base import CollectorError, ParserChangedError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_HOST = "api.osv.dev"
_MAX_PAGES = 20
# OSVはパッケージに影響する全脆弱性を返すため、GitHub API用のmax_items（ページ幅）は使わず、
# 暴走検知用に十分大きな独立の上限を設ける。母集合の異常判定はパイプライン側が担う。
_MAX_RECORDS = 5000


class OsvCollector:
    """OSV.dev（osv.dev）からパッケージ単位で脆弱性を取得する。

    api.github.comを使わずGitHub Advisory Database相当のデータを取得できるため、
    GitHub APIへ到達できない環境でもGitHub由来ソースを収集できる。
    """

    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        if not source.osv_ecosystem or not source.osv_packages:
            raise CollectorError(f"{source.id}: OSV collector requires osv_ecosystem and packages")
        client = SafeHttpClient(
            source.model_copy(
                update={
                    "allowed_hosts": [OSV_HOST],
                    "content_types": ["application/json"],
                }
            )
        )
        records: list[RawRecord] = []
        seen: set[str] = set()
        for package in source.osv_packages:
            page_token: str | None = None
            for _ in range(_MAX_PAGES):
                body: dict[str, object] = {
                    "package": {"ecosystem": source.osv_ecosystem, "name": package}
                }
                if page_token:
                    body["page_token"] = page_token
                fetched = await client.post_json(OSV_QUERY_URL, body)
                try:
                    payload = json.loads(fetched.body)
                except json.JSONDecodeError as exc:
                    raise CollectorError(f"{source.id}: invalid OSV JSON: {exc}") from exc
                for vuln in payload.get("vulns", []):
                    identifier = vuln.get("id") if isinstance(vuln, dict) else None
                    if not identifier or identifier in seen:
                        continue
                    seen.add(identifier)
                    records.append(
                        RawRecord(
                            source_id=source.id,
                            url=f"https://osv.dev/vulnerability/{identifier}",
                            content=json.dumps(vuln, ensure_ascii=False, sort_keys=True),
                            content_type=fetched.content_type,
                            metadata=vuln,
                            fetched_at=datetime.now(UTC),
                        )
                    )
                    if len(records) > _MAX_RECORDS:
                        raise CollectorError(
                            f"{source.id}: OSV returned more than {_MAX_RECORDS} vulnerabilities"
                        )
                page_token = payload.get("next_page_token")
                if not page_token:
                    break
        if not records:
            raise ParserChangedError(f"{source.id}: OSV returned zero vulnerabilities")
        # OSVはパッケージに影響する全脆弱性の集合で、GitHub発行分とは母集合が異なるため、
        # complete_snapshot=Falseとして取り下げ誤判定を避ける。
        return CollectionResult(source_id=source.id, records=records, complete_snapshot=False)
