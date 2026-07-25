from __future__ import annotations

import re
from datetime import UTC, datetime

from vulnwatch.models import KevEntry, RawRecord

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def _date_added(value: object) -> datetime | None:
    """KEV の dateAdded（YYYY-MM-DD）を UTC の datetime へ変換する。"""

    if not value:
        return None
    try:
        return datetime.strptime(str(value)[:10], "%Y-%m-%d").replace(tzinfo=UTC)
    except ValueError:
        return None


def parse_cisa_kev(records: list[RawRecord]) -> dict[str, KevEntry]:
    """CISA KEV を CVE 単位の掲載情報へ変換する。

    掲載日（dateAdded）は、悪用確認を KEV より早く観測できたかを測るために保持する。
    """

    entries: dict[str, KevEntry] = {}
    for record in records:
        value = record.metadata.get("cveID") or record.metadata.get("cve")
        if not value or not CVE_PATTERN.match(str(value)):
            continue
        ransomware = (
            str(record.metadata.get("knownRansomwareCampaignUse", "")).casefold() == "known"
        )
        entries[str(value).upper()] = KevEntry(
            date_added=_date_added(record.metadata.get("dateAdded")),
            ransomware=ransomware,
        )
    return entries
