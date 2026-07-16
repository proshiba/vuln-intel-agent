from __future__ import annotations

import re

from vulnwatch.models import RawRecord

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def parse_cisa_kev(records: list[RawRecord]) -> set[str]:
    cves: set[str] = set()
    for record in records:
        value = record.metadata.get("cveID") or record.metadata.get("cve")
        if value and CVE_PATTERN.match(str(value)):
            cves.add(str(value).upper())
    return cves
