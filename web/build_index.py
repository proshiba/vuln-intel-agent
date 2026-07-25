#!/usr/bin/env python3
"""Build a compact search index (site/data/index.json) from vulndb/index.csv.

The full ledger CSV is tens of MB (its per-source column is huge); the UI only
needs a few fields to list, search, filter and sort. We emit an array-of-arrays
with a fields header, a flags bitmask, date-only timestamps and truncated text
so the client can fetch and search the whole dataset quickly (gzip-served).
"""

from __future__ import annotations

import csv
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "vulndb" / "index.csv"
OUT_PATH = Path(__file__).resolve().parent / "data" / "index.json"

FIELDS = ["id", "cve", "vendors", "products", "title", "cvss", "sev", "prio", "flags", "pub", "upd"]
FLAG_FIXED, FLAG_POC, FLAG_EXPLOITED, FLAG_KEV = 1, 2, 4, 8


def _day(value: str) -> str:
    return value[:10] if value else ""


def _short(value: str, limit: int) -> str:
    value = " ".join(value.split())
    return value if len(value) <= limit else value[: limit - 1] + "…"


def _vendors(value: str) -> str:
    parts = [p for p in value.split(";") if p]
    return "; ".join(parts[:3]) + (" …" if len(parts) > 3 else "")


def main() -> int:
    if not CSV_PATH.exists():
        print(f"missing {CSV_PATH}", file=sys.stderr)
        return 1
    csv.field_size_limit(10_000_000)
    rows: list[list[object]] = []
    vendors_set: set[str] = set()
    stats = {"total": 0, "kev": 0, "exploited": 0, "poc": 0, "fixed": 0}
    prio_counts: dict[str, int] = {}
    with CSV_PATH.open(encoding="utf-8", newline="") as handle:
        for r in csv.DictReader(handle):
            flags = 0
            if r["fixed"] == "true":
                flags |= FLAG_FIXED
                stats["fixed"] += 1
            if r["poc_public"] == "true":
                flags |= FLAG_POC
                stats["poc"] += 1
            if r["known_exploited"] == "true":
                flags |= FLAG_EXPLOITED
                stats["exploited"] += 1
            if r["cisa_kev"] == "true":
                flags |= FLAG_KEV
                stats["kev"] += 1
            try:
                cvss: float | str = round(float(r["cvss_score"]), 1)
            except (TypeError, ValueError):
                cvss = ""
            for v in r["vendors"].split(";"):
                if v:
                    vendors_set.add(v)
            prio = r["priority"] or "INFO"
            prio_counts[prio] = prio_counts.get(prio, 0) + 1
            stats["total"] += 1
            rows.append(
                [
                    r["vuln_id"],
                    r["cve"],
                    _vendors(r["vendors"]),
                    _short(r["products"], 80),
                    _short(r["title"], 160),
                    cvss,
                    r["vendor_severity"] or "",
                    prio,
                    flags,
                    _day(r["published_at"]),
                    _day(r["updated_at"]),
                ]
            )
    # Newest first so the default view shows the most recently updated entries.
    rows.sort(key=lambda row: row[10], reverse=True)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "fields": FIELDS,
        "flags": {
            "fixed": FLAG_FIXED,
            "poc": FLAG_POC,
            "exploited": FLAG_EXPLOITED,
            "kev": FLAG_KEV,
        },
        "stats": {**stats, "priorities": prio_counts},
        "vendors": sorted(vendors_set),
        "rows": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), "utf-8")
    print(f"wrote {OUT_PATH} ({OUT_PATH.stat().st_size / 1_000_000:.1f} MB, {stats['total']} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
