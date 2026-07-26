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
ATTACK_SURFACE_PATH = ROOT / "config" / "attack_surface.yaml"

FIELDS = [
    "id",
    "cve",
    "vendors",
    "products",
    "title",
    "cvss",
    "sev",
    "prio",
    "flags",
    "pub",
    "upd",
    "asc",
    "lag",
]
FLAG_FIXED, FLAG_POC, FLAG_EXPLOITED, FLAG_KEV, FLAG_RANSOMWARE = 1, 2, 4, 8, 16


def _load_classifier():
    """Load the attack-surface classifier if the package is importable.

    The Pages workflow installs the package so the class is derived here; when it
    is unavailable we fall back to the CSV column (populated by the daily run).
    """

    try:
        from vulnwatch.attack_surface import AttackSurfaceClassifier, load_attack_surface
    except ImportError:
        return None
    return AttackSurfaceClassifier(load_attack_surface(ATTACK_SURFACE_PATH))


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
    classifier = _load_classifier()
    rows: list[list[object]] = []
    vendors_set: set[str] = set()
    stats = {
        "total": 0,
        "kev": 0,
        "exploited": 0,
        "poc": 0,
        "fixed": 0,
        "ransomware": 0,
        "kev_lag": 0,
    }
    prio_counts: dict[str, int] = {}
    surface_counts: dict[str, int] = {}
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
            # Columns added later; read defensively so an older ledger CSV still builds.
            if r.get("ransomware_use") == "true":
                flags |= FLAG_RANSOMWARE
                stats["ransomware"] += 1
            try:
                lag: int | str = int(r.get("kev_lag_days") or "")
                stats["kev_lag"] += 1
            except ValueError:
                lag = ""
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
            if classifier is not None:
                asc = classifier.classify(r["vendors"].split(";"), r["products"].split(";")) or ""
            else:
                asc = r.get("attack_surface_class", "") or ""
            if asc:
                surface_counts[asc] = surface_counts.get(asc, 0) + 1
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
                    asc,
                    lag,
                ]
            )
    # Newest first so the default view shows the most recently updated entries.
    rows.sort(key=lambda row: row[10], reverse=True)
    labels = classifier.labels() if classifier is not None else {}
    # Keep only classes that actually occur, in the config's declared order.
    surfaces = {cid: labels.get(cid, cid) for cid in labels if cid in surface_counts}
    for cid in surface_counts:
        surfaces.setdefault(cid, cid)
    payload = {
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "fields": FIELDS,
        "flags": {
            "fixed": FLAG_FIXED,
            "poc": FLAG_POC,
            "exploited": FLAG_EXPLOITED,
            "kev": FLAG_KEV,
            "ransomware": FLAG_RANSOMWARE,
        },
        "stats": {**stats, "priorities": prio_counts, "surfaces": surface_counts},
        "attack_surfaces": surfaces,
        "vendors": sorted(vendors_set),
        "rows": rows,
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), "utf-8")
    print(f"wrote {OUT_PATH} ({OUT_PATH.stat().st_size / 1_000_000:.1f} MB, {stats['total']} rows)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
