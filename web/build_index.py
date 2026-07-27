#!/usr/bin/env python3
"""Build the static JSON API served from GitHub Pages.

Emits two files under web/api/v1/:

- search.json … compact index of the whole ledger. The full CSV is tens of MB
  (its per-source column is huge), so we emit an array-of-arrays with a fields
  header, a flags bitmask, date-only timestamps and truncated text. Both the
  bundled viewer and any external portal search over this in the browser.
- meta.json   … discovery document: counts, schema version and how to build a
  detail URL. Per-entry detail is not pre-generated; the ledger YAML already
  lives in the repository and is readable from raw.githubusercontent.com, which
  is always current and richer than anything we would duplicate here.

Both hosts send Access-Control-Allow-Origin: *, so a portal on another origin
can read all of this directly from JavaScript.
"""

from __future__ import annotations

import csv
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = ROOT / "vulndb" / "index.csv"
VULNS_ROOT = ROOT / "vulndb" / "vulns"
API_DIR = Path(__file__).resolve().parent / "api" / "v1"
SEARCH_PATH = API_DIR / "search.json"  # ポータル連携仕様 v1（エンティティ配列）
VIEWER_PATH = API_DIR / "viewer.json"  # ビューア専用（列指向）
META_PATH = API_DIR / "meta.json"
ATTACK_SURFACE_PATH = ROOT / "config" / "attack_surface.yaml"

REPOSITORY = os.environ.get("VULNWATCH_REPOSITORY", "proshiba/vuln-intel-agent")
REF = os.environ.get("VULNWATCH_REF", "main")
SITE_URL = os.environ.get("VULNWATCH_SITE_URL", "https://proshiba.github.io/vuln-intel-agent/")

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
    "prefix",
]
FLAG_FIXED, FLAG_POC, FLAG_EXPLOITED, FLAG_KEV, FLAG_RANSOMWARE = 1, 2, 4, 8, 16


def _load_webapi():
    """Import the shared API helpers, which live in the package."""

    from vulnwatch.threatintel import ThreatIntelStore
    from vulnwatch.webapi import (
        build_entities,
        build_meta,
        build_search_document,
        build_threat_entities,
        encode_prefixes,
        scan_entry_prefixes,
    )

    return (
        ThreatIntelStore,
        build_entities,
        build_meta,
        build_search_document,
        build_threat_entities,
        encode_prefixes,
        scan_entry_prefixes,
    )


(
    ThreatIntelStore,
    build_entities,
    build_meta,
    build_search_document,
    build_threat_entities,
    encode_prefixes,
    scan_entry_prefixes,
) = _load_webapi()


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
                    -1,  # placeholder; replaced with the prefix-dictionary index below
                ]
            )
    # Newest first so the default view shows the most recently updated entries.
    rows.sort(key=lambda row: row[10], reverse=True)
    # Tell callers where each entry's detail YAML lives. Vendor x year/month combinations
    # repeat heavily, so a dictionary keeps this nearly free once gzipped.
    prefix_dictionary, encoded = encode_prefixes(
        [str(row[0]) for row in rows], scan_entry_prefixes(VULNS_ROOT)
    )
    prefix_column = FIELDS.index("prefix")
    for row, prefix_index in zip(rows, encoded, strict=True):
        row[prefix_column] = prefix_index
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
        "prefix_dictionary": prefix_dictionary,
        "vendors": sorted(vendors_set),
        "rows": rows,
    }
    generated_at = datetime.now(UTC).isoformat(timespec="seconds")
    payload["generated_at"] = generated_at
    activities_for_stats = list(ThreatIntelStore(ROOT).iter_activities())
    entity_counts: dict[str, int] = {
        "cve": sum(1 for row in rows if row[1]),
        "report": sum(1 for row in rows if not row[1]),
    }
    for entity in build_threat_entities(activities_for_stats):
        entity_counts[entity["type"]] = entity_counts.get(entity["type"], 0) + 1
    meta = build_meta(
        generated_at=generated_at,
        repository=REPOSITORY,
        site_url=SITE_URL,
        ref=REF,
        stats={**stats, **entity_counts, "priorities": prio_counts, "surfaces": surface_counts},
        fields=FIELDS,
        flags=payload["flags"],
        attack_surfaces=surfaces,
    )
    entities = build_entities(rows, FIELDS, payload["flags"], prefix_dictionary)
    # 攻撃活動（マルウェア・攻撃者・IOC）はポータルの横串の要になるため、索引に載せる。
    activities = list(ThreatIntelStore(ROOT).iter_activities())
    threat_entities = build_threat_entities(activities)
    entities.extend(threat_entities)
    search = build_search_document(generated_at=generated_at, entities=entities)

    API_DIR.mkdir(parents=True, exist_ok=True)
    VIEWER_PATH.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), "utf-8")
    SEARCH_PATH.write_text(json.dumps(search, ensure_ascii=False, separators=(",", ":")), "utf-8")
    META_PATH.write_text(json.dumps(meta, ensure_ascii=False, indent=2), "utf-8")
    for label, path in (("viewer", VIEWER_PATH), ("search", SEARCH_PATH)):
        print(f"wrote {path} ({path.stat().st_size / 1_000_000:.1f} MB, {label})")
    print(
        f"wrote {META_PATH} ({len(entities)} entities from {stats['total']} rows, "
        f"{len(threat_entities)} from threat activity)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
