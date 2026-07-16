from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, cast

from dateutil.parser import parse as parse_date

from vulnwatch.models import AdvisoryDraft, RawRecord, SourceDefinition

CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def _date(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        return cast(datetime, parse_date(str(value)))
    except (TypeError, ValueError, OverflowError):
        return None


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value if item not in (None, "")]
    if isinstance(value, dict):
        return [str(item) for item in value.values() if item not in (None, "")]
    return [str(value)]


def _sha(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def parse_record(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    if source.parser == "csaf":
        return _parse_csaf(source, raw)
    if source.parser in {"palo_alto", "json_feed", "json"}:
        return _parse_json(source, raw)
    return _parse_generic(source, raw)


def _parse_generic(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    title = str(raw.metadata.get("title") or raw.metadata.get("summary") or source.vendor)
    text = f"{title}\n{raw.content}"
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=str(raw.metadata.get("id") or "") or None,
        title=title,
        source_url=raw.url,
        published_at=_date(raw.metadata.get("published")),
        updated_at=_date(raw.metadata.get("updated")),
        cves=sorted(set(CVE_PATTERN.findall(text.upper()))),
        products=source.products,
        body_excerpt=raw.content[:30_000],
        raw_sha256=_sha(raw.content),
    )


def _parse_json(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    item = raw.metadata
    title = str(
        item.get("title")
        or item.get("summary")
        or item.get("description")
        or item.get("cveID")
        or item.get("id")
        or source.vendor
    )
    advisory_id = (
        item.get("id")
        or item.get("cve")
        or item.get("cveID")
        or item.get("advisory_id")
        or item.get("advisoryId")
    )
    text = json.dumps(item, ensure_ascii=False)
    products = (
        _list(
            item.get("products")
            or item.get("product")
            or item.get("affected_products")
            or item.get("product_name")
        )
        or source.products
    )
    affected = _list(
        item.get("affected_versions") or item.get("affected") or item.get("affectedVersions")
    )
    fixed = _list(
        item.get("fixed_versions")
        or item.get("unaffected")
        or item.get("fixedVersions")
        or item.get("solution")
    )
    score = item.get("cvss") or item.get("cvss_score") or item.get("cvssScore")
    try:
        cvss = float(score) if score is not None else None
    except (TypeError, ValueError):
        cvss = None
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=str(advisory_id) if advisory_id else None,
        title=title,
        source_url=str(item.get("url") or item.get("external_url") or raw.url),
        published_at=_date(
            item.get("date_published")
            or item.get("published")
            or item.get("datePublished")
            or item.get("published_at")
        ),
        updated_at=_date(
            item.get("date_modified")
            or item.get("updated")
            or item.get("dateUpdated")
            or item.get("updated_at")
        ),
        cves=sorted(set(CVE_PATTERN.findall(text.upper()))),
        products=products,
        affected_versions=affected,
        fixed_versions=fixed,
        vendor_severity=str(item.get("severity")) if item.get("severity") else None,
        cvss_score=cvss,
        known_exploited=item.get("known_exploited"),
        body_excerpt=text[:30_000],
        raw_sha256=_sha(text),
    )


def _parse_csaf(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    payload = raw.metadata
    document = payload.get("document", {}) if isinstance(payload, dict) else {}
    tracking = document.get("tracking", {}) if isinstance(document, dict) else {}
    vulnerabilities = payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
    cves: set[str] = set()
    scores: list[float] = []
    vectors: list[str] = []
    mitigations: list[str] = []
    fixed_versions: list[str] = []
    for vulnerability in vulnerabilities if isinstance(vulnerabilities, list) else []:
        if not isinstance(vulnerability, dict):
            continue
        if vulnerability.get("cve"):
            cves.add(str(vulnerability["cve"]).upper())
        for score in vulnerability.get("scores", []):
            cvss = score.get("cvss_v3") or score.get("cvss_v4") or score.get("cvss_v2") or {}
            if isinstance(cvss, dict):
                base = cvss.get("baseScore")
                if isinstance(base, (int, float)):
                    scores.append(float(base))
                if cvss.get("vectorString"):
                    vectors.append(str(cvss["vectorString"]))
        for remediation in vulnerability.get("remediations", []):
            if not isinstance(remediation, dict):
                continue
            details = str(remediation.get("details", "")).strip()
            if remediation.get("category") in {"vendor_fix", "none_available"} and details:
                fixed_versions.append(details)
            elif details:
                mitigations.append(details)
    product_tree = payload.get("product_tree", {}) if isinstance(payload, dict) else {}
    full_names = (
        product_tree.get("full_product_names", []) if isinstance(product_tree, dict) else []
    )
    products = [
        str(item.get("name")) for item in full_names if isinstance(item, dict) and item.get("name")
    ] or source.products
    title = str(document.get("title") or tracking.get("id") or source.vendor)
    aggregate = document.get("aggregate_severity") if isinstance(document, dict) else None
    severity = aggregate.get("text") if isinstance(aggregate, dict) else None
    content = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=str(tracking.get("id")) if tracking.get("id") else None,
        title=title,
        source_url=raw.url,
        published_at=_date(tracking.get("initial_release_date")),
        updated_at=_date(tracking.get("current_release_date")),
        cves=sorted(cves),
        products=products,
        fixed_versions=sorted(set(fixed_versions)),
        vendor_severity=str(severity) if severity else None,
        cvss_score=max(scores) if scores else None,
        cvss_vector=vectors[0] if vectors else None,
        mitigations=sorted(set(mitigations)),
        body_excerpt=content[:30_000],
        raw_sha256=_sha(content),
    )
