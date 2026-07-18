from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, cast

from cvss import CVSS2, CVSS3, CVSS4
from cvss.exceptions import CVSSError
from dateutil.parser import parse as parse_date

from vulnwatch.exploitation import infer_exploitation_status
from vulnwatch.models import AdvisoryDraft, AdvisoryStatus, RawRecord, SourceDefinition

CVE_PATTERN = re.compile(r"(?<![A-Z0-9])CVE-\d{4}-\d{4,}(?![A-Z0-9])", re.IGNORECASE)


def _cvss_base_score(vector: str) -> float | None:
    try:
        if vector.startswith("CVSS:4"):
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            return float(CVSS3(vector).base_score)
        return float(CVSS2(vector).base_score)
    except (CVSSError, ValueError, TypeError, ZeroDivisionError):
        return None


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


def _optional_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, (dict, list)):
        return bool(value)
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().casefold()
        if normalized in {"true", "yes", "1", "public", "available", "published"}:
            return True
        if normalized in {"false", "no", "0", "none", "unavailable"}:
            return False
        if normalized.startswith(("http://", "https://")):
            return True
    return None


def _sha(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def parse_record(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    if source.parser == "csaf":
        return _parse_csaf(source, raw)
    if source.parser == "osv":
        return _parse_osv(source, raw)
    if source.parser == "github_advisory":
        return _parse_github_advisory(source, raw)
    if source.parser in {"palo_alto", "json_feed", "json"}:
        return _parse_json(source, raw)
    return _parse_generic(source, raw)


def _parse_generic(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    title = str(raw.metadata.get("title") or raw.metadata.get("summary") or source.vendor)
    text = f"{title}\n{raw.content}"
    known_exploited, poc_public = infer_exploitation_status(text)
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
        known_exploited=known_exploited,
        poc_public=poc_public,
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
        or item.get("ID")
        or item.get("cve")
        or item.get("cveID")
        or item.get("advisory_id")
        or item.get("advisoryId")
    )
    text = json.dumps(item, ensure_ascii=False)
    inferred_exploited, inferred_poc = infer_exploitation_status(text)
    known_value = item.get("known_exploited")
    if known_value is None:
        known_value = item.get("knownExploited")
    poc_value = item.get("poc_public")
    if poc_value is None:
        poc_value = item.get("pocPublic")
    if poc_value is None:
        poc_value = item.get("proof_of_concept") or item.get("proofOfConcept")
    known_exploited = _optional_bool(known_value)
    poc_public = _optional_bool(poc_value)
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
    score = (
        item.get("cvss") or item.get("cvss_score") or item.get("cvssScore") or item.get("baseScore")
    )
    try:
        cvss = float(score) if score is not None else None
    except (TypeError, ValueError):
        cvss = None
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=str(advisory_id) if advisory_id else None,
        title=title,
        source_url=str(
            item.get("url")
            or item.get("external_url")
            or (
                f"{source.advisory_url.rstrip('/')}/{advisory_id}"
                if source.parser == "palo_alto" and advisory_id
                else raw.url
            )
        ),
        published_at=_date(
            item.get("date_published")
            or item.get("published")
            or item.get("datePublished")
            or item.get("published_at")
            or item.get("date")
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
        vendor_severity=(
            str(item.get("severity") or item.get("baseSeverity"))
            if item.get("severity") or item.get("baseSeverity")
            else None
        ),
        cvss_score=cvss,
        known_exploited=known_exploited if known_exploited is not None else inferred_exploited,
        poc_public=poc_public if poc_public is not None else inferred_poc,
        body_excerpt=text[:30_000],
        raw_sha256=_sha(text),
    )


def _parse_github_advisory(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    item = raw.metadata
    content = json.dumps(item, ensure_ascii=False, sort_keys=True)
    description = str(item.get("description") or "")
    known_exploited, poc_public = infer_exploitation_status(description)

    cves = set(CVE_PATTERN.findall(content.upper()))
    cve_id = item.get("cve_id")
    if isinstance(cve_id, str) and CVE_PATTERN.fullmatch(cve_id.upper()):
        cves.add(cve_id.upper())
    for identifier in item.get("identifiers", []):
        if not isinstance(identifier, dict) or identifier.get("type") != "CVE":
            continue
        value = str(identifier.get("value") or "").upper()
        if CVE_PATTERN.fullmatch(value):
            cves.add(value)

    products: list[str] = []
    affected_versions: list[str] = []
    fixed_versions: list[str] = []
    for vulnerability in item.get("vulnerabilities", []):
        if not isinstance(vulnerability, dict):
            continue
        package = vulnerability.get("package")
        package_name = ""
        if isinstance(package, dict):
            package_name = str(package.get("name") or "").strip()
        if package_name:
            products.append(package_name)
        affected = str(vulnerability.get("vulnerable_version_range") or "").strip()
        if affected:
            affected_versions.append(f"{package_name}: {affected}" if package_name else affected)
        fixed = str(vulnerability.get("patched_versions") or "").strip()
        if fixed:
            fixed_versions.append(f"{package_name}: {fixed}" if package_name else fixed)

    cvss = item.get("cvss")
    if not isinstance(cvss, dict):
        cvss = {}
    if cvss.get("score") is None:
        severities = item.get("cvss_severities")
        if isinstance(severities, dict):
            for key in ("cvss_v4", "cvss_v3"):
                candidate = severities.get(key)
                if isinstance(candidate, dict) and candidate.get("score") is not None:
                    cvss = candidate
                    break
    try:
        score = float(cvss["score"]) if cvss.get("score") is not None else None
    except (TypeError, ValueError):
        score = None
    vector = str(cvss.get("vector_string") or "") or None
    remote = "/AV:N" in vector if vector else None
    authentication_required = None
    if vector:
        if "/PR:N" in vector:
            authentication_required = False
        elif "/PR:L" in vector or "/PR:H" in vector:
            authentication_required = True

    withdrawn = bool(item.get("withdrawn_at")) or item.get("state") == "withdrawn"
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=str(item.get("ghsa_id") or "") or None,
        title=str(item.get("summary") or item.get("ghsa_id") or source.vendor),
        source_url=str(item.get("html_url") or raw.url),
        published_at=_date(item.get("published_at")),
        updated_at=_date(item.get("updated_at")),
        status=AdvisoryStatus.WITHDRAWN if withdrawn else AdvisoryStatus.ACTIVE,
        cves=sorted(cves),
        products=sorted(set(products)) or source.products,
        affected_versions=sorted(set(affected_versions)),
        fixed_versions=sorted(set(fixed_versions)),
        vendor_severity=str(item.get("severity") or "") or None,
        cvss_score=score,
        cvss_vector=vector,
        remote=remote,
        authentication_required=authentication_required,
        known_exploited=known_exploited,
        poc_public=poc_public,
        body_excerpt=content[:30_000],
        raw_sha256=_sha(content),
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
    known_exploited, poc_public = infer_exploitation_status(content)
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
        known_exploited=known_exploited,
        poc_public=poc_public,
        mitigations=sorted(set(mitigations)),
        body_excerpt=content[:30_000],
        raw_sha256=_sha(content),
    )


_OSV_SEVERITY_RANK = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3}
_OSV_REFERENCE_PRIORITY = {"ADVISORY": 0, "WEB": 1, "REPORT": 2, "FIX": 3, "PACKAGE": 4}


def _osv_source_url(references: list[Any], fallback: str) -> str:
    candidates: list[tuple[int, str]] = []
    for reference in references:
        if not isinstance(reference, dict):
            continue
        url = str(reference.get("url") or "")
        if not url.startswith("https://"):
            continue
        rank = _OSV_REFERENCE_PRIORITY.get(str(reference.get("type") or ""), 9)
        if "/security/advisories/" in url:
            rank -= 5
        candidates.append((rank, url))
    if not candidates:
        return fallback
    return min(candidates, key=lambda item: item[0])[1]


def _parse_osv(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    item = raw.metadata
    content = json.dumps(item, ensure_ascii=False, sort_keys=True)
    identifier = str(item.get("id") or "")

    cves: set[str] = set()
    for alias in item.get("aliases", []) or []:
        value = str(alias).upper()
        if CVE_PATTERN.fullmatch(value):
            cves.add(value)
    if CVE_PATTERN.fullmatch(identifier.upper()):
        cves.add(identifier.upper())

    products: list[str] = []
    fixed_versions: list[str] = []
    for affected in item.get("affected", []) or []:
        if not isinstance(affected, dict):
            continue
        package = affected.get("package")
        name = str(package.get("name")) if isinstance(package, dict) and package.get("name") else ""
        if name:
            products.append(name)
        for entry in affected.get("ranges", []) or []:
            if not isinstance(entry, dict):
                continue
            for event in entry.get("events", []) or []:
                if isinstance(event, dict) and event.get("fixed"):
                    fixed = str(event["fixed"])
                    fixed_versions.append(f"{name}: {fixed}" if name else fixed)

    best_vector: str | None = None
    best_rank = 99
    for severity in item.get("severity", []) or []:
        if not isinstance(severity, dict):
            continue
        vector = str(severity.get("score") or "")
        if not vector.startswith("CVSS:"):
            continue
        rank = 0 if severity.get("type") == "CVSS_V4" else 1
        if rank < best_rank:
            best_rank, best_vector = rank, vector
    cvss_score = _cvss_base_score(best_vector) if best_vector else None

    database_specific = item.get("database_specific")
    vendor_severity = None
    if isinstance(database_specific, dict) and database_specific.get("severity"):
        vendor_severity = str(database_specific["severity"])

    remote = "/AV:N/" in f"/{best_vector}/" if best_vector else None
    authentication_required = None
    if best_vector:
        if "/PR:N" in best_vector:
            authentication_required = False
        elif "/PR:L" in best_vector or "/PR:H" in best_vector:
            authentication_required = True

    summary = str(item.get("summary") or "").strip()
    details = str(item.get("details") or "").strip()
    title = summary or details.splitlines()[0][:200] if (summary or details) else identifier
    known_exploited, poc_public = infer_exploitation_status(f"{summary}\n{details}")

    references = item.get("references", []) or []
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=identifier or None,
        title=title or source.vendor,
        source_url=_osv_source_url(references, raw.url),
        published_at=_date(item.get("published")),
        updated_at=_date(item.get("modified")),
        status=AdvisoryStatus.WITHDRAWN if item.get("withdrawn") else AdvisoryStatus.ACTIVE,
        cves=sorted(cves),
        products=sorted(set(products)) or source.products,
        fixed_versions=sorted(set(fixed_versions)),
        vendor_severity=vendor_severity,
        cvss_score=cvss_score,
        cvss_vector=best_vector,
        remote=remote,
        authentication_required=authentication_required,
        known_exploited=known_exploited,
        poc_public=poc_public,
        body_excerpt=(details or summary)[:30_000],
        raw_sha256=_sha(content),
    )
