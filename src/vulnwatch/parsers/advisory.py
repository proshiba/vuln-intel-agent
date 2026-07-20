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
    if source.parser == "nvd":
        return _parse_nvd(source, raw)
    if source.parser == "netapp":
        return _parse_netapp(source, raw)
    if source.parser == "apache_httpd":
        return _parse_apache_httpd(source, raw)
    if source.parser in {"palo_alto", "json_feed", "json"}:
        return _parse_json(source, raw)
    return _parse_generic(source, raw)


def _nested_dict(value: object, *keys: str) -> dict[str, Any]:
    current: object = value
    for key in keys:
        if not isinstance(current, dict):
            return {}
        current = current.get(key)
    return current if isinstance(current, dict) else {}


def _apache_timeline_date(item: dict[str, Any]) -> datetime | None:
    legacy_timeline = item.get("timeline")
    cna = _nested_dict(item, "containers", "cna")
    timeline = legacy_timeline if isinstance(legacy_timeline, list) else cna.get("timeline")
    if not isinstance(timeline, list):
        return None
    release_dates: list[datetime] = []
    other_dates: list[datetime] = []
    for event in timeline:
        if not isinstance(event, dict):
            continue
        observed = _date(event.get("time"))
        if observed is None:
            continue
        other_dates.append(observed)
        label = str(event.get("value") or "").casefold()
        if "public" in label or "released" in label:
            release_dates.append(observed)
    candidates = release_dates or other_dates
    return max(candidates) if candidates else None


def _apache_affected(item: dict[str, Any]) -> tuple[list[str], list[str]]:
    products: set[str] = set()
    affected_versions: set[str] = set()

    legacy_vendor = _nested_dict(item, "affects", "vendor")
    vendor_data = legacy_vendor.get("vendor_data")
    if isinstance(vendor_data, list):
        for vendor in vendor_data:
            product_data = _nested_dict(vendor, "product").get("product_data")
            if not isinstance(product_data, list):
                continue
            for product in product_data:
                if not isinstance(product, dict):
                    continue
                name = str(product.get("product_name") or "").strip()
                if name:
                    products.add(name)
                versions = _nested_dict(product, "version").get("version_data")
                if not isinstance(versions, list):
                    continue
                for version in versions:
                    if not isinstance(version, dict):
                        continue
                    value = str(version.get("version_value") or "").strip()
                    relation = str(version.get("version_affected") or "").strip()
                    if value:
                        detail = f"{relation} {value}".strip()
                        affected_versions.add(f"{name}: {detail}" if name else detail)

    current_affected = _nested_dict(item, "containers", "cna").get("affected")
    if isinstance(current_affected, list):
        for product in current_affected:
            if not isinstance(product, dict):
                continue
            name = str(product.get("product") or "").strip()
            if name:
                products.add(name)
            versions = product.get("versions")
            if not isinstance(versions, list):
                continue
            for version in versions:
                if not isinstance(version, dict) or version.get("status") != "affected":
                    continue
                bounds: list[str] = []
                start = str(version.get("version") or "").strip()
                if start and start not in {"0", "*"}:
                    bounds.append(f">= {start}")
                for key, operator in (
                    ("lessThan", "<"),
                    ("lessThanOrEqual", "<="),
                ):
                    value = str(version.get(key) or "").strip()
                    if value and value != "*":
                        bounds.append(f"{operator} {value}")
                if not bounds and start:
                    bounds.append(start)
                if bounds:
                    detail = ", ".join(bounds)
                    affected_versions.add(f"{name}: {detail}" if name else detail)
    return sorted(products), sorted(affected_versions)


def _apache_text_values(value: object, *path: str) -> list[str]:
    current: object = value
    for key in path:
        if not isinstance(current, dict):
            return []
        current = current.get(key)
    if not isinstance(current, list):
        return []
    return [
        str(entry.get("value"))
        for entry in current
        if isinstance(entry, dict) and entry.get("value")
    ]


def _parse_apache_httpd(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    """Normalize both CVE 4.0 and CVE 5.1 records in Apache's mixed JSON feed."""

    item = raw.metadata
    legacy_meta = item.get("CVE_data_meta")
    if not isinstance(legacy_meta, dict):
        legacy_meta = {}
    current_meta = item.get("cveMetadata")
    if not isinstance(current_meta, dict):
        current_meta = {}
    cna = _nested_dict(item, "containers", "cna")
    identifier = str(legacy_meta.get("ID") or current_meta.get("cveId") or "").upper()
    if not CVE_PATTERN.fullmatch(identifier):
        raise ValueError("Apache HTTP Server record omitted a valid CVE identifier")

    descriptions = _apache_text_values(item, "description", "description_data")
    descriptions.extend(_apache_text_values(item, "containers", "cna", "descriptions"))
    title = str(legacy_meta.get("TITLE") or cna.get("title") or identifier)
    products, affected_versions = _apache_affected(item)

    severity: str | None = None
    impact = item.get("impact")
    if isinstance(impact, list):
        severity = next(
            (
                str(entry.get("other"))
                for entry in impact
                if isinstance(entry, dict) and entry.get("other")
            ),
            None,
        )
    metrics = cna.get("metrics")
    if severity is None and isinstance(metrics, list):
        for metric in metrics:
            other = metric.get("other") if isinstance(metric, dict) else None
            content = other.get("content") if isinstance(other, dict) else None
            if isinstance(content, dict) and content.get("text"):
                severity = str(content["text"])
                break

    fixed_versions: set[str] = set()
    aggregate_text = "\n".join(descriptions)
    for match in re.findall(
        r"(?:upgrade to|fixed in|released)\s+(?:version\s+)?"
        r"(\d+(?:\.\d+){1,3})(?!\.\d|\.x\b|\w)",
        f"{aggregate_text}\n{json.dumps(item.get('timeline'), ensure_ascii=False)}\n"
        f"{json.dumps(cna.get('timeline'), ensure_ascii=False)}",
        re.IGNORECASE,
    ):
        fixed_versions.add(match)

    content = json.dumps(item, ensure_ascii=False, sort_keys=True)
    known_exploited, poc_public = infer_exploitation_status(content)
    published = _date(
        legacy_meta.get("DATE_PUBLIC")
        or current_meta.get("datePublished")
        or current_meta.get("dateUpdated")
    ) or _apache_timeline_date(item)
    withdrawn = str(legacy_meta.get("STATE") or current_meta.get("state") or "").casefold() in {
        "rejected",
        "withdrawn",
    }
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=identifier,
        title=title,
        source_url=raw.url,
        published_at=published,
        updated_at=_date(current_meta.get("dateUpdated")),
        status=AdvisoryStatus.WITHDRAWN if withdrawn else AdvisoryStatus.ACTIVE,
        cves=[identifier],
        products=products or source.products,
        affected_versions=affected_versions,
        fixed_versions=sorted(fixed_versions),
        vendor_severity=severity.upper() if severity else None,
        known_exploited=known_exploited,
        poc_public=poc_public,
        body_excerpt=("\n\n".join(descriptions) or content)[:30_000],
        raw_sha256=_sha(content),
    )


def _parse_netapp(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    item = raw.metadata
    content = json.dumps(item, ensure_ascii=False, sort_keys=True)
    identifier = str(item.get("ntap_advisory_id") or "").strip()
    cves = {
        str(value).upper()
        for value in _list(item.get("kb_cve"))
        if CVE_PATTERN.fullmatch(str(value).upper())
    }
    cves.update(CVE_PATTERN.findall(content.upper()))

    score_candidates: list[tuple[float, str]] = []
    scoring = item.get("kb_scoring")
    if isinstance(scoring, dict):
        for candidate in scoring.values():
            if not isinstance(candidate, str):
                continue
            candidate_vector = candidate.strip()
            candidate_score = _cvss_base_score(candidate_vector)
            if candidate_score is not None:
                score_candidates.append((candidate_score, candidate_vector))
    score: float | None = None
    vector: str | None = None
    if score_candidates:
        score, vector = max(score_candidates, key=lambda value: value[0])

    products = sorted(
        {
            value.strip()
            for key in ("kb_affected_list", "kb_revised_list", "kb_investigating_list")
            for value in _list(item.get(key))
            if value.strip()
        }
    )
    fixed_versions: list[str] = []
    mitigations = _list(item.get("kb_workarounds"))
    fixes = item.get("kb_fixes")
    if isinstance(fixes, list):
        for fix in fixes:
            if not isinstance(fix, dict):
                continue
            product = str(fix.get("product") or "").strip()
            for fixed in _list(fix.get("fixes")):
                fixed_versions.append(f"{product}: {fixed}" if product else fixed)
            instructions = str(fix.get("instructions") or "").strip()
            if instructions:
                mitigations.append(instructions)

    known_exploited, poc_public = infer_exploitation_status(content)
    severity: str | None = None
    if score is not None:
        if score >= 9:
            severity = "CRITICAL"
        elif score >= 7:
            severity = "HIGH"
        elif score >= 4:
            severity = "MEDIUM"
        else:
            severity = "LOW"
    remote = "/AV:N" in vector if vector else None
    authentication_required: bool | None = None
    if vector:
        if "/PR:N" in vector:
            authentication_required = False
        elif "/PR:L" in vector or "/PR:H" in vector:
            authentication_required = True
    withdrawn = str(item.get("kb_status") or "").casefold() == "withdrawn"
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=identifier or None,
        title=str(item.get("kb_title") or identifier or source.vendor),
        source_url=raw.url,
        published_at=_date(item.get("published_date")),
        updated_at=_date(item.get("updated_date") or item.get("modified_date")),
        status=AdvisoryStatus.WITHDRAWN if withdrawn else AdvisoryStatus.ACTIVE,
        cves=sorted(cves),
        products=products or source.products,
        fixed_versions=sorted(set(fixed_versions)),
        vendor_severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        remote=remote,
        authentication_required=authentication_required,
        known_exploited=known_exploited,
        poc_public=poc_public,
        mitigations=sorted(set(value for value in mitigations if value.strip())),
        body_excerpt=content[:30_000],
        raw_sha256=_sha(content),
    )


def _parse_nvd(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    item = raw.metadata
    identifier = str(item.get("id") or "")
    descriptions = item.get("descriptions")
    title = identifier or source.vendor
    if isinstance(descriptions, list):
        english = next(
            (
                str(description.get("value"))
                for description in descriptions
                if isinstance(description, dict)
                and description.get("lang") == "en"
                and description.get("value")
            ),
            None,
        )
        if english:
            title = english

    score: float | None = None
    vector: str | None = None
    severity: str | None = None
    metrics = item.get("metrics")
    if isinstance(metrics, dict):
        candidates: list[tuple[float, str | None, str | None]] = []
        for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            values = metrics.get(key)
            if not isinstance(values, list):
                continue
            for value in values:
                data = value.get("cvssData") if isinstance(value, dict) else None
                if not isinstance(data, dict) or not isinstance(
                    data.get("baseScore"), (int, float)
                ):
                    continue
                candidates.append(
                    (
                        float(data["baseScore"]),
                        str(data.get("vectorString")) if data.get("vectorString") else None,
                        str(data.get("baseSeverity") or value.get("baseSeverity") or "") or None,
                    )
                )
        if candidates:
            score, vector, severity = max(candidates, key=lambda candidate: candidate[0])

    products: set[str] = set()
    affected_versions: set[str] = set()
    fixed_versions: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, list):
            for child in value:
                walk(child)
            return
        if not isinstance(value, dict):
            return
        criteria = value.get("criteria")
        if isinstance(criteria, str) and criteria.startswith("cpe:2.3:"):
            parts = criteria.split(":")
            if len(parts) > 4:
                product = f"{parts[3]} {parts[4]}".replace("_", " ")
                products.add(product)
                bounds = [
                    f"{key}={value[key]}"
                    for key in (
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    )
                    if value.get(key)
                ]
                if bounds:
                    affected_versions.add(f"{product}: {', '.join(bounds)}")
                fixed = value.get("versionEndExcluding")
                if isinstance(fixed, str) and fixed.strip():
                    fixed_versions.add(f"{product}: {fixed.strip()}")
        for child in value.values():
            if isinstance(child, (dict, list)):
                walk(child)

    walk(item.get("configurations"))
    content = json.dumps(item, ensure_ascii=False, sort_keys=True)
    known_exploited, poc_public = infer_exploitation_status(content)
    cves = [identifier.upper()] if CVE_PATTERN.fullmatch(identifier.upper()) else []
    remote = "/AV:N" in vector if vector else None
    authentication_required: bool | None = None
    if vector:
        if "/PR:N" in vector:
            authentication_required = False
        elif "/PR:L" in vector or "/PR:H" in vector:
            authentication_required = True
    return AdvisoryDraft(
        source_id=source.id,
        vendor=source.vendor,
        vendor_advisory_id=identifier or None,
        title=title[:1000],
        source_url=raw.url,
        published_at=_date(item.get("published")),
        updated_at=_date(item.get("lastModified")),
        cves=cves,
        products=sorted(products) or source.products,
        affected_versions=sorted(affected_versions),
        fixed_versions=sorted(fixed_versions),
        vendor_severity=severity,
        cvss_score=score,
        cvss_vector=vector,
        remote=remote,
        authentication_required=authentication_required,
        known_exploited=known_exploited,
        poc_public=poc_public,
        body_excerpt=content[:30_000],
        raw_sha256=_sha(content),
    )


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
        products=_list(raw.metadata.get("products")) or source.products,
        known_exploited=known_exploited,
        poc_public=poc_public,
        body_excerpt=raw.content[:30_000],
        raw_sha256=_sha(raw.content),
    )


def _parse_json(source: SourceDefinition, raw: RawRecord) -> AdvisoryDraft:
    item = raw.metadata
    title = str(
        item.get("title")
        or item.get("ADVISORY")
        or item.get("item_title")
        or item.get("summary")
        or item.get("description")
        or item.get("cveID")
        or item.get("id")
        or source.vendor
    )
    advisory_id = (
        item.get("id")
        or item.get("CVE_ID")
        or item.get("ID")
        or item.get("documentId")
        or item.get("cve")
        or item.get("cveID")
        or item.get("advisory_id")
        or item.get("advisoryId")
        or item.get("advisoryNumber")
        or item.get("nid")
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
    product_value = (
        item.get("products")
        or item.get("product")
        or item.get("affected_products")
        or item.get("product_name")
        or item.get("supportProducts")
        or item.get("field_product")
        or item.get("Product_list")
    )
    if isinstance(product_value, list) and all(
        isinstance(product, dict) for product in product_value
    ):
        product_value = [
            product.get("display_value")
            for product in product_value
            if isinstance(product, dict) and product.get("display_value")
        ]
    products = _list(product_value) or source.products
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
        # The collector has already resolved untrusted item links and checked the
        # source allowlist. Reading the raw JSON link again here would bypass that
        # boundary (some official APIs still emit plain-HTTP legacy URLs).
        source_url=(
            f"{source.advisory_url.rstrip('/')}/{advisory_id}"
            if source.parser == "palo_alto" and advisory_id
            else raw.url
        ),
        published_at=_date(
            item.get("date_published")
            or item.get("item_date")
            or item.get("published")
            or item.get("datePublished")
            or item.get("published_at")
            or item.get("date")
            or item.get("field_pub_date")
            or item.get("Fixed")
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
            str(
                item.get("severity")
                or item.get("baseSeverity")
                or item.get("field_cvss_base_score")
                or item.get("CVSS_Severity_Rating")
            )
            if item.get("severity")
            or item.get("baseSeverity")
            or item.get("field_cvss_base_score")
            or item.get("CVSS_Severity_Rating")
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
