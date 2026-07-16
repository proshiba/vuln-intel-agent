from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from vulnwatch.models import Advisory, AdvisoryDraft

_TRACKING_QUERY_KEYS = {"id", "advisory", "advisory_id", "vulnerability_id"}


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9._-]+", "-", value.lower()).strip("-._")
    return slug or hashlib.sha256(value.encode()).hexdigest()[:16]


def normalize_url(url: str) -> str:
    parts = urlsplit(url)
    host = (parts.hostname or "").lower()
    netloc = host
    if parts.port and not (parts.scheme == "https" and parts.port == 443):
        netloc = f"{host}:{parts.port}"
    path = re.sub(r"/+", "/", parts.path).rstrip("/") or "/"
    query = urlencode(
        sorted((k, v) for k, v in parse_qsl(parts.query) if k in _TRACKING_QUERY_KEYS)
    )
    return urlunsplit((parts.scheme.lower(), netloc, path, query, ""))


def canonical_id(draft: AdvisoryDraft) -> str:
    vendor = slugify(draft.vendor)
    if draft.vendor_advisory_id:
        local_id = slugify(draft.vendor_advisory_id)
    elif draft.source_url:
        local_id = hashlib.sha256(normalize_url(draft.source_url).encode()).hexdigest()[:24]
    else:
        published = draft.published_at or draft.updated_at
        published_date = published.date() if published else date.min
        seed = f"{draft.vendor}|{draft.source_id}|{draft.title}|{published_date.isoformat()}"
        local_id = hashlib.sha256(seed.encode()).hexdigest()[:24]
    return f"{vendor}:{local_id}"


def semantic_hash(advisory: Advisory) -> str:
    payload = {
        "title": advisory.title,
        "cves": advisory.facts.cves,
        "products": advisory.facts.products,
        "affected_versions": advisory.facts.affected_versions,
        "fixed_versions": advisory.facts.fixed_versions,
        "severity": advisory.facts.vendor_severity,
        "cvss_score": advisory.facts.cvss_score,
        "cvss_vector": advisory.facts.cvss_vector,
        "status": advisory.status,
        "mitigations": advisory.facts.mitigations,
        "known_exploited": advisory.facts.known_exploited,
    }
    canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()
