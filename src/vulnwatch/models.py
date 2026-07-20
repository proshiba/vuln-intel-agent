from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


def _normalize_cves(values: list[str]) -> list[str]:
    normalized = sorted({value.upper() for value in values})
    invalid = [value for value in normalized if not _CVE_PATTERN.fullmatch(value)]
    if invalid:
        raise ValueError(f"invalid CVE identifiers: {invalid}")
    return normalized


def _validate_https_url(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            or character in "<>|\\"
            for character in value
        )
    ):
        raise ValueError("URL must be an absolute HTTPS URL")
    return value


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class SourceRole(StrEnum):
    ADVISORY = "advisory"
    ENRICHMENT = "enrichment"
    COVERAGE = "coverage"


class CollectorKind(StrEnum):
    CSAF = "csaf"
    JSON_API = "json_api"
    BROADCOM = "broadcom"
    UBIQUITI = "ubiquiti"
    FEED = "feed"
    HTML = "html"
    BROWSER = "browser"
    PDF = "pdf"
    OSV = "osv"
    NVD = "nvd"
    OSV_GLOBAL = "osv_global"


class Tier(StrEnum):
    EDGE = "edge"
    DAILY = "daily"


class Priority(StrEnum):
    P1 = "P1"
    P2 = "P2"
    P3 = "P3"
    INFO = "INFO"


class ChangeStatus(StrEnum):
    NEW = "new"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    WITHDRAWN = "withdrawn"
    QUARANTINED = "quarantined"


class SourceOutcomeStatus(StrEnum):
    SUCCESS = "success"
    NOT_MODIFIED = "not_modified"
    PARTIAL = "partial"
    FAILED = "failed"


class AdvisoryStatus(StrEnum):
    ACTIVE = "active"
    WITHDRAWN = "withdrawn"


class AiStatus(StrEnum):
    PENDING = "pending"
    SUCCESS = "success"
    SKIPPED = "skipped"
    FAILED = "failed"
    REFUSED = "refused"


class SourceDefinition(StrictModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]*$")
    category: str
    vendor: str
    products: list[str] = Field(default_factory=list)
    advisory_url: str
    enabled: bool = False
    role: SourceRole = SourceRole.ADVISORY
    collector: CollectorKind | None = None
    fallback_collectors: list[CollectorKind] = Field(default_factory=list)
    url: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)
    tier: Tier = Tier.DAILY
    rate_limit_per_second: float = Field(default=1.0, gt=0, le=20)
    timeout_seconds: float = Field(default=30.0, gt=0, le=120)
    max_response_bytes: int = Field(default=20_000_000, gt=0)
    max_items: int = Field(default=1000, gt=0, le=100_000)
    max_index_items: int = Field(default=100_000, gt=0, le=1_000_000)
    max_detail_fetches: int = Field(default=100, ge=0, le=100_000)
    bootstrap_window_hours: int | None = Field(default=None, gt=0, le=168)
    parser: str | None = None
    osv_ecosystem: str | None = None
    osv_packages: list[str] = Field(default_factory=list)
    osv_id_prefixes: list[str] = Field(default_factory=list)
    detail_collector: CollectorKind | None = None
    selectors: dict[str, str] = Field(default_factory=dict)
    wait_for: str | None = None
    content_types: list[str] = Field(default_factory=list)
    feed_status: str | None = None
    feed_formats: list[str] = Field(default_factory=list)
    feed_urls: list[str] = Field(default_factory=list)
    alternative_channels: list[str] = Field(default_factory=list)
    note: str | None = None

    @field_validator("products", mode="before")
    @classmethod
    def normalize_products(cls, value: Any) -> Any:
        if isinstance(value, str):
            cleaned = value.removesuffix("など")
            return [part.strip() for part in cleaned.replace("/", "／").split("、") if part.strip()]
        return value

    @model_validator(mode="after")
    def validate_runtime_source(self) -> SourceDefinition:
        if self.osv_packages and not self.osv_ecosystem:
            raise ValueError("osv_packages require osv_ecosystem")
        if self.osv_id_prefixes and self.collector != CollectorKind.OSV_GLOBAL:
            raise ValueError("osv_id_prefixes are only supported by osv_global")
        if any(
            not prefix
            or len(prefix) > 64
            or any(
                not character.isascii()
                or (not character.isalnum() and character not in "-._")
                for character in prefix
            )
            for prefix in self.osv_id_prefixes
        ):
            raise ValueError("osv_id_prefixes must contain bounded safe identifier prefixes")
        if (
            self.bootstrap_window_hours is not None
            and self.collector != CollectorKind.OSV_GLOBAL
        ):
            raise ValueError("bootstrap_window_hours is only supported by osv_global")
        if self.enabled:
            if self.collector is None or self.url is None:
                raise ValueError("enabled sources require collector and url")
            if not self.allowed_hosts:
                raise ValueError("enabled sources require allowed_hosts")
        for candidate in [self.advisory_url, self.url] if self.url else [self.advisory_url]:
            if candidate and not candidate.startswith("https://"):
                raise ValueError(f"source URLs must use HTTPS: {candidate}")
        normalized_hosts = {host.casefold() for host in self.allowed_hosts}
        if any("/" in host or ":" in host for host in normalized_hosts):
            raise ValueError("allowed_hosts entries must be hostnames without schemes or ports")
        if self.enabled:
            for runtime_url in (self.advisory_url, self.url):
                if (
                    runtime_url
                    and (urlsplit(runtime_url).hostname or "").casefold() not in normalized_hosts
                ):
                    raise ValueError(
                        f"source URL host must be listed in allowed_hosts: {runtime_url}"
                    )
        return self


class Category(StrictModel):
    id: str
    name: str


class SourceRegistry(StrictModel):
    schema_version: int = 1
    as_of: str
    description: str | None = None
    categories: list[Category]
    sources: list[SourceDefinition]

    @model_validator(mode="after")
    def validate_references(self) -> SourceRegistry:
        ids = [source.id for source in self.sources]
        if len(ids) != len(set(ids)):
            raise ValueError("source IDs must be unique")
        categories = {category.id for category in self.categories}
        unknown = {source.category for source in self.sources} - categories
        if unknown:
            raise ValueError(f"unknown categories: {sorted(unknown)}")
        return self


class Exposure(StrEnum):
    INTERNET = "internet"
    INTERNAL = "internal"


class ProductAsset(StrictModel):
    id: str
    vendor: str
    names: list[str]
    aliases: list[str] = Field(default_factory=list)
    exposure: Exposure = Exposure.INTERNAL
    owner: str
    enabled: bool = True


class ProductRegistry(StrictModel):
    schema_version: int = 1
    products: list[ProductAsset] = Field(default_factory=list)


class RawRecord(StrictModel):
    source_id: str
    url: str
    content: str
    content_type: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    fetched_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class AdvisoryDraft(StrictModel):
    source_id: str
    vendor: str
    vendor_advisory_id: str | None = None
    title: str
    source_url: str
    published_at: datetime | None = None
    updated_at: datetime | None = None
    status: AdvisoryStatus = AdvisoryStatus.ACTIVE
    cves: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    vendor_severity: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    remote: bool | None = None
    authentication_required: bool | None = None
    known_exploited: bool | None = None
    poc_public: bool | None = None
    mitigations: list[str] = Field(default_factory=list)
    body_excerpt: str = ""
    raw_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str) -> str:
        return _validate_https_url(value)

    @field_validator("cves")
    @classmethod
    def normalize_cves(cls, values: list[str]) -> list[str]:
        return _normalize_cves(values)


class AdvisoryFacts(StrictModel):
    cves: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    vendor_severity: str | None = None
    cvss_score: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    remote: bool | None = None
    authentication_required: bool | None = None
    known_exploited: bool | None = None
    poc_public: bool | None = None
    mitigations: list[str] = Field(default_factory=list)

    @field_validator("cves")
    @classmethod
    def normalize_cves(cls, values: list[str]) -> list[str]:
        return _normalize_cves(values)


class AdvisoryEnrichment(StrictModel):
    cisa_kev: bool = False
    asset_match: bool = False
    matched_asset_ids: list[str] = Field(default_factory=list)
    internet_exposed: bool = False


class AdvisoryDecision(StrictModel):
    priority: Priority = Priority.INFO
    reasons: list[str] = Field(default_factory=list)


class Provenance(StrictModel):
    source_type: str
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    extractor_version: str


class AiMetadata(StrictModel):
    status: AiStatus = AiStatus.PENDING
    model: str | None = None
    prompt_version: str | None = None
    input_hash: str | None = None
    summary_ja: str | None = None
    affected_assets: list[str] = Field(default_factory=list)
    exposure_conditions: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    evidence_urls: list[str] = Field(default_factory=list)
    error: str | None = None


class Advisory(StrictModel):
    schema_version: int = 1
    canonical_id: str
    source_id: str
    vendor: str
    vendor_advisory_id: str | None = None
    title: str
    source_url: str
    published_at: datetime | None = None
    updated_at: datetime | None = None
    first_seen_at: datetime
    status: AdvisoryStatus = AdvisoryStatus.ACTIVE
    facts: AdvisoryFacts
    enrichment: AdvisoryEnrichment = Field(default_factory=AdvisoryEnrichment)
    decision: AdvisoryDecision = Field(default_factory=AdvisoryDecision)
    provenance: Provenance
    body_excerpt: str = ""
    ai: AiMetadata = Field(default_factory=AiMetadata)

    @field_validator("source_url")
    @classmethod
    def validate_source_url(cls, value: str) -> str:
        return _validate_https_url(value)


class SourceState(StrictModel):
    source_id: str
    etag: str | None = None
    last_modified: str | None = None
    last_success_at: datetime | None = None
    last_failure_at: datetime | None = None
    consecutive_failures: int = 0
    item_count: int = 0
    known_ids: list[str] = Field(default_factory=list)
    missing_counts: dict[str, int] = Field(default_factory=dict)
    first_missing_at: dict[str, datetime] = Field(default_factory=dict)


class CollectionResult(StrictModel):
    source_id: str
    records: list[RawRecord] = Field(default_factory=list)
    etag: str | None = None
    last_modified: str | None = None
    not_modified: bool = False
    complete_snapshot: bool = True


class ChangeRecord(StrictModel):
    canonical_id: str
    source_id: str
    status: ChangeStatus
    priority: Priority
    path: str | None = None
    message: str | None = None


class SourceOutcome(StrictModel):
    source_id: str
    status: SourceOutcomeStatus
    collector: CollectorKind
    endpoint_url: str
    record_count: int = Field(default=0, ge=0)
    parsed_count: int = Field(default=0, ge=0)
    parse_failure_count: int = Field(default=0, ge=0)
    error: str | None = None

    @field_validator("endpoint_url")
    @classmethod
    def validate_endpoint_url(cls, value: str) -> str:
        return _validate_https_url(value)


class RunManifest(StrictModel):
    schema_version: int = 1
    started_at: datetime
    completed_at: datetime | None = None
    profile: Tier
    since: datetime
    baseline: bool = False
    changes: list[ChangeRecord] = Field(default_factory=list)
    source_outcomes: list[SourceOutcome] = Field(default_factory=list)

    @model_validator(mode="after")
    def validate_source_outcome_ids(self) -> RunManifest:
        source_ids = [outcome.source_id for outcome in self.source_outcomes]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source outcome IDs must be unique")
        return self
