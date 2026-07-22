from __future__ import annotations

import asyncio
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnwatch.collectors import CollectorError, create_collector
from vulnwatch.collectors.osv import OSV_HOST, OSV_QUERY_URL
from vulnwatch.collectors.osv_global import (
    OSV_MODIFIED_INDEX_URL,
    OSV_STORAGE_HOST,
)
from vulnwatch.config import load_products, load_sources
from vulnwatch.identity import canonical_id, semantic_hash
from vulnwatch.models import (
    Advisory,
    AdvisoryDraft,
    AdvisoryFacts,
    AdvisoryStatus,
    AiMetadata,
    ChangeRecord,
    ChangeStatus,
    CollectionResult,
    CollectorKind,
    Priority,
    Provenance,
    RunManifest,
    SourceDefinition,
    SourceOutcome,
    SourceOutcomeStatus,
    SourceRole,
    SourceState,
    Tier,
)
from vulnwatch.parsers import parse_cisa_kev, parse_record
from vulnwatch.priority import decide_priority, enrich_assets
from vulnwatch.storage.filesystem import FileSystemStorage, write_json
from vulnwatch.vulndb import VulnDb

GITHUB_BACKEND_ENV = "VULNWATCH_GITHUB_BACKEND"
_GITHUB_PUBLIC_HTML_SOURCE_IDS = frozenset({"redis", "nextcloud", "immich_github"})
_GITHUB_ADVISORY_SELECTOR = "a[href*='/security/advisories/GHSA-']"


def resolve_github_backend() -> str:
    """GitHub由来ソースの取り込み元。'github'（直接）または'osv'。既定は'github'。"""

    backend = os.environ.get(GITHUB_BACKEND_ENV, "github").strip().lower()
    return backend if backend in {"github", "osv"} else "github"


def apply_backend(source: SourceDefinition, backend: str) -> SourceDefinition:
    """Use bounded, credential-free alternatives for GitHub advisory API sources."""

    if backend != "osv" or source.parser != "github_advisory":
        return source

    if source.id == "github_advisory_database":
        variant = source.model_copy(
            update={
                "collector": CollectorKind.OSV_GLOBAL,
                "fallback_collectors": [],
                "parser": "osv",
                "url": OSV_MODIFIED_INDEX_URL,
                "allowed_hosts": sorted(set(source.allowed_hosts) | {OSV_STORAGE_HOST}),
                "content_types": ["text/csv", "text/plain", "application/json"],
                "max_items": 5_000,
                "max_response_bytes": 60_000_000,
                "max_index_items": 1_000_000,
                "max_detail_fetches": 5_000,
                "rate_limit_per_second": 20,
                "bootstrap_window_hours": 1,
                "osv_id_prefixes": ["GHSA-"],
            }
        )
        # model_copy intentionally avoids validation; round-trip the backend-only
        # fields so its endpoint/collector invariants remain enforced.
        return SourceDefinition.model_validate(variant.model_dump())

    if source.id in _GITHUB_PUBLIC_HTML_SOURCE_IDS:
        return source.model_copy(
            update={
                "collector": CollectorKind.HTML,
                "fallback_collectors": [],
                "parser": "generic",
                "url": source.advisory_url,
                "allowed_hosts": ["github.com"],
                "content_types": ["text/html", "application/xhtml+xml"],
                "selectors": {
                    "item": f"li.Box-row:has({_GITHUB_ADVISORY_SELECTOR})",
                    "link": _GITHUB_ADVISORY_SELECTOR,
                    "title": _GITHUB_ADVISORY_SELECTOR,
                    "published_at": "relative-time[datetime]",
                    "next": "a.next_page[rel='next'][href]",
                },
                "max_detail_fetches": min(source.max_items, 100),
            }
        )

    if source.osv_ecosystem and source.osv_packages:
        return source.model_copy(
            update={
                "collector": CollectorKind.OSV,
                "fallback_collectors": [],
                "parser": "osv",
                "url": OSV_QUERY_URL,
                "allowed_hosts": sorted(set(source.allowed_hosts) | {OSV_HOST}),
                "content_types": ["application/json"],
            }
        )
    return source


class Pipeline:
    def __init__(
        self,
        repository_root: Path,
        output_root: Path,
        sources_path: Path = Path("config/sources.yaml"),
        products_path: Path = Path("config/products.yaml"),
    ) -> None:
        self.repository_root = repository_root.resolve()
        self.output_root = output_root.resolve()
        self.sources = load_sources(sources_path)
        self.products = load_products(products_path)
        self.storage = FileSystemStorage(self.output_root)

    async def run(self, profile: Tier, since: datetime) -> RunManifest:
        FileSystemStorage.prepare_staging(self.repository_root, self.output_root)
        self.storage.reset_advisory_cache()
        started = datetime.now(UTC)
        baseline = not any(
            (self.repository_root / "data" / "vendors").glob("*/advisories/*/*/advisory.json")
        )
        manifest = RunManifest(
            started_at=started,
            profile=profile,
            since=since,
            baseline=baseline,
        )
        backend = resolve_github_backend()
        selected = [
            apply_backend(source, backend)
            for source in self.sources.sources
            if source.enabled and (profile == Tier.DAILY or source.tier == Tier.EDGE)
        ]
        results: dict[str, CollectionResult] = {}
        ordered_sources = sorted(selected, key=lambda item: item.role != SourceRole.ENRICHMENT)
        states = {source.id: self.storage.load_state(source.id) for source in ordered_sources}
        collector_states = {
            source_id: state.model_copy(deep=True) for source_id, state in states.items()
        }
        semaphore = asyncio.Semaphore(6)
        attempts = await asyncio.gather(
            *(
                self._collect_limited(source, collector_states[source.id], since, semaphore)
                for source in ordered_sources
            )
        )
        outcomes: dict[str, SourceOutcome] = {}
        for source, (result, collector, error) in zip(ordered_sources, attempts, strict=True):
            state = states[source.id]
            assert source.collector is not None
            assert source.url is not None
            outcome = SourceOutcome(
                source_id=source.id,
                status=SourceOutcomeStatus.SUCCESS,
                collector=collector or source.collector,
                endpoint_url=source.url,
                record_count=len(result.records) if result is not None else 0,
            )
            outcomes[source.id] = outcome
            try:
                if error is not None:
                    raise error
                assert result is not None
                self._validate_volume(source, state, result)
                if result.not_modified:
                    outcome.status = SourceOutcomeStatus.NOT_MODIFIED
                results[source.id] = result
                if result.not_modified:
                    self._write_success_state(state, result, started)
            except Exception as exc:
                outcome.status = SourceOutcomeStatus.FAILED
                outcome.error = str(exc)
                self._write_failure_state(state)
                quarantine_path = self.storage.write_quarantine(
                    source.id,
                    {
                        "source_id": source.id,
                        "detected_at": datetime.now(UTC).isoformat(),
                        "error": str(exc),
                    },
                )
                manifest.changes.append(
                    ChangeRecord(
                        canonical_id=f"{source.id}:collection",
                        source_id=source.id,
                        status=ChangeStatus.QUARANTINED,
                        priority=Priority.INFO,
                        path=str(quarantine_path.relative_to(self.output_root)),
                        message=str(exc),
                    )
                )

        kev: set[str] = set()
        if "cisa_kev" in results:
            kev = parse_cisa_kev(results["cisa_kev"].records)
            kev_outcome = outcomes["cisa_kev"]
            if kev_outcome.status == SourceOutcomeStatus.SUCCESS:
                kev_outcome.parsed_count = kev_outcome.record_count
                self._write_success_state(states["cisa_kev"], results["cisa_kev"], started)

        coverage_changes: list[Advisory] = []
        for source in selected:
            if source.role not in {SourceRole.ADVISORY, SourceRole.COVERAGE}:
                continue
            selected_result = results.get(source.id)
            if selected_result is None or selected_result.not_modified:
                continue
            current_ids: list[str] = []
            parsed_count = 0
            parse_errors: list[str] = []
            for raw in selected_result.records:
                try:
                    draft = parse_record(source, raw)
                except Exception as exc:
                    parse_errors.append(str(exc))
                    manifest.changes.append(
                        ChangeRecord(
                            canonical_id=f"{source.id}:parse",
                            source_id=source.id,
                            status=ChangeStatus.QUARANTINED,
                            priority=Priority.INFO,
                            message=str(exc),
                        )
                    )
                    continue
                parsed_count += 1
                current_ids.append(canonical_id(draft))
                observed = draft.updated_at or draft.published_at
                if observed and self._aware(observed) < since:
                    continue
                advisory = self._normalize(draft, source, kev)
                found = self.storage.find(advisory.canonical_id)
                existing = found[1] if found else None
                if existing:
                    advisory.first_seen_at = existing.first_seen_at
                    advisory.ai = (
                        existing.ai
                        if semantic_hash(existing) == semantic_hash(advisory)
                        else AiMetadata()
                    )
                if source.role == SourceRole.COVERAGE:
                    changed = existing is None or semantic_hash(existing) != semantic_hash(advisory)
                    if changed:
                        self.storage.write(advisory)
                        coverage_changes.append(advisory)
                    continue
                status = (
                    ChangeStatus.NEW
                    if existing is None
                    else ChangeStatus.UNCHANGED
                    if semantic_hash(existing) == semantic_hash(advisory)
                    else ChangeStatus.UPDATED
                )
                path = (
                    found[0]
                    if found and status == ChangeStatus.UNCHANGED
                    else self.storage.write(advisory)
                )
                manifest.changes.append(
                    ChangeRecord(
                        canonical_id=advisory.canonical_id,
                        source_id=source.id,
                        status=status,
                        priority=advisory.decision.priority,
                        path=str(path.relative_to(self.output_root)),
                    )
                )
            outcome = outcomes[source.id]
            outcome.parsed_count = parsed_count
            outcome.parse_failure_count = len(parse_errors)
            if parse_errors:
                outcome.status = SourceOutcomeStatus.PARTIAL
                outcome.error = parse_errors[0]
                self._write_failure_state(states[source.id])
            if parse_errors and parsed_count == 0:
                quarantine_path = self.storage.write_quarantine(
                    source.id,
                    {
                        "source_id": source.id,
                        "detected_at": datetime.now(UTC).isoformat(),
                        "error": "all collected records failed to parse",
                        "record_count": len(selected_result.records),
                    },
                )
                manifest.changes.append(
                    ChangeRecord(
                        canonical_id=f"{source.id}:parse-all",
                        source_id=source.id,
                        status=ChangeStatus.QUARANTINED,
                        priority=Priority.INFO,
                        path=str(quarantine_path.relative_to(self.output_root)),
                        message="all collected records failed to parse",
                    )
                )
            if parse_errors:
                continue
            next_state = states[source.id].model_copy(deep=True)
            if source.role == SourceRole.COVERAGE:
                # Coverage feeds are incremental aggregators and never participate in
                # report withdrawal inference. Retaining their ever-growing ID union
                # would make the Git-managed state file unbounded without adding a
                # correctness guarantee.
                self._write_success_state(next_state, selected_result, started)
                continue
            if selected_result.complete_snapshot:
                self._handle_missing(source, next_state, current_ids, manifest)
                next_state.known_ids = sorted(set(current_ids))
            else:
                for present in current_ids:
                    next_state.missing_counts.pop(present, None)
                    next_state.first_missing_at.pop(present, None)
                next_state.known_ids = sorted(set(next_state.known_ids) | set(current_ids))
            self._write_success_state(next_state, selected_result, started)

        manifest.source_outcomes = [outcomes[source.id] for source in selected]
        self._update_vulndb(manifest, coverage_changes)
        self.storage.rebuild_indexes()
        manifest.completed_at = datetime.now(UTC)
        write_json(
            self.output_root / "run-manifest.json",
            manifest.model_dump(mode="json", exclude_none=True),
        )
        self._write_summary(manifest)
        return manifest

    async def _collect_with_fallbacks(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> tuple[CollectionResult, CollectorKind]:
        assert source.collector is not None
        errors: list[str] = []
        for kind in [source.collector, *source.fallback_collectors]:
            try:
                return await create_collector(kind).collect(source, state, since), kind
            except CollectorError as exc:
                errors.append(f"{kind}: {exc}")
        raise CollectorError("; ".join(errors))

    async def _collect_limited(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
        semaphore: asyncio.Semaphore,
    ) -> tuple[CollectionResult | None, CollectorKind | None, Exception | None]:
        async with semaphore:
            try:
                result, collector = await self._collect_with_fallbacks(source, state, since)
                return result, collector, None
            except Exception as exc:
                return None, None, exc

    @staticmethod
    def _validate_volume(
        source: SourceDefinition,
        state: SourceState,
        result: CollectionResult,
    ) -> None:
        if result.not_modified:
            return
        count = len(result.records)
        if source.role == SourceRole.ADVISORY and count > 1000:
            raise CollectorError(f"{source.id}: anomalous new item volume")
        if not result.complete_snapshot:
            return
        if count == 0:
            raise CollectorError(f"{source.id}: HTTP success with zero records")
        if state.item_count >= 20 and count <= state.item_count * 0.15:
            raise CollectorError(f"{source.id}: item count dropped by at least 85%")
        if source.role == SourceRole.ADVISORY and (
            state.item_count and count > state.item_count * 10
        ):
            raise CollectorError(f"{source.id}: anomalous new item volume")

    def _write_success_state(
        self,
        state: SourceState,
        result: CollectionResult,
        collection_started_at: datetime,
    ) -> None:
        """Commit collection watermarks only after the source is fully usable.

        The start boundary deliberately precedes every upstream request in this run.
        Delta collectors therefore overlap updates that arrive while collection or
        parsing is still in progress instead of skipping them on the next run.
        """

        success_state = state.model_copy(deep=True)
        success_state.etag = result.etag or success_state.etag
        success_state.last_modified = result.last_modified or success_state.last_modified
        success_state.last_success_at = collection_started_at
        success_state.consecutive_failures = 0
        if not result.not_modified:
            success_state.item_count = len(result.records)
        self.storage.write_state(success_state)

    def _write_failure_state(self, state: SourceState) -> None:
        """Record a failed/partial attempt without advancing successful state."""

        failed_state = state.model_copy(deep=True)
        failed_state.last_failure_at = datetime.now(UTC)
        failed_state.consecutive_failures += 1
        self.storage.write_state(failed_state)

    def _normalize(
        self,
        draft: AdvisoryDraft,
        source: SourceDefinition,
        kev: set[str],
    ) -> Advisory:
        draft_id = canonical_id(draft)
        facts = AdvisoryFacts(
            cves=draft.cves,
            products=draft.products,
            affected_versions=draft.affected_versions,
            fixed_versions=draft.fixed_versions,
            vendor_severity=draft.vendor_severity,
            cvss_score=draft.cvss_score,
            cvss_vector=draft.cvss_vector,
            remote=draft.remote,
            authentication_required=draft.authentication_required,
            known_exploited=draft.known_exploited,
            poc_public=draft.poc_public,
            mitigations=draft.mitigations,
        )
        enrichment = enrich_assets(source.vendor, facts.products, self.products)
        enrichment.cisa_kev = bool(set(facts.cves) & kev)
        decision = decide_priority(facts, enrichment)
        return Advisory(
            canonical_id=draft_id,
            source_id=source.id,
            vendor=source.vendor,
            vendor_advisory_id=draft.vendor_advisory_id,
            title=draft.title,
            source_url=draft.source_url,
            published_at=draft.published_at,
            updated_at=draft.updated_at,
            first_seen_at=datetime.now(UTC),
            status=draft.status,
            facts=facts,
            enrichment=enrichment,
            decision=decision,
            provenance=Provenance(
                source_type=str(source.collector),
                content_sha256=draft.raw_sha256,
                extractor_version="0.1.0",
            ),
            body_excerpt=draft.body_excerpt,
        )

    def _update_vulndb(
        self,
        manifest: RunManifest,
        coverage_changes: list[Advisory] | None = None,
    ) -> None:
        db = VulnDb(self.output_root)
        now = datetime.now(UTC)
        if db.initialized:
            advisories: list[Advisory] = []
            seen: set[str] = set()
            for change in manifest.changes:
                if change.status not in {
                    ChangeStatus.NEW,
                    ChangeStatus.UPDATED,
                    ChangeStatus.WITHDRAWN,
                }:
                    continue
                if change.canonical_id in seen:
                    continue
                seen.add(change.canonical_id)
                found = self.storage.find(change.canonical_id)
                if found:
                    advisories.append(found[1])
            advisories.extend(coverage_changes or [])
        else:
            # 初回はリポジトリ内の全アドバイザリから台帳をシードする。
            advisories = self.storage.all_advisories()
        db.apply(advisories, now)
        db.write()

    def _handle_missing(
        self,
        source: SourceDefinition,
        state: SourceState,
        current_ids: list[str],
        manifest: RunManifest,
    ) -> None:
        now = datetime.now(UTC)
        current = set(current_ids)
        for missing in set(state.known_ids) - current:
            state.missing_counts[missing] = state.missing_counts.get(missing, 0) + 1
            state.first_missing_at.setdefault(missing, now)
            first_missing = self._aware(state.first_missing_at[missing])
            if state.missing_counts[missing] < 3 or now - first_missing < timedelta(hours=24):
                continue
            found = self.storage.find(missing)
            if not found:
                continue
            path, advisory = found
            advisory.status = AdvisoryStatus.WITHDRAWN
            self.storage.write(advisory)
            manifest.changes.append(
                ChangeRecord(
                    canonical_id=missing,
                    source_id=source.id,
                    status=ChangeStatus.WITHDRAWN,
                    priority=advisory.decision.priority,
                    path=str(path.relative_to(self.output_root)),
                )
            )
        for present in current:
            state.missing_counts.pop(present, None)
            state.first_missing_at.pop(present, None)

    def _write_summary(self, manifest: RunManifest) -> None:
        counts: dict[str, int] = {}
        priorities: dict[str, int] = {}
        source_statuses = {status.value: 0 for status in SourceOutcomeStatus}
        for change in manifest.changes:
            counts[change.status] = counts.get(change.status, 0) + 1
            priorities[change.priority] = priorities.get(change.priority, 0) + 1
        for outcome in manifest.source_outcomes:
            source_statuses[outcome.status] += 1
        lines = [
            "# Vulnerability collection run",
            "",
            f"- Profile: {manifest.profile}",
            f"- Started: {manifest.started_at.isoformat()}",
            f"- Completed: {manifest.completed_at.isoformat() if manifest.completed_at else '-'}",
            "",
            "## Changes",
            "",
            *[f"- {key}: {value}" for key, value in sorted(counts.items())],
            "",
            "## Priorities",
            "",
            *[f"- {key}: {value}" for key, value in sorted(priorities.items())],
            "",
            "## Source outcomes",
            "",
            *[f"- {key}: {value}" for key, value in sorted(source_statuses.items())],
            "",
        ]
        unsuccessful = sorted(
            (
                outcome
                for outcome in manifest.source_outcomes
                if outcome.status in {SourceOutcomeStatus.FAILED, SourceOutcomeStatus.PARTIAL}
            ),
            key=lambda outcome: outcome.source_id,
        )
        if unsuccessful:
            lines.extend(
                [
                    "## Unsuccessful sources",
                    "",
                    *[
                        f"- {outcome.source_id} ({outcome.status}, {outcome.collector}): "
                        f"records={outcome.record_count}, "
                        f"parse_failures={outcome.parse_failure_count}"
                        + (f" — {outcome.error}" if outcome.error else "")
                        for outcome in unsuccessful
                    ],
                    "",
                ]
            )
        (self.output_root / "run-summary.md").write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
