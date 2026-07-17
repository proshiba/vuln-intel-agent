from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from vulnwatch.collectors import CollectorError, create_collector
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
    Priority,
    Provenance,
    RunManifest,
    SourceDefinition,
    SourceRole,
    SourceState,
    Tier,
)
from vulnwatch.parsers import parse_cisa_kev, parse_record
from vulnwatch.priority import decide_priority, enrich_assets
from vulnwatch.storage.filesystem import FileSystemStorage, write_json


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
        selected = [
            source
            for source in self.sources.sources
            if source.enabled and (profile == Tier.DAILY or source.tier == Tier.EDGE)
        ]
        results: dict[str, CollectionResult] = {}
        states: dict[str, SourceState] = {}
        for source in sorted(selected, key=lambda item: item.role != SourceRole.ENRICHMENT):
            state = self.storage.load_state(source.id)
            states[source.id] = state
            try:
                result = await self._collect_with_fallbacks(source, state, since)
                results[source.id] = result
                self._validate_volume(source, state, result)
                state.etag = result.etag or state.etag
                state.last_modified = result.last_modified or state.last_modified
                state.last_success_at = datetime.now(UTC)
                state.consecutive_failures = 0
                if not result.not_modified:
                    state.item_count = len(result.records)
                self.storage.write_state(state)
            except Exception as exc:
                state.last_failure_at = datetime.now(UTC)
                state.consecutive_failures += 1
                self.storage.write_state(state)
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

        for source in selected:
            if source.role != SourceRole.ADVISORY:
                continue
            selected_result = results.get(source.id)
            if selected_result is None or selected_result.not_modified:
                continue
            current_ids: list[str] = []
            parsed_count = 0
            for raw in selected_result.records:
                try:
                    draft = parse_record(source, raw)
                except Exception as exc:
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
            if parsed_count == 0:
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
                continue
            self._handle_missing(source, states[source.id], current_ids, manifest)
            states[source.id].known_ids = sorted(current_ids)
            self.storage.write_state(states[source.id])

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
    ) -> CollectionResult:
        assert source.collector is not None
        errors: list[str] = []
        for kind in [source.collector, *source.fallback_collectors]:
            try:
                return await create_collector(kind).collect(source, state, since)
            except CollectorError as exc:
                errors.append(f"{kind}: {exc}")
        raise CollectorError("; ".join(errors))

    @staticmethod
    def _validate_volume(
        source: SourceDefinition,
        state: SourceState,
        result: CollectionResult,
    ) -> None:
        if result.not_modified:
            return
        count = len(result.records)
        if count == 0:
            raise CollectorError(f"{source.id}: HTTP success with zero records")
        if state.item_count >= 20 and count <= state.item_count * 0.15:
            raise CollectorError(f"{source.id}: item count dropped by at least 85%")
        if source.role == SourceRole.ADVISORY and (
            count > 1000 or (state.item_count and count > state.item_count * 10)
        ):
            raise CollectorError(f"{source.id}: anomalous new item volume")

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
        for change in manifest.changes:
            counts[change.status] = counts.get(change.status, 0) + 1
            priorities[change.priority] = priorities.get(change.priority, 0) + 1
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
        ]
        (self.output_root / "run-summary.md").write_text("\n".join(lines), encoding="utf-8")

    @staticmethod
    def _aware(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
