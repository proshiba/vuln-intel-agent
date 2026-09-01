from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from pathlib import Path

from pydantic import Field
from ruamel.yaml import YAML

from vulnwatch.attack_surface import classify as classify_attack_surface
from vulnwatch.attack_surface import default_classifier
from vulnwatch.identity import slugify
from vulnwatch.models import (
    Advisory,
    AdvisoryEnrichment,
    AdvisoryFacts,
    AdvisoryStatus,
    ExploitationReport,
    KevEntry,
    Priority,
    StrictModel,
)
from vulnwatch.priority import decide_priority
from vulnwatch.storage.filesystem import atomic_write_text, write_json

VULNDB_DIRECTORY = "vulndb"
_VULN_ID_PATTERN = r"^VW-\d{4}-\d{4,}$"
_PRIORITY_RANK = {Priority.P1: 0, Priority.P2: 1, Priority.P3: 2, Priority.INFO: 3}
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "important": 1,
    "medium": 2,
    "moderate": 2,
    "low": 3,
}
CSV_COLUMNS = (
    "vuln_id",
    "cve",
    "status",
    "vendors",
    "products",
    "title",
    "published_at",
    "fixed",
    "poc_public",
    "known_exploited",
    "exploitation_observed_at",
    "exploitation_source",
    "cisa_kev",
    "kev_listed_at",
    "kev_lag_days",
    "ransomware_use",
    "exploitation_report_count",
    "exploitation_report_sources",
    "attack_surface_class",
    "cvss_score",
    "vendor_severity",
    "priority",
    "sources",
    "superseded_by",
    "created_at",
    "updated_at",
)


def _vuln_id_sort_key(vuln_id: str) -> tuple[int, int]:
    """Sort internal IDs by numeric year and sequence, including 5+ digit sequences."""

    _, year, sequence = vuln_id.split("-", 2)
    return int(year), int(sequence)


class VulnSourceRef(StrictModel):
    canonical_id: str
    source_id: str
    vendor: str
    url: str
    status: AdvisoryStatus = AdvisoryStatus.ACTIVE
    first_seen_at: datetime
    last_seen_at: datetime


class VulnRecord(StrictModel):
    schema_version: int = 1
    vuln_id: str = Field(pattern=_VULN_ID_PATTERN)
    cve: str | None = None
    cve_assigned_at: datetime | None = None
    superseded_by: str | None = None
    title: str
    vendors: list[str] = Field(default_factory=list)
    products: list[str] = Field(default_factory=list)
    status: AdvisoryStatus = AdvisoryStatus.ACTIVE
    published_at: datetime | None = None
    fixed: bool = False
    fixed_versions: list[str] = Field(default_factory=list)
    fix_observed_at: datetime | None = None
    poc_public: bool = False
    poc_observed_at: datetime | None = None
    known_exploited: bool = False
    exploitation_observed_at: datetime | None = None
    # 最初に悪用確認を裏づけた出典（source_id、CISA KEV 由来なら "cisa_kev"）。
    exploitation_source: str | None = None
    cisa_kev: bool = False
    # CISA KEV の掲載日と、KEV 掲載より何日早く悪用を観測できたか。
    kev_listed_at: datetime | None = None
    kev_lag_days: int | None = None
    ransomware_use: bool = False
    # OSINT のリサーチ記事が報じた実悪用。悪用確認の候補であり、確定ではない。
    exploitation_reports: list[ExploitationReport] = Field(default_factory=list)
    cvss_score: float | None = None
    vendor_severity: str | None = None
    priority: Priority = Priority.INFO
    sources: list[VulnSourceRef] = Field(default_factory=list)
    created_at: datetime
    updated_at: datetime


class VulnRegistry(StrictModel):
    schema_version: int = 1
    sequences: dict[str, int] = Field(default_factory=dict)
    cve_index: dict[str, str] = Field(default_factory=dict)
    advisory_index: dict[str, list[str]] = Field(default_factory=dict)


def _priority_from_entry(record: VulnRecord) -> Priority:
    """台帳エントリ自身の事実から優先度を導き直す。

    `_merge` は優先度を上げる方向にしか動かさないため、誤って付いた P1 は
    そのままでは二度と下がらない。KEV の掲載状態を直したときは、ここで
    エントリの現状に合わせて付け直す。

    自組織資産との一致や攻撃経路はエントリに保持していないので加味できない。
    それらを根拠とする優先度は、次回そのエントリに触れる収集で `_merge` が
    上書きするため、ここで下げても失われない。
    """

    classifier = default_classifier()
    surface = classifier.classify(record.vendors, record.products)
    return decide_priority(
        AdvisoryFacts(
            known_exploited=record.known_exploited,
            poc_public=record.poc_public,
            cvss_score=record.cvss_score,
            vendor_severity=record.vendor_severity,
            fixed_versions=["fixed"] if record.fixed else [],
        ),
        AdvisoryEnrichment(
            cisa_kev=record.cisa_kev,
            attack_surface_class=surface,
            attack_surface_reach=classifier.reach_of(surface),
        ),
    ).priority


def _partition_vendor(record: VulnRecord) -> str:
    """フォルダ分けに使う代表ベンダー。最初の出典（採番時のベンダー）を用いる。"""

    if record.sources:
        return record.sources[0].vendor
    if record.vendors:
        return record.vendors[0]
    return "unknown"


def relative_entry_path(record: VulnRecord) -> Path:
    """脆弱性YAMLの相対パス: <ベンダー>/<年>/<月>/<vuln_id>.yaml。

    年・月は最初に観測したタイミング（created_at）を用いる。created_atは採番時に
    一度だけ設定され以後不変なので、ファイルの配置は恒久的に安定する。
    """

    observed = _aware(record.created_at)
    return (
        Path(slugify(_partition_vendor(record)))
        / f"{observed.year:04d}"
        / f"{observed.month:02d}"
        / f"{record.vuln_id}.yaml"
    )


class VulnDb:
    """CVE単位の脆弱性台帳。全体索引CSVと脆弱性ごとのYAMLを生成する。

    CVE未採番の脆弱性には内部ID（VW-YYYY-年内通番、4桁以上）を採番し、
    内部IDを恒久キーとして
    維持する。後からCVEが判明した場合はエントリのcveフィールドへ付与するだけで、
    ファイルの移動や統合は行わない。
    """

    def __init__(self, root: Path) -> None:
        self.root = root / VULNDB_DIRECTORY
        self.vulns_root = self.root / "vulns"
        self.registry_path = self.root / "registry.json"
        self.csv_path = self.root / "index.csv"
        self.registry = self._load_registry()
        self._entries: dict[str, VulnRecord] = {}
        self._dirty: set[str] = set()
        self._paths: dict[str, Path] = self._scan_paths()

    @property
    def initialized(self) -> bool:
        return self.registry_path.exists()

    def _load_registry(self) -> VulnRegistry:
        if not self.registry_path.exists():
            return VulnRegistry()
        return VulnRegistry.model_validate_json(self.registry_path.read_text(encoding="utf-8"))

    def _scan_paths(self) -> dict[str, Path]:
        """既存のYAML（新旧レイアウトを問わず）をvuln_id→パスで索引する。"""

        if not self.vulns_root.exists():
            return {}
        return {path.stem: path for path in self.vulns_root.rglob("*.yaml")}

    def desired_path(self, record: VulnRecord) -> Path:
        return self.vulns_root / relative_entry_path(record)

    def load_entry(self, vuln_id: str) -> VulnRecord | None:
        if vuln_id in self._entries:
            return self._entries[vuln_id]
        path = self._paths.get(vuln_id)
        if path is None or not path.exists():
            return None
        yaml = YAML(typ="safe")
        record = VulnRecord.model_validate(yaml.load(path.read_text(encoding="utf-8")))
        self._entries[vuln_id] = record
        return record

    def _allocate(self, published_at: datetime | None, now: datetime) -> str:
        year = (published_at or now).year
        key = str(year)
        sequence = self.registry.sequences.get(key, 0) + 1
        self.registry.sequences[key] = sequence
        return f"VW-{year}-{sequence:04d}"

    def apply(self, advisories: list[Advisory], now: datetime) -> None:
        """新規・更新・取り下げアドバイザリを台帳へ反映する。"""

        ordered = sorted(
            advisories,
            key=lambda item: (
                _aware(item.published_at or item.first_seen_at).isoformat(),
                item.canonical_id,
            ),
        )
        for advisory in ordered:
            self._apply_one(advisory, now)

    def _apply_one(self, advisory: Advisory, now: datetime) -> None:
        linked = self.registry.advisory_index.get(advisory.canonical_id, [])
        touched: list[str] = []
        if advisory.facts.cves:
            attachable = [
                vuln_id
                for vuln_id in linked
                if (entry := self.load_entry(vuln_id)) is not None
                and entry.cve is None
                and entry.superseded_by is None
            ]
            for cve in advisory.facts.cves:
                vuln_id = self.registry.cve_index.get(cve)
                if vuln_id is None and attachable:
                    # CVE未採番で登録済みのエントリへ、判明したCVEを付与する。
                    vuln_id = attachable.pop(0)
                    entry = self._entries[vuln_id]
                    entry.cve = cve
                    entry.cve_assigned_at = now
                    self.registry.cve_index[cve] = vuln_id
                elif vuln_id is None:
                    vuln_id = self._create(advisory, cve, now)
                entry = self.load_entry(vuln_id)
                if entry is None:
                    raise ValueError(f"vulndb registry maps {cve} to a missing entry: {vuln_id}")
                self._merge(entry, advisory, now)
                touched.append(vuln_id)
            # CVEが別エントリへ解決され、取り残された内部ID採番のみのエントリは
            # supersededとして記録する（ファイルの統合や削除はしない）。
            for vuln_id in attachable:
                entry = self._entries[vuln_id]
                entry.superseded_by = touched[0]
                entry.updated_at = now
                self._dirty.add(vuln_id)
                touched.append(vuln_id)
        else:
            active = [
                vuln_id
                for vuln_id in linked
                if (entry := self.load_entry(vuln_id)) is not None and entry.superseded_by is None
            ]
            if not active:
                active = [self._create(advisory, None, now)]
            for vuln_id in active:
                self._merge(self._entries[vuln_id], advisory, now)
                touched.append(vuln_id)
        merged = [*self.registry.advisory_index.get(advisory.canonical_id, [])]
        merged.extend(vuln_id for vuln_id in touched if vuln_id not in merged)
        self.registry.advisory_index[advisory.canonical_id] = merged

    def reconcile_kev(self, kev: dict[str, KevEntry], now: datetime) -> tuple[int, int]:
        """全エントリの KEV 掲載状態を、その日の KEV カタログと突き合わせて直す。

        掲載は CISA 側で増えることも取り下げられることもあり、過去に誤って付いた
        フラグは、そのエントリが再び更新されるまで残り続ける。索引CSVの書き出しで
        どのみち全エントリを読むので、ここで毎回まとめて整合させる。

        戻り値は (掲載として付け直した件数, 掲載でないとして外した件数)。
        """

        added = removed = 0
        for path in sorted(self.vulns_root.rglob("*.yaml")):
            entry = self.load_entry(path.stem)
            if entry is None or entry.cve is None:
                continue
            listed = kev.get(entry.cve)
            if listed is not None:
                if entry.cisa_kev and entry.kev_listed_at is not None:
                    continue
                entry.cisa_kev = True
                if listed.date_added is not None:
                    entry.kev_listed_at = _aware(listed.date_added)
                entry.ransomware_use = entry.ransomware_use or listed.ransomware
                if not entry.known_exploited:
                    entry.known_exploited = True
                    entry.exploitation_observed_at = now
                    entry.exploitation_source = "cisa_kev"
                added += 1
            elif entry.cisa_kev:
                entry.cisa_kev = False
                entry.kev_listed_at = None
                # ランサムウェア悪用は KEV だけが根拠なので、掲載でなければ外す。
                entry.ransomware_use = False
                # 悪用確認が KEV 由来だけだった場合は取り消す。ベンダーが独自に
                # 悪用を報告している場合（exploitation_source がソースID）は残す。
                if entry.exploitation_source in {None, "", "cisa_kev"}:
                    entry.known_exploited = False
                    entry.exploitation_observed_at = None
                    entry.exploitation_source = None
                removed += 1
            else:
                continue
            entry.kev_lag_days = _kev_lag_days(entry)
            entry.priority = _priority_from_entry(entry)
            entry.updated_at = now
            self._dirty.add(entry.vuln_id)
        return added, removed

    def apply_exploitation_reports(
        self, reports: list[ExploitationReport], now: datetime
    ) -> tuple[int, int]:
        """OSINT の実悪用報告を台帳へ反映し、(記録した報告数, 昇格した件数) を返す。

        報告は候補として蓄積するだけで、単独では確定した悪用フラグを立てない。独立した
        2 ソース以上が同じ CVE を報じた時点で、はじめて known_exploited へ昇格させる。
        単一ソースの誤読が、取り消せない悪用確認として台帳に残らないようにするため。
        台帳に存在しない CVE の報告は、対象を特定できないため無視する。
        """

        recorded = 0
        promoted = 0
        for report in reports:
            vuln_id = self.registry.cve_index.get(report.cve)
            entry = self.load_entry(vuln_id) if vuln_id else None
            if entry is None or entry.superseded_by is not None:
                continue
            if any(
                existing.source_id == report.source_id and existing.url == report.url
                for existing in entry.exploitation_reports
            ):
                continue
            entry.exploitation_reports.append(report)
            recorded += 1
            if not entry.known_exploited and _corroborated(entry):
                entry.known_exploited = True
                entry.exploitation_observed_at = _earliest_report_at(entry)
                entry.exploitation_source = "osint"
                entry.kev_lag_days = _kev_lag_days(entry)
                promoted += 1
            entry.updated_at = now
            self._dirty.add(entry.vuln_id)
        return recorded, promoted

    def _create(self, advisory: Advisory, cve: str | None, now: datetime) -> str:
        vuln_id = self._allocate(advisory.published_at, now)
        record = VulnRecord(
            vuln_id=vuln_id,
            cve=cve,
            cve_assigned_at=now if cve else None,
            title=advisory.title,
            created_at=now,
            updated_at=now,
        )
        self._entries[vuln_id] = record
        self._dirty.add(vuln_id)
        if cve:
            self.registry.cve_index[cve] = vuln_id
        return vuln_id

    def _merge(self, entry: VulnRecord, advisory: Advisory, now: datetime) -> None:
        facts = advisory.facts
        entry.vendors = sorted(set(entry.vendors) | {advisory.vendor})
        entry.products = sorted(set(entry.products) | set(facts.products))
        if advisory.published_at is not None:
            published = _aware(advisory.published_at)
            if entry.published_at is None or published < _aware(entry.published_at):
                entry.published_at = published
        if facts.fixed_versions:
            if not entry.fixed:
                entry.fixed = True
                entry.fix_observed_at = now
            entry.fixed_versions = sorted(set(entry.fixed_versions) | set(facts.fixed_versions))
        if facts.poc_public is True and not entry.poc_public:
            entry.poc_public = True
            entry.poc_observed_at = now
        if facts.known_exploited is True and not entry.known_exploited:
            entry.known_exploited = True
            entry.exploitation_observed_at = now
            entry.exploitation_source = advisory.source_id
        # KEV はこのエントリのCVE自身が掲載されている場合にのみ適用する。アドバイザリ
        # 単位の集約値を使うと、1本のRHSAが扱う他のCVEの掲載を、無関係なCVEまで
        # 引き継いでしまう。
        kev_entry = (
            advisory.enrichment.kev_entries.get(entry.cve) if entry.cve is not None else None
        )
        if kev_entry is not None:
            if not entry.known_exploited:
                entry.known_exploited = True
                entry.exploitation_observed_at = now
                entry.exploitation_source = "cisa_kev"
            entry.cisa_kev = True
            listed = kev_entry.date_added
            if listed is not None and (
                entry.kev_listed_at is None or _aware(listed) < _aware(entry.kev_listed_at)
            ):
                entry.kev_listed_at = _aware(listed)
            entry.ransomware_use = entry.ransomware_use or kev_entry.ransomware
        entry.kev_lag_days = _kev_lag_days(entry)
        if facts.cvss_score is not None and (
            entry.cvss_score is None or facts.cvss_score > entry.cvss_score
        ):
            entry.cvss_score = facts.cvss_score
        severity = (facts.vendor_severity or "").casefold()
        if severity in _SEVERITY_RANK and (
            entry.vendor_severity is None
            or _SEVERITY_RANK[severity] < _SEVERITY_RANK.get(entry.vendor_severity.casefold(), 9)
        ):
            entry.vendor_severity = facts.vendor_severity
        # 優先度もこのCVE自身のKEV状態で決め直す。アドバイザリの判定をそのまま使うと、
        # 同居している別CVEのKEV掲載を根拠にP1が付いてしまう。
        decision = decide_priority(
            facts,
            advisory.enrichment.model_copy(
                update={
                    "cisa_kev": kev_entry is not None,
                    "kev_ransomware": kev_entry.ransomware if kev_entry is not None else False,
                }
            ),
        )
        if _PRIORITY_RANK[decision.priority] < _PRIORITY_RANK[entry.priority]:
            entry.priority = decision.priority
        self._upsert_source(entry, advisory, now)
        if entry.sources and entry.sources[0].canonical_id == advisory.canonical_id:
            entry.title = advisory.title
        entry.status = (
            AdvisoryStatus.WITHDRAWN
            if entry.sources
            and all(source.status == AdvisoryStatus.WITHDRAWN for source in entry.sources)
            else AdvisoryStatus.ACTIVE
        )
        entry.updated_at = now
        self._dirty.add(entry.vuln_id)

    @staticmethod
    def _upsert_source(entry: VulnRecord, advisory: Advisory, now: datetime) -> None:
        for source in entry.sources:
            if source.canonical_id == advisory.canonical_id:
                source.status = advisory.status
                source.url = advisory.source_url
                source.last_seen_at = now
                return
        entry.sources.append(
            VulnSourceRef(
                canonical_id=advisory.canonical_id,
                source_id=advisory.source_id,
                vendor=advisory.vendor,
                url=advisory.source_url,
                status=advisory.status,
                first_seen_at=now,
                last_seen_at=now,
            )
        )

    def write(self) -> None:
        """registry、変更されたYAMLエントリ、全体索引CSVを書き出す。"""

        for vuln_id in sorted(self._dirty, key=_vuln_id_sort_key):
            self._write_entry(self._entries[vuln_id])
        self._migrate_flat_entries()
        write_json(self.registry_path, self.registry.model_dump(mode="json"))
        self._write_csv()
        self._dirty.clear()

    def _write_entry(self, record: VulnRecord) -> None:
        yaml = YAML(typ="safe")
        yaml.default_flow_style = False
        buffer = io.StringIO()
        yaml.dump(record.model_dump(mode="json", exclude_none=True), buffer)
        target = self.desired_path(record)
        atomic_write_text(target, buffer.getvalue())
        previous = self._paths.get(record.vuln_id)
        if previous is not None and previous != target and previous.exists():
            previous.unlink()
        self._paths[record.vuln_id] = target

    def _migrate_flat_entries(self) -> None:
        """旧レイアウト（vulns/直下のフラットなYAML）を新レイアウトへ移設する。"""

        if not self.vulns_root.exists():
            return
        yaml = YAML(typ="safe")
        for path in sorted(self.vulns_root.glob("*.yaml")):
            record = self._entries.get(path.stem)
            if record is None:
                record = VulnRecord.model_validate(yaml.load(path.read_text(encoding="utf-8")))
                self._entries[record.vuln_id] = record
            self._write_entry(record)

    def _write_csv(self) -> None:
        entries = [
            record
            for path in sorted(self.vulns_root.rglob("*.yaml"))
            if (record := self.load_entry(path.stem)) is not None
        ]
        buffer = io.StringIO()
        writer = csv.writer(buffer, lineterminator="\n")
        writer.writerow(CSV_COLUMNS)
        for record in sorted(entries, key=lambda item: _vuln_id_sort_key(item.vuln_id)):
            writer.writerow(
                [
                    record.vuln_id,
                    record.cve or "",
                    record.status,
                    ";".join(record.vendors),
                    ";".join(record.products),
                    record.title,
                    record.published_at.isoformat() if record.published_at else "",
                    _flag(record.fixed),
                    _flag(record.poc_public),
                    _flag(record.known_exploited),
                    record.exploitation_observed_at.isoformat()
                    if record.exploitation_observed_at
                    else "",
                    record.exploitation_source or "",
                    _flag(record.cisa_kev),
                    record.kev_listed_at.isoformat() if record.kev_listed_at else "",
                    record.kev_lag_days if record.kev_lag_days is not None else "",
                    _flag(record.ransomware_use),
                    len(record.exploitation_reports) or "",
                    ";".join(sorted({report.source_id for report in record.exploitation_reports})),
                    classify_attack_surface(record.vendors, record.products) or "",
                    record.cvss_score if record.cvss_score is not None else "",
                    record.vendor_severity or "",
                    record.priority,
                    ";".join(source.canonical_id for source in record.sources),
                    record.superseded_by or "",
                    record.created_at.isoformat(),
                    record.updated_at.isoformat(),
                ]
            )
        atomic_write_text(self.csv_path, buffer.getvalue())


def validate_vulndb(root: Path) -> int:
    """vulndbツリーの整合性を検証し、エントリ数を返す。"""

    base = root / VULNDB_DIRECTORY
    if not base.exists():
        return 0
    registry = VulnRegistry.model_validate_json(
        (base / "registry.json").read_text(encoding="utf-8")
    )
    yaml = YAML(typ="safe")
    vulns_root = base / "vulns"
    entries: dict[str, VulnRecord] = {}
    for path in sorted(vulns_root.rglob("*.yaml")):
        record = VulnRecord.model_validate(yaml.load(path.read_text(encoding="utf-8")))
        if record.vuln_id != path.stem:
            raise ValueError(f"vulndb entry ID does not match its file name: {path}")
        expected = relative_entry_path(record)
        if path.relative_to(vulns_root) != expected:
            raise ValueError(
                f"vulndb entry is in the wrong folder: {path.relative_to(vulns_root)} "
                f"(expected {expected})"
            )
        if record.cve and registry.cve_index.get(record.cve) != record.vuln_id:
            raise ValueError(f"vulndb registry does not index {record.cve} to {record.vuln_id}")
        entries[record.vuln_id] = record
    for cve, vuln_id in registry.cve_index.items():
        entry = entries.get(vuln_id)
        if entry is None or entry.cve != cve:
            raise ValueError(f"vulndb registry maps {cve} to a missing or mismatched entry")
    csv_path = base / "index.csv"
    if not csv_path.exists():
        raise ValueError("vulndb index.csv is missing")
    with csv_path.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.reader(handle))
    if not rows or tuple(rows[0]) != CSV_COLUMNS:
        raise ValueError("vulndb index.csv header is invalid")
    listed = {row[0] for row in rows[1:]}
    if listed != set(entries):
        raise ValueError("vulndb index.csv does not match the YAML entries")
    return len(entries)


_MIN_CORROBORATING_SOURCES = 2


def _corroborated(entry: VulnRecord) -> bool:
    """独立した複数ソースが同じ CVE の実悪用を報じていれば True。"""

    return (
        len({report.source_id for report in entry.exploitation_reports})
        >= _MIN_CORROBORATING_SOURCES
    )


def _earliest_report_at(entry: VulnRecord) -> datetime | None:
    """最も早い報告日時。KEV 掲載との差を測る基準に使う。"""

    stamps = [_aware(report.observed_at) for report in entry.exploitation_reports]
    return min(stamps) if stamps else None


def _kev_lag_days(entry: VulnRecord) -> int | None:
    """CISA KEV 掲載より何日早く悪用を観測できたかを返す。

    KEV 以外の出典（ベンダーの「悪用を確認」記述など）で先に悪用を観測できた場合にのみ、
    掲載日との差を日数で返す。KEV が先に掲載していた場合や、悪用確認そのものが KEV 由来の
    場合は、速報できたとは言えないため None を返す。既存データの初回取り込みでは観測日が
    実行日になり掲載日より後になるため、この条件により誤って速報扱いされることはない。
    """

    if entry.kev_listed_at is None or entry.exploitation_observed_at is None:
        return None
    if entry.exploitation_source in {None, "cisa_kev"}:
        return None
    # KEV の掲載日は日付単位のため、時刻を含めた差分では切り捨てで1日短く出る。
    # 暦日の差で数える。
    listed = _aware(entry.kev_listed_at).date()
    observed = _aware(entry.exploitation_observed_at).date()
    lag = (listed - observed).days
    return lag if lag > 0 else None


def _flag(value: bool) -> str:
    return "true" if value else "false"


def _aware(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
