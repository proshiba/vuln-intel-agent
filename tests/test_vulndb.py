from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from vulnwatch.models import (
    AdvisoryEnrichment,
    AdvisoryFacts,
    AdvisoryStatus,
    ExploitationReport,
    KevEntry,
    SurfaceReach,
)
from vulnwatch.vulndb import VulnDb, VulnRecord, validate_vulndb

NOW = datetime(2026, 7, 18, 9, 0, tzinfo=UTC)
LATER = datetime(2026, 7, 19, 9, 0, tzinfo=UTC)


def _read_entry(root: Path, vuln_id: str) -> VulnRecord:
    yaml = YAML(typ="safe")
    matches = list((root / "vulndb" / "vulns").rglob(f"{vuln_id}.yaml"))
    assert matches, f"vulndb entry not found: {vuln_id}"
    return VulnRecord.model_validate(yaml.load(matches[0].read_text(encoding="utf-8")))


def _read_csv(root: Path) -> list[dict[str, str]]:
    with (root / "vulndb" / "index.csv").open(encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _kev_enrichment(
    cve: str,
    *,
    date_added: datetime | None = None,
    ransomware: bool = False,
    surface: str | None = None,
) -> AdvisoryEnrichment:
    """KEV に載っている CVE を1件持つ enrichment。

    台帳は CVE ごとに掲載可否を見るため、集約値だけでは何も起きない。
    """

    entry = KevEntry(date_added=date_added, ransomware=ransomware)
    return AdvisoryEnrichment(
        cisa_kev=True,
        kev_date_added=date_added,
        kev_ransomware=ransomware,
        kev_entries={cve: entry},
        # 収集時にパイプラインが付ける分類。優先度の判定はこれを見る。
        attack_surface_class=surface,
        attack_surface_reach=SurfaceReach.NETWORK_PIVOT if surface else None,
    )


def test_advisory_with_cve_creates_entry_csv_and_yaml(tmp_path: Path, advisory_factory) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.cve == "CVE-2026-12345"
    assert entry.vendors == ["Example"]
    assert entry.sources[0].canonical_id == "example:ADV-1"
    rows = _read_csv(tmp_path)
    assert rows[0]["vuln_id"] == "VW-2026-0001"
    assert rows[0]["cve"] == "CVE-2026-12345"
    assert validate_vulndb(tmp_path) == 1


def test_sequence_grows_beyond_four_digits(tmp_path: Path, advisory_factory) -> None:
    db = VulnDb(tmp_path)
    db.registry.sequences["2026"] = 9998
    first = advisory_factory()
    second = advisory_factory(
        canonical_id="example:ADV-2",
        vendor_advisory_id="ADV-2",
        source_url="https://security.example/ADV-2",
        facts=AdvisoryFacts(cves=["CVE-2026-12346"]),
    )
    db.apply([first, second], NOW)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-10000")
    assert entry.cve == "CVE-2026-12346"
    assert [row["vuln_id"] for row in _read_csv(tmp_path)] == [
        "VW-2026-9999",
        "VW-2026-10000",
    ]
    assert VulnDb(tmp_path).load_entry("VW-2026-10000") == entry
    assert validate_vulndb(tmp_path) == 2


def test_multi_cve_advisory_creates_one_entry_per_cve(tmp_path: Path, advisory_factory) -> None:
    advisory = advisory_factory(facts=AdvisoryFacts(cves=["CVE-2026-11111", "CVE-2026-22222"]))
    db = VulnDb(tmp_path)
    db.apply([advisory], NOW)
    db.write()

    rows = _read_csv(tmp_path)
    assert [row["cve"] for row in rows] == ["CVE-2026-11111", "CVE-2026-22222"]
    assert validate_vulndb(tmp_path) == 2


def test_cve_less_advisory_gets_internal_id_then_cve_attaches(
    tmp_path: Path, advisory_factory
) -> None:
    zero_day = advisory_factory(facts=AdvisoryFacts(products=["Example OS"]))
    db = VulnDb(tmp_path)
    db.apply([zero_day], NOW)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.cve is None
    assert entry.cve_assigned_at is None

    updated = advisory_factory(facts=AdvisoryFacts(cves=["CVE-2026-99999"]))
    db = VulnDb(tmp_path)
    db.apply([updated], LATER)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.cve == "CVE-2026-99999"
    assert entry.cve_assigned_at == LATER
    assert not list((tmp_path / "vulndb" / "vulns").rglob("VW-2026-0002.yaml"))
    assert validate_vulndb(tmp_path) == 1


def test_same_cve_from_two_vendors_merges_into_one_entry(tmp_path: Path, advisory_factory) -> None:
    first = advisory_factory()
    second = advisory_factory(
        canonical_id="other:ADV-9",
        source_id="other",
        vendor="Other",
        vendor_advisory_id="ADV-9",
        source_url="https://security.other.example/ADV-9",
        published_at=datetime(2026, 6, 1, tzinfo=UTC),
        facts=AdvisoryFacts(cves=["CVE-2026-12345"], fixed_versions=["2.0.1"]),
    )
    db = VulnDb(tmp_path)
    db.apply([first, second], NOW)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.vendors == ["Example", "Other"]
    assert {source.canonical_id for source in entry.sources} == {"example:ADV-1", "other:ADV-9"}
    assert entry.published_at == datetime(2026, 6, 1, tzinfo=UTC)
    assert entry.fixed is True
    assert entry.fixed_versions == ["2.0.1"]
    assert validate_vulndb(tmp_path) == 1


def test_exploitation_and_poc_flags_are_sticky_with_observed_dates(
    tmp_path: Path, advisory_factory
) -> None:
    exploited = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"], known_exploited=True, poc_public=True),
        enrichment=_kev_enrichment("CVE-2026-12345"),
    )
    db = VulnDb(tmp_path)
    db.apply([exploited], NOW)
    db.write()

    calmed = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"], known_exploited=False, poc_public=False),
    )
    db = VulnDb(tmp_path)
    db.apply([calmed], LATER)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.known_exploited is True
    assert entry.exploitation_observed_at == NOW
    assert entry.poc_public is True
    assert entry.poc_observed_at == NOW
    assert entry.cisa_kev is True


def test_kev_lag_records_how_early_a_vendor_signal_beat_the_kev_listing(
    tmp_path: Path, advisory_factory
) -> None:
    # A vendor advisory states exploitation on NOW; CISA lists the CVE six days later.
    vendor_signal = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"], known_exploited=True)
    )
    db = VulnDb(tmp_path)
    db.apply([vendor_signal], NOW)
    db.write()

    listed = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"]),
        enrichment=_kev_enrichment(
            "CVE-2026-12345", date_added=datetime(2026, 7, 24, tzinfo=UTC), ransomware=True
        ),
    )
    db = VulnDb(tmp_path)
    db.apply([listed], LATER)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.exploitation_source == "example"
    assert entry.exploitation_observed_at == NOW
    assert entry.kev_listed_at == datetime(2026, 7, 24, tzinfo=UTC)
    assert entry.kev_lag_days == 6
    assert entry.ransomware_use is True
    assert _read_csv(tmp_path)[0]["kev_lag_days"] == "6"


def test_kev_sourced_exploitation_claims_no_lag(tmp_path: Path, advisory_factory) -> None:
    # Exploitation established by KEV itself must never be credited as an early signal,
    # even though the historical listing date precedes the observation.
    listed = advisory_factory(
        enrichment=_kev_enrichment("CVE-2026-12345", date_added=datetime(2021, 5, 1, tzinfo=UTC)),
    )
    db = VulnDb(tmp_path)
    db.apply([listed], NOW)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.known_exploited is True
    assert entry.exploitation_source == "cisa_kev"
    assert entry.kev_lag_days is None
    assert _read_csv(tmp_path)[0]["kev_lag_days"] == ""


def test_kev_listing_before_our_observation_reports_no_lag(
    tmp_path: Path, advisory_factory
) -> None:
    # A vendor signal seen after CISA already listed the CVE is not an early warning.
    vendor_signal = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"], known_exploited=True)
    )
    db = VulnDb(tmp_path)
    db.apply([vendor_signal], NOW)
    db.write()

    listed = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"]),
        enrichment=_kev_enrichment("CVE-2026-12345", date_added=datetime(2026, 7, 1, tzinfo=UTC)),
    )
    db = VulnDb(tmp_path)
    db.apply([listed], LATER)
    db.write()

    assert _read_entry(tmp_path, "VW-2026-0001").kev_lag_days is None


def _report(cve: str, source_id: str, *, at: datetime, url: str | None = None):
    return ExploitationReport(
        cve=cve,
        source_id=source_id,
        url=url or f"https://{source_id}.example/post",
        evidence=f"{cve} is actively exploited.",
        observed_at=at,
    )


def test_single_osint_report_is_recorded_without_claiming_exploitation(
    tmp_path: Path, advisory_factory
) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    recorded, promoted = db.apply_exploitation_reports(
        [_report("CVE-2026-12345", "greynoise_blog", at=NOW)], NOW
    )
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert (recorded, promoted) == (1, 0)
    assert len(entry.exploitation_reports) == 1
    # A lone blog post must never set the irreversible exploitation flag.
    assert entry.known_exploited is False
    assert _read_csv(tmp_path)[0]["exploitation_report_count"] == "1"


def test_two_independent_osint_reports_promote_to_known_exploitation(
    tmp_path: Path, advisory_factory
) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    recorded, promoted = db.apply_exploitation_reports(
        [
            _report("CVE-2026-12345", "greynoise_blog", at=LATER),
            _report("CVE-2026-12345", "huntress_blog", at=NOW),
        ],
        LATER,
    )
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert (recorded, promoted) == (2, 1)
    assert entry.known_exploited is True
    assert entry.exploitation_source == "osint"
    # The earliest report date is what beats a later KEV listing.
    assert entry.exploitation_observed_at == NOW
    assert _read_csv(tmp_path)[0]["exploitation_report_sources"] == "greynoise_blog;huntress_blog"


def test_repeated_reports_from_one_source_never_promote(tmp_path: Path, advisory_factory) -> None:
    # One outlet republishing the same claim is not corroboration.
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    db.apply_exploitation_reports(
        [
            _report("CVE-2026-12345", "greynoise_blog", at=NOW, url="https://g.example/a"),
            _report("CVE-2026-12345", "greynoise_blog", at=LATER, url="https://g.example/b"),
        ],
        LATER,
    )
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert len(entry.exploitation_reports) == 2
    assert entry.known_exploited is False


def test_duplicate_report_is_not_recorded_twice(tmp_path: Path, advisory_factory) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    db.apply_exploitation_reports([_report("CVE-2026-12345", "greynoise_blog", at=NOW)], NOW)
    recorded, _ = db.apply_exploitation_reports(
        [_report("CVE-2026-12345", "greynoise_blog", at=LATER)], LATER
    )
    db.write()

    assert recorded == 0
    assert len(_read_entry(tmp_path, "VW-2026-0001").exploitation_reports) == 1


def test_reports_for_unknown_cves_are_ignored(tmp_path: Path, advisory_factory) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    recorded, promoted = db.apply_exploitation_reports(
        [_report("CVE-2026-00000", "greynoise_blog", at=NOW)], NOW
    )

    assert (recorded, promoted) == (0, 0)


def test_osint_promotion_can_beat_a_later_kev_listing(tmp_path: Path, advisory_factory) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    db.apply_exploitation_reports(
        [
            _report("CVE-2026-12345", "greynoise_blog", at=NOW),
            _report("CVE-2026-12345", "huntress_blog", at=NOW),
        ],
        NOW,
    )
    db.write()

    listed = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"]),
        enrichment=_kev_enrichment("CVE-2026-12345", date_added=datetime(2026, 7, 24, tzinfo=UTC)),
    )
    db = VulnDb(tmp_path)
    db.apply([listed], LATER)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.exploitation_source == "osint"
    assert entry.kev_lag_days == 6


def test_withdrawn_only_when_all_sources_withdraw(tmp_path: Path, advisory_factory) -> None:
    first = advisory_factory()
    second = advisory_factory(
        canonical_id="other:ADV-9",
        source_id="other",
        vendor="Other",
        source_url="https://security.other.example/ADV-9",
    )
    db = VulnDb(tmp_path)
    db.apply([first, second], NOW)
    db.write()

    db = VulnDb(tmp_path)
    db.apply([first.model_copy(update={"status": AdvisoryStatus.WITHDRAWN})], LATER)
    db.write()
    assert _read_entry(tmp_path, "VW-2026-0001").status == AdvisoryStatus.ACTIVE

    db = VulnDb(tmp_path)
    db.apply([second.model_copy(update={"status": AdvisoryStatus.WITHDRAWN})], LATER)
    db.write()
    assert _read_entry(tmp_path, "VW-2026-0001").status == AdvisoryStatus.WITHDRAWN


def test_leftover_internal_entry_is_superseded_when_cve_resolves_elsewhere(
    tmp_path: Path, advisory_factory
) -> None:
    other = advisory_factory(
        canonical_id="other:ADV-9",
        source_id="other",
        vendor="Other",
        source_url="https://security.other.example/ADV-9",
        published_at=datetime(2026, 6, 1, tzinfo=UTC),
    )
    zero_day = advisory_factory(facts=AdvisoryFacts())
    db = VulnDb(tmp_path)
    db.apply([other, zero_day], NOW)
    db.write()

    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], LATER)
    db.write()

    superseded = _read_entry(tmp_path, "VW-2026-0002")
    assert superseded.superseded_by == "VW-2026-0001"
    canonical = _read_entry(tmp_path, "VW-2026-0001")
    assert "example:ADV-1" in {source.canonical_id for source in canonical.sources}
    assert validate_vulndb(tmp_path) == 2


def test_entries_are_partitioned_by_vendor_year_month(tmp_path: Path, advisory_factory) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    db.write()

    expected = tmp_path / "vulndb" / "vulns" / "example" / "2026" / "07" / "VW-2026-0001.yaml"
    assert expected.is_file()
    assert not (tmp_path / "vulndb" / "vulns" / "VW-2026-0001.yaml").exists()
    assert validate_vulndb(tmp_path) == 1


def test_flat_entries_are_migrated_to_partitioned_layout(tmp_path: Path, advisory_factory) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    db.write()
    nested = next((tmp_path / "vulndb" / "vulns").rglob("VW-2026-0001.yaml"))
    flat = tmp_path / "vulndb" / "vulns" / "VW-2026-0001.yaml"
    nested.rename(flat)

    VulnDb(tmp_path).write()

    assert not flat.exists()
    migrated = tmp_path / "vulndb" / "vulns" / "example" / "2026" / "07" / "VW-2026-0001.yaml"
    assert migrated.is_file()
    assert validate_vulndb(tmp_path) == 1


def test_validate_vulndb_rejects_mismatched_file_name(tmp_path: Path, advisory_factory) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory()], NOW)
    db.write()
    original = next((tmp_path / "vulndb" / "vulns").rglob("VW-2026-0001.yaml"))
    original.rename(original.with_name("VW-2026-9999.yaml"))

    with pytest.raises(ValueError, match="does not match its file name"):
        validate_vulndb(tmp_path)


def test_validate_vulndb_passes_when_absent(tmp_path: Path) -> None:
    assert validate_vulndb(tmp_path) == 0


def test_a_kev_listing_does_not_spread_to_other_cves_in_the_same_advisory(
    tmp_path: Path, advisory_factory
) -> None:
    # 1本の RHSA が数十の CVE をまとめて扱うため、アドバイザリ単位で KEV を配ると
    # 同居しているだけの無関係な CVE まで「悪用確認済み」になる。実際に台帳の
    # cisa_kev のうち 87% がこれで誤っていた。
    advisory = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-11111", "CVE-2026-22222"]),
        enrichment=_kev_enrichment("CVE-2026-11111", date_added=datetime(2026, 7, 1, tzinfo=UTC)),
    )
    db = VulnDb(tmp_path)
    db.apply([advisory], NOW)
    db.write()

    by_cve = {row["cve"]: row for row in _read_csv(tmp_path)}
    assert by_cve["CVE-2026-11111"]["cisa_kev"] == "true"
    assert by_cve["CVE-2026-11111"]["known_exploited"] == "true"
    assert by_cve["CVE-2026-22222"]["cisa_kev"] == "false"
    assert by_cve["CVE-2026-22222"]["known_exploited"] == "false"


def test_reconcile_clears_a_listing_that_is_no_longer_in_the_catalogue(
    tmp_path: Path, advisory_factory
) -> None:
    # 誤って付いたフラグは、そのエントリが再び更新されるまで残り続ける。毎回
    # カタログと突き合わせないと、過去の誤りは自力では消えない。
    advisory = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"]),
        enrichment=_kev_enrichment("CVE-2026-12345", date_added=NOW, ransomware=True),
    )
    db = VulnDb(tmp_path)
    db.apply([advisory], NOW)
    db.write()

    db = VulnDb(tmp_path)
    added, removed = db.reconcile_kev({}, LATER)
    db.write()

    assert (added, removed) == (0, 1)
    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.cisa_kev is False
    assert entry.kev_listed_at is None
    assert entry.ransomware_use is False
    assert entry.known_exploited is False


def test_reconcile_keeps_exploitation_a_vendor_reported_independently(
    tmp_path: Path, advisory_factory
) -> None:
    # KEV から外れても、ベンダー自身が悪用を報告していた事実は消えない。
    advisory = advisory_factory(
        facts=AdvisoryFacts(cves=["CVE-2026-12345"], known_exploited=True),
        enrichment=_kev_enrichment("CVE-2026-12345", date_added=NOW),
    )
    db = VulnDb(tmp_path)
    db.apply([advisory], NOW)
    db.write()

    db = VulnDb(tmp_path)
    db.reconcile_kev({}, LATER)
    db.write()

    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.cisa_kev is False
    assert entry.known_exploited is True
    assert entry.exploitation_source == "example"


def test_reconcile_adds_a_listing_that_appeared_after_the_entry_was_written(
    tmp_path: Path, advisory_factory
) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory(facts=AdvisoryFacts(cves=["CVE-2026-12345"]))], NOW)
    db.write()

    db = VulnDb(tmp_path)
    added, removed = db.reconcile_kev(
        {"CVE-2026-12345": KevEntry(date_added=LATER, ransomware=True)}, LATER
    )
    db.write()

    assert (added, removed) == (1, 0)
    entry = _read_entry(tmp_path, "VW-2026-0001")
    assert entry.cisa_kev is True
    assert entry.ransomware_use is True
    assert entry.exploitation_source == "cisa_kev"


def test_priority_is_not_inherited_from_another_cve_in_the_same_advisory(
    tmp_path: Path, advisory_factory
) -> None:
    # KEV 掲載を根拠に P1 が付くのは、掲載されている CVE 自身に対してだけ。
    advisory = advisory_factory(
        vendor="Ivanti",
        facts=AdvisoryFacts(cves=["CVE-2026-11111", "CVE-2026-22222"], products=["Connect Secure"]),
        enrichment=_kev_enrichment("CVE-2026-11111", date_added=NOW, surface="vpn_gateway"),
    )
    db = VulnDb(tmp_path)
    db.apply([advisory], NOW)
    db.write()

    by_cve = {row["cve"]: row for row in _read_csv(tmp_path)}
    assert by_cve["CVE-2026-11111"]["priority"] == "P1"
    assert by_cve["CVE-2026-22222"]["priority"] != "P1"


def test_reconcile_lowers_a_priority_that_only_the_bad_kev_flag_justified(
    tmp_path: Path, advisory_factory
) -> None:
    # _merge は優先度を上げる方向にしか動かないため、誤って付いた P1 は
    # 突き合わせで下げないと二度と下がらない。
    advisory = advisory_factory(
        vendor="Ivanti",
        facts=AdvisoryFacts(cves=["CVE-2026-12345"], products=["Connect Secure"]),
        enrichment=_kev_enrichment("CVE-2026-12345", date_added=NOW, surface="vpn_gateway"),
    )
    db = VulnDb(tmp_path)
    db.apply([advisory], NOW)
    db.write()
    assert _read_csv(tmp_path)[0]["priority"] == "P1"

    db = VulnDb(tmp_path)
    db.reconcile_kev({}, LATER)
    db.write()

    assert _read_csv(tmp_path)[0]["priority"] != "P1"


def test_only_a_single_cve_advisory_supplies_the_cvss_vector(
    tmp_path: Path, advisory_factory
) -> None:
    # 数十のCVEをまとめたアドバイザリのベクタは、そのうちどのCVEのものか分からない。
    # 初期アクセス判定の根拠にするには出所が確定している必要がある。
    ambiguous = advisory_factory(
        canonical_id="example:many",
        facts=AdvisoryFacts(
            cves=["CVE-2026-11111", "CVE-2026-22222"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    )
    db = VulnDb(tmp_path)
    db.apply([ambiguous], NOW)
    db.write()
    assert all(row["cvss_vector"] == "" for row in _read_csv(tmp_path))

    definite = advisory_factory(
        canonical_id="example:one",
        facts=AdvisoryFacts(
            cves=["CVE-2026-11111"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    )
    db = VulnDb(tmp_path)
    db.apply([definite], LATER)
    db.write()

    by_cve = {row["cve"]: row for row in _read_csv(tmp_path)}
    assert by_cve["CVE-2026-11111"]["cvss_vector"].startswith("CVSS:3.1/AV:N")
    assert by_cve["CVE-2026-22222"]["cvss_vector"] == ""


def test_the_initial_access_tag_needs_both_an_exposed_product_and_a_usable_flaw(
    tmp_path: Path, advisory_factory
) -> None:
    entry_point = advisory_factory(
        canonical_id="example:vpn",
        vendor="Ivanti",
        facts=AdvisoryFacts(
            cves=["CVE-2026-11111"],
            products=["Connect Secure"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    )
    # 同じ攻撃条件でも、外部公開されやすい製品でなければ付かない。
    internal = advisory_factory(
        canonical_id="example:lib",
        facts=AdvisoryFacts(
            cves=["CVE-2026-22222"],
            products=["Example Library"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    )
    db = VulnDb(tmp_path)
    db.apply([entry_point, internal], NOW)
    db.write()

    by_cve = {row["cve"]: row for row in _read_csv(tmp_path)}
    assert by_cve["CVE-2026-11111"]["potential_initial_access"] == "true"
    assert by_cve["CVE-2026-22222"]["potential_initial_access"] == "false"


def test_backfill_fills_vectors_for_entries_written_before_the_column_existed(
    tmp_path: Path, advisory_factory
) -> None:
    db = VulnDb(tmp_path)
    db.apply([advisory_factory(facts=AdvisoryFacts(cves=["CVE-2026-12345"]))], NOW)
    db.write()
    assert _read_csv(tmp_path)[0]["cvss_vector"] == ""

    db = VulnDb(tmp_path)
    filled = db.backfill_from_advisories({"CVE-2026-12345": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N"}, set())
    db.write()

    assert filled == 1
    assert _read_csv(tmp_path)[0]["cvss_vector"].startswith("CVSS:3.1")
    # 2回目は何もしない。収集で入った値を上書きしないため。
    db = VulnDb(tmp_path)
    assert (
        db.backfill_from_advisories({"CVE-2026-12345": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R"}, set()) == 0
    )


def test_the_tag_is_not_derived_from_the_merged_vendor_and_product_lists(
    tmp_path: Path, advisory_factory
) -> None:
    # 同じCVEを複数ベンダーが扱うと、台帳の vendors/products は平坦に統合され
    # 「どのベンダーのどの製品か」の対応が失われる。そこから分類し直すと、
    # ライブラリの不具合が VPN 機器の脆弱性として扱われる。
    library = advisory_factory(
        canonical_id="example:lib",
        facts=AdvisoryFacts(
            cves=["CVE-2026-11111"],
            products=["axios"],
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        ),
    )
    # 同じCVEを、VPN機器のベンダーが自製品の同梱ライブラリとして報告する。
    bundled = advisory_factory(
        canonical_id="example:vendor",
        vendor="Ivanti",
        facts=AdvisoryFacts(cves=["CVE-2026-11111"], products=["Connect Secure"]),
    )
    db = VulnDb(tmp_path)
    db.apply([library, bundled], NOW)
    db.write()

    row = _read_csv(tmp_path)[0]
    # 統合後の一覧には Ivanti と Connect Secure が入るが、攻撃条件を伴う
    # アドバイザリはライブラリ側なので、タグは付かない。
    assert "Ivanti" in row["vendors"]
    assert row["potential_initial_access"] == "false"
