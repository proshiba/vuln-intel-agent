from __future__ import annotations

import csv
from datetime import UTC, datetime
from pathlib import Path

import pytest
from ruamel.yaml import YAML

from vulnwatch.models import AdvisoryEnrichment, AdvisoryFacts, AdvisoryStatus
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
        enrichment=AdvisoryEnrichment(cisa_kev=True),
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
