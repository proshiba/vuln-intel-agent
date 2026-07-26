from __future__ import annotations

from pathlib import Path

from vulnwatch.webapi import build_meta, encode_prefixes, scan_entry_prefixes


def _entry(root: Path, prefix: str, vuln_id: str) -> None:
    path = root / prefix / f"{vuln_id}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"vuln_id: {vuln_id}\n", encoding="utf-8")


def test_scan_maps_entries_to_their_vendor_year_month(tmp_path: Path) -> None:
    _entry(tmp_path, "ivanti/2026/07", "VW-2026-0001")
    _entry(tmp_path, "microsoft/2025/12", "VW-2025-0009")

    assert scan_entry_prefixes(tmp_path) == {
        "VW-2026-0001": "ivanti/2026/07",
        "VW-2025-0009": "microsoft/2025/12",
    }


def test_scan_skips_flat_legacy_entries(tmp_path: Path) -> None:
    # A pre-migration entry sitting directly under vulns/ has no vendor/year/month to
    # build a detail URL from, so it must not appear with a bogus prefix.
    (tmp_path / "VW-2020-0001.yaml").parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / "VW-2020-0001.yaml").write_text("vuln_id: VW-2020-0001\n", encoding="utf-8")
    _entry(tmp_path, "ivanti/2026/07", "VW-2026-0001")

    assert scan_entry_prefixes(tmp_path) == {"VW-2026-0001": "ivanti/2026/07"}


def test_scan_returns_empty_when_ledger_absent(tmp_path: Path) -> None:
    assert scan_entry_prefixes(tmp_path / "missing") == {}


def test_prefixes_are_dictionary_encoded_and_reusable() -> None:
    prefixes = {
        "VW-2026-0001": "ivanti/2026/07",
        "VW-2026-0002": "ivanti/2026/07",
        "VW-2026-0003": "cisco/2026/07",
    }

    dictionary, encoded = encode_prefixes(
        ["VW-2026-0001", "VW-2026-0002", "VW-2026-0003"], prefixes
    )

    # The repeated prefix is stored once and referenced by index.
    assert dictionary == ["ivanti/2026/07", "cisco/2026/07"]
    assert encoded == [0, 0, 1]


def test_unknown_entries_encode_to_a_sentinel() -> None:
    dictionary, encoded = encode_prefixes(["VW-2026-0001"], {})

    assert dictionary == []
    assert encoded == [-1]


def test_meta_exposes_a_usable_detail_url_template() -> None:
    meta = build_meta(
        generated_at="2026-07-26T00:00:00+00:00",
        repository="proshiba/vuln-intel-agent",
        site_url="https://proshiba.github.io/vuln-intel-agent/",
        ref="main",
        stats={"total": 3},
        fields=["id", "cve"],
        flags={"kev": 8},
        attack_surfaces={"vpn_gateway": "VPN/リモートアクセス"},
    )

    template = meta["endpoints"]["detail_url_template"]
    resolved = template.format(prefix="ivanti/2026/07", vuln_id="VW-2026-0001")
    assert resolved == (
        "https://raw.githubusercontent.com/proshiba/vuln-intel-agent/main/"
        "vulndb/vulns/ivanti/2026/07/VW-2026-0001.yaml"
    )
    assert meta["endpoints"]["search"] == "api/v1/search.json"
    # Integrators (including agents) must be able to find the guide from meta alone.
    assert meta["endpoints"]["documentation"] == "INTEGRATION.md"
    assert meta["endpoints"]["openapi"] == "openapi.yaml"
    assert meta["cors"] is True
    assert meta["stats"]["total"] == 3
