from __future__ import annotations

import pytest

from vulnwatch.initial_access import TAG, is_entry_point, is_potential_initial_access

UNAUTH_RCE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


def test_tag_name_is_stable() -> None:
    # ポータルや外部の絞り込みが文字列で参照するため、勝手に変えない。
    assert TAG == "potential-initial-access"


def test_an_unauthenticated_remote_flaw_on_an_exposed_product_is_tagged() -> None:
    assert is_potential_initial_access("vpn_gateway", UNAUTH_RCE) is True


def test_a_product_that_is_not_an_exposed_surface_is_never_tagged() -> None:
    # 認証不要のRCEでも、外に出ていない製品なら侵入の起点にはならない。
    assert is_potential_initial_access(None, UNAUTH_RCE) is False
    assert is_potential_initial_access("", UNAUTH_RCE) is False


@pytest.mark.parametrize(
    ("vector", "why"),
    [
        ("CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "ローカルからしか届かない"),
        ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "先に権限が要る"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H", "利用者の操作が要る"),
        ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L", "攻撃者の制御外の条件が要る"),
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", "可用性だけへの影響（DoS）"),
    ],
)
def test_flaws_that_cannot_be_the_way_in_are_excluded(vector: str, why: str) -> None:
    assert is_potential_initial_access("vpn_gateway", vector) is False, why


def test_a_gadget_that_needs_another_bug_first_is_excluded() -> None:
    # CVE-2026-44495（axios のプロトタイプ汚染ガジェット）の実際のベクタ。単独では
    # 悪用できず、別の脆弱性が先に必要。これが AC:H を条件に入れている理由。
    assert (
        is_potential_initial_access(
            "webmail_collab", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:L/A:L"
        )
        is False
    )


def test_falls_back_to_the_collected_flags_when_there_is_no_vector() -> None:
    # ベクタを出さない収集元があるため、代替の判定を残す。
    assert is_entry_point(None, remote=True, authentication_required=False) is True
    assert is_entry_point(None, remote=True, authentication_required=True) is False
    assert is_entry_point(None, remote=False, authentication_required=False) is False


def test_nothing_is_assumed_when_there_is_no_evidence() -> None:
    # 判定材料が無いものを初期アクセス扱いすると、重視すべき対象がぼやける。
    assert is_entry_point(None) is False
    assert is_potential_initial_access("vpn_gateway", None) is False


def test_a_malformed_vector_falls_back_instead_of_crashing() -> None:
    assert is_entry_point("not-a-vector", remote=True, authentication_required=False) is True
    assert is_entry_point("not-a-vector") is False
