"""初期アクセスに使われうる脆弱性の判定。

`attack_surface.py` が「その製品が外部公開されやすい面か」を見るのに対し、ここでは
「その脆弱性自体が侵入の起点になりうるか」を見る。両方が揃って初めて
`potential-initial-access` タグを付ける。

片方だけでは足りない。外部公開される製品に同梱されたHTTPクライアントライブラリの
不具合（実例: CVE-2026-44495）は、製品としては初期アクセス面に載るが、攻撃者が
外部から叩いて侵入できるものではない。逆に、認証不要のリモートコード実行でも、
利用者しかいない内部ツールなら侵入の起点にはならない。
"""

from __future__ import annotations

import re

TAG = "potential-initial-access"

_METRIC = re.compile(r"([A-Z]{1,2}):([A-Z])")


def _metrics(vector: str) -> dict[str, str]:
    return dict(_METRIC.findall(vector.upper()))


def is_entry_point(
    cvss_vector: str | None,
    remote: bool | None = None,
    authentication_required: bool | None = None,
) -> bool:
    """その脆弱性が、単体で侵入の起点になりうるか。

    CVSS ベクタがあればそれを使う。判定は次の全てを満たすこと。

    - `AV:N`   ネットワーク越しに届く
    - `PR:N`   事前の権限が要らない
    - `UI:N`   利用者の操作を必要としない
    - `AC:L`   攻撃者の制御外の条件を必要としない
    - `C` か `I` に影響がある

    最後の条件は、可用性だけに影響するもの（DoS）を除くため。サービスを止めても
    侵入の起点にはならない。実データでは 103 件がこれで外れた。

    `AC:L` は、別の脆弱性が先に必要なガジェット類を外すために要る。

    ベクタが無い場合は、収集元が個別に持つ「リモート」「認証不要」で代用する。
    どちらも無ければ判定できないので False を返す（付けない側に倒す）。
    """

    if cvss_vector:
        metrics = _metrics(cvss_vector)
        if all(key in metrics for key in ("AV", "PR", "UI", "AC")):
            return (
                metrics["AV"] == "N"
                and metrics["PR"] == "N"
                and metrics["UI"] == "N"
                and metrics["AC"] == "L"
                and not (metrics.get("C", "N") == "N" and metrics.get("I", "N") == "N")
            )
    return remote is True and authentication_required is False


def is_potential_initial_access(
    attack_surface_class: str | None,
    cvss_vector: str | None,
    remote: bool | None = None,
    authentication_required: bool | None = None,
) -> bool:
    """外部公開されやすい製品で、かつ単体で侵入の起点になりうるか。"""

    if not attack_surface_class:
        return False
    return is_entry_point(cvss_vector, remote, authentication_required)
