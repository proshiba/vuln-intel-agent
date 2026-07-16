from __future__ import annotations

from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from vulnwatch.models import Advisory, ChangeStatus, RunManifest
from vulnwatch.storage.filesystem import atomic_write_text


def generate_report(root: Path) -> Path:
    manifest = RunManifest.model_validate_json(
        (root / "run-manifest.json").read_text(encoding="utf-8")
    )
    now = datetime.now(ZoneInfo("Asia/Tokyo"))
    path = root / "reports" / "daily" / f"{now:%Y}" / f"{now:%m}" / f"{now:%Y-%m-%d}.md"
    lines = [
        f"# 脆弱性情報 日次レポート {now:%Y-%m-%d}",
        "",
        "| 優先度 | 状態 | ベンダー | アドバイザリ |",
        "|---|---|---|---|",
    ]
    for change in manifest.changes:
        if change.status == ChangeStatus.UNCHANGED or not change.path:
            continue
        advisory_path = root / change.path
        if advisory_path.name != "advisory.json" or not advisory_path.exists():
            continue
        advisory = Advisory.model_validate_json(advisory_path.read_text(encoding="utf-8"))
        title = advisory.title.replace("|", "\\|")
        lines.append(
            f"| {advisory.decision.priority} | {change.status} | "
            f"{advisory.vendor} | [{title}]({advisory.source_url}) |"
        )
    if len(lines) == 4:
        lines.extend(["", "新規・更新アドバイザリはありません。"])
    atomic_write_text(path, "\n".join(lines) + "\n")
    return path
