from __future__ import annotations

import subprocess
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _is_ignored(path: str) -> bool:
    result = subprocess.run(
        ["git", "check-ignore", "--no-index", "--quiet", path],
        cwd=REPOSITORY_ROOT,
        check=False,
    )
    return result.returncode == 0


def test_generated_artifacts_are_git_visible() -> None:
    generated_paths = (
        "data/vendors/example/index.json",
        "data/vendors/example/advisories/2026/example/advisory.json",
        "data/vendors/example/advisories/2026/example/summary.ja.md",
        "reports/daily/2026/07/2026-07-18.md",
        "state/sources/example.json",
        "quarantine/example/latest.json",
        "run-manifest.json",
        "run-summary.md",
    )

    assert all(not _is_ignored(path) for path in generated_paths)


def test_temporary_and_secret_paths_remain_ignored() -> None:
    assert _is_ignored("staging/data/vendors/example/index.json")
    assert _is_ignored(".env")
    assert _is_ignored(".venv/secret")
    assert _is_ignored(".pytest_cache/example")
