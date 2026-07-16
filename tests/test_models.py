from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from vulnwatch.models import AdvisoryDraft, Priority


def test_draft_normalizes_cves_and_validates_cvss() -> None:
    draft = AdvisoryDraft(
        source_id="example",
        vendor="Example",
        title="Example",
        source_url="https://security.example.com/1",
        published_at=datetime(2026, 7, 1, tzinfo=UTC),
        cves=["cve-2026-12345", "CVE-2026-12345"],
        cvss_score=9.8,
        raw_sha256="a" * 64,
    )
    assert draft.cves == ["CVE-2026-12345"]
    assert Priority("P1") == Priority.P1

    with pytest.raises(ValidationError):
        AdvisoryDraft(
            source_id="example",
            vendor="Example",
            title="Example",
            source_url="https://security.example.com/1",
            cvss_score=10.1,
            raw_sha256="a" * 64,
        )

    with pytest.raises(ValidationError):
        AdvisoryDraft(
            source_id="example",
            vendor="Example",
            title="Example",
            source_url="http://security.example.com/1",
            cves=["not-a-cve"],
            raw_sha256="short",
        )
