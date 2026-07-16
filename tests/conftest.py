from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from vulnwatch.models import Advisory, AdvisoryFacts, Provenance


@pytest.fixture
def advisory_factory():
    def build(**overrides: Any) -> Advisory:
        payload: dict[str, Any] = {
            "canonical_id": "example:ADV-1",
            "source_id": "example",
            "vendor": "Example",
            "vendor_advisory_id": "ADV-1",
            "title": "Example advisory",
            "source_url": "https://security.example.com/ADV-1",
            "published_at": datetime(2026, 7, 1, tzinfo=UTC),
            "first_seen_at": datetime(2026, 7, 2, tzinfo=UTC),
            "facts": AdvisoryFacts(cves=["CVE-2026-12345"], products=["Example OS"]),
            "provenance": Provenance(
                source_type="json_api",
                content_sha256="a" * 64,
                extractor_version="0.1.0",
            ),
        }
        payload.update(overrides)
        return Advisory(**payload)

    return build
