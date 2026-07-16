from datetime import UTC, datetime

from vulnwatch.identity import canonical_id, normalize_url, semantic_hash
from vulnwatch.models import AdvisoryDraft, AiMetadata, AiStatus


def _draft(**overrides: object) -> AdvisoryDraft:
    values: dict[str, object] = {
        "source_id": "vendor",
        "vendor": "Example Vendor",
        "vendor_advisory_id": "ADV-2026-1",
        "title": "A vulnerability",
        "source_url": "https://security.example.com/advisory/1",
        "published_at": datetime(2026, 7, 1, tzinfo=UTC),
        "raw_sha256": "a" * 64,
    }
    values.update(overrides)
    return AdvisoryDraft.model_validate(values)


def test_canonical_id_prefers_vendor_advisory_id() -> None:
    assert canonical_id(_draft()) == "example-vendor:adv-2026-1"


def test_canonical_id_uses_normalized_url_without_vendor_id() -> None:
    first = _draft(
        vendor_advisory_id=None,
        source_url="HTTPS://Security.Example.com:443/advisory//1/?utm_source=x&id=7#top",
    )
    second = _draft(
        vendor_advisory_id=None,
        source_url="https://security.example.com/advisory/1?id=7",
    )

    assert canonical_id(first) == canonical_id(second)
    assert normalize_url(first.source_url) == "https://security.example.com/advisory/1?id=7"


def test_semantic_hash_ignores_ai_and_observation_time(advisory_factory) -> None:
    first = advisory_factory()
    second = first.model_copy(deep=True)
    second.first_seen_at = datetime(2026, 7, 15, tzinfo=UTC)
    second.ai = AiMetadata(status=AiStatus.SUCCESS, summary_ja="要約")

    assert semantic_hash(first) == semantic_hash(second)

    second.title = "Changed title"
    assert semantic_hash(first) != semantic_hash(second)
