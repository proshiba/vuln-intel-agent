from __future__ import annotations

import io
from datetime import UTC, datetime

from vulnwatch.collectors.base import OptionalDependencyError, SafeHttpClient
from vulnwatch.models import CollectionResult, RawRecord, SourceDefinition, SourceState


class PdfCollector:
    async def collect(
        self,
        source: SourceDefinition,
        state: SourceState,
        since: datetime,
    ) -> CollectionResult:
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise OptionalDependencyError("PDF collector requires pip install -e .[pdf]") from exc
        assert source.url is not None
        fetched = await SafeHttpClient(source).fetch(source.url, state, conditional=True)
        if fetched.not_modified:
            return CollectionResult(source_id=source.id, not_modified=True)
        reader = PdfReader(io.BytesIO(fetched.body))
        text = "\n".join(page.extract_text() or "" for page in reader.pages)
        return CollectionResult(
            source_id=source.id,
            records=[
                RawRecord(
                    source_id=source.id,
                    url=fetched.url,
                    content=text,
                    content_type=fetched.content_type,
                    metadata={"title": source.vendor},
                    fetched_at=datetime.now(UTC),
                )
            ],
            etag=fetched.etag,
            last_modified=fetched.last_modified,
        )
