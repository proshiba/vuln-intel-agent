from __future__ import annotations

from typing import Protocol

from vulnwatch.models import Advisory
from vulnwatch.summarizers.schema import AiSummary


class Summarizer(Protocol):
    async def summarize(self, advisory: Advisory) -> AiSummary: ...
