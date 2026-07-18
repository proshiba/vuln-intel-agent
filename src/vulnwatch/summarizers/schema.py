import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_JAPANESE_TEXT = re.compile(r"[\u3040-\u30ff\u3400-\u9fff]")
_INLINE_MARKDOWN = re.compile(r"[<>{}\[\]`*_|]")


class AiSummary(BaseModel):
    summary_ja: str
    affected_assets: list[str] = Field(default_factory=list)
    exposure_conditions: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    evidence_urls: list[str] = Field(default_factory=list)


class ReportSectionSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    critical_summary_ja: str = Field(min_length=1, max_length=2000)
    exploitation_summary_ja: str = Field(min_length=1, max_length=2000)

    @field_validator("critical_summary_ja", "exploitation_summary_ja")
    @classmethod
    def normalize_summary(cls, value: str) -> str:
        normalized = " ".join(value.split())
        sentence_count = len([sentence for sentence in normalized.split("。") if sentence])
        if (
            not _JAPANESE_TEXT.search(normalized)
            or not normalized.endswith("。")
            or not 2 <= sentence_count <= 4
            or "AIサマリは未生成" in normalized
            or _INLINE_MARKDOWN.search(normalized)
            or normalized.startswith(("#", "-", ">"))
        ):
            raise ValueError("report summary must be 2-4 non-placeholder Japanese sentences")
        return normalized
