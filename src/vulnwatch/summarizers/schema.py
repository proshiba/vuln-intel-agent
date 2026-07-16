from pydantic import BaseModel, Field


class AiSummary(BaseModel):
    summary_ja: str
    affected_assets: list[str] = Field(default_factory=list)
    exposure_conditions: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    uncertainties: list[str] = Field(default_factory=list)
    evidence_urls: list[str] = Field(default_factory=list)
