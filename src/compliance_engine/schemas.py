"""Request models for the two policy packs.

The models validate shape and provenance, never legality: a payload that passes
here can still be denied by the Rego engine, and nothing in this module is
allowed to compute a verdict.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

# Mirrors of the provenance sets in policies/export_control/decision.rego.
AuthoritativeSource = Literal[
    "MANUAL_VERIFICATION",
    "CERTIFICATE",
    "DECLARATION",
    "SIGNED_SPEC_SHEET",
    "REGULATOR_RULING",
    "ERP_MASTER_DATA",
]
MachineSource = Literal["GEMINI_EXTRACTION", "LLM_EXTRACTION", "MODEL_EXTRACTED", "RULE_BASED_PARSER"]
FactSource = AuthoritativeSource | MachineSource

ScreeningStatus = Literal["CLEAR", "HIT", "STALE", "NOT_RUN"]
TransferRelationship = Literal["CONTROLLER_TO_CONTROLLER", "CONTROLLER_TO_PROCESSOR", "PROCESSOR_TO_PROCESSOR"]
Activity = Literal["EXPORT", "REEXPORT", "PROVIDE_TECHNOLOGY", "TRANSFER_INTERNALLY"]
JobActivity = Literal[
    "CROSS_BORDER_ANALYTICS",
    "AGGREGATE_REPORTING",
    "MODEL_TRAINING",
    "DATA_MIGRATION",
]


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Provenance(Strict):
    """Where a fact came from. `ref` is what makes it auditable at all."""

    source: FactSource
    ref: str = Field(min_length=1, max_length=300)
    quote: str | None = Field(default=None, max_length=500)
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @field_validator("ref")
    @classmethod
    def _ref_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("evidence.ref must carry a document, ticket or master-data identifier")
        return value.strip()


class Fact(Strict):
    value: Any
    unit: str | None = Field(default=None, max_length=24)
    evidence: Provenance


class ItemInput(Strict):
    sku: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=4000)
    technical_parameters: dict[str, Fact] = Field(default_factory=dict)


class EndUserInput(Strict):
    screening_status: ScreeningStatus = "NOT_RUN"
    screening_ref: str | None = Field(default=None, max_length=200)
    indicators: list[str] = Field(default_factory=list, max_length=40)


class GovernanceInput(Strict):
    min_fact_confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    review_sla_hours: int | None = Field(default=None, gt=0, le=24 * 14)


class IntentInput(Strict):
    activity: Activity = "EXPORT"
    end_use_statement_ref: str | None = Field(default=None, max_length=200)


class ClockInput(Strict):
    milliseconds: int


class ExportControlRequest(Strict):
    tenant_id: str = Field(min_length=1, max_length=120)
    request_id: str | None = Field(default=None, max_length=120)
    item: ItemInput
    destination_country: str = Field(min_length=2, max_length=3)
    end_user: EndUserInput = Field(default_factory=EndUserInput)
    intent: IntentInput = Field(default_factory=IntentInput)
    evidence: dict[str, Any] = Field(default_factory=dict)
    governance: GovernanceInput = Field(default_factory=GovernanceInput)
    clock: ClockInput | None = None

    @field_validator("destination_country")
    @classmethod
    def _upper_country(cls, value: str) -> str:
        return value.strip().upper()


class DatasetInput(Strict):
    registry_id: str = Field(min_length=1, max_length=120)
    purpose: str = Field(min_length=1, max_length=120)
    origin_jurisdiction: str | None = Field(default=None, max_length=8)
    categories: list[str] = Field(min_length=1, max_length=40)
    subject_count: int = Field(ge=0)
    retention_days_requested: int = Field(ge=0)
    row_level_read: bool = False
    relationship: TransferRelationship | None = "CONTROLLER_TO_PROCESSOR"
    same_corporate_group: bool = False
    aggregation: dict[str, Any] = Field(default_factory=dict)

    @field_validator("categories")
    @classmethod
    def _clean_categories(cls, value: list[str]) -> list[str]:
        cleaned = [v.strip() for v in value if v.strip()]
        if not cleaned:
            raise ValueError("dataset.categories must name at least one data category")
        return cleaned


class OperationInput(Strict):
    type: JobActivity = "CROSS_BORDER_ANALYTICS"
    processing_region: str = Field(min_length=1, max_length=60)
    agent_id: str | None = Field(default=None, max_length=120)
    writes_pii: bool = False

    @field_validator("processing_region")
    @classmethod
    def _lower_region(cls, value: str) -> str:
        return value.strip().lower()


class TransferGateRequest(Strict):
    tenant_id: str = Field(min_length=1, max_length=120)
    request_id: str | None = Field(default=None, max_length=120)
    operation: OperationInput
    dataset: DatasetInput
    flags: dict[str, Any] = Field(default_factory=dict)
    evidence: dict[str, Any] = Field(default_factory=dict)
    governance: GovernanceInput = Field(default_factory=GovernanceInput)
    clock: ClockInput | None = None
