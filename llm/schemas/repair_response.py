"""``LLMRepairResponse``, the structured output of the model (Doc 10 §11, §25; C-184, C-187).

§11: "LLMRepairResponse { schema_version, status = PATCH | NO_SOLUTION | UNCERTAIN | INVALID,
summary, patch, changed_addresses[], assumptions[], rationale }." ``patch`` is Terraform HCL text
in the format the fixed-patch loop accepts (``PatchFormat.TERRAFORM_HCL``, C-184) for PATCH, and
null for every other status. ``assumptions`` are never verified facts and ``rationale`` is
never a safety proof: neither is read by anything that decides.

§25: "Any confidence score returned by the model is advisory metadata only." Schema version 1 has
one optional field, ``confidence`` (a number), kept as metadata and read by nothing that decides.

``RESPONSE_JSON_SCHEMA`` is the JSON schema handed to the provider as a generation hint (Ollama's
``format``, C-185). It is never trusted as validation: ``llm.validation.parser`` checks every reply.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

RESPONSE_SCHEMA_VERSION: Final = "dail-llm-repair-response/1"
REQUIRED_FIELDS: Final = (
    "schema_version",
    "status",
    "summary",
    "patch",
    "changed_addresses",
    "assumptions",
    "rationale",
)
OPTIONAL_FIELDS: Final = ("confidence",)


class RepairStatus(StrEnum):
    """§11 ``status``."""

    PATCH = "PATCH"
    NO_SOLUTION = "NO_SOLUTION"
    UNCERTAIN = "UNCERTAIN"
    INVALID = "INVALID"


@dataclass(frozen=True)
class LLMRepairResponse:
    """A response that passed the parser. Nothing in it is verified; it is an untrusted proposal."""

    schema_version: str
    status: RepairStatus
    summary: str
    patch: str | None
    changed_addresses: tuple[str, ...]
    assumptions: tuple[str, ...]
    rationale: str
    confidence: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "status": self.status.value,
            "summary": self.summary,
            "patch": self.patch,
            "changed_addresses": list(self.changed_addresses),
            "assumptions": list(self.assumptions),
            "rationale": self.rationale,
            "confidence": self.confidence,
        }


RESPONSE_JSON_SCHEMA: Final[dict[str, Any]] = {
    "type": "object",
    "properties": {
        "schema_version": {"type": "string", "enum": [RESPONSE_SCHEMA_VERSION]},
        "status": {"type": "string", "enum": [s.value for s in RepairStatus]},
        "summary": {"type": "string"},
        "patch": {"type": ["string", "null"]},
        "changed_addresses": {"type": "array", "items": {"type": "string"}},
        "assumptions": {"type": "array", "items": {"type": "string"}},
        "rationale": {"type": "string"},
        "confidence": {"type": "number"},
    },
    "required": list(REQUIRED_FIELDS),
    "additionalProperties": False,
}
