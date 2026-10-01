"""Domain enumerations (Doc 05 §4.1, Doc 06 §5; P1a step 5).

Values are stable strings equal to their names (Doc 05 §27: "Enum values are
stable strings"). Uncertainty is a first-class value in every enum that has
one (Doc 05 §29, §39): UNKNOWN, UNSUPPORTED, UNCERTAIN and VERIFIER_ERROR are
never collapsed into a boolean, a null or a generic string.

``EvidenceKind`` is deliberately not defined here: P2-fix owns the single
evidence taxonomy (C-06, C-36).
"""

from __future__ import annotations

from enum import StrEnum

# --- Doc 05 §4.1 ---------------------------------------------------------------


class CandidateSource(StrEnum):
    FIXED_PATCH = "FIXED_PATCH"
    LLM = "LLM"


class StateKind(StrEnum):
    TRUSTED = "TRUSTED"
    CANDIDATE = "CANDIDATE"


class IdentityStatus(StrEnum):
    SAME = "SAME"
    DIFFERENT = "DIFFERENT"
    UNCERTAIN = "UNCERTAIN"


class ChangeType(StrEnum):
    UNCHANGED = "UNCHANGED"
    MODIFIED = "MODIFIED"
    CREATED = "CREATED"
    DELETED = "DELETED"
    REPLACED = "REPLACED"
    UNCERTAIN = "UNCERTAIN"


class VerificationResult(StrEnum):
    """What a verifier reports (Doc 05 §4.1, Doc 09 §4).

    ``is_pass`` is the only way code may ask whether a result satisfies proof:
    UNKNOWN, UNSUPPORTED and VERIFIER_ERROR never do (Doc 09 §4, §37).
    """

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"
    VERIFIER_ERROR = "VERIFIER_ERROR"

    @property
    def is_pass(self) -> bool:
        return self is VerificationResult.PASS


class DecisionType(StrEnum):
    PROMOTE = "PROMOTE"
    REJECT = "REJECT"
    RETRY = "RETRY"
    ESCALATE = "ESCALATE"


class InvariantStatus(StrEnum):
    """Where an invariant is in its lifecycle (Doc 05 §4.1, Doc 06 §8).

    A status is not a verification result: PASS, FAIL, UNKNOWN, UNSUPPORTED and
    VERIFIER_ERROR are ``VerificationResult`` values, mapped to a status only by
    ``core.domain.lifecycle.apply_verification_result`` (C-30).
    """

    REGISTERED = "REGISTERED"
    VERIFYING = "VERIFYING"
    PROTECTED = "PROTECTED"
    AFFECTED = "AFFECTED"
    REVERIFYING = "REVERIFYING"
    VIOLATED = "VIOLATED"
    UNCERTAIN = "UNCERTAIN"


class ImpactStatus(StrEnum):
    UNAFFECTED = "UNAFFECTED"
    AFFECTED = "AFFECTED"
    UNCERTAIN = "UNCERTAIN"


class ResourceSupport(StrEnum):
    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


# --- Supporting enumerations -------------------------------------------------------


class CandidateStatus(StrEnum):
    """Candidate lifecycle (Doc 06 §5, C-29)."""

    CREATED = "CREATED"
    BUILDING = "BUILDING"
    FAILED = "FAILED"
    READY = "READY"
    ANALYZING = "ANALYZING"
    REJECTED = "REJECTED"
    RETRY_REQUIRED = "RETRY_REQUIRED"
    ESCALATED = "ESCALATED"
    PROMOTABLE = "PROMOTABLE"
    PROMOTED = "PROMOTED"


class InvariantCategory(StrEnum):
    """Doc 05 §10.1."""

    SECURITY = "SECURITY"
    FUNCTIONAL = "FUNCTIONAL"


class ReferenceResolution(StrEnum):
    """Doc 05 §5.3. Separate from ``ResourceSupport`` so the two meanings never merge (§39)."""

    SUPPORTED = "SUPPORTED"
    UNKNOWN = "UNKNOWN"
    UNSUPPORTED = "UNSUPPORTED"


class ProvenanceSourceKind(StrEnum):
    """Doc 05 §6."""

    TERRAFORM_CONFIG = "TERRAFORM_CONFIG"
    TERRAFORM_PLAN = "TERRAFORM_PLAN"
    TERRAFORM_STATE = "TERRAFORM_STATE"
    AWS_API = "AWS_API"
    LLM = "LLM"
    DERIVED = "DERIVED"


class PatchFormat(StrEnum):
    """Doc 05 §9."""

    TERRAFORM_HCL = "TERRAFORM_HCL"


class DependencyStatus(StrEnum):
    """Doc 05 §29."""

    KNOWN = "KNOWN"
    UNCERTAIN = "UNCERTAIN"
    UNSUPPORTED = "UNSUPPORTED"
