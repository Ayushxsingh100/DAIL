"""The promotion policies (P6a; Doc 09 §20, §28; C-22, C-157 to C-161; P8a: C-198, C-205).

``dail_policy`` is the DAIL condition (carry-forward on). ``stateful_full_policy`` is the
Stateful-Full comparison condition of Doc 13: the same controller, the same table, the same budget,
with carry-forward disabled, so every required invariant has to be verified again (C-22). The two
differ in one field and a test pins that.

``stateless_policy`` (P8a) is condition A, Stateless: Stateful Full with an explicit required set
(``explicit_required_set``): the gate items and the ``required`` invariants only, no baseline item
and no other invariant of the state (C-205). Its rules carry the version
``STATELESS_RULES_VERSION``.

Nothing here reads configuration. ``automatic_enabled`` has no default: the caller passes the
reviewed ``promotion.automatic_enabled`` value (Doc 14 §37), so a policy can never be built with the
emergency switch left to chance.

Standard library and ``core.domain`` only (R18).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from core.domain.enums import DecisionType, VerificationResult
from core.domain.invariant import Invariant
from core.domain.promotion import PromotionPolicy

# The verifier ids that the verification engine gives the two gate items (core.verification.engine).
# core.promotion may not import that package (R18), so they are copied here; a test pins them.
GATE_VERIFIERS: Final = (
    ("CONSISTENCY", "dail.verify.consistency", "1"),
    ("STRUCTURAL", "dail.verify.structural", "1"),
)
DEFAULT_NON_SUCCESS: Final = (
    (VerificationResult.UNKNOWN, DecisionType.RETRY),
    (VerificationResult.UNSUPPORTED, DecisionType.REJECT),
    (VerificationResult.VERIFIER_ERROR, DecisionType.ESCALATE),
)
DEFAULT_MIN_EVIDENCE_LEVEL: Final = "L1"
DEFAULT_MAX_ATTEMPTS: Final = 3
# The version of the rules ``stateless_policy`` builds (C-205); a change to them is a new version.
STATELESS_RULES_VERSION: Final = "dail-stateless-1"


def _policy(
    *,
    carry_forward_enabled: bool,
    policy_version: str,
    invariants: Iterable[Invariant],
    automatic_enabled: bool,
    invariant_registry_version: int,
    extra_required: Iterable[str],
    transient_errors: Iterable[str],
    max_attempts: int,
    conflict_decision: DecisionType,
    min_evidence_level: str,
    explicit_required_set: bool = False,
) -> PromotionPolicy:
    return PromotionPolicy(
        policy_version=policy_version,
        invariant_registry_version=invariant_registry_version,
        invariants=tuple(invariants),
        extra_required=tuple(extra_required),
        min_evidence_level=min_evidence_level,
        carry_forward_enabled=carry_forward_enabled,
        non_success=DEFAULT_NON_SUCCESS,
        transient_errors=tuple(transient_errors),
        max_attempts=max_attempts,
        conflict_decision=conflict_decision,
        automatic_enabled=automatic_enabled,
        accept_oracle_for_unknown=False,
        gate_verifiers=GATE_VERIFIERS,
        explicit_required_set=explicit_required_set,
    )


def dail_policy(
    *,
    policy_version: str,
    invariants: Iterable[Invariant],
    automatic_enabled: bool,
    invariant_registry_version: int = 1,
    extra_required: Iterable[str] = (),
    transient_errors: Iterable[str] = (),
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    conflict_decision: DecisionType = DecisionType.ESCALATE,
    min_evidence_level: str = DEFAULT_MIN_EVIDENCE_LEVEL,
) -> PromotionPolicy:
    """The DAIL condition: an unaffected, protected invariant may be carried forward (C-159)."""
    return _policy(
        carry_forward_enabled=True,
        policy_version=policy_version,
        invariants=invariants,
        automatic_enabled=automatic_enabled,
        invariant_registry_version=invariant_registry_version,
        extra_required=extra_required,
        transient_errors=transient_errors,
        max_attempts=max_attempts,
        conflict_decision=conflict_decision,
        min_evidence_level=min_evidence_level,
    )


def stateful_full_policy(
    *,
    policy_version: str,
    invariants: Iterable[Invariant],
    automatic_enabled: bool,
    invariant_registry_version: int = 1,
    extra_required: Iterable[str] = (),
    transient_errors: Iterable[str] = (),
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    conflict_decision: DecisionType = DecisionType.ESCALATE,
    min_evidence_level: str = DEFAULT_MIN_EVIDENCE_LEVEL,
) -> PromotionPolicy:
    """The Stateful-Full condition (Doc 13, C-22): nothing is carried forward."""
    return _policy(
        carry_forward_enabled=False,
        policy_version=policy_version,
        invariants=invariants,
        automatic_enabled=automatic_enabled,
        invariant_registry_version=invariant_registry_version,
        extra_required=extra_required,
        transient_errors=transient_errors,
        max_attempts=max_attempts,
        conflict_decision=conflict_decision,
        min_evidence_level=min_evidence_level,
    )


def stateless_policy(
    *,
    policy_version: str,
    invariants: Iterable[Invariant],
    automatic_enabled: bool,
    required: Iterable[str],
    invariant_registry_version: int = 1,
    transient_errors: Iterable[str] = (),
    max_attempts: int = DEFAULT_MAX_ATTEMPTS,
    conflict_decision: DecisionType = DecisionType.ESCALATE,
    min_evidence_level: str = DEFAULT_MIN_EVIDENCE_LEVEL,
) -> PromotionPolicy:
    """Condition A, Stateless (C-198, C-205): the gate items and ``required`` only, nothing is
    carried forward. ``required`` is the repair target, or nothing for a change request (C-197);
    every id must be defined in ``invariants``. Rules version ``STATELESS_RULES_VERSION``."""
    return _policy(
        carry_forward_enabled=False,
        policy_version=policy_version,
        invariants=invariants,
        automatic_enabled=automatic_enabled,
        invariant_registry_version=invariant_registry_version,
        extra_required=required,
        transient_errors=transient_errors,
        max_attempts=max_attempts,
        conflict_decision=conflict_decision,
        min_evidence_level=min_evidence_level,
        explicit_required_set=True,
    )
