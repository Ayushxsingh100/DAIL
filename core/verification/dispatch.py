"""Which verifier answers which invariant: a table, not code (C-144; P5a step 6).

The definition of an invariant names its verifier (``verifier_id``, ``verifier_version``, registry
§10) and its parameters (``predicate.parameters``). The table maps that pair to a function
``(definition, inputs) -> PredicateOutcome``. A pair the table does not have is not an error of the
engine: the item is UNSUPPORTED ``verifier.not_available``, never PASS. INV-FUNC-001 is such a pair
until P5b adds its verifier.

The table is data so that a test can inject a verifier that raises, or one that returns something
that is not an outcome, and watch the engine fail closed.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import Final

from core.domain.invariant import Invariant
from core.verification.inputs import VerificationInputs
from core.verification.outcome import PredicateOutcome
from core.verification.public_ingress import evaluate_public_ingress
from core.verification.rds_public_flag import evaluate_rds_public_flag

Verifier = Callable[[Invariant, VerificationInputs], PredicateOutcome]
VerifierTable = Mapping[tuple[str, str], Verifier]

PUBLIC_INGRESS: Final = ("dail.verify.public_ingress", "1")
RDS_PUBLIC_FLAG: Final = ("dail.verify.rds_public_flag", "1")
REACHABILITY_CFG: Final = ("dail.verify.reachability_cfg", "1")  # P5b; not in the table yet


def _port(definition: Invariant) -> int:
    parameters = definition.predicate.get("parameters")
    port = parameters.get("p") if isinstance(parameters, Mapping) else None
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError(f"{definition.invariant_id}: parameter p must be a port number")
    return port


def public_ingress(definition: Invariant, inputs: VerificationInputs) -> PredicateOutcome:
    """INV-SEC-001 and INV-SEC-002: ``PIP(p)`` with ``p`` from the definition."""
    return evaluate_public_ingress(
        _port(definition),
        inputs.candidate_resources,
        parent_resources=inputs.parent_resources,
        identity=inputs.identity,
    )


def rds_public_flag(_definition: Invariant, inputs: VerificationInputs) -> PredicateOutcome:
    """INV-SEC-003."""
    return evaluate_rds_public_flag(inputs.candidate_resources)


DEFAULT_VERIFIERS: Final[VerifierTable] = MappingProxyType(
    {
        PUBLIC_INGRESS: public_ingress,
        RDS_PUBLIC_FLAG: rds_public_flag,
    }
)
