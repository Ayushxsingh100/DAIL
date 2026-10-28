"""The reachability verifier driven from Terraform text (P5b). Not a test module.

Standard library plus ``core.*`` (tests may import every package; ``core.verification`` may not).
"""

from __future__ import annotations

from core.domain.invariant import Invariant
from core.verification.inputs import VerificationInputs
from core.verification.outcome import PredicateOutcome
from core.verification.reachability import evaluate_reachability
from tests.pipeline_builders import inputs_for


def inputs(text: str, parent: str | None = None) -> VerificationInputs:
    """Inputs for a candidate text (and the pipeline of its parent text); no graphs are built."""
    return inputs_for(text, parent, with_graphs=False)


def definition(of: VerificationInputs) -> Invariant:
    found = of.invariant("INV-FUNC-001", 1)
    assert found is not None
    return found


def evaluate(text: str, parent: str | None = None) -> PredicateOutcome:
    """INV-FUNC-001 for a candidate text, with the identity of its parent text if it has one."""
    given = inputs(text, parent)
    return evaluate_reachability(definition(given), given)
