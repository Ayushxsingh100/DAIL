"""Impact engine errors (C-137)."""

from __future__ import annotations

from core.domain.errors import DomainValidationError


class ImpactInputError(DomainValidationError):
    """The inputs of the impact engine are inconsistent, so no report can be built.

    Raised for an identity report that belongs to another candidate or parent, graphs and resource
    tuples that disagree, an invariant without a node in a graph, duplicate invariants or prior
    proofs, a malformed walk token and a malformed address. It is a refusal, never a report that
    guesses (Doc 08 §3: no prior evidence is not a pass, no edge is not no dependency).
    """
