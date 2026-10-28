"""Impact engine: which protected obligations must be checked again (Doc 08; P4; C-137 to C-142).

``compute_impact`` takes a parent state, a candidate, their ``IdentityReport`` and their two
``DependencyGraph``s and returns an ``ImpactReport``: per invariant AFFECTED, UNCERTAIN or
explicitly unaffected, why, along which graph path, which prior evidence loses eligibility and what
verification work is required. Impact decides what must be checked, never what is true (Doc 08 §3).

    AFFECTED != VIOLATED     AFFECTED != UNKNOWN
    NO EDGE != NO DEPENDENCY NO PRIOR EVIDENCE != PASS

The footprint of each invariant is realised from its own declaration (``walk``); the changed set
(``changes``) and the computation (``engine``) are resource-level and follow the registry
footprints (C-140). Historical evidence is retained: the report says what is eligible for the
candidate and the next state, never for the parent.

Import restrictions (tests/contract/test_architecture_boundaries.py, rule R16): the standard
library, ``core.domain.*`` and this package only; never ``core.dependency``, ``core.identity``,
``core.terraform_model``, ``core.persistence``, ``core.application`` or ``core.promotion``.
"""

from core.impact.engine import compute_impact
from core.impact.errors import ImpactInputError
from core.impact.inputs import PriorProof
from core.impact.walk import Footprint, footprint

__all__ = ["Footprint", "ImpactInputError", "PriorProof", "compute_impact", "footprint"]
