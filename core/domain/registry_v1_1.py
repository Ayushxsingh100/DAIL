"""The four registry-v1.1 invariants as data (P6d; registry v1.1 §1.4, §3, §4, §10; C-178 to C-181).

Registry v1.1 changes the ``possible`` clause of §3.3, so INV-SEC-001 and INV-SEC-002 are version 2;
INV-SEC-003 and INV-FUNC-001 are unchanged at version 1. ``registry_v1_1_invariants`` therefore
takes the v1.0 definitions of ``registry_v1`` and:

* for INV-SEC-001 and INV-SEC-002 sets ``version = 2`` and cites ``registry-v1.1`` in
  ``predicate.registry`` and in the description; scope, verifier id and verifier version stay as
  they are (registry §10 is unchanged, C-180);
* keeps INV-SEC-003 and INV-FUNC-001 exactly as v1.0 builds them, so their ``definition_hash`` is
  the one already stored for that id and version (C-181 (1)).

``registry_v1`` is not changed: it still builds the v1.0 definitions, which the TerraPreserve v1.0
labels and the existing fixtures cite. The verifier reads ``predicate.registry`` to choose the
§3.3 clause (``core.verification.dispatch``).

DAIL stores registry v1.1 as the integer ``invariant_registry_version`` 2 (C-180, the user's
decision of 11 Nov 2026; the field is an integer, C-32): ``REGISTRY_VERSION_V1_1``.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Final

from core.domain.invariant import Invariant
from core.domain.jsonvalue import thaw_json
from core.domain.registry_v1 import REGISTRY_TAG, registry_v1_invariants

REGISTRY_TAG_V1_0: Final = REGISTRY_TAG
REGISTRY_TAG_V1_1: Final = "registry-v1.1"
REGISTRY_VERSION_V1_0: Final = 1
REGISTRY_VERSION_V1_1: Final = 2
# Registry v1.1 §1.4: the invariants whose version changes, and their new version.
_BUMPED: Final = {"INV-SEC-001": 2, "INV-SEC-002": 2}


def _bumped(definition: Invariant, version: int) -> Invariant:
    predicate = thaw_json(definition.predicate)
    predicate["registry"] = REGISTRY_TAG_V1_1
    return replace(
        definition,
        version=version,
        predicate=predicate,
        description=definition.description.replace(REGISTRY_TAG_V1_0, REGISTRY_TAG_V1_1),
    )


def registry_v1_1_invariants(
    now: datetime, *, source: str, destination: str
) -> tuple[Invariant, ...]:
    """The four ``registry-v1.1`` invariant definitions, sorted by id (bindings as in v1.0)."""
    definitions = registry_v1_invariants(now, source=source, destination=destination)
    return tuple(
        _bumped(d, _BUMPED[d.invariant_id]) if d.invariant_id in _BUMPED else d for d in definitions
    )
