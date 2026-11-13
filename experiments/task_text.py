"""The repair task given to the model (P10a decision 4, C-219).

"The task given to the model is a fixed template per target invariant: "Repair ``<invariant id>``:
``<the registry's one-line statement of the invariant>``. Keep every other protected invariant
satisfied. Make the smallest change."" The statement is the ``description`` of DAIL's own registry
definition (``core.domain.registry_v1_1``), read here from a DAIL ``Invariant`` and nothing else.
TerraPreserve's ``target.description`` and ``intent`` are never read (C-219).

This module sits outside ``experiments/generation/`` because the generation package may not name
``description`` at all (the blinding contract, check (c)): the name there could only mean
TerraPreserve's field.
"""

from __future__ import annotations

from typing import Final

from core.domain.invariant import Invariant

TASK_TEMPLATE: Final = (
    "Repair {invariant_id}: {statement} Keep every other protected invariant satisfied. "
    "Make the smallest change."
)


def objective_for(definition: Invariant) -> str:
    if not isinstance(definition, Invariant):
        raise TypeError("objective_for needs a DAIL Invariant definition")
    return TASK_TEMPLATE.format(
        invariant_id=definition.invariant_id, statement=definition.description
    )
