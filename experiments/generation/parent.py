"""The parent of every LLM candidate: S0 (P10a Section 3.3 "Parent"; P7b verdict limit 6).

"Parent: the S0 trusted state built by the existing baseline flow with the registry v1.1 definitions
(the same S0 every condition starts from)." ``s0_parent`` copies S0's configuration files into a
directory of its own (``config_only_copy``: ``*.tf`` and ``*.tf.json`` at the top level, nothing
else, so a candidate built from it holds configuration only, P7b verdict limit 6), and establishes
the baseline there through ``core.application.baseline.establish_baseline`` in a fresh store, with
the four registry-v1.1 definitions (earlier versions registered first, Doc 06 §4.2) and the
INV-FUNC-001 binding of the scenario's endpoints, as condition C's lineage does (C-198, C-203).

Ids are name-based and the clock is the harness's logical clock (C-207), so the same S0 gives the
same parent state id and hash every time it is built (for generation and again for the export).
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from core.application.baseline import BaselineRequest, establish_baseline
from core.dependency.invariants import SemanticBinding
from core.domain.invariant import Invariant
from core.domain.registry_v1 import registry_v1_invariants
from core.domain.registry_v1_1 import REGISTRY_VERSION_V1_1, registry_v1_1_invariants
from core.domain.repositories import UnitOfWork
from core.domain.state import TrustedState
from core.persistence.schema import initialize_database
from core.persistence.sqlite import SqliteUnitOfWork
from core.promotion.commit import PromotionContext
from experiments.conditions import FUNC_BINDING
from experiments.definition import name_id
from experiments.generation.task import GenerationInput
from experiments.trial import DAIL_CLOCK_BASE, LogicalClock

CONFIG_SUFFIXES: Final = (".tf", ".tf.json")


def config_only_copy(source: Path, target: Path) -> Path:
    """Copy the configuration files at the top level of ``source`` into a new ``target``."""
    target.mkdir(parents=True)
    for path in sorted(Path(source).iterdir()):
        if path.is_file() and not path.is_symlink() and path.name.endswith(CONFIG_SUFFIXES):
            shutil.copyfile(path, target / path.name)
    return target


@dataclass(frozen=True)
class Parent:
    state: TrustedState
    directory: Path  # the configuration-only copy of S0
    definitions: tuple[Invariant, ...]
    bindings: tuple[SemanticBinding, ...]


def definitions_for(given: GenerationInput) -> tuple[Invariant, ...]:
    return registry_v1_1_invariants(
        DAIL_CLOCK_BASE, source=given.source_endpoint, destination=given.destination_endpoint
    )


def s0_parent(given: GenerationInput, work: Path, purpose: str) -> Parent:
    """Build S0 under ``work`` (which must not exist); ``purpose`` names the ids."""
    work = Path(work)
    directory = config_only_copy(given.s0_dir, work / "s0")
    definitions = definitions_for(given)
    func, protocol, port = FUNC_BINDING
    bindings = (
        SemanticBinding(func, given.source_endpoint, given.destination_endpoint, protocol, port),
    )
    held = {d.invariant_id: d.version for d in definitions}
    history = tuple(
        d
        for d in registry_v1_invariants(
            DAIL_CLOCK_BASE, source=given.source_endpoint, destination=given.destination_endpoint
        )
        if d.version < held[d.invariant_id]
    )
    store = work / "store" / "dail.sqlite"
    store.parent.mkdir(parents=True)
    initialize_database(store)

    def factory() -> UnitOfWork:
        return SqliteUnitOfWork(store)

    with factory() as uow:  # earlier versions first: no gaps (Doc 06 §4.2)
        for definition in history:
            uow.invariants.register_definition(definition)
    clock = LogicalClock()

    def nid(*parts: object) -> str:
        return name_id("p10a-parent", purpose, given.scenario_id, given.s0_content_hash, *parts)

    request = BaselineRequest(
        baseline_id=nid("baseline"),
        lineage_id=nid("lineage"),
        baseline_dir=directory,
        variables=dict(given.variable_values),
        definitions=definitions,
        bindings=bindings,
        context=PromotionContext(
            run_id=nid("run"),
            correlation_id=nid("correlation"),
            operation_id=nid("operation"),
            attempt_id=nid("attempt"),
            actor_id=None,
        ),
        now=clock(),
        eligible=True,
        registry_version=REGISTRY_VERSION_V1_1,
    )
    made = establish_baseline(factory, request)
    return Parent(made.state, directory, definitions, bindings)
