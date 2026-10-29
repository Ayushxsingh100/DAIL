"""Builders for the orchestrator tests (P6c steps 4 and 5). Not a test module.

``OrchestratorCase`` gives a test a database, a factory over it, a configuration with the
emergency switch set either way, and the real ``EvaluationOrchestrator`` and baseline flow. Every
candidate of a test is a fixture directory written against a state of the database; nothing here
computes an expected decision.
"""

from __future__ import annotations

import dataclasses
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

from core.application.baseline import BaselineRequest, BaselineResult, establish_baseline
from core.application.config import ResolvedConfig, load_config
from core.application.orchestrator import (
    EvaluationOrchestrator,
    EvaluationRequest,
    EvaluationResult,
)
from core.application.scope_policy import DailScopePolicy
from core.dependency.invariants import SemanticBinding
from core.domain.enums import CandidateSource
from core.domain.patch import Patch
from core.domain.state import TrustedState
from core.promotion.commit import PromotionContext
from tests.domain_builders import LINEAGE, uid
from tests.fixture_catalog import REPO_ROOT
from tests.identity_builders import NOW as PIPELINE_NOW
from tests.impact_builders import registry
from tests.persistence_builders import RepoCase
from tests.pipeline_builders import fixed_clock

FIXTURES = REPO_ROOT / "fixtures"
BASELINE_DIR = FIXTURES / "canonical_regression" / "baseline"
PATCH_SAFE_DIR = FIXTURES / "canonical_regression" / "patch_safe"
PATCH_REGRESSION_DIR = FIXTURES / "canonical_regression" / "patch_regression"
SOURCE, DESTINATION = "aws_instance.app", "aws_db_instance.database"
BASELINE_ID = uid(3100)


def config_with(automatic_enabled: bool) -> ResolvedConfig:
    """The repository configuration, with ``promotion.automatic_enabled`` set in a (copied) reviewed
    base file: the only way a safety-critical flag can be turned on (Doc 14 §37)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp) / "config"
        shutil.copytree(REPO_ROOT / "config", root)
        (root / "base" / "promotion.toml").write_text(
            f"automatic_enabled = {'true' if automatic_enabled else 'false'}\n", encoding="utf-8"
        )
        return load_config(root, "test", environ={})


def definitions() -> tuple[Any, ...]:
    return tuple(registry(SOURCE, DESTINATION).values())


def bindings() -> tuple[SemanticBinding, ...]:
    return (SemanticBinding("INV-FUNC-001", SOURCE, DESTINATION, "TCP", 5432),)


def context_for(n: int) -> PromotionContext:
    """A context of its own (run, correlation, operation and attempt ids) for evaluation n."""
    return PromotionContext(
        run_id=uid(0x7B00 + n),
        correlation_id=uid(0x7B10 + n),
        operation_id=uid(0x7B20 + n),
        attempt_id=uid(0x7B30 + n),
        actor_id=None,
    )


class OrchestratorCase(RepoCase):
    """A database, a factory over it, and helpers that run the real orchestrator."""

    automatic_enabled = True

    def setUp(self) -> None:
        super().setUp()
        self.opened = 0

    def factory(self, checkpoint: Callable[[str], None] | None = None) -> Callable[[], Any]:
        return lambda: self.uow(checkpoint=checkpoint)

    def orchestrator(
        self,
        *,
        config: ResolvedConfig | None = None,
        checkpoint: Callable[[str], None] | None = None,
        db_checkpoint: Callable[[str], None] | None = None,
        **options: Any,
    ) -> EvaluationOrchestrator:
        settings: dict[str, Any] = {
            "config": config or config_with(self.automatic_enabled),
            "scope_policy": DailScopePolicy(),
            "clock": fixed_clock(60),
            "policy_version": "policy-p6c",
            "checkpoint": checkpoint,
        }
        settings.update(options)
        return EvaluationOrchestrator(self.factory(db_checkpoint), **settings)

    def baseline(
        self, directory: Path = BASELINE_DIR, *, baseline_id: str = BASELINE_ID, **changes: Any
    ) -> BaselineResult:
        request = BaselineRequest(
            baseline_id=baseline_id,
            lineage_id=LINEAGE,
            baseline_dir=directory,
            variables=None,
            definitions=definitions(),
            bindings=bindings(),
            context=context_for(0),
            now=PIPELINE_NOW,
            eligible=True,
        )
        return establish_baseline(self.factory(), dataclasses.replace(request, **changes))

    def request(
        self,
        parent: TrustedState,
        directory: Path,
        *,
        n: int = 1,
        attempt: int = 1,
        **changes: Any,
    ) -> EvaluationRequest:
        """The n-th candidate of the lineage, written against ``parent``."""
        base = EvaluationRequest(
            lineage_id=parent.lineage_id,
            candidate_id=uid(3400 + n),
            candidate_sequence=n,
            attempt_number=attempt,
            patch=Patch.create(
                source=CandidateSource.FIXED_PATCH,
                content=f"fixed patch {n} for {directory.name}\n",
                parent_state_id=parent.state_id,
                now=PIPELINE_NOW,
                patch_id=uid(3500 + n),
            ),
            candidate_dir=directory,
            variables=None,
            definitions=definitions(),
            bindings=bindings(),
            context=context_for(n),
        )
        return dataclasses.replace(base, **changes)

    def current(self) -> TrustedState:
        with self.uow() as u:
            state = u.trusted_states.get_current(LINEAGE)
        assert state is not None
        return state

    def evaluate(self, request: EvaluationRequest, **options: Any) -> EvaluationResult:
        return self.orchestrator(**options).evaluate(request)
