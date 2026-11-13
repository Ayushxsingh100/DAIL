"""Baseline items under registry v1.1 (P8b-2; C-216; Doc 08 §16; C-148; C-150, C-178).

Expected values come from the decided text (C-216): "Baseline items (C-148) use the definition that
the run's definitions hold for the invariant they belong to (INV-SEC-001 for security groups and
rules, INV-SEC-003 for database instances). If more than one version is present, the highest is
used. The item's evidence records that id and version, and the §3.3 clause it applies is that
definition's registry (version 1 -> registry-v1.0, version 2 -> registry-v1.1) ... If no definition
is present, the item stays UNSUPPORTED invariant.unknown, as now."

The v1.1 §3.3 clause (C-178): an indeterminate rule whose resolved IPv4 sources cover 0.0.0.0/0 is
``possible`` -> UNKNOWN; registry v1.0 has no such alternative -> PASS.
"""

from __future__ import annotations

import dataclasses
import functools
import shutil
import tempfile
import unittest
from pathlib import Path

from core.application.orchestrator import ResultKind
from core.domain.enums import VerificationResult
from core.domain.registry_v1 import registry_v1_invariants
from core.domain.registry_v1_1 import REGISTRY_VERSION_V1_1, registry_v1_1_invariants
from core.domain.verification import VerificationReason
from core.promotion.policy import dail_policy
from core.verification.baseline import verify_baseline
from tests.identity_builders import NOW
from tests.pipeline_builders import inputs_for
from tests.promotion_orchestrator_builders import (
    DESTINATION,
    PATCH_SAFE_DIR,
    SOURCE,
    OrchestratorCase,
    bindings,
    context_for,
)
from tests.security_builders import VARS, inline, sg

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)
R = VerificationReason
OLD = sg("db")
NEW = "aws_security_group.new"
RULE = "aws_security_group_rule.r"
V1_1 = registry_v1_1_invariants(NOW, source=SOURCE, destination=DESTINATION)
V1_0 = registry_v1_invariants(NOW, source=SOURCE, destination=DESTINATION)

CLOSED = OLD + sg("new", inline("ingress", "tcp", 443, 443, ["10.0.0.0/8"]))
OPEN_22 = OLD + sg("new", inline("ingress", "tcp", 22, 22, ["0.0.0.0/0"]))
UNRESOLVED_PORT_RULE = (
    VARS
    + OLD
    + sg("new")
    + 'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n'
    + '  security_group_id = aws_security_group.new.id\n  protocol = "tcp"\n'
    + '  from_port = var.u\n  to_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
)


def item(address: str, text: str, definitions):  # type: ignore[no-untyped-def]
    inputs = dataclasses.replace(inputs_for(text, OLD), invariants=tuple(definitions))
    return verify_baseline(address, inputs)


class TestUnderRegistryV1_1(unittest.TestCase):
    def test_a_closed_created_group_passes_and_names_version_2(self) -> None:
        outcome = item(NEW, CLOSED, V1_1)
        self.assertEqual((outcome.result, outcome.reason), (P, None))
        self.assertEqual(outcome.observations["invariant_id"], "INV-SEC-001")
        self.assertEqual(outcome.observations["invariant_version"], 2)
        self.assertEqual(outcome.observations["registry"], "registry-v1.1")
        self.assertEqual(
            (outcome.verifier_id, outcome.verifier_version), ("dail.verify.public_ingress", "1")
        )

    def test_a_created_group_open_on_ssh_fails(self) -> None:
        outcome = item(NEW, OPEN_22, V1_1)
        self.assertEqual((outcome.result, outcome.reason), (F, R.PREDICATE_VIOLATED))

    def test_a_created_rule_with_an_unresolved_port_and_a_public_source_is_unknown(self) -> None:
        outcome = item(RULE, UNRESOLVED_PORT_RULE, V1_1)
        self.assertEqual((outcome.result, outcome.reason), (U, R.RULE_INDETERMINATE))

    def test_the_highest_version_is_used_when_both_are_present(self) -> None:
        both = [*V1_0, *[d for d in V1_1 if d.version == 2]]
        outcome = item(RULE, UNRESOLVED_PORT_RULE, both)
        self.assertEqual(outcome.observations["invariant_version"], 2)
        self.assertEqual(outcome.result, U)

    def test_a_created_database_names_inv_sec_003(self) -> None:
        text = (
            OLD
            + 'resource "aws_db_instance" "extra" {\n  identifier = "e"\n'
            + "  publicly_accessible = false\n}\n"
        )
        outcome = item("aws_db_instance.extra", text, V1_1)
        self.assertEqual(outcome.result, P)
        self.assertEqual(
            (outcome.observations["invariant_id"], outcome.observations["invariant_version"]),
            ("INV-SEC-003", 1),
        )

    def test_without_the_definition_it_stays_unsupported(self) -> None:
        others = [d for d in V1_1 if d.invariant_id != "INV-SEC-001"]
        outcome = item(NEW, CLOSED, others)
        self.assertEqual((outcome.result, outcome.reason), (S, R.INVARIANT_UNKNOWN))


class TestUnderRegistryV1_0(unittest.TestCase):
    def test_the_same_three_give_the_v1_0_results(self) -> None:
        self.assertEqual(item(NEW, CLOSED, V1_0).result, P)
        self.assertEqual(item(NEW, OPEN_22, V1_0).result, F)
        outcome = item(RULE, UNRESOLVED_PORT_RULE, V1_0)
        self.assertEqual(outcome.result, P)  # registry v1.0 has no 'possible' for this rule
        self.assertEqual(outcome.observations["invariant_version"], 1)
        self.assertEqual(outcome.observations["registry"], "registry-v1.0")


EXTRA_CLOSED = (
    'resource "aws_security_group" "extra" {\n  name = "extra"\n  description = "extra group"\n'
    "  vpc_id = aws_vpc.main.id\n  ingress = []\n}\n"
)
EXTRA_OPEN = (
    'resource "aws_security_group" "extra" {\n  name = "extra"\n  description = "extra group"\n'
    "  vpc_id = aws_vpc.main.id\n  ingress {\n    from_port = 22\n    to_port = 22\n"
    '    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
)


class TestEndToEndUnderV1_1(OrchestratorCase):
    """C under registry v1.1 through the orchestrator: v0 = patch_safe (every invariant
    PROTECTED)."""

    def setUp(self) -> None:
        super().setUp()
        self._dirs = tempfile.TemporaryDirectory(prefix="dail-p8b2-")
        self.addCleanup(self._dirs.cleanup)
        with self.uow() as u:  # version 1 before version 2 (Doc 06 §4.2, C-207 (2))
            for d in V1_0:
                if d.invariant_id in ("INV-SEC-001", "INV-SEC-002"):
                    u.invariants.register_definition(d)
        self.v0 = self.baseline(
            PATCH_SAFE_DIR, definitions=V1_1, registry_version=REGISTRY_VERSION_V1_1
        ).state

    def candidate(self, name: str, extra: str) -> Path:
        target = Path(self._dirs.name) / name
        shutil.copytree(PATCH_SAFE_DIR, target, ignore=shutil.ignore_patterns("expected.json"))
        (target / "extra.tf").write_text(extra, encoding="utf-8")
        return target

    def evaluate_v1_1(self, directory: Path):  # type: ignore[no-untyped-def]
        request = dataclasses.replace(
            self.request(self.v0, directory),
            definitions=V1_1,
            bindings=bindings(),
            context=context_for(1),
        )
        return self.evaluate(
            request,
            policy_factory=functools.partial(
                dail_policy, invariant_registry_version=REGISTRY_VERSION_V1_1
            ),
        )

    def test_a_closed_new_group_promotes(self) -> None:
        result = self.evaluate_v1_1(self.candidate("closed", EXTRA_CLOSED))
        self.assertIs(result.kind, ResultKind.PROMOTED)
        assert result.verification is not None
        row = next(
            r
            for r in result.verification.results
            if r.target_id == "RESOURCE:aws_security_group.extra"
        )
        self.assertIs(row.result, P)

    def test_a_new_group_open_on_ssh_rejects_on_the_resource_item(self) -> None:
        result = self.evaluate_v1_1(self.candidate("open", EXTRA_OPEN))
        self.assertIs(result.kind, ResultKind.REJECTED)
        assert result.decision is not None
        on_item = {
            c.code.value
            for c in result.decision.blocking_conditions
            if c.target == "RESOURCE:aws_security_group.extra"
        }
        self.assertEqual(on_item, {"REQUIRED_CHECK_FAILED"})
        self.assertNotIn(
            "REQUIRED_UNSUPPORTED", {c.code.value for c in result.decision.blocking_conditions}
        )


if __name__ == "__main__":
    unittest.main()
