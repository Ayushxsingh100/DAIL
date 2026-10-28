"""The identity-strategy seam (C-20, C-127, hypothesis H3; P3b step 5).

The ablation is a labelled experiment condition. These tests pin what it is, that it is not the
default, that no configuration reaches it, and exactly where it differs from the full strategy.
Nothing here measures whether it changes a result: that is H3 and stays a hypothesis.
"""

from __future__ import annotations

import dataclasses
import inspect
import random
import re
import unittest
from collections.abc import Sequence
from pathlib import Path

from core.domain.enums import ChangeType
from core.domain.identity import EvidenceSource, EvidenceType, IdentityReport
from core.domain.resource import Resource
from core.identity.engine import IdentityStrategyError, compare
from core.identity.findings import Draft, Evidencer
from core.identity.strategy import (
    ADDRESS_ONLY_ALGORITHM_VERSION,
    DEFAULT_STRATEGY,
    IDENTITY_ALGORITHM_VERSION,
    AddressOnlyIdentity,
    EvidenceIdentity,
    IdentityStrategy,
)
from tests.identity_builders import (
    CANDIDATE,
    NOW,
    PARENT,
    change_of,
    changes,
    compare_texts,
    make_resource,
    resources_of,
)
from tests.unit.test_identity_engine import VAR_N, moved, sg, tf, vpc

REPO_ROOT = Path(__file__).resolve().parents[2]
ABLATION = AddressOnlyIdentity()


def both(trusted: str, candidate: str) -> tuple[IdentityReport, IdentityReport]:
    return compare_texts(trusted, candidate), compare_texts(trusted, candidate, strategy=ABLATION)


class TestTheDefault(unittest.TestCase):
    def test_the_versions_are_the_documented_labels(self) -> None:
        self.assertEqual(IDENTITY_ALGORITHM_VERSION, "dail-identity-1")
        self.assertEqual(ADDRESS_ONLY_ALGORITHM_VERSION, "dail-identity-addr-1")
        self.assertEqual(EvidenceIdentity().algorithm_version, "dail-identity-1")
        self.assertEqual(ABLATION.algorithm_version, "dail-identity-addr-1")

    def test_omitting_the_strategy_gives_the_full_strategy(self) -> None:
        report = compare_texts(tf(vpc()), tf(vpc()))
        self.assertEqual(report.algorithm_version, "dail-identity-1")

    def test_the_default_argument_is_the_full_strategy_and_not_the_ablation(self) -> None:
        default = inspect.signature(compare).parameters["strategy"].default
        self.assertIsInstance(default, EvidenceIdentity)
        self.assertNotIsInstance(default, AddressOnlyIdentity)
        self.assertIsInstance(DEFAULT_STRATEGY, EvidenceIdentity)

    def test_the_ablation_must_be_passed_explicitly_and_labels_its_report(self) -> None:
        report = compare_texts(tf(vpc()), tf(vpc()), strategy=ABLATION)
        self.assertEqual(report.algorithm_version, "dail-identity-addr-1")
        for item in report.evidence:
            self.assertEqual(item.algorithm_version, "dail-identity-addr-1")

    def test_the_two_reports_of_one_comparison_have_different_hashes(self) -> None:
        full, ablated = both(tf(vpc()), tf(vpc()))
        self.assertNotEqual(full.content_hash, ablated.content_hash)

    def test_strategies_are_immutable_and_stateless(self) -> None:
        self.assertEqual(EvidenceIdentity(), EvidenceIdentity())
        self.assertNotEqual(EvidenceIdentity(), AddressOnlyIdentity())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            EvidenceIdentity().x = 1  # type: ignore[attr-defined]


class TestNoConfigurationReachesTheAblation(unittest.TestCase):
    def python_files(self, *roots: str) -> list[Path]:
        return [
            path
            for root in roots
            for path in (REPO_ROOT / root).rglob("*.py")
            if "__pycache__" not in path.parts
        ]

    def test_no_production_module_names_the_ablation(self) -> None:
        """Only its definition mentions it; the experiment harness (P8) will import it later."""
        home = REPO_ROOT / "core" / "identity" / "strategy.py"
        for path in self.python_files("core", "evidence", "llm", "scripts"):
            if path == home:
                continue
            with self.subTest(path=str(path.relative_to(REPO_ROOT))):
                self.assertNotIn("AddressOnlyIdentity", path.read_text(encoding="utf-8"))
                self.assertNotIn("ADDRESS_ONLY", path.read_text(encoding="utf-8"))

    def test_no_configuration_key_or_environment_variable_selects_a_strategy(self) -> None:
        """No file where a switch could live mentions one: the configuration data and schema, the
        configuration code, and the scripts."""
        words = re.compile(r"identity[_-]?strategy|ablation|address[_-]?only|DAIL_IDENTITY", re.I)
        places = [
            *(path for path in (REPO_ROOT / "config").rglob("*") if path.is_file()),
            *self.python_files("scripts"),
            *(REPO_ROOT / "core" / "application").glob("*.py"),
        ]
        self.assertTrue(places)
        for path in places:
            with self.subTest(path=str(path.relative_to(REPO_ROOT))):
                self.assertIsNone(words.search(path.read_text(encoding="utf-8")))

    def test_the_identity_package_reads_no_environment(self) -> None:
        for path in (REPO_ROOT / "core" / "identity").glob("*.py"):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                for word in ("os.environ", "getenv", "argparse", "sys.argv", "import os"):
                    self.assertNotIn(word, text)


class TestWhereTheAblationDiffersAndWhereItDoesNot(unittest.TestCase):
    def assert_same_changes(self, trusted: str, candidate: str) -> None:
        full, ablated = both(trusted, candidate)
        self.assertEqual(changes(ablated), changes(full))
        self.assertEqual(
            sorted((m.key, m.rule.value) for m in ablated.resource_matches),
            sorted((m.key, m.rule.value) for m in full.resource_matches),
        )

    def test_it_equals_the_full_strategy_on_unchanged_modified_created_and_deleted(self) -> None:
        text = tf(vpc("same"), vpc("edit", cidr="10.0.0.0/16"), vpc("gone"))
        other = tf(vpc("same"), vpc("edit", cidr="10.1.0.0/16"), vpc("made"))
        self.assert_same_changes(text, other)
        self.assert_same_changes(text, text)
        self.assert_same_changes("", other)
        self.assert_same_changes(text, "")

    def test_it_equals_the_full_strategy_on_rule_order_and_unsupported_types(self) -> None:
        acl = 'resource "aws_network_acl" "n" {\n  vpc_id = "v"\n}\n'
        self.assert_same_changes(tf(acl, vpc()), tf(acl, vpc()))
        first = tf(sg("g", 'description = "a"'))
        self.assert_same_changes(first, tf(sg("g", 'description = "b"')))

    def test_it_keeps_placeholders_and_indeterminate_blocks_uncertain(self) -> None:
        """It removes identity evidence, not the rule that unknown is not a pass."""
        known = tf(vpc("v", "count = 2"))
        unknown = tf(VAR_N, vpc("v", "count = var.n"))
        for before, after in (
            (unknown, unknown),
            (known, unknown),
            (unknown, known),
            ("", unknown),
        ):
            with self.subTest():
                self.assert_same_changes(before, after)
        report = compare_texts(known, unknown, strategy=ABLATION)
        self.assertEqual({m.change_type for m in report.resource_matches}, {ChangeType.UNCERTAIN})

    def test_it_keeps_the_content_flags(self) -> None:
        text = tf(VAR_N, sg("g", name="var.n"))
        report = compare_texts(text, text, strategy=ABLATION)
        kinds = {e.evidence_type for e in report.evidence}
        self.assertIn(EvidenceType.UNRESOLVED_CONTENT, kinds)

    def test_it_differs_on_a_moved_resource(self) -> None:
        trusted, candidate = tf(vpc("a")), tf(vpc("b"), moved("aws_vpc.a", "aws_vpc.b"))
        full, ablated = both(trusted, candidate)
        self.assertEqual(changes(full), {"aws_vpc.a->aws_vpc.b": "UNCHANGED"})
        self.assertEqual(changes(ablated), {"aws_vpc.a->-": "DELETED", "-->aws_vpc.b": "CREATED"})

    def test_it_differs_on_an_implicit_count_move(self) -> None:
        full, ablated = both(tf(vpc()), tf(vpc("v", "count = 2")))
        self.assertEqual(change_of(full, "aws_vpc.v[0]"), "MODIFIED")
        self.assertEqual(
            changes(ablated),
            {"aws_vpc.v->-": "DELETED", "-->aws_vpc.v[0]": "CREATED", "-->aws_vpc.v[1]": "CREATED"},
        )

    def test_it_differs_on_a_replacement(self) -> None:
        full, ablated = both(tf(sg(name='"db"')), tf(sg(name='"db-v2"')))
        self.assertEqual(change_of(full, "aws_security_group.g"), "REPLACED")
        self.assertEqual(change_of(ablated, "aws_security_group.g"), "MODIFIED")

    def test_it_differs_on_an_unresolved_name(self) -> None:
        full, ablated = both(tf(sg(name='"x"')), tf(VAR_N, sg(name="var.n")))
        self.assertEqual(change_of(full, "aws_security_group.g"), "UNCERTAIN")
        self.assertEqual(change_of(ablated, "aws_security_group.g"), "MODIFIED")

    def test_it_differs_on_an_ambiguity(self) -> None:
        full, ablated = both(tf(vpc("ops")), tf(vpc("ops", 'for_each = toset(["a", "b"])')))
        self.assertEqual({m.change_type for m in full.resource_matches}, {ChangeType.UNCERTAIN})
        self.assertEqual(
            changes(ablated),
            {
                "aws_vpc.ops->-": "DELETED",
                '-->aws_vpc.ops["a"]': "CREATED",
                '-->aws_vpc.ops["b"]': "CREATED",
            },
        )

    def test_it_ignores_the_moves_it_is_given(self) -> None:
        trusted = resources_of(tf(vpc("a")))
        candidate = resources_of(tf(vpc("b")))
        report = compare(
            trusted,
            candidate,
            [("aws_vpc.a", "aws_vpc.b")],
            parent_state_id=PARENT,
            candidate_id=CANDIDATE,
            now=NOW,
            strategy=ABLATION,
        )
        self.assertEqual(changes(report), {"aws_vpc.a->-": "DELETED", "-->aws_vpc.b": "CREATED"})

    def test_it_never_produces_replaced_or_ambiguity_evidence(self) -> None:
        scenarios = [
            (tf(sg(name='"a"')), tf(sg(name='"b"'))),
            (tf(vpc("ops")), tf(vpc("ops", 'for_each = toset(["a", "b"])'))),
            (tf(vpc("a")), tf(vpc("b"), moved("aws_vpc.a", "aws_vpc.b"))),
            (tf(vpc()), tf(vpc("v", "count = 2"))),
        ]
        forbidden = {
            EvidenceType.REPLACE_TRIGGER_FIELD,
            EvidenceType.REPLACE_TRIGGER_UNRESOLVED,
            EvidenceType.AMBIGUOUS_CANDIDATES,
            EvidenceType.EXPLICIT_MOVE,
            EvidenceType.IMPLICIT_COUNT_MOVE,
            EvidenceType.CONFLICTING_MOVE,
        }
        for before, after in scenarios:
            report = compare_texts(before, after, strategy=ABLATION)
            self.assertFalse(forbidden & {e.evidence_type for e in report.evidence})

    def test_it_is_deterministic(self) -> None:
        trusted = list(resources_of(tf(vpc("a"), vpc("b"), sg(name='"x"'))))
        candidate = list(resources_of(tf(vpc("a"), vpc("c"), sg(name='"y"'))))
        rng = random.Random(3)
        hashes = {
            compare(
                rng.sample(trusted, len(trusted)),
                rng.sample(candidate, len(candidate)),
                [],
                parent_state_id=PARENT,
                candidate_id=CANDIDATE,
                now=NOW,
                strategy=ABLATION,
            ).content_hash
            for _ in range(10)
        }
        self.assertEqual(len(hashes), 1)

    def test_a_pair_of_two_types_at_one_address_is_still_uncertain(self) -> None:
        report = compare(
            [make_resource("aws_vpc.a", "aws_vpc")],
            [make_resource("aws_vpc.a", "aws_subnet")],
            [],
            parent_state_id=PARENT,
            candidate_id=CANDIDATE,
            now=NOW,
            strategy=ABLATION,
        )
        self.assertEqual(report.resource_matches[0].change_type, ChangeType.UNCERTAIN)


class TestTheSeam(unittest.TestCase):
    def test_compare_uses_whatever_strategy_it_is_given(self) -> None:
        class EverythingUncertain:
            """A third strategy: the protocol is the only coupling."""

            algorithm_version = "test-everything-uncertain-1"

            def decide(
                self,
                trusted: Sequence[Resource],
                candidate: Sequence[Resource],
                candidate_moves: Sequence[tuple[str, str]],
            ) -> list[Draft]:
                del candidate_moves
                ev = Evidencer(self.algorithm_version)
                drafts = []
                for left, right in [(r, None) for r in trusted] + [(None, r) for r in candidate]:
                    proof = ev.about(
                        left,
                        right,
                        EvidenceType.INDETERMINATE_BLOCK,
                        EvidenceSource.BOTH,
                        {"note": "test"},
                        "A test strategy gives up.",
                    )
                    drafts.append(
                        Draft(left, right, ChangeType.UNCERTAIN, proof.evidence_type, [proof])
                    )
                return drafts

        strategy: IdentityStrategy = EverythingUncertain()
        report = compare_texts(tf(vpc("a")), tf(vpc("a")), strategy=strategy)
        self.assertEqual(report.algorithm_version, "test-everything-uncertain-1")
        self.assertEqual(
            changes(report), {"aws_vpc.a->-": "UNCERTAIN", "-->aws_vpc.a": "UNCERTAIN"}
        )
        self.assertEqual(report.candidate_id, CANDIDATE)

    def test_a_strategy_cannot_hide_a_resource(self) -> None:
        """compare() checks the partition for every strategy: a resource in no match, or in two,
        is refused (C-124 rule 11), so a strategy cannot drop or double a resource silently."""

        class Forgetful:
            algorithm_version = "test-forgetful-1"

            def decide(
                self,
                trusted: Sequence[Resource],
                candidate: Sequence[Resource],
                candidate_moves: Sequence[tuple[str, str]],
            ) -> list[Draft]:
                del trusted, candidate, candidate_moves
                return []

        with self.assertRaises(IdentityStrategyError):
            compare_texts(tf(vpc("a")), tf(vpc("a")), strategy=Forgetful())
        with self.assertRaises(IdentityStrategyError):
            compare_texts("", tf(vpc("a")), strategy=Forgetful())

    def test_a_strategy_cannot_put_a_resource_in_two_matches(self) -> None:
        class Doubling:
            algorithm_version = "test-doubling-1"

            def decide(
                self,
                trusted: Sequence[Resource],
                candidate: Sequence[Resource],
                candidate_moves: Sequence[tuple[str, str]],
            ) -> list[Draft]:
                full = EvidenceIdentity().decide(trusted, candidate, candidate_moves)
                return [*full, full[0]]

        with self.assertRaises(IdentityStrategyError):
            compare_texts(tf(vpc("a")), tf(vpc("a")), strategy=Doubling())


if __name__ == "__main__":
    unittest.main()
