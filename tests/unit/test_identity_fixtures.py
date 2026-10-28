"""The identity engine against the hand-written ``changes`` blocks of the fixtures (P3b step 6;
Doc 07 §36, Doc 12 §9, C-89, C-90).

The expected change classes come from each fixture's ``expected.json`` (derived by hand from
registry-v1.0 and Docs 07-09, C-89), never from the engine. If a fixture and the engine disagree,
the test fails and prints the address, the expected and the actual class and the canonical JSON
difference of the two resources: the disagreement is review material, and neither the engine nor
the fixture is changed to hide it.
"""

from __future__ import annotations

import difflib
import json
import unittest

from core.domain.enums import ChangeType, IdentityStatus
from core.domain.identity import EvidenceType, IdentityMatch, IdentityReport
from core.domain.resource import Resource
from core.identity.engine import compare
from core.identity.strategy import AddressOnlyIdentity
from core.terraform_model.normalization import NormalizationOutcome, normalize_directory
from tests import fixture_catalog as fc
from tests.identity_builders import CANDIDATE, NOW, PARENT

ROOT = fc.REPO_ROOT
OPS = "fixtures/identity/ambiguous_identity_uncertain_v1"
REPLACEMENT = "fixtures/impact/sg_replacement_resource_promote_v1"

_CACHE: dict[str, NormalizationOutcome] = {}


def normalized(folder: str) -> NormalizationOutcome:
    if folder not in _CACHE:
        _CACHE[folder] = normalize_directory(ROOT / folder, None, now=NOW)
    return _CACHE[folder]


def run(fixture: fc.Fixture, strategy: AddressOnlyIdentity | None = None) -> IdentityReport:
    """Normalize ``parent`` and ``config`` of a fixture and compare them."""
    before, after = normalized(fixture.data["parent"]), normalized(fixture.data["config"])
    extra = {} if strategy is None else {"strategy": strategy}
    return compare(
        before.resources,
        after.resources,
        after.moves,
        parent_state_id=PARENT,
        candidate_id=CANDIDATE,
        now=NOW,
        **extra,  # type: ignore[arg-type]
    )


def fixtures_with_changes() -> list[fc.Fixture]:
    return [fx for _, fx in sorted(fc.load_all().items()) if fx.data["changes"] is not None]


def resource_lookup(outcome: NormalizationOutcome) -> dict[str, Resource]:
    return {resource.address: resource for resource in outcome.resources}


def disagreement(
    fixture: fc.Fixture,
    address: str,
    expected: dict[str, str | None] | str,
    match: IdentityMatch | None,
) -> str:
    """Address, expected, actual and the canonical JSON difference."""
    before = resource_lookup(normalized(fixture.data["parent"]))
    after = resource_lookup(normalized(fixture.data["config"]))
    left = before.get(address)
    right = after.get(address)
    diff = ""
    if left is not None and right is not None:
        diff = "".join(
            difflib.unified_diff(
                json.dumps(json.loads(left.canonical_json), indent=1, sort_keys=True).splitlines(
                    True
                ),
                json.dumps(json.loads(right.canonical_json), indent=1, sort_keys=True).splitlines(
                    True
                ),
                "trusted",
                "candidate",
            )
        )
    actual = (
        "no match"
        if match is None
        else f"identity={match.identity_status.value} change={match.change_type.value} "
        f"({match.key}; rule {match.rule.value})"
    )
    return f"{fixture.fixture_id}: {address}: expected {expected}, actual {actual}" + (
        f"\n{diff}" if diff else ""
    )


def problems_of(fixture: fc.Fixture, report: IdentityReport) -> list[str]:
    """Every disagreement between ``changes`` and the report (an empty list means they agree)."""
    changes = fixture.data["changes"]
    assert changes["default"] == "UNCHANGED"
    expected = changes["resources"]
    problems: list[str] = []
    listed: set[str] = set()
    for address, entry in expected.items():
        found = [
            m
            for m in report.resource_matches
            if address in (m.trusted_resource_ref, m.candidate_resource_ref)
        ]
        if len(found) != 1:
            problems.append(disagreement(fixture, address, entry, None))
            continue
        match = found[0]
        listed.add(match.key)
        has_null_ref = match.trusted_resource_ref is None or match.candidate_resource_ref is None
        identity = entry["identity"]
        identity_agrees = (
            has_null_ref and match.identity_status is IdentityStatus.DIFFERENT
            if identity is None
            else (not has_null_ref or identity == "UNCERTAIN")
            and match.identity_status.value == identity
        )
        if not identity_agrees or match.change_type.value != entry["change"]:
            problems.append(disagreement(fixture, address, entry, match))
    for match in report.resource_matches:
        if match.key not in listed and match.change_type is not ChangeType.UNCHANGED:
            problems.append(
                disagreement(fixture, match.key, "default UNCHANGED (not listed)", match)
            )
    before = {r.address for r in normalized(fixture.data["parent"]).resources}
    after = {r.address for r in normalized(fixture.data["config"]).resources}
    seen_t = {m.trusted_resource_ref for m in report.resource_matches if m.trusted_resource_ref}
    seen_c = {m.candidate_resource_ref for m in report.resource_matches if m.candidate_resource_ref}
    if seen_t != before or seen_c != after:
        problems.append(
            f"{fixture.fixture_id}: the matches do not cover every resource "
            f"(missing trusted {sorted(before - seen_t)}, "
            f"missing candidate {sorted(after - seen_c)})"
        )
    return problems


class TestTheChangesBlocks(unittest.TestCase):
    def test_there_are_eighteen_fixtures_with_a_changes_block(self) -> None:
        self.assertEqual(len(fixtures_with_changes()), 18)

    def test_every_changes_block_agrees_with_the_engine(self) -> None:
        for fixture in fixtures_with_changes():
            with self.subTest(fixture=fixture.fixture_id):
                report = run(fixture)
                problems = problems_of(fixture, report)
                self.assertEqual(problems, [], "\n" + "\n".join(problems))

    def test_the_checker_reports_a_disagreement(self) -> None:
        """A checker that cannot fail proves nothing: feed it a wrong expectation."""
        fixture = fc.load_all()[REPLACEMENT]
        wrong = fc.Fixture(
            fixture.folder,
            {
                **fixture.data,
                "changes": {
                    "default": "UNCHANGED",
                    "resources": {
                        "aws_security_group.db": {"identity": "SAME", "change": "MODIFIED"}
                    },
                },
            },
        )
        problems = problems_of(wrong, run(wrong))
        self.assertEqual(len(problems), 1)
        self.assertIn("aws_security_group.db", problems[0])
        self.assertIn("REPLACED", problems[0])
        unlisted = fc.Fixture(
            fixture.folder,
            {
                **fixture.data,
                "changes": {
                    "default": "UNCHANGED",
                    "resources": {"aws_vpc.v": {"identity": "SAME", "change": "MODIFIED"}},
                },
            },
        )
        self.assertTrue(problems_of(unlisted, run(unlisted)))

    def test_every_fixture_is_reported_by_the_identity_status_it_lists(self) -> None:
        """`identity: null` is exactly CREATED and DELETED: a match with a null ref."""
        for fixture in fixtures_with_changes():
            report = run(fixture)
            for address, entry in fixture.data["changes"]["resources"].items():
                match = next(
                    m
                    for m in report.resource_matches
                    if address in (m.trusted_resource_ref, m.candidate_resource_ref)
                )
                with self.subTest(fixture=fixture.fixture_id, address=address):
                    if entry["identity"] is None:
                        self.assertIn(
                            None, (match.trusted_resource_ref, match.candidate_resource_ref)
                        )
                    else:
                        self.assertEqual(match.identity_status.value, entry["identity"])


class TestTheTwoPinningFixtures(unittest.TestCase):
    def test_ambiguous_identity_uncertain_v1(self) -> None:
        """Parent: one aws_security_group.ops. Candidate: for_each a and b, no moved block.
        All three are identity UNCERTAIN, change UNCERTAIN; everything else UNCHANGED (C-90 AMB-1).
        """
        fixture = fc.load_all()[OPS]
        report = run(fixture)
        got = {
            m.key: (m.identity_status.value, m.change_type.value, m.rule.value)
            for m in report.resource_matches
            if m.change_type is not ChangeType.UNCHANGED
        }
        self.assertEqual(
            got,
            {
                "aws_security_group.ops->-": ("UNCERTAIN", "UNCERTAIN", "AMBIGUOUS_CANDIDATES"),
                '-->aws_security_group.ops["a"]': (
                    "UNCERTAIN",
                    "UNCERTAIN",
                    "AMBIGUOUS_CANDIDATES",
                ),
                '-->aws_security_group.ops["b"]': (
                    "UNCERTAIN",
                    "UNCERTAIN",
                    "AMBIGUOUS_CANDIDATES",
                ),
            },
        )
        self.assertEqual(problems_of(fixture, report), [])
        unchanged = {
            m.key for m in report.resource_matches if m.change_type is ChangeType.UNCHANGED
        }
        self.assertTrue(unchanged)

    def test_sg_replacement_resource_promote_v1(self) -> None:
        """aws_security_group.db renamed from name "db" to "db-v2" (ForceNew): SAME + REPLACED and
        nothing else changes, because the dependents refer to the group by reference (C-90 RT-1)."""
        fixture = fc.load_all()[REPLACEMENT]
        report = run(fixture)
        changed = [m for m in report.resource_matches if m.change_type is not ChangeType.UNCHANGED]
        self.assertEqual([m.key for m in changed], ["aws_security_group.db->aws_security_group.db"])
        match = changed[0]
        self.assertEqual(
            (match.identity_status, match.change_type, match.rule),
            (IdentityStatus.SAME, ChangeType.REPLACED, EvidenceType.REPLACE_TRIGGER_FIELD),
        )

    def test_the_ablation_loses_the_two_identity_decisions(self) -> None:
        """Hypothesis H3 is not tested here; this only shows where the labelled ablation differs on
        the two fixtures that pin identity."""
        ops = run(fc.load_all()[OPS], AddressOnlyIdentity())
        self.assertEqual(
            {
                m.change_type.value
                for m in ops.resource_matches
                if m.change_type is not ChangeType.UNCHANGED
            },
            {"DELETED", "CREATED"},
        )
        replacement = run(fc.load_all()[REPLACEMENT], AddressOnlyIdentity())
        db = next(
            m
            for m in replacement.resource_matches
            if m.trusted_resource_ref == "aws_security_group.db"
        )
        self.assertEqual(db.change_type, ChangeType.MODIFIED)


class TestFixtureReportsAreStable(unittest.TestCase):
    def test_every_fixture_report_round_trips_and_names_the_algorithm(self) -> None:
        for fixture in fixtures_with_changes():
            with self.subTest(fixture=fixture.fixture_id):
                report = run(fixture)
                self.assertEqual(IdentityReport.from_dict(report.to_dict()), report)
                self.assertEqual(report.algorithm_version, "dail-identity-1")

    def test_a_fixture_compared_with_itself_is_unchanged_except_placeholders(self) -> None:
        for folder, fixture in sorted(fc.load_all().items()):
            outcome = normalized(folder)
            report = compare(
                outcome.resources,
                outcome.resources,
                [],
                parent_state_id=PARENT,
                candidate_id=CANDIDATE,
                now=NOW,
            )
            with self.subTest(fixture=fixture.fixture_id):
                self.assertEqual(
                    {m.change_type.value for m in report.resource_matches},
                    {"UNCHANGED"} if outcome.resources else set(),
                )


if __name__ == "__main__":
    unittest.main()
