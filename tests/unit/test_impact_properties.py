"""Determinism and the no-silent-under-approximation sweep (P4 step 7; Doc 08 §30, §32; Doc 12
§11, §18; Doc 15 §11.2; C-140).

Seeded ``random`` only (standard library), so a failure is reproducible from the seed in the
message. The sweep generates small transitions from the network of ``tests.impact_builders.NET``
and checks, for every invariant, that no change that reaches its footprint is ever reported as
unaffected.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import textwrap
import unittest
from collections.abc import Callable
from pathlib import Path

from core.domain.enums import ChangeType, ImpactStatus
from core.domain.impact import ImpactReport, UnaffectedInvariant, WorkTargetType
from core.domain.resource import Resource
from core.identity.engine import compare
from core.impact.walk import footprint, walkable_types
from tests.identity_builders import normalize
from tests.impact_builders import (
    DB_BLOCK,
    NET,
    NOW,
    PIPE_CANDIDATE,
    PIPE_PARENT,
    graph_of,
    impact_of_outcomes,
    impacted,
    impacted_ids,
    registry,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SEC_TYPES = {
    "aws_security_group",
    "aws_security_group_rule",
    "aws_vpc_security_group_ingress_rule",
    "aws_default_security_group",
    "aws_vpc_security_group_rules_exclusive",
}
STRUCTURAL = (ChangeType.MODIFIED, ChangeType.CREATED, ChangeType.DELETED, ChangeType.REPLACED)

# --- generated transitions -----------------------------------------------------------------------

VPC_OLD = 'cidr_block = "10.0.0.0/16" }\nresource "aws_vpc" "elsewhere"'
VPC_NEW = 'cidr_block = "10.1.0.0/16" }\nresource "aws_vpc" "elsewhere"'
INSTANCE_APP = 'resource "aws_instance" "app" {\n  ami = "a"'
INSTANCE_OTHER = 'resource "aws_instance" "unrelated" {\n  ami = "a"'
TAGS = '{\n  vpc_id = aws_vpc.main.id\n  tags = { x = "1" }\n}'


def drop_block(text: str, header: str) -> str | None:
    start = text.find(header)
    if start == -1:
        return None
    end = text.index("\n}\n", start) + 3
    return text[:start] + text[end:]


def replace(old: str, new: str) -> Callable[[str], str | None]:
    return lambda text: text.replace(old, new, 1) if text.count(old) == 1 else None


def remove(header: str) -> Callable[[str], str | None]:
    return lambda text: drop_block(text, header)


def add(block: str) -> Callable[[str], str | None]:
    return lambda text: text + block


# name -> edit of the candidate text (None when the anchor is gone)
MUTATIONS: dict[str, Callable[[str], str | None]] = {
    "sg_app": replace('description = "d"', 'description = "e"'),
    "sg_db_replace": replace('name = "db"', 'name = "db2"'),
    "rule_app": replace("from_port = 0", "from_port = 1"),
    "rule_db": replace("from_port = 5432", "from_port = 5433"),
    "rule_stray": replace("from_port = 80", "from_port = 81"),
    "instance_app": replace(INSTANCE_APP, INSTANCE_APP.replace('"a"', '"b"')),
    "instance_unrelated": replace(INSTANCE_OTHER, INSTANCE_OTHER.replace('"a"', '"b"')),
    "database": replace('identifier = "d"', 'identifier = "e"'),
    "vpc_main": replace(VPC_OLD, VPC_NEW),
    "vpc_elsewhere": replace('cidr_block = "10.9.0.0/16"', 'cidr_block = "10.8.0.0/16"'),
    "subnet_app": replace('cidr_block = "10.0.1.0/24"', 'cidr_block = "10.0.2.0/24"'),
    "subnet_other": replace('cidr_block = "10.0.9.0/24"', 'cidr_block = "10.0.8.0/24"'),
    "igw_tag": replace(
        'resource "aws_internet_gateway" "igw" { vpc_id = aws_vpc.main.id }',
        'resource "aws_internet_gateway" "igw" {\n  vpc_id = aws_vpc.main.id\n'
        '  tags = { x = "1" }\n}',
    ),
    "rt_public_tag": replace(
        'resource "aws_route_table" "public" { vpc_id = aws_vpc.main.id }',
        'resource "aws_route_table" "public" ' + TAGS,
    ),
    "rt_elsewhere_tag": replace(
        'resource "aws_route_table" "elsewhere" { vpc_id = aws_vpc.elsewhere.id }',
        'resource "aws_route_table" "elsewhere" {\n  vpc_id = aws_vpc.elsewhere.id\n'
        '  tags = { x = "1" }\n}',
    ),
    "association": replace(
        "route_table_id = aws_route_table.public.id",
        "route_table_id = aws_route_table.elsewhere.id",
    ),
    "del_rule_stray": remove('resource "aws_security_group_rule" "to_stray"'),
    "del_rule_app": remove('resource "aws_security_group_rule" "to_app"'),
    "del_unrelated": remove('resource "aws_instance" "unrelated"'),
    "del_database": replace(DB_BLOCK, ""),
    "add_sg": add('resource "aws_security_group" "extra" {\n  name = "x"\n}\n'),
    "add_subnet": add('resource "aws_subnet" "new" {\n  cidr_block = "10.0.7.0/24"\n}\n'),
    "add_acl": add('resource "aws_network_acl" "extra" {\n  vpc_id = aws_vpc.main.id\n}\n'),
}
UNRELATED = (
    "igw_tag",
    "association",
    "rt_elsewhere_tag",
    "vpc_elsewhere",
    "subnet_other",
    "instance_unrelated",
    "del_unrelated",
)

OLD_SUBNET = (
    "  subnet_id = aws_subnet.app.id\n  vpc_security_group_ids = [aws_security_group.app.id]"
)
BASES: dict[str, Callable[[str], str]] = {
    "plain": lambda text: text,
    "unknown_subnet": lambda text: text.replace(
        OLD_SUBNET, OLD_SUBNET.replace("aws_subnet.app.id", "var.unset")
    ),
    "loose_rule": lambda text: text.replace(
        'cidr_blocks = ["0.0.0.0/0"]', "cidr_blocks = [var.unset]"
    ),
}
OPS_SINGLE = 'resource "aws_security_group" "ops" {\n  name = "ops"\n}\n'
OPS_KEYED = (
    'resource "aws_security_group" "ops" {\n  for_each = toset(["a", "b"])\n'
    '  name = "ops-${each.key}"\n}\n'
)


def build_case(rng: random.Random) -> tuple[str, str, list[str], str] | None:
    base_name = rng.choice(sorted(BASES))
    old = BASES[base_name](NET)
    ambiguous = rng.random() < 0.15
    new = old
    chosen: list[str] = []
    for name in rng.sample(sorted(MUTATIONS), rng.randint(0, 4)):
        edited = MUTATIONS[name](new)
        if edited is not None:
            new = edited
            chosen.append(name)
    if ambiguous:
        old, new = old + OPS_SINGLE, new + OPS_KEYED
        chosen.append("ops_identity")
    return old, new, sorted(chosen), base_name


def pipeline(
    old: str, new: str, *, shuffle: random.Random | None = None
) -> tuple[ImpactReport, tuple[Resource, ...], tuple[Resource, ...]]:
    before, after = normalize(old), normalize(new)
    trusted, candidate = list(before.resources), list(after.resources)
    if shuffle is not None:
        shuffle.shuffle(trusted)
        shuffle.shuffle(candidate)
    report = impact_of_outcomes(tuple(trusted), tuple(candidate), list(after.moves))
    return report, tuple(trusted), tuple(candidate)


# --- the properties -----------------------------------------------------------------------


def check_no_silent_under_approximation(
    report: ImpactReport,
    trusted: tuple[Resource, ...],
    candidate: tuple[Resource, ...],
    where: object,
) -> None:
    """Raises AssertionError when a change that reaches an invariant's footprint is not reported."""
    definitions = registry()
    identity = compare(
        trusted,
        candidate,
        [],
        parent_state_id=PIPE_PARENT,
        candidate_id=PIPE_CANDIDATE,
        now=NOW,
    )
    trusted_graph = graph_of(trusted, invariants=list(definitions.values()))
    candidate_graph = graph_of(candidate, invariants=list(definitions.values()))
    changes = [m for m in identity.resource_matches if m.change_type is not ChangeType.UNCHANGED]
    types = {r.address: r.resource_type for r in (*trusted, *candidate)}
    unaffected = {u.key(): u for u in report.unaffected}
    impacted_by_id = {item.invariant_id: item for item in report.affected_invariants}
    for invariant_id, definition in definitions.items():
        key = (invariant_id, definition.version)
        footprints = (
            footprint(trusted_graph, definition),
            footprint(candidate_graph, definition),
        )
        reached = []
        for match in changes:
            refs = [r for r in (match.trusted_resource_ref, match.candidate_resource_ref) if r]
            member = any(f.find(ref) for f in footprints for ref in refs)
            if invariant_id in ("INV-SEC-001", "INV-SEC-002"):  # independent of the walk
                member = member or any(types[ref] in SEC_TYPES for ref in refs)
            if invariant_id == "INV-SEC-003":
                member = member or any(types[ref] == "aws_db_instance" for ref in refs)
            if member:
                reached.append(match)
        # (1) a change that reaches the footprint is never unaffected
        if reached:
            assert (
                key not in unaffected
            ), f"{where}: {invariant_id} unaffected but {reached[0]} reaches it"
            assert invariant_id in impacted_by_id, f"{where}: {invariant_id} missing"
            if any(m.change_type in STRUCTURAL for m in reached):
                assert (
                    impacted_by_id[invariant_id].status is ImpactStatus.AFFECTED
                ), f"{where}: {invariant_id} should be AFFECTED"
        # (2) an unaffected invariant: nothing reaches it, no absent endpoint, and an incomplete
        # footprint has no changed resource of a walkable type
        if key in unaffected:
            assert all(not f.absent_seeds for f in footprints), f"{where}: {invariant_id} absent"
            if any(not f.complete for f in footprints):
                walkable = walkable_types(definition, list(footprints))
                for match in changes:
                    ref = match.candidate_resource_ref or match.trusted_resource_ref
                    assert ref is not None
                    assert walkable is not None and types[ref] not in walkable, (
                        f"{where}: {invariant_id} unaffected under an incomplete walk, "
                        f"{ref} is walkable"
                    )
    # (3) the work set
    work_targets = {w.target_id for w in report.verification_work}
    for item in report.affected_invariants:
        assert f"INVARIANT:{item.invariant_id}:{item.invariant_version}" in work_targets, where
    for change in report.changed_resources:
        if change.change_type is ChangeType.CREATED:
            assert f"RESOURCE:{change.address}" in work_targets, f"{where}: no baseline work"
    assert all(w.priority.value == "BLOCKING" for w in report.verification_work), where
    for work in report.verification_work:
        if work.target_type is WorkTargetType.RESOURCE:
            assert work.target_id.removeprefix("RESOURCE:") in {
                c.address for c in report.changed_resources
            }, where


class TestNoSilentUnderApproximation(unittest.TestCase):
    SEED = 20261028
    CASES = 120

    def test_generated_transitions_are_never_under_approximated(self) -> None:
        checked = 0
        for case in range(self.CASES):
            rng = random.Random(self.SEED + case)
            old, new, chosen, base = build_case(rng)  # type: ignore[misc]
            try:
                report, trusted, candidate = pipeline(old, new)
            except AssertionError:
                continue  # the front end did not accept this combination
            check_no_silent_under_approximation(
                report, trusted, candidate, f"seed {self.SEED + case} {base} {chosen}"
            )
            checked += 1
        self.assertGreaterEqual(checked, 100, "the generator should mostly give valid transitions")

    def test_the_generator_reaches_every_kind_of_outcome(self) -> None:
        seen: set[str] = set()
        for case in range(self.CASES):
            rng = random.Random(self.SEED + case)
            old, new, _, _ = build_case(rng)  # type: ignore[misc]
            try:
                report, _, _ = pipeline(old, new)
            except AssertionError:
                continue
            for item in report.affected_invariants:
                seen.add(item.status.value)
                seen.update(r.code.value for r in item.reasons)
            if not report.affected_invariants:
                seen.add("NOTHING")
            seen.update(w.reason.value for w in report.verification_work)
        for wanted in (
            "AFFECTED",
            "UNCERTAIN",
            "NOTHING",
            "SCOPE_RESOURCE_CHANGED",
            "SCOPE_TYPE_CHANGED",
            "FOOTPRINT_MEMBER_CHANGED",
            "CREATED_IN_SCOPE",
            "DELETED_IN_SCOPE",
            "REPLACED_IN_SCOPE",
            "IDENTITY_UNCERTAIN",
            "UNRESOLVED_CONTENT",
            "WALK_INCOMPLETE",
            "ENDPOINT_ABSENT",
            "CREATED_BASELINE",
        ):
            self.assertIn(wanted, seen, wanted)

    def test_the_checker_fails_when_an_invariant_is_dropped(self) -> None:
        # a checker that cannot fail proves nothing: move an impacted invariant to "unaffected"
        old = NET
        new = NET.replace('description = "d"', 'description = "e"')
        report, trusted, candidate = pipeline(old, new)
        check_no_silent_under_approximation(report, trusted, candidate, "intact")
        dropped = report.affected_invariants[0]
        kept = [i for i in report.affected_invariants if i is not dropped]
        broken = ImpactReport.create(
            parent_state_id=report.parent_state_id,
            candidate_id=report.candidate_id,
            changed_resources=report.changed_resources,
            affected_invariants=kept,
            verification_work=[
                w for w in report.verification_work if dropped.invariant_id not in w.target_id
            ],
            uncertainty=[],
            unaffected=[
                *report.unaffected,
                UnaffectedInvariant(
                    dropped.invariant_id,
                    dropped.invariant_version,
                    (),
                    False,
                    next(iter({u.reason for u in report.unaffected})),
                ),
            ],
            graph_version=report.graph_version,
            trusted_graph_hash=report.trusted_graph_hash,
            candidate_graph_hash=report.candidate_graph_hash,
            identity_report_hash=report.identity_report_hash,
            now=NOW,
        )
        with self.assertRaises(AssertionError):
            check_no_silent_under_approximation(broken, trusted, candidate, "broken")

    def test_the_checker_fails_when_a_work_item_is_dropped(self) -> None:
        old = NET
        new = NET + 'resource "aws_subnet" "new" {\n  cidr_block = "10.0.7.0/24"\n}\n'
        report, trusted, candidate = pipeline(old, new)
        check_no_silent_under_approximation(report, trusted, candidate, "intact")
        self.assertEqual(len(report.verification_work), 1)
        with self.assertRaises(ValueError):  # the report type itself refuses a report without it
            ImpactReport.create(
                parent_state_id=report.parent_state_id,
                candidate_id=report.candidate_id,
                changed_resources=report.changed_resources,
                affected_invariants=[],
                verification_work=[],
                uncertainty=[],
                unaffected=report.unaffected,
                graph_version=report.graph_version,
                trusted_graph_hash=report.trusted_graph_hash,
                candidate_graph_hash=report.candidate_graph_hash,
                identity_report_hash=report.identity_report_hash,
                now=NOW,
            )


class TestUnrelatedChanges(unittest.TestCase):
    """On a complete walk, adding changes outside every footprint changes nothing (Doc 08 §30)."""

    SEED = 77

    def test_unrelated_changes_do_not_alter_the_impacted_invariants(self) -> None:
        for case in range(40):
            rng = random.Random(self.SEED + case)
            old = NET
            core_edits = rng.sample(
                [
                    m
                    for m in sorted(MUTATIONS)
                    if m not in UNRELATED and not m.startswith("add_acl")
                ],
                rng.randint(0, 3),
            )
            base = old
            for name in core_edits:
                edited = MUTATIONS[name](base)
                if edited is not None:
                    base = edited
            plus = base
            for name in UNRELATED:
                edited = MUTATIONS[name](plus)
                if edited is not None:
                    plus = edited
            if plus == base:
                continue
            try:
                without, _, _ = pipeline(old, base)
                with_noise, _, _ = pipeline(old, plus)
            except AssertionError:
                continue
            with self.subTest(case=case, edits=core_edits):
                self.assertEqual(impacted_ids(without), impacted_ids(with_noise))
                for invariant_id, item in impacted(without).items():
                    other = impacted(with_noise)[invariant_id]
                    self.assertEqual(item.status, other.status)
                    self.assertEqual(
                        {r.code for r in item.reasons}, {r.code for r in other.reasons}
                    )


# --- determinism --------------------------------------------------------------------------


class TestDeterminism(unittest.TestCase):
    SEED = 20261028

    def test_shuffled_inputs_give_the_same_hash(self) -> None:
        old = NET + OPS_SINGLE
        new = NET.replace('description = "d"', 'description = "e"') + OPS_KEYED
        reference, _, _ = pipeline(old, new)
        rng = random.Random(self.SEED)
        for _ in range(8):
            again, _, _ = pipeline(old, new, shuffle=rng)
            self.assertEqual(again.content_hash, reference.content_hash)
            self.assertEqual(
                again.to_dict()["affected_invariants"], reference.to_dict()["affected_invariants"]
            )
            self.assertEqual(
                again.to_dict()["verification_work"], reference.to_dict()["verification_work"]
            )

    def test_shuffled_invariant_order_gives_the_same_hash(self) -> None:
        old, new = NET, NET.replace('identifier = "d"', 'identifier = "e"')
        before, after = normalize(old), normalize(new)
        definitions = list(registry().values())
        rng = random.Random(self.SEED)
        hashes = set()
        for _ in range(6):
            order = rng.sample(definitions, len(definitions))
            report = impact_of_outcomes(
                before.resources, after.resources, list(after.moves), invariants=order
            )
            hashes.add(report.content_hash)
        self.assertEqual(len(hashes), 1)

    def test_repeated_runs_are_identical(self) -> None:
        old, new = NET, NET.replace('description = "d"', 'description = "e"')
        self.assertEqual(len({pipeline(old, new)[0].content_hash for _ in range(6)}), 1)

    def test_the_report_id_and_the_clock_do_not_reach_the_hash(self) -> None:
        first, _, _ = pipeline(NET, NET.replace('description = "d"', 'description = "e"'))
        second, _, _ = pipeline(NET, NET.replace('description = "d"', 'description = "e"'))
        self.assertNotEqual(first.report_id, second.report_id)
        self.assertEqual(first.content_hash, second.content_hash)

    SCRIPT = textwrap.dedent("""
        import sys
        sys.path.insert(0, ".")
        from core.terraform_model.normalization import normalize_directory
        from tests.impact_builders import NOW, impact_of_outcomes

        pairs = (
            ("canonical_regression/baseline", "canonical_regression/patch_safe"),
            ("canonical_regression/patch_safe", "dependency/func_unknown_dependency_unknown_v1"),
            ("identity/ambiguous_identity_parent_v1", "identity/ambiguous_identity_uncertain_v1"),
            ("canonical_regression/patch_safe", "impact/rds_deleted_dependency_fail_v1"),
        )
        for parent, config in pairs:
            before = normalize_directory("fixtures/" + parent, None, now=NOW)
            after = normalize_directory("fixtures/" + config, None, now=NOW)
            report = impact_of_outcomes(before.resources, after.resources, list(after.moves))
            print(report.content_hash)
        """)

    def hashes_under(self, *flags: str, seed: str | None = None) -> list[str]:
        env = {key: value for key, value in os.environ.items() if key != "PYTHONHASHSEED"}
        if seed is not None:
            env["PYTHONHASHSEED"] = seed
        env["PYTHONPATH"] = str(REPO_ROOT)
        result = subprocess.run(
            [sys.executable, *flags, "-c", self.SCRIPT],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.split()

    def test_the_hash_does_not_depend_on_the_hash_seed(self) -> None:
        """Four fixed PYTHONHASHSEED values, then two isolated runs (``-I`` ignores the variable
        and picks a random seed each time, so the fixed seeds run without it)."""
        reference = self.hashes_under(seed="0")
        self.assertEqual(len(reference), 4)
        self.assertEqual(len(set(reference)), 4)
        for seed in ("1", "4242", "99991"):
            with self.subTest(PYTHONHASHSEED=seed):
                self.assertEqual(self.hashes_under(seed=seed), reference)
        for attempt in range(2):
            with self.subTest(isolated=attempt):
                self.assertEqual(self.hashes_under("-I"), reference)


if __name__ == "__main__":
    unittest.main()
