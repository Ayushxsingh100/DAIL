"""Determinism and properties of the identity engine (Doc 07 §28, §36-§37; P3b step 6).

Random configurations come from a seeded generator (stdlib ``random``); the properties are stated
from the spec, not read off the engine: a comparison of a state with itself changes nothing and
leaves unknown things unknown, swapping the two sides swaps CREATED and DELETED, every resource
is in exactly one match, and neither the order of the inputs nor the hash seed changes the report.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import textwrap
import unittest
from collections.abc import Sequence

from core.domain.enums import ChangeType, ResourceSupport
from core.domain.identity import IdentityReport
from core.domain.resource import Resource
from core.identity.addresses import block_of
from core.identity.engine import compare
from core.identity.errors import IdentityInputError
from core.identity.strategy import AddressOnlyIdentity
from tests import fixture_catalog as fc
from tests.identity_builders import CANDIDATE, NOW, PARENT, normalize
from tests.unit.test_identity_engine import VAR_N, block, tf, vpc

REPO_ROOT = fc.REPO_ROOT
LABELS = ("a", "b", "c", "d")
SWAP = {ChangeType.CREATED: ChangeType.DELETED, ChangeType.DELETED: ChangeType.CREATED}


KINDS = ("none", "vpc", "vpc", "count", "each", "unknown", "sg", "sg", "sg_unknown", "acl")
Spec = dict[str, tuple[str, str]]


def random_part(rng: random.Random, kind: str) -> tuple[str, str]:
    """The parameter of a kind: a CIDR, a count, a key set, a name or a tag."""
    if kind == "vpc":
        return kind, rng.choice(["10.0.0.0/16", "10.1.0.0/16"])
    if kind == "count":
        return kind, str(rng.choice([1, 2, 3]))
    if kind == "each":
        return kind, "".join(sorted(rng.sample("xyz", rng.choice([1, 2, 3]))))
    if kind == "sg":
        return kind, rng.choice(["p", "q", "unset"])
    if kind == "acl":
        return kind, rng.choice(["one", "two"])
    return kind, ""


def random_spec(rng: random.Random) -> Spec:
    return {label: random_part(rng, rng.choice(KINDS)) for label in LABELS}


def mutate_spec(rng: random.Random, spec: Spec) -> Spec:
    """A candidate near the trusted state: most labels unchanged, some tweaked, some replaced."""
    changed: Spec = {}
    for label, (kind, part) in spec.items():
        roll = rng.random()
        if roll < 0.45:
            changed[label] = (kind, part)
        elif roll < 0.7:
            changed[label] = random_part(rng, kind)
        else:
            changed[label] = random_part(rng, rng.choice(KINDS))
    return changed


def render(spec: Spec) -> str:
    blocks = [VAR_N]
    for label, (kind, part) in spec.items():
        if kind in ("vpc", "count", "each", "unknown"):
            extra = {
                "vpc": [],
                "count": [f"count = {part}"],
                "each": ["for_each = toset([" + ", ".join(f'"{k}"' for k in part) + "])"],
                "unknown": ["count = var.n"],
            }[kind]
            cidr = part if kind == "vpc" else "10.0.0.0/16"
            blocks.append(vpc(label, *extra, cidr=cidr))
        elif kind == "sg":
            name = {"p": 'name = "p"', "q": 'name = "q"', "unset": 'description = "d"'}[part]
            blocks.append(block(f'resource "aws_security_group" "{label}"', name))
        elif kind == "sg_unknown":
            blocks.append(block(f'resource "aws_security_group" "{label}"', "name = var.n"))
        elif kind == "acl":
            blocks.append(
                block(
                    f'resource "aws_network_acl" "{label}"',
                    'vpc_id = "v"',
                    f'tags = {{ Name = "{part}" }}',
                )
            )
    return tf(*blocks)


def random_moves(
    rng: random.Random, trusted: Sequence[Resource], candidate: Sequence[Resource]
) -> list[tuple[str, str]]:
    """A few pairs of addresses, valid or not; the engine must accept or refuse them cleanly. Most
    go from a trusted address to a candidate address of the same type."""
    moves = []
    for _ in range(rng.choice([0, 0, 1, 1, 2, 3])):
        if trusted and candidate and rng.random() < 0.7:
            source = rng.choice(trusted).address
            kind = source.split(".")[0]
            same_type = [r.address for r in candidate if r.address.split(".")[0] == kind]
            target = rng.choice(same_type or [r.address for r in candidate])
        else:
            pool = [r.address for r in trusted] + [f"aws_vpc.{label}" for label in LABELS]
            keyed = [f'aws_vpc.{label}["x"]' for label in LABELS]
            source, target = rng.choice(pool), rng.choice(pool + keyed)
        moves.append((source, target))
    return moves


def run(
    trusted: Sequence[Resource],
    candidate: Sequence[Resource],
    moves: Sequence[tuple[str, str]] = (),
    **kwargs: object,
) -> IdentityReport:
    return compare(
        trusted,
        candidate,
        moves,
        parent_state_id=PARENT,
        candidate_id=CANDIDATE,
        now=NOW,
        **kwargs,  # type: ignore[arg-type]
    )


def cases(
    seed: int, count: int
) -> list[tuple[Sequence[Resource], Sequence[Resource], random.Random]]:
    """Pairs of normalized states: the candidate is a mutation of the trusted state."""
    rng = random.Random(seed)
    found = []
    for _ in range(count):
        spec = random_spec(rng)
        trusted = normalize(render(spec)).resources
        candidate = normalize(render(mutate_spec(rng, spec))).resources
        found.append((trusted, candidate, rng))
    return found


class TestProperties(unittest.TestCase):
    SEED = 20261028

    def test_the_generator_reaches_every_class_so_the_properties_are_not_vacuous(self) -> None:
        changes: set[str] = set()
        rules: set[str] = set()
        evidence: set[str] = set()
        for trusted, candidate, rng in cases(self.SEED + 9, 150):
            moves = random_moves(rng, trusted, candidate)
            for given in (moves, []):
                try:
                    report = run(trusted, candidate, given)
                except IdentityInputError:
                    continue
                changes |= {m.change_type.value for m in report.resource_matches}
                rules |= {m.rule.value for m in report.resource_matches}
                evidence |= {e.evidence_type.value for e in report.evidence}
        self.assertEqual(
            changes, {"UNCHANGED", "MODIFIED", "CREATED", "DELETED", "REPLACED", "UNCERTAIN"}
        )
        for kind in (
            "AMBIGUOUS_CANDIDATES",
            "INDETERMINATE_BLOCK",
            "REPLACE_TRIGGER_UNRESOLVED",
            "CONFLICTING_MOVE",
        ):
            self.assertIn(kind, rules)
        for kind in ("EXPLICIT_MOVE", "IMPLICIT_COUNT_MOVE", "UNSUPPORTED_TYPE"):
            self.assertIn(kind, evidence)
        self.assertIn("UNRESOLVED_CONTENT", evidence)

    def test_comparing_a_state_with_itself_changes_nothing_and_leaves_unknowns_unknown(
        self,
    ) -> None:
        for resources, _, _ in cases(self.SEED, 60):
            report = run(resources, resources)
            by_address = {r.address: r for r in resources}
            self.assertEqual(len(report.resource_matches), len(resources))
            for match in report.resource_matches:
                self.assertEqual(match.trusted_resource_ref, match.candidate_resource_ref)
                placeholder = by_address[match.trusted_resource_ref or ""].support_status is (
                    ResourceSupport.UNKNOWN
                )
                expected = ChangeType.UNCERTAIN if placeholder else ChangeType.UNCHANGED
                self.assertIs(match.change_type, expected, match.key)

    def test_swapping_the_sides_swaps_created_and_deleted_and_keeps_the_rest(self) -> None:
        """No moves: MODIFIED, REPLACED and UNCERTAIN are symmetric (C-125 includes the
        symmetric ambiguity and C-126 the unresolved name on either side)."""
        for trusted, candidate, _ in cases(self.SEED + 1, 80):
            forward = run(trusted, candidate)
            backward = run(candidate, trusted)
            expected = {
                (m.candidate_resource_ref, m.trusted_resource_ref): SWAP.get(
                    m.change_type, m.change_type
                )
                for m in forward.resource_matches
            }
            actual = {
                (m.trusted_resource_ref, m.candidate_resource_ref): m.change_type
                for m in backward.resource_matches
            }
            self.assertEqual(actual, expected)

    def test_every_resource_is_in_exactly_one_match_with_and_without_moves(self) -> None:
        refused = 0
        for trusted, candidate, rng in cases(self.SEED + 2, 120):
            moves = random_moves(rng, trusted, candidate)
            try:
                report = run(trusted, candidate, moves)
            except IdentityInputError:
                refused += 1  # a cycle, or two destinations: refused as Terraform refuses them
                continue
            seen_t = sorted(
                m.trusted_resource_ref for m in report.resource_matches if m.trusted_resource_ref
            )
            seen_c = sorted(
                m.candidate_resource_ref
                for m in report.resource_matches
                if m.candidate_resource_ref
            )
            self.assertEqual(seen_t, sorted(r.address for r in trusted))
            self.assertEqual(seen_c, sorted(r.address for r in candidate))
        self.assertLess(refused, 60)

    def test_the_change_agrees_with_the_fingerprints_of_the_pair(self) -> None:
        for trusted, candidate, _ in cases(self.SEED + 3, 80):
            before = {r.address: r for r in trusted}
            after = {r.address: r for r in candidate}
            for match in run(trusted, candidate).resource_matches:
                if match.trusted_resource_ref is None or match.candidate_resource_ref is None:
                    continue
                left, right = (
                    before[match.trusted_resource_ref],
                    after[match.candidate_resource_ref],
                )
                if match.change_type is ChangeType.UNCHANGED:
                    self.assertEqual(left.fingerprint, right.fingerprint)
                    self.assertNotIn(
                        ResourceSupport.UNKNOWN, (left.support_status, right.support_status)
                    )
                if match.change_type is ChangeType.MODIFIED:
                    self.assertNotEqual(left.fingerprint, right.fingerprint)

    def test_unknown_is_never_created_or_deleted(self) -> None:
        """Missing knowledge is not proof of absence: a CREATED or DELETED resource never sits in
        a block whose other side has an unknown number of instances."""
        for trusted, candidate, _ in cases(self.SEED + 4, 100):
            placeholders_t = {
                r.address for r in trusted if r.support_status is ResourceSupport.UNKNOWN
            }
            placeholders_c = {
                r.address for r in candidate if r.support_status is ResourceSupport.UNKNOWN
            }
            for match in run(trusted, candidate).resource_matches:
                if match.change_type is ChangeType.DELETED:
                    self.assertNotIn(block_of(match.trusted_resource_ref or ""), placeholders_c)
                if match.change_type is ChangeType.CREATED:
                    self.assertNotIn(block_of(match.candidate_resource_ref or ""), placeholders_t)
                for ref, side in (
                    (match.trusted_resource_ref, placeholders_t),
                    (match.candidate_resource_ref, placeholders_c),
                ):
                    if ref in side:
                        self.assertIs(match.change_type, ChangeType.UNCERTAIN, match.key)

    def test_the_ablation_keeps_the_same_partition_and_never_reports_replaced(self) -> None:
        for trusted, candidate, _ in cases(self.SEED + 5, 60):
            report = run(trusted, candidate, strategy=AddressOnlyIdentity())
            self.assertEqual(
                sorted(
                    m.trusted_resource_ref
                    for m in report.resource_matches
                    if m.trusted_resource_ref
                ),
                sorted(r.address for r in trusted),
            )
            self.assertNotIn(ChangeType.REPLACED, {m.change_type for m in report.resource_matches})

    def test_every_report_validates_and_round_trips(self) -> None:
        for trusted, candidate, _ in cases(self.SEED + 6, 40):
            report = run(trusted, candidate)
            self.assertEqual(IdentityReport.from_dict(report.to_dict()), report)


class TestDeterminism(unittest.TestCase):
    SEED = 424242

    def test_shuffled_inputs_give_a_byte_identical_report_hash(self) -> None:
        shuffler = random.Random(self.SEED)
        for trusted, candidate, rng in cases(self.SEED, 50):
            moves = random_moves(rng, trusted, candidate)
            try:
                reference = run(trusted, candidate, moves)
            except IdentityInputError:
                continue
            for _ in range(3):
                again = run(
                    shuffler.sample(list(trusted), len(trusted)),
                    shuffler.sample(list(candidate), len(candidate)),
                    shuffler.sample(moves, len(moves)),
                )
                self.assertEqual(again.content_hash, reference.content_hash)
                self.assertEqual(
                    again.to_dict()["resource_matches"], reference.to_dict()["resource_matches"]
                )
                self.assertEqual(again.to_dict()["evidence"], reference.to_dict()["evidence"])

    def test_repeated_runs_are_identical(self) -> None:
        trusted, candidate, _ = cases(self.SEED + 1, 1)[0]
        hashes = {run(trusted, candidate).content_hash for _ in range(10)}
        self.assertEqual(len(hashes), 1)

    SCRIPT = textwrap.dedent("""
        import sys
        sys.path.insert(0, ".")
        from core.identity.engine import compare
        from core.identity.strategy import AddressOnlyIdentity
        from tests.identity_builders import CANDIDATE, NOW, PARENT, normalize
        from tests.unit.test_identity_engine import VAR_N, moved, sg, tf, vpc

        before = tf(VAR_N, vpc("ops"), vpc("a"), sg("g", name='"x"'))
        before += tf(vpc("u", "count = var.n"), vpc("k", "count = 2"))
        keys = 'for_each = toset(["a", "b", "c"])'
        text = tf(VAR_N, vpc("ops", keys), vpc("b"), moved("aws_vpc.a", "aws_vpc.b"))
        text += tf(sg("g", name='"y"'), vpc("u", "count = 2"), vpc("k"), vpc("n"))
        trusted, after = normalize(before).resources, normalize(text)
        for strategy in (None, AddressOnlyIdentity()):
            extra = {} if strategy is None else {"strategy": strategy}
            report = compare(
                trusted, after.resources, after.moves,
                parent_state_id=PARENT, candidate_id=CANDIDATE, now=NOW, **extra,
            )
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
        """Four fixed PYTHONHASHSEED values, then two isolated runs. ``-I`` makes Python ignore
        PYTHONHASHSEED and pick a random seed each time, so the fixed seeds run without it."""
        reference = self.hashes_under(seed="0")
        self.assertEqual(len(reference), 2)
        self.assertNotEqual(reference[0], reference[1])
        for seed in ("1", "4242", "99991"):
            with self.subTest(PYTHONHASHSEED=seed):
                self.assertEqual(self.hashes_under(seed=seed), reference)
        for attempt in range(2):
            with self.subTest(isolated=attempt):
                self.assertEqual(self.hashes_under("-I"), reference)


if __name__ == "__main__":
    unittest.main()
