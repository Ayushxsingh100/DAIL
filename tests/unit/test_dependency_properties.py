"""Determinism, metamorphic and no-silent-gap properties of the dependency graph (P3c step 7;
Doc 07 §24, §28, §34, §36.3; Doc 12 §18; Doc 15 §10.3).

Seeded ``random`` only (standard library), so a failure is reproducible from the seed in the
message.
"""

from __future__ import annotations

import os
import random
import subprocess
import sys
import textwrap
import unittest
from collections import Counter
from collections.abc import Sequence
from pathlib import Path

from core.dependency.build import build_graph
from core.domain.enums import DependencyStatus, ResourceSupport
from core.domain.graph import DerivationRule, EdgeType
from core.domain.resource import Resource
from tests.graph_builders import (
    BASELINE,
    NOW,
    STATE,
    fixture_resources,
    func_001,
    func_binding,
    resources_of,
    sec_001,
    sec_002,
    sec_003,
)
from tests.unit.test_dependency_infrastructure import SECTION_16

REPO_ROOT = Path(__file__).resolve().parents[2]
UC, UN = DependencyStatus.UNCERTAIN, DependencyStatus.UNSUPPORTED


def graph_of(resources: Sequence[Resource]):  # type: ignore[no-untyped-def]
    return build_graph(
        resources,
        [sec_001(), sec_002(), sec_003(), func_001()],
        [func_binding()],
        state_id=STATE,
        now=NOW,
    )


# --- determinism -------------------------------------------------------------------------------


class TestDeterminism(unittest.TestCase):
    SEED = 20261028

    def test_resource_and_invariant_order_do_not_change_the_hash(self) -> None:
        rng = random.Random(self.SEED)
        base = list(fixture_resources(BASELINE))
        reference = graph_of(base)
        for _ in range(10):
            shuffled = rng.sample(base, len(base))
            invariants = rng.sample([sec_001(), sec_002(), sec_003(), func_001()], 4)
            again = build_graph(shuffled, invariants, [func_binding()], state_id=STATE, now=NOW)
            self.assertEqual(again.graph_hash, reference.graph_hash)
            self.assertEqual(again.to_dict()["nodes"], reference.to_dict()["nodes"])
            self.assertEqual(
                [e.edge_key for e in again.edges], [e.edge_key for e in reference.edges]
            )

    def test_repeated_runs_are_identical(self) -> None:
        base = list(fixture_resources(BASELINE))
        self.assertEqual(len({graph_of(base).graph_hash for _ in range(10)}), 1)

    SCRIPT = textwrap.dedent("""
        import sys
        sys.path.insert(0, ".")
        from core.dependency.build import build_graph
        from tests.graph_builders import NOW, STATE, fixture_resources, func_001, func_binding
        from tests.graph_builders import sec_001, sec_002, sec_003

        folders = (
            "fixtures/canonical_regression/baseline",
            "fixtures/dependency/func_unknown_dependency_unknown_v1",
            "fixtures/identity/ambiguous_identity_uncertain_v1",
            "fixtures/impact/rds_deleted_dependency_fail_v1",
        )
        for folder in folders:
            graph = build_graph(
                fixture_resources(folder),
                [sec_001(), sec_002(), sec_003(), func_001()],
                [func_binding()],
                state_id=STATE,
                now=NOW,
            )
            print(graph.graph_hash)

        # two start nodes that both reach the vpc at the same depth: which edge first reached it
        # must not depend on the order a set of start nodes happens to iterate in
        from core.dependency.traversal import Direction, reachable

        graph = build_graph(fixture_resources(folders[0]), [], state_id=STATE, now=NOW)
        found = reachable(
            graph,
            {"RESOURCE:aws_instance.app", "RESOURCE:aws_db_instance.database"},
            direction=Direction.FORWARD,
        )
        print(found.via["RESOURCE:aws_vpc.main"])
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
        self.assertEqual(len(reference), 5)  # four graph hashes and one traversal edge key
        self.assertEqual(len(set(reference[:4])), 4)
        for seed in ("1", "4242", "99991"):
            with self.subTest(PYTHONHASHSEED=seed):
                self.assertEqual(self.hashes_under(seed=seed), reference)
        for attempt in range(2):
            with self.subTest(isolated=attempt):
                self.assertEqual(self.hashes_under("-I"), reference)

    def test_the_subprocess_hash_equals_the_in_process_hash(self) -> None:
        in_process = graph_of(list(fixture_resources(BASELINE))).graph_hash
        self.assertEqual(self.hashes_under(seed="7")[0], in_process)


# --- metamorphic -------------------------------------------------------------------------------

BASE = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_security_group" "app" {
  name = "app"
  description = "d"
  vpc_id = aws_vpc.main.id
  tags = { team = "a" }
}
resource "aws_security_group" "db" {
  name = "db"
  vpc_id = aws_vpc.main.id
}
%(rules)s
resource "aws_instance" "app" {
  ami = "ami-1"
  subnet_id = "subnet-1"
  vpc_security_group_ids = [aws_security_group.app.id]
  tags = { team = "a" }
}
"""

RULE_A = """
resource "aws_security_group_rule" "a" {
  type = "ingress"
  protocol = "tcp"
  from_port = 5432
  to_port = 5432
  cidr_blocks = ["10.0.0.0/8", "192.168.0.0/16"]
  security_group_id = aws_security_group.db.id
}
"""
RULE_B = """
resource "aws_security_group_rule" "b" {
  type = "ingress"
  protocol = "tcp"
  from_port = 22
  to_port = 22
  source_security_group_id = aws_security_group.app.id
  security_group_id = aws_security_group.db.id
}
"""


def hash_of(text: str) -> str:
    return graph_of(list(resources_of(text))).graph_hash


class TestMetamorphic(unittest.TestCase):
    def base(self, rules: str = RULE_A + RULE_B) -> str:
        return BASE % {"rules": rules}

    def test_the_order_of_the_rule_resources_does_not_change_the_hash(self) -> None:
        self.assertEqual(hash_of(self.base(RULE_A + RULE_B)), hash_of(self.base(RULE_B + RULE_A)))

    def test_the_order_of_the_cidrs_does_not_change_the_hash(self) -> None:
        reversed_rule = RULE_A.replace(
            '["10.0.0.0/8", "192.168.0.0/16"]', '["192.168.0.0/16", "10.0.0.0/8"]'
        )
        self.assertEqual(hash_of(self.base()), hash_of(self.base(reversed_rule + RULE_B)))

    def test_the_order_of_inline_blocks_does_not_change_the_hash(self) -> None:
        def group(first: str, second: str) -> str:
            return f"""
resource "aws_vpc" "main" {{ cidr_block = "10.0.0.0/16" }}
resource "aws_security_group" "g" {{
  name = "g"
  vpc_id = aws_vpc.main.id
  {first}
  {second}
}}
"""

        def block(port: int) -> str:
            return (
                "ingress {\n"
                '    protocol = "tcp"\n'
                f"    from_port = {port}\n"
                f"    to_port = {port}\n"
                '    cidr_blocks = ["10.0.0.0/8"]\n'
                "  }"
            )

        ssh, pg = block(22), block(5432)
        self.assertEqual(hash_of(group(ssh, pg)), hash_of(group(pg, ssh)))

    def test_a_tag_only_change_does_not_change_the_hash(self) -> None:
        tagged = self.base().replace('team = "a"', 'team = "b", extra = "c"')
        self.assertNotEqual(tagged, self.base())
        self.assertEqual(hash_of(tagged), hash_of(self.base()))

    def test_a_description_and_name_change_does_not_change_the_hash(self) -> None:
        renamed = (
            self.base()
            .replace('description = "d"', 'description = "other"')
            .replace('name = "db"', 'name = "db-v2"')
        )
        self.assertEqual(hash_of(renamed), hash_of(self.base()))

    def test_a_port_change_changes_the_rule_node_and_the_hash(self) -> None:
        changed = self.base().replace("to_port = 5432", "to_port = 5433")
        self.assertNotEqual(hash_of(changed), hash_of(self.base()))

    def test_a_source_change_changes_the_rule_node_and_the_hash(self) -> None:
        changed = self.base().replace('"192.168.0.0/16"', '"0.0.0.0/0"')
        self.assertNotEqual(hash_of(changed), hash_of(self.base()))
        before = graph_of(list(resources_of(self.base())))
        after = graph_of(list(resources_of(changed)))
        node = "RESOURCE:aws_security_group_rule.a"
        self.assertNotEqual(
            before.node(node).attributes["rule_key"],  # type: ignore[union-attr]
            after.node(node).attributes["rule_key"],  # type: ignore[union-attr]
        )

    def test_a_changed_reference_changes_the_hash(self) -> None:
        changed = self.base().replace(
            "vpc_security_group_ids = [aws_security_group.app.id]",
            "vpc_security_group_ids = [aws_security_group.db.id]",
        )
        self.assertNotEqual(hash_of(changed), hash_of(self.base()))

    def test_a_literal_in_place_of_a_reference_changes_the_hash(self) -> None:
        changed = self.base().replace(
            "vpc_security_group_ids = [aws_security_group.app.id]",
            'vpc_security_group_ids = ["sg-1"]',
        )
        self.assertNotEqual(hash_of(changed), hash_of(self.base()))

    def test_a_renamed_resource_changes_the_hash(self) -> None:
        self.assertNotEqual(
            hash_of(self.base()),
            hash_of(self.base().replace('"aws_instance" "app"', '"aws_instance" "web"')),
        )

    def test_rule_rewrites_that_keep_the_meaning_keep_the_rule_key(self) -> None:
        # registry §2.6: an inline rule and a rule resource with the same meaning share a key
        inline = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_security_group" "db" {
  name = "db"
  vpc_id = aws_vpc.main.id
  ingress {
    protocol = "tcp"
    from_port = 5432
    to_port = 5432
    cidr_blocks = ["10.0.0.0/8"]
  }
}
"""
        separate = """
resource "aws_vpc" "main" { cidr_block = "10.0.0.0/16" }
resource "aws_security_group" "db" {
  name = "db"
  vpc_id = aws_vpc.main.id
}
resource "aws_security_group_rule" "r" {
  type = "ingress"
  protocol = "tcp"
  from_port = 5432
  to_port = 5432
  cidr_blocks = ["10.0.0.0/8"]
  security_group_id = aws_security_group.db.id
}
"""
        first = graph_of(list(resources_of(inline)))
        second = graph_of(list(resources_of(separate)))
        inline_keys = first.node("RESOURCE:aws_security_group.db").attributes["inline_rule_keys"]  # type: ignore[union-attr]
        rule_key = second.node("RESOURCE:aws_security_group_rule.r").attributes["rule_key"]  # type: ignore[union-attr]
        self.assertEqual(list(inline_keys), [rule_key])


# --- no silent gap -----------------------------------------------------------------------------

# Kinds in dependency order, so a generated configuration has no reference cycle.
KINDS = (
    ("aws_vpc", "v0"),
    ("aws_subnet", "s0"),
    ("aws_subnet", "s1"),
    ("aws_internet_gateway", "g0"),
    ("aws_security_group", "sg0"),
    ("aws_security_group", "sg1"),
    ("aws_route_table", "rt0"),
    ("aws_route_table_association", "a0"),
    ("aws_instance", "i0"),
    ("aws_instance", "i1"),
    ("aws_db_instance", "d0"),
    ("aws_security_group_rule", "r0"),
    ("aws_security_group_rule", "r1"),
    ("aws_network_acl", "n0"),
    ("aws_db_subnet_group", "dg0"),
)
META = ("", "", "", "count = 2", 'for_each = toset(["a", "b"])', "count = var.n")
SET_ARGS = {"vpc_security_group_ids", "security_groups"}
SLOT_ARGS = {
    "aws_subnet": (("vpc_id", "aws_vpc"),),
    "aws_route_table": (("vpc_id", "aws_vpc"),),
    "aws_route_table_association": (
        ("subnet_id", "aws_subnet"),
        ("route_table_id", "aws_route_table"),
    ),
    "aws_internet_gateway": (("vpc_id", "aws_vpc"),),
    "aws_instance": (
        ("subnet_id", "aws_subnet"),
        ("vpc_security_group_ids", "aws_security_group"),
        ("security_groups", "aws_security_group"),
    ),
    "aws_db_instance": (("vpc_security_group_ids", "aws_security_group"),),
    "aws_security_group_rule": (
        ("security_group_id", "aws_security_group"),
        ("source_security_group_id", "aws_security_group"),
    ),
    "aws_network_acl": (("vpc_id", "aws_vpc"),),
}


def generate(rng: random.Random) -> str:
    """A small configuration with random meta-arguments and random slot values."""
    present = [(t, n) for t, n in KINDS if rng.random() < 0.8]
    meta: dict[tuple[str, str], str] = {key: rng.choice(META) for key in present}

    def reference(target_type: str, earlier: list[tuple[str, str]]) -> str:
        options = [(t, n) for t, n in earlier if t == target_type]
        if not options:
            return rng.choice(['"x-1"', "var.u", "null", "timestamp()"])
        t, n = rng.choice(options)
        kind = meta[(t, n)]
        form = rng.random()
        if kind.startswith("count = 2") and form < 0.5:
            return f"{t}.{n}[{rng.choice(['0', '1', 'var.i'])}].id"
        if kind.startswith("count = 2") and form < 0.7:
            return f"{t}.{n}[5].id"
        return f"{t}.{n}.id"

    def value(target_type: str, earlier: list[tuple[str, str]]) -> str | None:
        roll = rng.random()
        if roll < 0.45:
            return reference(target_type, earlier)
        if roll < 0.55:
            other = rng.choice(earlier) if earlier else ("aws_vpc", "v0")
            return f"{other[0]}.{other[1]}.id" if earlier else '"x"'
        if roll < 0.65:
            return "var.u"
        if roll < 0.72:
            return '"lit-1"'
        if roll < 0.78:
            return "null"
        if roll < 0.82:
            return "timestamp()"
        return None  # omit

    lines = ['variable "u" {}', 'variable "i" {}', 'variable "n" {}']
    earlier: list[tuple[str, str]] = []
    for t, n in present:
        body = [meta[(t, n)]] if meta[(t, n)] else []
        for argument, target_type in SLOT_ARGS.get(t, ()):
            chosen = value(target_type, earlier)
            if chosen is None:
                continue
            if argument in SET_ARGS:
                shape = rng.random()
                chosen = (
                    "[]" if shape < 0.15 else f"[{chosen}]" if shape < 0.7 else f'[{chosen}, "lit"]'
                )
            body.append(f"{argument} = {chosen}")
        if t == "aws_security_group_rule":
            body += ['type = "ingress"', 'protocol = "tcp"', "from_port = 5432", "to_port = 5432"]
        if t == "aws_security_group":
            body.append(f'name = "{n}"')
        if t == "aws_vpc":
            body.append('cidr_block = "10.0.0.0/16"')
        if t == "aws_instance":
            body.append('ami = "a"')
        if t == "aws_db_instance":
            body.append(f'identifier = "{n}"')
        if t == "aws_db_subnet_group":
            body.append(f'name = "{n}"')
        lines.append(f'resource "{t}" "{n}" {{\n  ' + "\n  ".join(body) + "\n}")
        earlier.append((t, n))
    return "\n".join(lines) + "\n"


def check_no_silent_gap(resources: Sequence[Resource], seed: object) -> Counter[str]:
    """The properties of "No silent missing dependencies"; returns the derivation rules seen."""
    built = graph_of(resources)
    nodes = {n.node_id for n in built.nodes}
    by_address = {r.address: r for r in resources}
    instances: dict[str, list[str]] = {}
    for address in by_address:
        if address.endswith("]"):
            instances.setdefault(address[: address.index("[")], []).append(address)
    where = f"seed {seed}"

    for edge in built.edges:  # every endpoint is a node, every edge has a rule
        assert edge.source_node_id in nodes and edge.target_node_id in nodes, where
        assert isinstance(edge.evidence.derivation_rule, DerivationRule), where
        assert edge.evidence.source_fact and edge.evidence.target_fact, where

    ref_edges = [e for e in built.edges if e.edge_type is EdgeType.TERRAFORM_REFERENCE]
    for resource in resources:  # every Reference has a reference edge (fan-out included)
        for ref in resource.references:
            wanted = [ref.target_address]
            if ref.target_address not in by_address and ref.target_address in instances:
                wanted = sorted(instances[ref.target_address])
            for target in wanted:
                found = [
                    e
                    for e in ref_edges
                    if e.source_node_id == f"RESOURCE:{resource.address}"
                    and e.target_node_id == f"RESOURCE:{target}"
                    and e.attributes.get("source_attribute") == ref.source_attribute
                ]
                assert found, f"{where}: no edge for {resource.address} {ref.source_attribute}"

    slot_edges = [e for e in built.edges if e.edge_type is EdgeType.INFRASTRUCTURE]
    for resource in resources:  # every section 16 slot of a supported source has an edge
        if resource.support_status is ResourceSupport.UNSUPPORTED:
            continue
        for source_type, _argument, _target, relationship in SECTION_16:
            if resource.resource_type != source_type:
                continue
            mine = [
                e
                for e in slot_edges
                if e.source_node_id == f"RESOURCE:{resource.address}"
                and e.relationship is relationship
            ]
            assert mine, f"{where}: {resource.address} has no {relationship.value} edge"

    for edge in built.edges:  # status never improves on its inputs
        if edge.edge_type not in (EdgeType.TERRAFORM_REFERENCE, EdgeType.INFRASTRUCTURE):
            continue
        source = by_address[edge.source_node_id.removeprefix("RESOURCE:")]
        if source.support_status is ResourceSupport.UNSUPPORTED:
            assert edge.status is UN, f"{where}: {edge.source_node_id}"
        if source.support_status is ResourceSupport.UNKNOWN:
            assert edge.status is not DependencyStatus.KNOWN, f"{where}: {edge.source_node_id}"
        node = built.node(edge.target_node_id)
        assert node is not None
        if node.attributes.get("kind") == "absent":
            assert edge.status is not DependencyStatus.KNOWN, f"{where}: {edge.target_node_id}"
    return Counter(e.evidence.derivation_rule.value for e in built.edges)


class TestNoSilentGap(unittest.TestCase):
    SEED = 20261028
    CASES = 80

    def test_generated_states_have_no_silent_missing_dependency(self) -> None:
        seen: Counter[str] = Counter()
        checked = 0
        for case in range(self.CASES):
            rng = random.Random(self.SEED + case)
            text = generate(rng)
            try:
                resources = list(resources_of(text))
            except AssertionError:
                continue  # the front end did not accept this combination; nothing to check
            seen += check_no_silent_gap(resources, self.SEED + case)
            checked += 1
        self.assertGreaterEqual(checked, 60, "the generator should mostly give valid states")

    def test_the_generator_reaches_every_way_a_slot_can_be_unresolved(self) -> None:
        seen: Counter[str] = Counter()
        for case in range(self.CASES):
            text = generate(random.Random(self.SEED + case))
            try:
                resources = list(resources_of(text))
            except AssertionError:
                continue
            seen += Counter(e.evidence.derivation_rule.value for e in graph_of(resources).edges)
        for rule in (
            DerivationRule.REFERENCE,
            DerivationRule.BLOCK_FANOUT,
            DerivationRule.SLOT_REFERENCE,
            DerivationRule.SLOT_UNKNOWN_VALUE,
            DerivationRule.SLOT_UNSUPPORTED_VALUE,
            DerivationRule.EXTERNAL_OBJECT,
            DerivationRule.UNSET,
            DerivationRule.TYPE_MISMATCH,
            DerivationRule.SCOPE_TYPE,
        ):
            self.assertGreater(seen[rule.value], 0, rule.value)

    def test_the_sweep_is_reproducible(self) -> None:
        self.assertEqual(generate(random.Random(5)), generate(random.Random(5)))

    def test_the_checker_fails_on_a_graph_with_a_dropped_edge(self) -> None:
        # a checker that cannot fail proves nothing: remove one edge and expect the assertion
        resources = list(fixture_resources(BASELINE))
        built = graph_of(resources)
        dropped = next(e for e in built.edges if e.relationship.value == "INSTANCE_IN_SUBNET")
        remaining = [e for e in built.edges if e is not dropped]
        self.assertEqual(len(remaining), len(built.edges) - 1)
        import core.dependency.build as build_module

        original = build_module.finalize

        def without(drafts):  # type: ignore[no-untyped-def]
            return tuple(e for e in original(drafts) if e.edge_key != dropped.edge_key)

        build_module.finalize = without  # type: ignore[assignment]
        try:
            with self.assertRaises(AssertionError):
                check_no_silent_gap(resources, "dropped")
        finally:
            build_module.finalize = original  # type: ignore[assignment]


if __name__ == "__main__":
    unittest.main()
