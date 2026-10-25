"""Properties of normalization over seeded random configurations (P3a-3 step 7; Doc 04 §6, §18;
Doc 12 §17).

Doc 12 §17: "Canonicalization is idempotent. Hash of canonical equivalent states is equal."
Here: normalizing twice gives identical fingerprints and canonical JSON; permuting the order of
files, resources, set-like blocks, CIDR lists, group lists and object keys in the source changes
nothing; a change of ``tags`` changes only ``attributes``; no float appears anywhere.

The generator is deterministic; a failure names the seed and the case index.
"""

from __future__ import annotations

import json
import random
import unittest
from dataclasses import dataclass, field
from datetime import timedelta

from core.domain.jsonvalue import thaw_json, validate_json
from core.terraform_model.evaluation import evaluate_configuration
from core.terraform_model.normalization import NormalizationOutcome, normalize_configuration
from core.terraform_model.security_rules import rules_of
from tests.tf_builders import NOW, parse_files

SEEDS = (20261025, 3, 11, 424242, 99991)
CASES_PER_SEED = 70  # 350 in all
CIDRS = ("10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12", "0.0.0.0/0", "10.1.0.0/16", "::/0")


@dataclass
class Rule:
    port: int
    protocol: str
    cidrs: list[str]
    groups: list[str]


@dataclass
class Group:
    name: str
    inline: list[Rule]
    separate: list[Rule]
    egress: str  # "absent", "empty" or "blocks"
    style: str  # inline rules as "blocks" or as an attribute "list"
    tags: dict[str, str]


@dataclass
class Spec:
    vpc_cidr: str
    groups: list[Group]
    instances: list[tuple[str, list[str], dict[str, str]]]
    subnets: int
    tags: dict[str, str] = field(default_factory=dict)


def make_spec(rng: random.Random) -> Spec:
    names = [f"g{i}" for i in range(rng.randint(1, 4))]

    def rule(allowed: list[str]) -> Rule:
        cidrs = rng.sample(CIDRS, rng.randint(0, 3))
        groups = rng.sample(allowed, rng.randint(0, min(2, len(allowed))))
        return Rule(rng.choice((22, 80, 443, 5432)), rng.choice(("tcp", "udp")), cidrs, groups)

    # an inline rule may name only an earlier group (a group cannot refer to itself or to a
    # later one that refers back: Terraform rejects the cycle); a separate rule may name any
    groups = [
        Group(
            name,
            [rule(names[:position]) for _ in range(rng.randint(0, 3))],
            [rule(names) for _ in range(rng.randint(0, 2))],
            rng.choice(("absent", "empty", "blocks")),
            rng.choice(("blocks", "list")),
            {f"k{j}": f"v{rng.randint(0, 9)}" for j in range(rng.randint(0, 3))},
        )
        for position, name in enumerate(names)
    ]
    instances = [
        (
            f"i{i}",
            rng.sample(names, rng.randint(1, len(names))),
            {f"t{j}": str(rng.randint(0, 9)) for j in range(rng.randint(0, 2))},
        )
        for i in range(rng.randint(0, 3))
    ]
    return Spec(rng.choice(CIDRS[:5]), groups, instances, rng.randint(0, 3), {"Name": "main"})


def quoted(items: list[str]) -> str:
    return "[" + ", ".join(f'"{item}"' for item in items) + "]"


def refs(names: list[str]) -> str:
    return "[" + ", ".join(f"aws_security_group.{name}.id" for name in names) + "]"


def tag_text(tags: dict[str, str], rng: random.Random | None) -> str:
    items = [f'{key} = "{value}"' for key, value in tags.items()]
    if rng is not None:
        rng.shuffle(items)
    return "{ " + ", ".join(items) + " }"


def rule_body(rule: Rule, rng: random.Random | None, *, separate: bool) -> list[str]:
    cidrs = list(rule.cidrs)
    groups = list(rule.groups)
    if rng is not None:
        rng.shuffle(cidrs)
        rng.shuffle(groups)
    v4 = [c for c in cidrs if ":" not in c]
    v6 = [c for c in cidrs if ":" in c]
    lines = [
        f'  protocol = "{rule.protocol}"',
        f"  from_port = {rule.port}",
        f"  to_port = {rule.port}",
    ]
    if v4:
        lines.append(f"  cidr_blocks = {quoted(v4)}")
    if v6:
        lines.append(f"  ipv6_cidr_blocks = {quoted(v6)}")
    if groups:
        if separate:
            lines.append(f"  source_security_group_id = aws_security_group.{rule.groups[0]}.id")
        else:
            lines.append(f"  security_groups = {refs(groups)}")
    return lines


def chunks(spec: Spec, rng: random.Random | None) -> list[str]:
    """The resource blocks of the spec, as text; ``rng`` permutes what does not matter."""
    out = [
        'resource "aws_vpc" "main" {\n'
        f'  cidr_block = "{spec.vpc_cidr}"\n  tags = {tag_text(spec.tags, rng)}\n}}\n'
    ]
    if spec.subnets:
        out.append(
            'resource "aws_subnet" "s" {\n'
            f"  count = {spec.subnets}\n"
            "  vpc_id = aws_vpc.main.id\n"
            "}\n"
        )
    for group in spec.groups:
        rendered = [rule_body(r, rng, separate=False) for r in group.inline]
        if rng is not None:
            rng.shuffle(rendered)
        if group.style == "list" and rendered:
            elements = ["{ " + ", ".join(x.strip() for x in lines) + " }" for lines in rendered]
            inline = ["  ingress = [" + ", ".join(elements) + "]"]
        else:
            inline = [
                "  ingress {\n" + "\n".join("  " + x for x in lines) + "\n  }" for lines in rendered
            ]
        body = [f'  name = "{group.name}"', f"  tags = {tag_text(group.tags, rng)}", *inline]
        if group.egress == "empty":
            body.append("  egress = []")
        elif group.egress == "blocks":
            body.append('  egress {\n    protocol = "-1"\n    from_port = 0\n    to_port = 0\n  }')
        out.append(f'resource "aws_security_group" "{group.name}" {{\n' + "\n".join(body) + "\n}\n")
        for index, rule in enumerate(group.separate):
            lines = rule_body(rule, rng, separate=True)
            out.append(
                f'resource "aws_security_group_rule" "{group.name}_r{index}" {{\n'
                '  type = "ingress"\n'
                f"  security_group_id = aws_security_group.{group.name}.id\n"
                + "\n".join(lines)
                + "\n}\n"
            )
    for name, group_names, tags in spec.instances:
        order = list(group_names)
        if rng is not None:
            rng.shuffle(order)
        subnet = "  subnet_id = aws_subnet.s[0].id\n" if spec.subnets else ""
        out.append(
            f'resource "aws_instance" "{name}" {{\n{subnet}'
            f"  vpc_security_group_ids = {refs(order)}\n  tags = {tag_text(tags, rng)}\n}}\n"
        )
    if rng is not None:
        rng.shuffle(out)
    return out


def files_of(spec: Spec, rng: random.Random | None) -> dict[str, str]:
    parts = chunks(spec, rng)
    if rng is None:
        return {"main.tf": "\n".join(parts)}
    count = rng.randint(1, 3)
    files: dict[str, list[str]] = {f"f{i}.tf": [] for i in range(count)}
    for part in parts:
        files[rng.choice(list(files))].append(part)
    return {name: "\n".join(texts) for name, texts in files.items() if texts} or {"f0.tf": ""}


def normalize_files(files: dict[str, str], now=NOW) -> NormalizationOutcome:  # type: ignore[no-untyped-def]
    parsed = parse_files(files)
    return normalize_configuration(parsed, evaluate_configuration(parsed), now=now)


def has_float(value: object) -> bool:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, float):
            return True
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return False


CASES = [
    (seed, index, make_spec(random.Random(seed * 1000 + index)))
    for seed in SEEDS
    for index in range(CASES_PER_SEED)
]


class TestProperties(unittest.TestCase):
    def test_there_are_at_least_300_cases(self) -> None:
        self.assertGreaterEqual(len(CASES), 300)

    def test_normalizing_twice_gives_identical_fingerprints_and_json(self) -> None:
        for seed, index, spec in CASES:
            files = files_of(spec, None)
            first = normalize_files(files)
            second = normalize_files(files, NOW + timedelta(days=30))
            with self.subTest(seed=seed, index=index):
                self.assertEqual(first.status.value, "OK", first.diagnostics)
                self.assertEqual(first.resource_set_hash, second.resource_set_hash)
                self.assertEqual(
                    [(r.address, r.fingerprint, r.canonical_json) for r in first.resources],
                    [(r.address, r.fingerprint, r.canonical_json) for r in second.resources],
                )

    def test_permuting_what_does_not_matter_changes_nothing(self) -> None:
        for seed, index, spec in CASES:
            baseline = normalize_files(files_of(spec, None))
            rng = random.Random(seed * 7919 + index)
            shuffled = normalize_files(files_of(spec, rng))
            with self.subTest(seed=seed, index=index):
                self.assertEqual(
                    {r.address: r.fingerprint for r in baseline.resources},
                    {r.address: r.fingerprint for r in shuffled.resources},
                )
                self.assertEqual(baseline.resource_set_hash, shuffled.resource_set_hash)
                self.assertEqual(
                    {r.address: [x.rule_key() for x in rules_of(r)] for r in baseline.resources},
                    {r.address: [x.rule_key() for x in rules_of(r)] for r in shuffled.resources},
                )

    def test_a_tag_change_changes_only_attributes(self) -> None:
        for seed, index, spec in CASES:
            before = {r.address: r for r in normalize_files(files_of(spec, None)).resources}
            spec.tags = dict(spec.tags, Name="changed-by-the-test")
            after = {r.address: r for r in normalize_files(files_of(spec, None)).resources}
            spec.tags = dict(spec.tags, Name="main")
            with self.subTest(seed=seed, index=index):
                self.assertNotEqual(
                    before["aws_vpc.main"].fingerprint, after["aws_vpc.main"].fingerprint
                )
                self.assertNotEqual(
                    plain(before["aws_vpc.main"].attributes),
                    plain(after["aws_vpc.main"].attributes),
                )
                for view in ("security_attributes", "semantic_attributes", "logical_identity"):
                    self.assertEqual(
                        plain(getattr(before["aws_vpc.main"], view)),
                        plain(getattr(after["aws_vpc.main"], view)),
                    )
                for address, resource in before.items():
                    if address != "aws_vpc.main":
                        self.assertEqual(resource.fingerprint, after[address].fingerprint, address)

    def test_no_float_anywhere_and_valid_domain_json(self) -> None:
        for seed, index, spec in CASES:
            outcome = normalize_files(files_of(spec, None))
            with self.subTest(seed=seed, index=index):
                for resource in outcome.resources:
                    self.assertFalse(has_float(json.loads(resource.canonical_json)))
                    for name in ("attributes", "security_attributes", "semantic_attributes"):
                        validate_json(getattr(resource, name), name)

    def test_the_generator_makes_varied_configurations(self) -> None:
        sizes = {len(normalize_files(files_of(spec, None)).resources) for _, _, spec in CASES}
        self.assertGreater(len(sizes), 5)
        with_rules = sum(
            1 for _, _, spec in CASES if any(g.inline or g.separate for g in spec.groups)
        )
        self.assertGreater(with_rules, len(CASES) // 2)


def plain(mapping):  # type: ignore[no-untyped-def]
    return thaw_json(mapping)


if __name__ == "__main__":
    unittest.main()
