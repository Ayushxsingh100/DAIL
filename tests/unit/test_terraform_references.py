"""Reference extraction (P3a-3 step 5; Doc 04 §16.2; Doc 07 §15; Doc 05 §5.3; C-115).

Expected references are written by hand from the C-115 rules and the Doc 04 §16.2 example.
"""

from __future__ import annotations

import unittest
from collections.abc import Mapping

from core.domain.enums import ReferenceResolution
from core.domain.values import Reference
from core.terraform_model.config import DiagnosticSeverity
from core.terraform_model.normalize import normalize_instance
from core.terraform_model.references import (
    ATTRIBUTE_REFERENCE,
    DEPENDS_ON,
    Candidate,
    ReferenceContext,
    _Collector,
    expression_candidates,
    references_of,
    references_of_indeterminate,
)
from tests.tf_builders import NOW, evaluate_ok

S = ReferenceResolution.SUPPORTED
K = ReferenceResolution.UNKNOWN
U = ReferenceResolution.UNSUPPORTED
A = ATTRIBUTE_REFERENCE


def hcl(*lines: str) -> str:
    return "\n".join(lines) + "\n"


def refs(
    text: str, address: str, variables: Mapping[str, object] | None = None
) -> list[tuple[str, str, str, ReferenceResolution]]:
    parsed, outcome = evaluate_ok(text, variables)
    ctx = ReferenceContext(parsed, outcome.instances, outcome.indeterminate)
    if address in outcome.indeterminate:
        found, _ = references_of_indeterminate(outcome.indeterminate[address], ctx)
    else:
        found, _ = references_of(outcome.instances[address], ctx)
    for reference in found:
        assert reference.source_address == address
    return [
        (r.source_attribute, r.target_address, r.reference_type, r.resolution_status) for r in found
    ]


VPC = 'resource "aws_vpc" "main" {}'
SUBNET = 'resource "aws_subnet" "app" {}'


class TestTheSpecExample(unittest.TestCase):
    def test_instance_subnet_id(self) -> None:
        # Doc 04 §16.2: aws_instance.app.subnet_id = aws_subnet.app.id
        found = refs(
            hcl(SUBNET, 'resource "aws_instance" "app" {', "  subnet_id = aws_subnet.app.id", "}"),
            "aws_instance.app",
        )
        self.assertEqual(found, [("subnet_id", "aws_subnet.app", A, S)])

    def test_the_reference_is_a_domain_reference(self) -> None:
        parsed, outcome = evaluate_ok(
            hcl(SUBNET, 'resource "aws_instance" "app" {', "  subnet_id = aws_subnet.app.id", "}")
        )
        ctx = ReferenceContext(parsed, outcome.instances, outcome.indeterminate)
        found, diagnostics = references_of(outcome.instances["aws_instance.app"], ctx)
        self.assertEqual(
            found,
            [Reference("aws_instance.app", "subnet_id", "aws_subnet.app", A, S)],
        )
        self.assertEqual(diagnostics, [])
        resource = normalize_instance(
            outcome.instances["aws_instance.app"], now=NOW, references=found
        )
        self.assertEqual(resource.references, tuple(found))

    def test_several_references_are_sorted_and_unique(self) -> None:
        found = refs(
            hcl(
                'resource "aws_security_group" "a" {}',
                'resource "aws_security_group" "b" {}',
                'resource "aws_instance" "i" {',
                "  vpc_security_group_ids = [aws_security_group.b.id, aws_security_group.a.id,",
                "                            aws_security_group.a.id]",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(
            found,
            [
                ("vpc_security_group_ids", "aws_security_group.a", A, S),
                ("vpc_security_group_ids", "aws_security_group.b", A, S),
            ],
        )


class TestValuesAndExpressions(unittest.TestCase):
    def test_a_reference_in_a_template_function_or_conditional(self) -> None:
        found = refs(
            hcl(
                VPC,
                'resource "aws_instance" "i" {',
                '  a = "x-${aws_vpc.main.id}"',
                "  b = upper(aws_vpc.main.id)",
                "  c = true ? aws_vpc.main.id : null",
                "  d = { k = [aws_vpc.main.id] }",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(
            found,
            [(name, "aws_vpc.main", A, S) for name in ("a", "b", "c", "d")],
        )

    def test_a_reference_through_a_local(self) -> None:
        found = refs(
            hcl(
                VPC,
                "locals {",
                "  base = aws_vpc.main.id",
                '  pair = [local.base, "x"]',
                "}",
                'resource "aws_instance" "i" {',
                "  vpc = local.pair[0]",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(found, [("vpc", "aws_vpc.main", A, S)])

    def test_a_copied_value_through_a_local_is_found_only_by_the_expression(self) -> None:
        # the value of the local is the string "db", not a Ref: only (b) can see the dependency
        found = refs(
            hcl(
                'resource "aws_db_subnet_group" "db" {',
                '  name = "db"',
                "}",
                "locals {",
                "  n = aws_db_subnet_group.db.name",
                "}",
                'resource "aws_db_instance" "database" {',
                "  db_subnet_group_name = local.n",
                "}",
            ),
            "aws_db_instance.database",
        )
        self.assertEqual(found, [("db_subnet_group_name", "aws_db_subnet_group.db", A, U)])

    def test_a_reference_through_a_chain_of_locals_and_a_cycle_guard(self) -> None:
        text = hcl(
            VPC,
            "locals {",
            "  a = local.b",
            "  b = local.c",
            "  c = aws_vpc.main.id",
            "}",
            'resource "aws_instance" "i" {',
            "  vpc = local.a",
            "}",
        )
        self.assertEqual(refs(text, "aws_instance.i"), [("vpc", "aws_vpc.main", A, S)])
        parsed, _ = evaluate_ok(text)
        locals_ = {name: decl.attribute.expr for name, decl in parsed.locals.items()}
        looped = dict(locals_, c=locals_["a"])  # a local cycle must not loop forever
        candidates = expression_candidates(locals_["a"], looped)
        self.assertEqual(candidates, [])

    def test_a_value_copied_from_another_resource_is_still_a_reference(self) -> None:
        # the value of aws_subnet.app.cidr_block is known, and the dependency is still recorded
        found = refs(
            hcl(
                'resource "aws_subnet" "app" {',
                '  cidr_block = "10.0.1.0/24"',
                "}",
                'resource "aws_instance" "i" {',
                "  cidr = aws_subnet.app.cidr_block",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(found, [("cidr", "aws_subnet.app", A, S)])

    def test_variables_each_and_count_are_not_references(self) -> None:
        found = refs(
            hcl(
                'variable "v" {}',
                'resource "aws_subnet" "s" {',
                "  count = 2",
                "  a = var.v",
                "  b = count.index",
                "}",
            ),
            "aws_subnet.s[0]",
        )
        self.assertEqual(found, [])

    def test_a_for_expression_variable_is_not_a_reference(self) -> None:
        found = refs(
            hcl(
                'resource "aws_subnet" "all" {',
                "  count = 2",
                "}",
                'resource "aws_instance" "i" {',
                "  ids = [for s in aws_subnet.all : s.id]",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(
            found,
            [
                ("ids", "aws_subnet.all[0]", A, S),
                ("ids", "aws_subnet.all[1]", A, S),
            ],
        )

    def test_a_loop_variable_named_like_a_resource_type_is_not_a_target(self) -> None:
        found = refs(
            hcl(
                'resource "aws_instance" "i" {',
                '  x = [for aws_vpc in ["a"] : aws_vpc.id]',
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(found, [])


class TestIndexes(unittest.TestCase):
    COUNTED = hcl('resource "aws_subnet" "s" {', "  count = 2", "}")
    KEYED = hcl('resource "aws_security_group" "g" {', '  for_each = toset(["a", "b"])', "}")

    def test_a_constant_index_is_the_instance(self) -> None:
        found = refs(
            self.COUNTED + hcl('resource "aws_instance" "i" {', "  a = aws_subnet.s[1].id", "}"),
            "aws_instance.i",
        )
        self.assertEqual(found, [("a", "aws_subnet.s[1]", A, S)])

    def test_a_constant_string_key(self) -> None:
        found = refs(
            self.KEYED
            + hcl('resource "aws_instance" "i" {', '  a = aws_security_group.g["b"].id', "}"),
            "aws_instance.i",
        )
        self.assertEqual(found, [("a", 'aws_security_group.g["b"]', A, S)])

    def test_a_non_constant_index_adds_the_keyless_address_as_unknown(self) -> None:
        text = self.COUNTED + hcl(
            'resource "aws_instance" "i" {',
            "  count = 2",
            "  a = aws_subnet.s[count.index].id",
            "}",
        )
        self.assertEqual(
            refs(text, "aws_instance.i[1]"),
            [("a", "aws_subnet.s", A, K), ("a", "aws_subnet.s[1]", A, S)],
        )

    def test_a_constant_index_that_does_not_exist_is_unknown(self) -> None:
        # the value is unsupported (no such instance); the reference is still recorded
        found = refs(
            self.COUNTED + hcl('resource "aws_instance" "i" {', "  a = aws_subnet.s[5].id", "}"),
            "aws_instance.i",
        )
        self.assertEqual(found, [("a", "aws_subnet.s[5]", A, K)])

    def test_no_index_on_a_counted_resource_is_unknown_unless_the_instances_are_known(self) -> None:
        covered = refs(
            self.COUNTED + hcl('resource "aws_instance" "i" {', "  a = aws_subnet.s[*].id", "}"),
            "aws_instance.i",
        )
        self.assertEqual(covered, [("a", "aws_subnet.s[0]", A, S), ("a", "aws_subnet.s[1]", A, S)])
        bare = refs(
            self.COUNTED + hcl('resource "aws_instance" "i" {', "  n = length(aws_subnet.s)", "}"),
            "aws_instance.i",
        )
        self.assertEqual(bare, [("n", "aws_subnet.s", A, K)])

    def test_a_whole_counted_resource_used_as_a_value_gives_both(self) -> None:
        found = refs(
            self.COUNTED + hcl('resource "aws_instance" "i" {', "  all = aws_subnet.s", "}"),
            "aws_instance.i",
        )
        # the evaluated object holds the ids of both instances, so (a) covers the resource
        self.assertEqual(
            found, [("all", "aws_subnet.s[0]", A, S), ("all", "aws_subnet.s[1]", A, S)]
        )

    def test_a_single_resource_without_an_index_is_its_address(self) -> None:
        found = refs(
            hcl(VPC, 'resource "aws_instance" "i" {', "  v = aws_vpc.main", "}"), "aws_instance.i"
        )
        self.assertEqual(found, [("v", "aws_vpc.main", A, S)])


class TestStatuses(unittest.TestCase):
    def test_an_unsupported_type_is_unsupported(self) -> None:
        found = refs(
            hcl(
                VPC,
                'resource "aws_network_acl" "extra" {',
                "  vpc_id = aws_vpc.main.id",
                "}",
                'resource "aws_instance" "i" {',
                "  acl = aws_network_acl.extra.id",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(found, [("acl", "aws_network_acl.extra", A, U)])

    def test_the_tolerated_type_is_unsupported_even_when_only_its_name_is_copied(self) -> None:
        found = refs(
            hcl(
                'resource "aws_db_subnet_group" "db" {',
                '  name = "db"',
                "}",
                'resource "aws_db_instance" "database" {',
                "  db_subnet_group_name = aws_db_subnet_group.db.name",
                "}",
            ),
            "aws_db_instance.database",
        )
        self.assertEqual(found, [("db_subnet_group_name", "aws_db_subnet_group.db", A, U)])

    def test_a_data_source_is_unknown(self) -> None:
        found = refs(
            hcl(
                'data "aws_ami" "x" {}',
                'resource "aws_instance" "i" {',
                "  ami = data.aws_ami.x.id",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(found, [("ami", "data.aws_ami.x", A, K)])

    def test_an_indeterminate_target_is_unknown(self) -> None:
        text = hcl(
            'variable "n" {}',
            'resource "aws_subnet" "s" {',
            "  count = var.n",
            "}",
            'resource "aws_instance" "i" {',
            "  a = aws_subnet.s[0].id",
            "  b = aws_subnet.s[*].id",
            "}",
        )
        self.assertEqual(
            refs(text, "aws_instance.i"),
            [("a", "aws_subnet.s", A, K), ("b", "aws_subnet.s", A, K)],
        )

    def test_a_target_with_an_unresolved_dynamic_group_is_unknown(self) -> None:
        text = hcl(
            'variable "v" {}',
            'resource "aws_security_group" "g" {',
            '  dynamic "ingress" {',
            "    for_each = var.v",
            "    content {}",
            "  }",
            "}",
            'resource "aws_instance" "i" {',
            "  g = aws_security_group.g.id",
            "}",
        )
        self.assertEqual(refs(text, "aws_instance.i"), [("g", "aws_security_group.g", A, K)])

    def test_every_supported_type_is_supported(self) -> None:
        types = [
            "aws_vpc", "aws_subnet", "aws_route_table", "aws_route_table_association",
            "aws_internet_gateway", "aws_instance", "aws_security_group",
            "aws_security_group_rule", "aws_db_instance",
        ]  # fmt: skip
        for name in types:
            with self.subTest(name=name):
                text = hcl(
                    f'resource "{name}" "t" {{}}',
                    'resource "aws_vpc" "main" {',
                    "  x = " + name + ".t.id",
                    "}",
                )
                if name == "aws_vpc":
                    continue
                self.assertEqual(refs(text, "aws_vpc.main"), [("x", f"{name}.t", A, S)])

    def test_the_status_conflict_keeps_the_more_conservative_one(self) -> None:
        parsed, outcome = evaluate_ok(hcl(VPC))
        ctx = ReferenceContext(parsed, outcome.instances, outcome.indeterminate)
        collector = _Collector("aws_vpc.main", ctx)
        collector._add("x", "aws_a.t", A, S)
        collector._add("x", "aws_a.t", A, K)
        collector._add("x", "aws_a.t", A, U)
        collector._add("x", "aws_a.t", A, S)
        self.assertEqual([r.resolution_status for r in collector.references()], [U])
        self.assertEqual(len(collector.diagnostics), 3)
        self.assertTrue(
            all(
                d.severity is DiagnosticSeverity.UNSUPPORTED_CONSTRUCT
                for d in collector.diagnostics
            )
        )
        self.assertEqual(collector.diagnostics[0].code, "norm.reference_status_conflict")
        other = _Collector("aws_vpc.main", ctx)
        other._add("x", "aws_a.t", A, K)
        other._add("x", "aws_a.t", A, S)
        self.assertEqual([r.resolution_status for r in other.references()], [K])

    def test_the_same_target_with_another_type_or_attribute_is_another_reference(self) -> None:
        parsed, outcome = evaluate_ok(hcl(VPC))
        ctx = ReferenceContext(parsed, outcome.instances, outcome.indeterminate)
        collector = _Collector("aws_vpc.main", ctx)
        collector._add("x", "aws_a.t", A, S)
        collector._add("x", "aws_a.t", DEPENDS_ON, S)
        collector._add("y", "aws_a.t", A, S)
        self.assertEqual(len(collector.references()), 3)
        self.assertEqual(collector.diagnostics, [])


class TestDependsOnAndMeta(unittest.TestCase):
    def test_depends_on(self) -> None:
        found = refs(
            hcl(
                VPC,
                'resource "aws_subnet" "s" {',
                "  depends_on = [aws_vpc.main]",
                "}",
            ),
            "aws_subnet.s",
        )
        self.assertEqual(found, [("depends_on", "aws_vpc.main", DEPENDS_ON, S)])

    def test_depends_on_and_an_argument_naming_the_same_target(self) -> None:
        found = refs(
            hcl(
                VPC,
                'resource "aws_subnet" "s" {',
                "  vpc_id = aws_vpc.main.id",
                "  depends_on = [aws_vpc.main]",
                "}",
            ),
            "aws_subnet.s",
        )
        self.assertEqual(
            found,
            [
                ("depends_on", "aws_vpc.main", DEPENDS_ON, S),
                ("vpc_id", "aws_vpc.main", A, S),
            ],
        )

    def test_count_and_for_each_expressions(self) -> None:
        found = refs(
            hcl(
                'resource "aws_subnet" "all" {',
                "  count = 2",
                "}",
                'resource "aws_instance" "i" {',
                "  count = length(aws_subnet.all)",
                "}",
                'resource "aws_security_group" "g" {',
                "  for_each = toset([for s in aws_subnet.all : s.id])",
                "}",
            ),
            "aws_instance.i[0]",
        )
        self.assertEqual(found, [("count", "aws_subnet.all", A, K)])

    def test_lifecycle_provisioner_and_connection_expressions(self) -> None:
        found = refs(
            hcl(
                VPC,
                'resource "aws_subnet" "other" {}',
                'resource "aws_instance" "i" {',
                "  lifecycle {",
                "    replace_triggered_by = [aws_vpc.main.id]",
                "    ignore_changes = [tags]",
                "  }",
                '  provisioner "local-exec" {',
                '    command = "echo ${aws_subnet.other.id}"',
                "  }",
                "  connection {",
                "    host = aws_vpc.main.id",
                "  }",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(
            found,
            [
                ("connection[0].host", "aws_vpc.main", A, S),
                ("lifecycle.replace_triggered_by", "aws_vpc.main", A, S),
                ("provisioner[0].command", "aws_subnet.other", A, S),
            ],
        )


class TestBlocks(unittest.TestCase):
    GROUPS = hcl(
        'resource "aws_security_group" "a" {}',
        'resource "aws_security_group" "b" {}',
    )

    def test_a_nested_block_attribute_path(self) -> None:
        found = refs(
            self.GROUPS
            + hcl(
                'resource "aws_security_group" "g" {',
                "  ingress {",
                "    from_port = 22",
                "    security_groups = [aws_security_group.a.id]",
                "  }",
                "}",
            ),
            "aws_security_group.g",
        )
        self.assertEqual(found, [("ingress[0].security_groups", "aws_security_group.a", A, S)])

    def test_the_block_index_follows_the_canonical_order_of_set_like_blocks(self) -> None:
        # ingress blocks are a set: they are written sorted by their encoding, and the path
        # index is the position in that order, not the source order
        found = refs(
            self.GROUPS
            + hcl(
                'resource "aws_security_group" "g" {',
                "  ingress {",
                "    from_port = 80",
                "    security_groups = [aws_security_group.a.id]",
                "  }",
                "  ingress {",
                "    from_port = 22",
                "    security_groups = [aws_security_group.b.id]",
                "  }",
                "}",
            ),
            "aws_security_group.g",
        )
        self.assertEqual(
            found,
            [
                ("ingress[0].security_groups", "aws_security_group.b", A, S),
                ("ingress[1].security_groups", "aws_security_group.a", A, S),
            ],
        )

    def test_a_block_that_is_not_set_like_keeps_the_source_order(self) -> None:
        found = refs(
            self.GROUPS
            + hcl(
                'resource "aws_instance" "i" {',
                "  root_block_device {",
                "    kms_key_id = aws_security_group.b.id",
                "  }",
                "  other {",
                "    x = aws_security_group.a.id",
                "  }",
                "  other {",
                "    x = aws_security_group.b.id",
                "  }",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(
            found,
            [
                ("other[0].x", "aws_security_group.a", A, S),
                ("other[1].x", "aws_security_group.b", A, S),
                ("root_block_device[0].kms_key_id", "aws_security_group.b", A, S),
            ],
        )

    def test_nested_blocks_inside_blocks(self) -> None:
        found = refs(
            self.GROUPS
            + hcl(
                'resource "aws_instance" "i" {',
                "  outer {",
                "    inner {",
                "      x = aws_security_group.a.id",
                "    }",
                "  }",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(found, [("outer[0].inner[0].x", "aws_security_group.a", A, S)])

    def test_dynamic_block_content_per_expansion(self) -> None:
        found = refs(
            self.GROUPS
            + hcl(
                'resource "aws_security_group" "g" {',
                '  dynamic "ingress" {',
                "    for_each = [22, 80]",
                "    content {",
                "      from_port = ingress.value",
                "      security_groups = [aws_security_group.a.id]",
                "    }",
                "  }",
                "}",
            ),
            "aws_security_group.g",
        )
        self.assertEqual(
            found,
            [
                ("ingress[0].security_groups", "aws_security_group.a", A, S),
                ("ingress[1].security_groups", "aws_security_group.a", A, S),
            ],
        )

    def test_dynamic_block_content_that_never_expanded_is_not_lost(self) -> None:
        found = refs(
            self.GROUPS
            + hcl(
                'variable "v" {}',
                'resource "aws_security_group" "g" {',
                '  dynamic "ingress" {',
                "    for_each = var.v",
                "    content {",
                "      security_groups = [aws_security_group.a.id]",
                "    }",
                "  }",
                "}",
            ),
            "aws_security_group.g",
        )
        self.assertEqual(found, [("ingress[*].security_groups", "aws_security_group.a", A, S)])

    def test_the_for_each_and_labels_of_a_dynamic_block(self) -> None:
        found = refs(
            self.GROUPS
            + hcl(
                'resource "aws_instance" "i" {',
                '  dynamic "tag" {',
                "    for_each = [aws_security_group.a.id]",
                "    labels = [aws_security_group.b.id]",
                "    content {}",
                "  }",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(
            found,
            [
                ("tag.for_each", "aws_security_group.a", A, S),
                ("tag.labels", "aws_security_group.b", A, S),
            ],
        )

    def test_the_iterator_of_a_dynamic_block_is_not_a_reference(self) -> None:
        found = refs(
            hcl(
                'resource "aws_instance" "i" {',
                '  dynamic "network_interface" {',
                "    for_each = [1]",
                "    iterator = nic",
                "    content {",
                "      device_index = nic.value",
                "    }",
                "  }",
                "}",
            ),
            "aws_instance.i",
        )
        self.assertEqual(found, [])

    def test_a_reference_in_an_inline_attribute_list(self) -> None:
        found = refs(
            self.GROUPS
            + hcl(
                'resource "aws_security_group" "g" {',
                "  ingress = [{ from_port = 22, security_groups = [aws_security_group.a.id] }]",
                "}",
            ),
            "aws_security_group.g",
        )
        self.assertEqual(found, [("ingress", "aws_security_group.a", A, S)])


class TestCountAndEach(unittest.TestCase):
    def test_each_instance_has_its_own_references(self) -> None:
        text = hcl(
            'resource "aws_vpc" "v" {',
            '  for_each = toset(["a", "b"])',
            "}",
            'resource "aws_subnet" "s" {',
            '  for_each = toset(["a", "b"])',
            "  vpc_id = aws_vpc.v[each.key].id",
            "}",
        )
        self.assertEqual(
            refs(text, 'aws_subnet.s["a"]'),
            [("vpc_id", "aws_vpc.v", A, K), ("vpc_id", 'aws_vpc.v["a"]', A, S)],
        )
        self.assertEqual(
            refs(text, 'aws_subnet.s["b"]'),
            [("vpc_id", "aws_vpc.v", A, K), ("vpc_id", 'aws_vpc.v["b"]', A, S)],
        )

    def test_an_indeterminate_resource_keeps_the_references_of_its_expressions(self) -> None:
        text = hcl(
            'variable "n" {}',
            VPC,
            'resource "aws_subnet" "s" {',
            "  count = var.n",
            "  vpc_id = aws_vpc.main.id",
            "  depends_on = [aws_vpc.main]",
            "}",
        )
        self.assertEqual(
            refs(text, "aws_subnet.s"),
            [
                ("depends_on", "aws_vpc.main", DEPENDS_ON, S),
                ("vpc_id", "aws_vpc.main", A, S),
            ],
        )


class TestCandidates(unittest.TestCase):
    def test_what_an_expression_names(self) -> None:
        parsed, _ = evaluate_ok(hcl(VPC))
        from core.terraform_model.hcl.ast import Attribute
        from core.terraform_model.hcl.parser import parse_file

        def candidates(text: str) -> list[Candidate]:
            item = parse_file(f"x = {text}\n", "t.tf").items[0]
            assert isinstance(item, Attribute)
            return expression_candidates(item.expr, {})

        self.assertEqual(
            candidates("aws_vpc.main.id"), [Candidate("resource", "aws_vpc", "main", "none")]
        )
        self.assertEqual(
            candidates("aws_vpc.main[0].id"), [Candidate("resource", "aws_vpc", "main", "const", 0)]
        )
        self.assertEqual(
            candidates("aws_vpc.main[var.i].id"),
            [Candidate("resource", "aws_vpc", "main", "unknown")],
        )
        self.assertEqual(
            candidates("data.aws_ami.x.id"), [Candidate("data", "aws_ami", "x", "none")]
        )
        self.assertEqual(
            candidates("module.net.out"), [Candidate("module", "module", "net", "none")]
        )
        for text in (
            "var.x",
            "local.x",
            "each.key",
            "count.index",
            "path.module",
            "self.id",
            "tags",
        ):
            self.assertEqual(candidates(text), [], text)


class TestUndeclaredNeverReachesHere(unittest.TestCase):
    def test_a_reference_to_an_undeclared_resource_is_invalid_before_normalization(self) -> None:
        from core.terraform_model.config import ParseStatus
        from tests.tf_builders import evaluate_text

        _, outcome = evaluate_text(
            hcl('resource "aws_instance" "i" {', "  a = aws_nothing.x.id", "}")
        )
        self.assertEqual(outcome.status, ParseStatus.INVALID)
        self.assertEqual(dict(outcome.instances), {})


if __name__ == "__main__":
    unittest.main()
