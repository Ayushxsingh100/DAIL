"""Following moved blocks and implicit count moves (Registry §2.3, §2.9; C-76, C-123; P3b step 3).

Every expected value is read from the Terraform v1.15.8 source cited in C-123 (internal/refactoring
and internal/addrs), not from the implementation; each test names the lines it relies on.
"""

from __future__ import annotations

import itertools
import random
import unittest

from core.identity.addresses import block_of, key_kind, key_of, split_key
from core.identity.errors import IdentityInputError
from core.identity.moves import (
    MovePlan,
    MoveStatement,
    implicit_count_moves,
    plan_moves,
)

A, B, C, D = "aws_x.a", "aws_x.b", "aws_x.c", "aws_x.d"


def key(block: str, text: str) -> str:
    return f'{block}["{text}"]'


def count(block: str, index: int) -> str:
    return f"{block}[{index}]"


def plan(
    addresses: list[str],
    moves: list[tuple[str, str]],
    placeholders: tuple[str, ...] = (),
    implied: tuple[tuple[str, str], ...] = (),
) -> MovePlan:
    return plan_moves(addresses, moves, placeholders=placeholders, implied=implied)


class TestAddresses(unittest.TestCase):
    def test_a_block_and_its_last_key(self) -> None:
        cases = {
            "aws_x.a": ("aws_x.a", None),
            "aws_x.a[0]": ("aws_x.a", "[0]"),
            "aws_x.a[12]": ("aws_x.a", "[12]"),
            'aws_x.a["k"]': ("aws_x.a", '["k"]'),
            'aws_x.a[""]': ("aws_x.a", '[""]'),
            "module.m.aws_x.a": ("module.m.aws_x.a", None),
            'module.m["k"].aws_x.a': ('module.m["k"].aws_x.a', None),
            'module.m["k"].aws_x.a[1]': ('module.m["k"].aws_x.a', "[1]"),
            'module.m[0].aws_x.a["j"]': ("module.m[0].aws_x.a", '["j"]'),
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertEqual(split_key(address), expected)
                self.assertEqual(block_of(address), expected[0])
                self.assertEqual(key_of(address), expected[1])

    def test_brackets_dots_quotes_and_backslashes_inside_a_key_are_text(self) -> None:
        backslash, quote = chr(92), chr(34)
        texts = [
            "a]b",
            "a[b",
            "x.y",
            "[0]",
            f"say {quote}hi{quote}",
            f"a{quote}b",  # one quote: an unescaped reading would leave the key open
            f"end{backslash}",
            backslash,
            quote,
            f"{backslash}{quote}",
            f"{quote}]{quote}[{quote}",
        ]
        for text in texts:
            escaped = text.replace(backslash, backslash * 2).replace(quote, backslash + quote)
            key_text = "[" + quote + escaped + quote + "]"
            address = "aws_x.a" + key_text
            with self.subTest(text=text):
                self.assertEqual(split_key(address), ("aws_x.a", key_text))
                self.assertEqual(
                    split_key("module.m" + key_text + "." + address[:7] + key_text)[1], key_text
                )

    def test_a_malformed_address_is_refused(self) -> None:
        for bad in ("", "[0]", 'aws_x.a["k]', "aws_x.a[", "aws_x.a]", 'aws_x.a["k"', None, 3):
            with self.subTest(address=bad), self.assertRaises(IdentityInputError):
                split_key(bad)  # type: ignore[arg-type]

    def test_key_kinds(self) -> None:
        self.assertEqual(key_kind(None), "none")
        self.assertEqual(key_kind("[0]"), "int")
        self.assertEqual(key_kind('["0"]'), "str")


class TestStatements(unittest.TestCase):
    def test_a_statement_is_resource_level_only_when_neither_endpoint_has_a_key(self) -> None:
        """move_endpoint.go L173-L215 (UnifyMoveEndpoints), L280-L300 (internalAddrType)."""
        self.assertTrue(MoveStatement(A, B).resource_level)
        for source, target in ((A, count(B, 0)), (count(A, 0), B), (key(A, "x"), key(B, "y"))):
            with self.subTest(source=source, target=target):
                self.assertFalse(MoveStatement(source, target).resource_level)

    def test_a_move_to_itself_and_malformed_addresses_are_refused(self) -> None:
        with self.assertRaises(IdentityInputError):
            MoveStatement(A, A)
        with self.assertRaises(IdentityInputError):
            MoveStatement(A, "aws_x.b[")
        with self.assertRaises(IdentityInputError):
            MoveStatement(" aws_x.a", B)


class TestResourceLevel(unittest.TestCase):
    def test_every_instance_moves_with_the_same_key(self) -> None:
        """move_execute.go L152-L176: the whole resource moves; MoveDestination keeps the key."""
        cases = {
            "no key": ([A], {A: B}),
            "count": (
                [count(A, 0), count(A, 1)],
                {count(A, 0): count(B, 0), count(A, 1): count(B, 1)},
            ),
            "for_each": (
                [key(A, "x"), key(A, "y")],
                {key(A, "x"): key(B, "x"), key(A, "y"): key(B, "y")},
            ),
        }
        for name, (addresses, expected) in cases.items():
            with self.subTest(name=name):
                result = plan(addresses + [D], [(A, B)])
                self.assertEqual(result.moved, expected)
                self.assertEqual(result.final[D], D)
                self.assertEqual(result.blocked, ())
                self.assertEqual(result.noops, ())

    def test_other_blocks_are_not_touched(self) -> None:
        result = plan([A, C, key(D, "x")], [(A, B)])
        self.assertEqual(result.moved, {A: B})
        self.assertEqual(result.final[C], C)

    def test_it_is_skipped_when_the_target_resource_already_exists(self) -> None:
        """move_execute.go L157-L164: if state.Resource(newAddr) != nil the move is skipped and
        recorded as blocked, 'let the existing object take priority'. Nothing is merged."""
        result = plan([key(A, "x"), key(A, "y"), key(B, "z")], [(A, B)])
        self.assertEqual(result.moved, {})
        self.assertEqual(len(result.blocked), 1)
        blocked = result.blocked[0]
        self.assertEqual(blocked.statement, MoveStatement(A, B))
        self.assertEqual(blocked.movers, (key(A, "x"), key(A, "y")))
        self.assertEqual(blocked.occupants, (key(B, "z"),))
        self.assertEqual(blocked.intended, (key(B, "x"), key(B, "y")))
        self.assertEqual(result.conflicted, {key(A, "x"), key(A, "y"), key(B, "z")})

    def test_a_target_with_the_same_key_is_also_blocked_all_or_nothing(self) -> None:
        result = plan([count(A, 0), count(A, 1), count(B, 0)], [(A, B)])
        self.assertEqual(result.moved, {})
        self.assertEqual(len(result.conflicted), 3)


class TestInstanceLevel(unittest.TestCase):
    def test_exactly_the_named_instance_moves(self) -> None:
        """move_execute.go L177-L198: iAddr.MoveDestination; the other instances stay."""
        result = plan([key(A, "x"), key(A, "y")], [(key(A, "x"), key(B, "z"))])
        self.assertEqual(result.moved, {key(A, "x"): key(B, "z")})
        self.assertEqual(result.final[key(A, "y")], key(A, "y"))

    def test_a_key_less_side_is_the_no_key_instance(self) -> None:
        """UnifyMoveEndpoints: with an instance key on either side both become instance-level,
        so a to b[0] moves only the no-key instance and a[0] to b only the zero instance."""
        result = plan([A], [(A, count(B, 0))])
        self.assertEqual(result.moved, {A: count(B, 0)})
        result = plan([count(A, 0), count(A, 1)], [(count(A, 0), B)])
        self.assertEqual(result.moved, {count(A, 0): B})
        self.assertEqual(result.final[count(A, 1)], count(A, 1))

    def test_a_resource_level_statement_does_not_match_an_instance_level_source(self) -> None:
        """A key-less source with an indexed target is instance-level: an indexed instance of the
        source block is not the no-key instance and does not move."""
        result = plan([count(A, 0)], [(A, count(B, 0))])
        self.assertEqual(result.moved, {})
        self.assertEqual(result.noops, (MoveStatement(A, count(B, 0)),))

    def test_it_is_skipped_when_the_target_instance_exists(self) -> None:
        """move_execute.go L182-L189."""
        result = plan([key(A, "x"), key(B, "y")], [(key(A, "x"), key(B, "y"))])
        self.assertEqual(result.moved, {})
        self.assertEqual(result.blocked[0].movers, (key(A, "x"),))
        self.assertEqual(result.blocked[0].occupants, (key(B, "y"),))

    def test_an_instance_can_move_next_to_an_instance_of_the_target_block(self) -> None:
        result = plan([key(A, "x"), key(B, "y")], [(key(A, "x"), key(B, "z"))])
        self.assertEqual(result.moved, {key(A, "x"): key(B, "z")})
        self.assertEqual(result.blocked, ())


class TestNoOps(unittest.TestCase):
    def test_a_move_whose_source_has_no_trusted_object_changes_nothing(self) -> None:
        """move_execute.go L26-L29 and L152-L198: a statement that matches nothing is ignored
        (history: the object was moved in an earlier run)."""
        result = plan([B, C], [(A, B), (key(C, "x"), key(D, "x"))])
        self.assertEqual(result.moved, {})
        self.assertEqual(result.blocked, ())
        self.assertEqual(
            set(result.noops), {MoveStatement(A, B), MoveStatement(key(C, "x"), key(D, "x"))}
        )

    def test_a_stale_move_is_reported_as_a_no_op_not_as_a_conflict(self) -> None:
        # the target exists because the move was already carried out
        result = plan([B], [(A, B)])
        self.assertEqual(result.conflicted, frozenset())
        self.assertEqual(result.final, {B: B})


class TestChains(unittest.TestCase):
    def test_a_chain_reaches_the_final_location_when_the_middle_is_free(self) -> None:
        """move_execute.go L104, L247-L256: b to c must wait for a to b; each statement is applied
        to the state as it is then (L75-L87 summarizes the chain)."""
        result = plan([A], [(A, B), (B, C)])
        self.assertEqual(result.moved, {A: C})
        self.assertEqual(result.steps[A], (MoveStatement(A, B), MoveStatement(B, C)))
        self.assertEqual(result.blocked, ())

    def test_the_order_of_the_input_does_not_matter(self) -> None:
        moves = [(A, B), (B, C), (C, D)]
        reference = plan([A, key(D, "z")], moves)
        for order in itertools.permutations(moves):
            with self.subTest(order=order):
                self.assertEqual(plan([A, key(D, "z")], list(order)), reference)

    def test_a_chain_of_instances(self) -> None:
        result = plan([key(A, "x")], [(key(A, "x"), key(B, "x")), (key(B, "x"), key(C, "x"))])
        self.assertEqual(result.moved, {key(A, "x"): key(C, "x")})

    def test_an_occupied_middle_blocks_the_first_step_and_the_object_there_moves_on(self) -> None:
        """Statements run in dependency order, a to b first: b is occupied so a stays (L157-L164);
        then b to c moves the object that was at b. This is why a chain cannot be 'resolved' on
        paper (C-123): the result depends on what is at b."""
        result = plan([A, B], [(A, B), (B, C)])
        self.assertEqual(result.moved, {B: C})
        self.assertEqual(result.final[A], A)
        self.assertEqual(len(result.blocked), 1)
        self.assertEqual(result.blocked[0].statement, MoveStatement(A, B))
        self.assertEqual(result.conflicted, {A, B})

    def test_a_resource_level_move_and_an_instance_move_in_it_are_ordered_by_nesting(self) -> None:
        """statementDependsOn L269-L272: b[0]-to-c[0] has its from nested within a-to-b's to,
        so a-to-b runs first and a[0] can be carried on to c[0] in the same run."""
        addresses = [count(A, 0), count(A, 1)]
        moves = [(count(B, 0), count(C, 0)), (A, B)]
        result = plan(addresses, moves)
        self.assertEqual(result.moved, {count(A, 0): count(C, 0), count(A, 1): count(B, 1)})
        self.assertEqual(plan(addresses, list(reversed(moves))), result)

    def test_nesting_orders_statements_against_the_alphabetical_tie_break(self) -> None:
        """statementDependsOn L269-L272. d-to-a runs first although a[0]-to-c[0] sorts before it:
        d[0] arrives at a[0] and is carried on to c[0] in the same run. Without the nesting rule
        the second statement would find nothing at a[0] and be a no-op."""
        addresses = [count(D, 0), count(D, 1)]
        moves = [(count(A, 0), count(C, 0)), (D, A)]
        self.assertLess(MoveStatement(*moves[0]), MoveStatement(*moves[1]))
        result = plan(addresses, moves)
        self.assertEqual(result.moved, {count(D, 0): count(C, 0), count(D, 1): count(A, 1)})
        self.assertEqual(result.noops, ())

    def test_a_chain_blocked_at_its_end_leaves_the_object_in_the_middle(self) -> None:
        """a to b is applied (b is free); b to c is then skipped because c exists (L157-L164).
        Terraform leaves the object at b; the original address is what is reported as involved."""
        result = plan([A, C], [(A, B), (B, C)])
        self.assertEqual(result.final[A], B)
        self.assertEqual(result.blocked[0].movers, (A,))
        self.assertEqual(result.blocked[0].occupants, (C,))
        self.assertEqual(result.conflicted, {A, C})

    def test_two_objects_reaching_one_address_are_a_conflict(self) -> None:
        """a to b moves a[0] to b[0]; then c[0] to b[0] finds it occupied (L182-L189). Both are
        involved; which one 'won' does not decide who is reported."""
        addresses = [count(A, 0), count(C, 0)]
        moves = [(A, B), (count(C, 0), count(B, 0))]
        result = plan(addresses, moves)
        self.assertEqual(result.moved, {count(A, 0): count(B, 0)})
        self.assertEqual(result.conflicted, {count(A, 0), count(C, 0)})
        self.assertEqual(plan(addresses, list(reversed(moves))), result)

    def test_statements_are_deduplicated(self) -> None:
        self.assertEqual(plan([A], [(A, B), (A, B)]), plan([A], [(A, B)]))


class TestRefusedStatements(unittest.TestCase):
    def test_a_cycle_has_no_final_location(self) -> None:
        """move_validate.go L179-L207; ApplyMoves does nothing for a cyclic graph (L50-L53). P3a-2
        refuses cycles, so this is the defence."""
        for moves in (
            [(A, B), (B, A)],
            [(A, B), (B, C), (C, A)],
            [(key(A, "x"), key(B, "x")), (key(B, "x"), key(A, "x"))],
        ):
            with self.subTest(moves=moves), self.assertRaises(IdentityInputError) as caught:
                plan([A], moves)
            self.assertIn("cycle", str(caught.exception))

    def test_two_destinations_for_one_source_and_two_sources_for_one_target(self) -> None:
        """move_validate.go L120-L160."""
        with self.assertRaises(IdentityInputError) as caught:
            plan([A], [(A, B), (A, C)])
        self.assertIn("two destinations", str(caught.exception))
        with self.assertRaises(IdentityInputError) as caught:
            plan([A, C], [(A, B), (C, B)])
        self.assertIn("two sources", str(caught.exception))

    def test_bad_input_is_refused(self) -> None:
        for kwargs in (
            {"addresses": [A, A], "moves": []},
            {"addresses": [A], "moves": [(A, A)]},
            {"addresses": [A], "moves": ["ab"]},
            {"addresses": [A], "moves": [("a",)]},
            {"addresses": [A], "moves": [], "placeholders": ("aws_x.zzz",)},
            {"addresses": ["aws_x.a["], "moves": []},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(IdentityInputError):
                plan(kwargs["addresses"], kwargs["moves"], kwargs.get("placeholders", ()))  # type: ignore[arg-type]


class TestPlaceholders(unittest.TestCase):
    def test_a_placeholder_moves_with_its_block_under_a_resource_level_statement(self) -> None:
        result = plan([A], [(A, B)], placeholders=(A,))
        self.assertEqual(result.moved, {A: B})

    def test_a_resource_level_move_onto_a_placeholder_is_blocked(self) -> None:
        # the placeholder may hold instances, so the target may be occupied: unknown is a conflict
        result = plan([A, B], [(A, B)], placeholders=(B,))
        self.assertEqual(result.moved, {})
        self.assertEqual(result.conflicted, {A, B})

    def test_an_instance_statement_whose_source_block_is_a_placeholder_is_undecidable(self) -> None:
        for source, target in ((count(A, 0), count(B, 0)), (A, count(B, 0)), (key(A, "x"), B)):
            with self.subTest(source=source):
                result = plan([A], [(source, target)], placeholders=(A,))
                self.assertEqual(result.moved, {})
                self.assertEqual(len(result.undecidable), 1)
                item = result.undecidable[0]
                self.assertEqual((item.role, item.block, item.subjects), ("source", A, ()))

    def test_an_instance_statement_onto_a_placeholder_block_is_undecidable(self) -> None:
        result = plan([count(A, 0), B], [(count(A, 0), count(B, 0))], placeholders=(B,))
        self.assertEqual(result.moved, {})
        item = result.undecidable[0]
        self.assertEqual((item.role, item.block, item.subjects), ("target", B, (count(A, 0),)))
        # the same, onto the key-less address of the placeholder
        result = plan([count(A, 0), B], [(count(A, 0), B)], placeholders=(B,))
        self.assertEqual(result.undecidable[0].role, "target")

    def test_a_missing_source_in_a_determinate_block_is_a_plain_no_op(self) -> None:
        result = plan([count(A, 0), B], [(count(A, 5), count(C, 0))], placeholders=(B,))
        self.assertEqual(result.undecidable, ())
        self.assertEqual(len(result.noops), 1)


class TestImplicitCountMoves(unittest.TestCase):
    def implied(
        self,
        trusted: list[str],
        candidate: list[str],
        explicit: tuple[tuple[str, str], ...] | list[tuple[str, str]] = (),
        **kw: tuple[str, ...],
    ) -> tuple[tuple[str, str], ...]:
        return implicit_count_moves(trusted, candidate, explicit, **kw)

    def test_adding_count_moves_the_no_key_instance_to_zero(self) -> None:
        """move_statement.go L160-L168 (C-76, V10)."""
        self.assertEqual(self.implied([A], [count(A, 0), count(A, 1)]), ((A, count(A, 0)),))

    def test_removing_count_moves_zero_to_the_no_key_instance(self) -> None:
        """move_statement.go L169-L174; with count = 2 removed only index 0 moves (C-76)."""
        self.assertEqual(self.implied([count(A, 0), count(A, 1)], [A]), ((count(A, 0), A),))

    def test_nothing_else_is_implicit(self) -> None:
        cases = {
            "x[1] and above never move": ([count(A, 1)], [A]),
            "x[1] to x[0] is not a move": ([count(A, 1)], [count(A, 0)]),
            "into for_each": ([A], [key(A, "x")]),
            "out of for_each": ([key(A, "x")], [A]),
            "for_each key zero is not count zero": ([A], [key(A, "0")]),
            "count to for_each": ([count(A, 0)], [key(A, "x")]),
            "for_each to count": ([key(A, "x")], [count(A, 0)]),
            "no change": ([A], [A]),
            "count unchanged": ([count(A, 0)], [count(A, 0)]),
            "candidate has nothing": ([A], []),
            "trusted has nothing": ([], [count(A, 0)]),
            "no key stays when the candidate has only x[1]": ([A], [count(A, 1)]),
        }
        for name, (trusted, candidate) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(self.implied(trusted, candidate), ())

    def test_another_block_does_not_give_a_move(self) -> None:
        self.assertEqual(self.implied([A], [count(B, 0)]), ())

    def test_an_explicit_statement_on_the_block_suppresses_it_whatever_the_endpoint(self) -> None:
        """move_statement.go L176-L182, haveMoveStatementForResource L223-L239, SelectsResource
        move_endpoint_module.go L281-L312: any explicit statement that selects the block as from or
        to, instance-level included, replaces the implied move, 'because they may wish to select
        an instance key other than zero'."""
        trusted, candidate = [A], [count(A, 0), count(A, 1)]
        for explicit in (
            [(A, count(A, 1))],
            [(A, B)],
            [(C, A)],
            [(count(C, 0), count(A, 1))],
            [(key(A, "x"), key(D, "x"))],
        ):
            with self.subTest(explicit=explicit):
                self.assertEqual(self.implied(trusted, candidate, explicit), ())
        self.assertEqual(self.implied(trusted, candidate, [(C, D)]), ((A, count(A, 0)),))

    def test_a_placeholder_is_not_an_instance(self) -> None:
        self.assertEqual(self.implied([A], [count(A, 0)], trusted_placeholders=(A,)), ())
        self.assertEqual(self.implied([count(A, 0)], [A], candidate_placeholders=(A,)), ())
        self.assertEqual(
            self.implied([A], [A, count(A, 0)], candidate_placeholders=(A,)), ((A, count(A, 0)),)
        )

    def test_module_addresses_are_blocks_too(self) -> None:
        module = 'module.m["k"].aws_x.a'
        self.assertEqual(self.implied([module], [module + "[0]"]), ((module, module + "[0]"),))
        self.assertEqual(self.implied([module + "[0]"], [module]), ((module + "[0]", module),))
        self.assertEqual(self.implied([module], ["aws_x.a[0]"]), ())

    def test_a_deterministic_result_for_many_blocks(self) -> None:
        trusted = [A, count(B, 0), key(C, "x"), D]
        candidate = [count(A, 0), B, key(C, "x"), D]
        self.assertEqual(self.implied(trusted, candidate), ((A, count(A, 0)), (count(B, 0), B)))
        shuffled = list(trusted)
        random.Random(1).shuffle(shuffled)
        self.assertEqual(self.implied(shuffled, candidate), self.implied(trusted, candidate))

    def test_the_implied_statements_run_through_the_plan(self) -> None:
        pairs = self.implied([A, count(B, 0), count(B, 1)], [count(A, 0), B])
        result = plan([A, count(B, 0), count(B, 1)], [], implied=pairs)
        self.assertEqual(result.moved, {A: count(A, 0), count(B, 0): B})
        self.assertEqual(result.final[count(B, 1)], count(B, 1))
        self.assertTrue(all(s.implied for steps in result.steps.values() for s in steps))


class TestPlanIsDeterministic(unittest.TestCase):
    def test_shuffled_inputs_give_the_same_plan(self) -> None:
        addresses = [A, count(B, 0), count(B, 1), key(C, "x"), key(C, "y"), D]
        moves = [(A, key(D, "q")), (count(B, 0), count(B, 5)), (C, "aws_x.e"), (B, "aws_x.f")]
        reference = plan(addresses, moves)
        rng = random.Random(20261028)
        for _ in range(40):
            first, second = rng.sample(addresses, len(addresses)), rng.sample(moves, len(moves))
            self.assertEqual(plan(first, second), reference)


if __name__ == "__main__":
    unittest.main()
