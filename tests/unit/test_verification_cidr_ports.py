"""CIDR coverage and port logic of the security predicates (P5a step 3; registry §2.5, §3.3; C-146).

Hand-derived cases come from the registry text: "Covers means set containment of address ranges. A
list of CIDRs covers a range R when the union of the listed ranges contains R" (§2.5), and
``permits_tcp(r, p)`` is true when the protocol is ALL, or TCP with ``from_port <= p <= to_port``.
The brute-force check enumerates the addresses of a small target with the standard library's own
membership test and compares; it shares no code with ``covers``.
"""

from __future__ import annotations

import ipaddress
import random
import unittest

from core.verification.cidr import (
    IPV4_ANY,
    IPV6_ANY,
    CidrError,
    Network,
    covers,
    parse_network,
)
from core.verification.ports import PortsError, may_permit_tcp, permits_tcp


class TestParse(unittest.TestCase):
    def test_parse(self) -> None:
        self.assertEqual(parse_network("10.0.0.0/8"), Network(4, 10 << 24, (11 << 24) - 1))
        self.assertEqual(parse_network("0.0.0.0/0"), Network(4, 0, 2**32 - 1))
        self.assertEqual(parse_network("1.2.3.4/32"), Network(4, 0x01020304, 0x01020304))
        self.assertEqual(parse_network("::/0"), Network(6, 0, 2**128 - 1))
        self.assertEqual(parse_network("::1/128"), Network(6, 1, 1))

    def test_invalid_text_is_refused(self) -> None:
        for text in (
            "",
            "x",
            "10.0.0.0",
            "10.0.0.1/8",
            "1.2.3.4/33",
            "::/129",
            "10.0.0.0/-1",
            " 10.0.0.0/8",
        ):
            with self.subTest(text=text), self.assertRaises(CidrError):
                parse_network(text)

    def test_a_non_text_is_refused(self) -> None:
        for value in (None, 5, b"10.0.0.0/8"):
            with self.subTest(value=value), self.assertRaises(CidrError):
                parse_network(value)  # type: ignore[arg-type]


class TestCovers(unittest.TestCase):
    def test_the_whole_internet(self) -> None:
        self.assertTrue(covers([IPV4_ANY], IPV4_ANY))
        self.assertTrue(covers([IPV6_ANY], IPV6_ANY))

    def test_registry_s4_two_halves_cover_the_internet(self) -> None:
        self.assertTrue(covers(["0.0.0.0/1", "128.0.0.0/1"], IPV4_ANY))
        self.assertTrue(covers(["128.0.0.0/1", "0.0.0.0/1"], IPV4_ANY))

    def test_one_half_does_not(self) -> None:
        self.assertFalse(covers(["0.0.0.0/1"], IPV4_ANY))
        self.assertFalse(covers(["128.0.0.0/1"], IPV4_ANY))

    def test_adjacent_ranges_join_but_a_gap_does_not(self) -> None:
        self.assertTrue(covers(["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/1"], IPV4_ANY))
        self.assertFalse(covers(["0.0.0.0/2", "128.0.0.0/1"], IPV4_ANY))  # 64.0.0.0/2 is missing

    def test_overlap_and_duplicates_do_not_matter(self) -> None:
        self.assertTrue(covers(["0.0.0.0/1", "0.0.0.0/1", "0.0.0.0/3", "128.0.0.0/1"], IPV4_ANY))
        self.assertFalse(covers(["10.0.0.0/8", "10.0.0.0/8", "10.1.0.0/16"], IPV4_ANY))

    def test_nothing_covers_nothing(self) -> None:
        self.assertFalse(covers([], IPV4_ANY))
        self.assertFalse(covers([], "10.0.0.0/8"))

    def test_narrow_targets(self) -> None:
        self.assertTrue(covers(["10.0.0.0/8"], "10.1.0.0/16"))
        self.assertFalse(covers(["10.1.0.0/16"], "10.0.0.0/8"))
        self.assertTrue(covers(["10.0.0.0/9", "10.128.0.0/9"], "10.0.0.0/8"))

    def test_ipv6(self) -> None:
        self.assertTrue(covers(["::/1", "8000::/1"], IPV6_ANY))
        self.assertFalse(covers(["::/1"], IPV6_ANY))
        self.assertFalse(covers(["2001:db8::/32"], IPV6_ANY))

    def test_a_huge_target_is_not_enumerated(self) -> None:
        # an implementation that listed addresses would never return for 2**128 of them
        self.assertFalse(covers(["::/1"], IPV6_ANY))
        self.assertTrue(covers(["::/0"], IPV6_ANY))

    def test_mixing_the_families_is_a_caller_error(self) -> None:
        with self.assertRaises(CidrError):
            covers(["::/0"], IPV4_ANY)
        with self.assertRaises(CidrError):
            covers([IPV4_ANY], IPV6_ANY)

    def test_an_invalid_member_is_an_error_never_ignored(self) -> None:
        with self.assertRaises(CidrError):
            covers(["0.0.0.0/1", "nonsense"], IPV4_ANY)

    def test_the_order_of_the_input_does_not_matter(self) -> None:
        cidrs = ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"]
        rng = random.Random(20261028)
        for _ in range(20):
            rng.shuffle(cidrs)
            self.assertTrue(covers(list(cidrs), IPV4_ANY))

    def test_agrees_with_brute_force_on_small_ipv4_windows(self) -> None:
        self._brute_force(4, "10.0.0.0/27", range(27, 33), seed=1)

    def test_agrees_with_brute_force_on_small_ipv6_windows(self) -> None:
        self._brute_force(6, "2001:db8::/123", range(123, 129), seed=2)

    def _brute_force(self, version: int, window: str, prefixes: range, seed: int) -> None:
        universe = ipaddress.ip_network(window)
        rng = random.Random(seed)
        hits = misses = 0
        for _ in range(600):
            members = []
            for _ in range(rng.randint(0, 6)):
                prefix = rng.choice(list(prefixes))
                subnets = list(universe.subnets(new_prefix=prefix))
                members.append(rng.choice(subnets))
            target_prefix = rng.choice(list(prefixes)[:3])
            target = rng.choice(list(universe.subnets(new_prefix=target_prefix)))
            expected = all(any(address in net for net in members) for address in target)
            got = covers([str(net) for net in members], str(target))
            self.assertEqual(got, expected, (version, [str(n) for n in members], str(target)))
            hits += expected
            misses += not expected
        self.assertGreater(hits, 30)  # the check is not vacuous in either direction
        self.assertGreater(misses, 30)


class TestCoverageBoundaries(unittest.TestCase):
    """P5a carry-forward 1: the edges of the sweep, where an off-by-one would hide.

    A target network ``T`` covers the addresses ``first..last``. Members are built by cutting that
    range into CIDRs with ``summarize_address_range`` (input construction only: the expected answer
    follows from which addresses are left out, never from ``covers``). For each family:

    * a set that leaves out exactly one address in the middle does not cover ``T``; adding that
      address as a single-address member makes it cover;
    * leaving out only the last address (or only the first) does not cover; adding it does;
    * a single-address member (``/32``, ``/128``) at the cursor advances it: ``[x/32]`` covers
      ``x/32``, consecutive single-address members cover the network they tile, and a single
      address next to the target does not cover it;
    * order and duplicates never change any of these answers.
    """

    TARGETS = ("10.0.0.0/24", "2001:db8::/120")

    @staticmethod
    def cut(first: int, last: int, version: int) -> list[str]:
        """The CIDRs that exactly tile the addresses first..last (empty when first > last)."""
        if first > last:
            return []
        make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        return [str(net) for net in ipaddress.summarize_address_range(make(first), make(last))]

    @staticmethod
    def single(value: int, version: int) -> str:
        make = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
        return f"{make(value)}/{32 if version == 4 else 128}"

    def each_family(self) -> list[tuple[str, int, int, int]]:
        found = []
        for target in self.TARGETS:
            net = ipaddress.ip_network(target)
            found.append(
                (target, net.version, int(net.network_address), int(net.broadcast_address))
            )
        return found

    def check_every_order(self, members: list[str], target: str, expected: bool) -> None:
        rng = random.Random(len(members) * 31 + int(expected))
        variants = [members, [*members, *members]]
        for _ in range(4):
            shuffled = [*members, members[0]] if members else []
            rng.shuffle(shuffled)
            variants.append(shuffled)
        for variant in variants:
            self.assertIs(covers(variant, target), expected, (target, variant))

    def test_one_missing_address_in_the_middle(self) -> None:
        for target, version, first, last in self.each_family():
            gap = first + (last - first) // 2 + 1  # not at an edge, not on a CIDR boundary
            around = [*self.cut(first, gap - 1, version), *self.cut(gap + 1, last, version)]
            with self.subTest(target=target):
                self.check_every_order(around, target, False)
                self.check_every_order([*around, self.single(gap, version)], target, True)

    def test_the_last_address_uncovered(self) -> None:
        for target, version, first, last in self.each_family():
            short = self.cut(first, last - 1, version)
            with self.subTest(target=target):
                self.check_every_order(short, target, False)
                self.check_every_order([*short, self.single(last, version)], target, True)

    def test_the_first_address_uncovered(self) -> None:
        for target, version, first, last in self.each_family():
            short = self.cut(first + 1, last, version)
            with self.subTest(target=target):
                self.check_every_order(short, target, False)
                self.check_every_order([self.single(first, version), *short], target, True)

    def test_a_single_address_member_advances_the_cursor(self) -> None:
        for _target, version, first, _last in self.each_family():
            one = self.single(first + 5, version)
            with self.subTest(family=version):
                self.assertTrue(covers([one], one))
                self.assertFalse(covers([one], self.single(first + 6, version)))
                self.assertFalse(covers([one], self.single(first + 4, version)))

    def test_consecutive_single_address_members_tile_a_network(self) -> None:
        for _target, version, first, _last in self.each_family():
            bits = 30 if version == 4 else 126
            network = f"{ipaddress.ip_address(first)}/{bits}"
            tiles = [self.single(first + offset, version) for offset in range(4)]
            with self.subTest(family=version):
                self.check_every_order(tiles, network, True)
                self.check_every_order(tiles[:3], network, False)  # the fourth is missing
                self.check_every_order([tiles[0], tiles[1], tiles[3]], network, False)


class TestCoverageOracle(unittest.TestCase):
    """The work package's oracle: the address space is cut into 64 blocks (the /6 networks), a CIDR
    of prefix length 1 to 6 is a run of consecutive blocks, and coverage is plain set containment of
    block numbers. It shares no code with ``covers`` and does not use ``ipaddress`` to decide."""

    BLOCKS = 64

    @staticmethod
    def text(version: int, prefix: int, index: int) -> str:
        bits = 32 if version == 4 else 128
        value = index << (bits - prefix)
        if version == 4:
            return (
                f"{value >> 24}.{(value >> 16) & 255}.{(value >> 8) & 255}.{value & 255}/{prefix}"
            )
        groups = [f"{(value >> shift) & 0xFFFF:x}" for shift in range(112, -16, -16)]
        return ":".join(groups) + f"/{prefix}"

    def blocks(self, prefix: int, index: int) -> set[int]:
        width = 2 ** (6 - prefix)
        return set(range(index * width, (index + 1) * width))

    def run_family(self, version: int, seed: int) -> None:
        rng = random.Random(seed)
        everything = set(range(self.BLOCKS))
        covered = uncovered = 0
        for _ in range(800):
            members = []
            union: set[int] = set()
            for _ in range(rng.randint(0, 8)):
                prefix = rng.randint(1, 6)
                index = rng.randrange(2**prefix)
                members.append(self.text(version, prefix, index))
                union |= self.blocks(prefix, index)
            whole = "0.0.0.0/0" if version == 4 else "::/0"
            self.assertEqual(covers(members, whole), union == everything, members)
            target_prefix = rng.randint(1, 6)
            target_index = rng.randrange(2**target_prefix)
            wanted = self.blocks(target_prefix, target_index)
            got = covers(members, self.text(version, target_prefix, target_index))
            self.assertEqual(got, wanted <= union, (members, target_prefix, target_index))
            covered += wanted <= union
            uncovered += not wanted <= union
        self.assertGreater(covered, 40)
        self.assertGreater(uncovered, 40)

    def test_ipv4(self) -> None:
        self.run_family(4, 20261028)

    def test_ipv6(self) -> None:
        self.run_family(6, 424242)

    def test_the_oracle_renders_the_s4_split(self) -> None:
        self.assertEqual(self.text(4, 1, 0), "0.0.0.0/1")
        self.assertEqual(self.text(4, 1, 1), "128.0.0.0/1")
        self.assertEqual(self.text(6, 1, 1), "8000:0:0:0:0:0:0:0/1")


class TestPorts(unittest.TestCase):
    def test_permits_tcp_table(self) -> None:
        table = [
            ("ALL", None, None, 22, True),
            ("ALL", None, None, 5432, True),
            ("TCP", 22, 22, 22, True),
            ("TCP", 0, 65535, 22, True),
            ("TCP", 23, 100, 22, False),
            ("TCP", 0, 21, 22, False),
            ("TCP", 22, 22, 5432, False),
            ("TCP", 5432, 5432, 5432, True),
            ("TCP", 5431, 5433, 5432, True),
            ("TCP", 5433, 5433, 5432, False),
            ("UDP", 22, 22, 22, False),
            ("ICMP", -1, -1, 22, False),
            ("ICMPV6", -1, -1, 22, False),
            ("47", None, None, 22, False),
        ]
        for protocol, low, high, port, expected in table:
            with self.subTest(protocol=protocol, low=low, high=high, port=port):
                self.assertIs(permits_tcp(protocol, low, high, port), expected)

    def test_a_tcp_rule_without_ports_is_not_decided_here(self) -> None:
        for low, high in ((None, None), (22, None), (None, 22)):
            with self.subTest(low=low, high=high), self.assertRaises(PortsError):
                permits_tcp("TCP", low, high, 22)

    def test_a_missing_protocol_is_not_decided_here(self) -> None:
        with self.assertRaises(PortsError):
            permits_tcp(None, 22, 22, 22)

    def test_may_permit_tcp_is_true_when_something_is_unresolved(self) -> None:
        table = [
            (None, None, None, 22, True),  # protocol unresolved
            (None, 22, 22, 22, True),
            ("TCP", None, None, 22, True),  # ports unresolved
            ("TCP", None, 100, 22, True),
            ("TCP", 23, None, 22, True),
            ("ALL", None, None, 22, True),
            ("TCP", 22, 22, 22, True),  # resolved and permitting
            ("TCP", 23, 100, 22, False),  # resolved and not permitting
            ("UDP", None, None, 22, False),  # another protocol never permits TCP
            ("ICMP", None, None, 22, False),
            ("47", None, None, 22, False),
        ]
        for protocol, low, high, port, expected in table:
            with self.subTest(protocol=protocol, low=low, high=high, port=port):
                self.assertIs(may_permit_tcp(protocol, low, high, port), expected)


if __name__ == "__main__":
    unittest.main()
