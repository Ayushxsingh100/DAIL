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
