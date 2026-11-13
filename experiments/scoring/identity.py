"""Identity truth for H3 (P8b-2, C-213; metrics-draft-1 item 10).

``identity_truth.json`` gives, per TerraPreserve operator, the identity effect the catalogue
(D4_OPERATORS.md) states. ``true_pairs`` applies it to a step. Appearing addresses are those the
step's configuration declares and the previous step's does not; vanishing ones the reverse
(``ScenarioLabels.declared``). A MOVE pairs the one vanishing address of the type with the one
appearing address of the type; a REPLACE names an address the operator's mutation rows change on the
forcing attribute (both ``before`` and ``after`` set); a CREATE (DELETE) names every appearing
(vanishing) address of the type that the operator's mutation rows name. A MOVE whose addresses
cannot be recovered that way, and every address of an excluded operator, is an excluded pair,
counted.

``judge`` compares one true pair with DAIL's identity pairs of the transition (trusted ref,
candidate ref, change type), on addresses without instance keys: ``correct`` (MOVE: DAIL pairs the
old with the new address; REPLACE: REPLACED; CREATE: CREATED; DELETE: DELETED), ``uncertain`` (DAIL
says UNCERTAIN for it), or ``wrong``.
"""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from experiments.scoring.labels import ScenarioLabels

TABLE_PATH = Path(__file__).with_name("identity_truth.json")


@dataclass(frozen=True)
class IdentityTable:
    version: str
    rows: Mapping[str, Mapping[str, Any]]
    excluded: Mapping[str, str]


@dataclass(frozen=True)
class TruePair:
    operator: str
    effect: str
    resource_type: str
    old: str | None
    new: str | None


def load_identity_table(path: Path = TABLE_PATH) -> IdentityTable:
    data = json.loads(path.read_text(encoding="utf-8"))
    return IdentityTable(data["version"], data["rows"], data["excluded"])


def _type(address: str) -> str:
    return address.split(".", 1)[0]


def base(address: str | None) -> str | None:
    return None if address is None else address.split("[", 1)[0]


def true_pairs(
    table: IdentityTable, scenario: ScenarioLabels, step: int
) -> tuple[list[TruePair], list[dict[str, str]]]:
    """The true identity pairs of ``step`` and the excluded ones (operator, address, reason)."""
    by_op: dict[str, dict[str, list[Any]]] = defaultdict(lambda: defaultdict(list))
    for row in scenario.mutations:
        if row.step == step:
            by_op[row.operator][row.target_address].append(row)
    pairs: list[TruePair] = []
    excluded: list[dict[str, str]] = []
    for operator in sorted(by_op):
        addresses = by_op[operator]
        if operator in table.excluded:
            excluded += [
                {"operator": operator, "address": a, "reason": table.excluded[operator]}
                for a in sorted(addresses)
            ]
            continue
        spec = table.rows.get(operator)
        if spec is None:
            continue  # no identity effect: an attribute edit
        before, after = scenario.declared[step - 1], scenario.declared[step]
        appearing, vanishing = set(after - before), set(before - after)
        named = set(addresses)
        used: set[str] = set()
        for effect in spec["effects"]:
            kind, wanted = effect["effect"], effect["resource_type"]

            def fits(address: str, wanted: str = wanted) -> bool:
                return wanted == "*" or _type(address) == wanted

            if kind == "MOVE":
                olds = sorted(a for a in vanishing - used if fits(a))
                news = sorted(a for a in appearing - used if fits(a))
                if not (named & set(olds + news)):
                    olds, news = [], []
                if len(olds) == 1 and len(news) == 1:
                    pairs.append(TruePair(operator, kind, wanted, olds[0], news[0]))
                    used |= {olds[0], news[0]}
                else:
                    excluded.append(
                        {
                            "operator": operator,
                            "address": ",".join(olds + news) or "-",
                            "reason": "the renamed addresses cannot be recovered from the rows",
                        }
                    )
            elif kind == "REPLACE":
                for address in sorted(addresses):
                    rows = addresses[address]
                    if fits(address) and any(
                        r.attribute == effect["attribute"]
                        and r.before is not None
                        and r.after is not None
                        for r in rows
                    ):
                        pairs.append(TruePair(operator, kind, wanted, address, address))
                        used.add(address)
            else:
                pool = appearing if kind == "CREATE" else vanishing
                for address in sorted(a for a in (pool & named) - used if fits(a)):
                    old, new = (None, address) if kind == "CREATE" else (address, None)
                    pairs.append(TruePair(operator, kind, wanted, old, new))
                    used.add(address)
    return pairs, excluded


_EXPECTED = {"REPLACE": "REPLACED", "CREATE": "CREATED", "DELETE": "DELETED"}


def judge(pair: TruePair, dail: Sequence[tuple[str | None, str | None, str, bool]]) -> str:
    """``correct``, ``uncertain`` or ``wrong`` (see the module docstring)."""
    found = [(base(t), base(c), kind) for t, c, kind, _ in dail]
    touching = [
        kind
        for t, c, kind in found
        if (pair.old is not None and pair.old in (t, c))
        or (pair.new is not None and pair.new in (t, c))
    ]
    if pair.effect == "MOVE":
        if any(t == pair.old and c == pair.new for t, c, _ in found):
            return "correct"
    else:
        own = [
            kind
            for t, c, kind in found
            if (t == pair.old if pair.old is not None else t is None)
            and (c == pair.new if pair.new is not None else c is None)
        ]
        if _EXPECTED[pair.effect] in own:
            return "correct"
    return "uncertain" if "UNCERTAIN" in touching else "wrong"


def judge_all(
    pairs: Iterable[TruePair], dail: Sequence[tuple[str | None, str | None, str, bool]]
) -> list[tuple[TruePair, str]]:
    return [(p, judge(p, dail)) for p in pairs]
