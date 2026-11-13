"""A hand-built record set for the P8b metric tests. Not a test module.

Two invariants, S = INV-SEC-001 and F = INV-FUNC-001. Four scenarios:

* X  F8 repair (target S), controlled, cluster tpl-1, steps 0..2:
  T0 {S FAIL, F PASS}  T1 {S FAIL, F PASS}  T2 {S PASS, F PASS}; affected O1 {F}, O2 {S}.
* Y  F5 repair (target S), controlled, cluster tpl-2, steps 0..1:
  T0 {S FAIL, F PASS}  T1 {S PASS, F FAIL}; affected O1 {S, F}. Step 1 renames a rule with a moved
  block and replaces a security group (mutation rows below).
* Z  F1 change_request, real-world, cluster lin-1, steps 0..1:
  T0 {S PASS, F PASS}  T1 {S PASS, F PASS}; affected O1 {}. Step 1 adds a monitoring group.
* W  F8 repair (target S), controlled, cluster tpl-1, steps 0..2:
  T0 {S FAIL, F PASS}  T1 {S FAIL, F FAIL}  T2 {S PASS, F FAIL}; affected O1 {F}, O2 {S}.
  Step 1 uses op_f5_count_each_safe, which the identity table excludes.

DAIL's records, per condition (decision; work rows as invariant:origin:reason:result; gates are two
PASS rows in every evaluated transition):

C   X1 PROMOTE open[S]  S:condition:NOT_PROTECTED_IN_PARENT:FAIL  F:impact:PASS     impact {F}
    X2 PROMOTE          S:impact:PASS (F carried)                                   impact {S}
    Y1 PROMOTE          S:impact:PASS (F carried)                                   impact {S}
    Z1 RETRY            F:impact:UNKNOWN (S carried)                                impact {F}
    W1 REJECT  open[S]  S:condition:NOT_PROTECTED_IN_PARENT:FAIL  F:impact:FAIL     impact {F}
    W2 TRUNCATED
B   X1 PROMOTE  S:condition:CONDITION_SCOPE:FAIL F:impact:PASS
    X2 PROMOTE  S:impact:PASS F:condition:CONDITION_SCOPE:PASS
    Y1 REJECT   S:impact:PASS F:condition:CONDITION_SCOPE:FAIL
    Z1 PROMOTE  S:condition:CONDITION_SCOPE:PASS F:impact:PASS
    W1 REJECT   S:condition:CONDITION_SCOPE:FAIL F:impact:FAIL
    W2 TRUNCATED
A   X1 X2 Y1 Z1 W1 W2 all PROMOTE; S:condition (X1, W1) or S:impact (X2, Y1, W2); Z1 gates only
C'  as C, except Y1 also has F:impact:PASS (work 4), and its identity pairs differ.

Identity pairs: Y1 under C: rule r5432 -> r5432_v2 paired (MODIFIED, moved), group db -> db
MODIFIED; under C': r5432 DELETED and r5432_v2 CREATED, group db REPLACED. Z1 under C: mon
CREATED; under C': mon UNCERTAIN. B's S0 results: as T0, except Z's F is UNKNOWN.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from types import MappingProxyType

from experiments.metrics.model import Transition, WorkRow
from experiments.scoring.labels import MutationRow, ScenarioLabels

S, F = "INV-SEC-001", "INV-FUNC-001"
P, X_ = "PASS", "FAIL"


def _t(**truth: str) -> Mapping[str, str]:
    return MappingProxyType({S: truth["s"], F: truth["f"]})


def _d(*addresses: str) -> frozenset[str]:
    return frozenset(addresses)


BASE = ("aws_instance.app", "aws_security_group.db")


def scenarios() -> dict[str, ScenarioLabels]:
    rename = (
        MutationRow(
            1,
            "op_f5_db_rule_moved_safe",
            "aws_security_group_rule.r5432",
            "from_port",
            "5432",
            None,
        ),
        MutationRow(
            1,
            "op_f5_db_rule_moved_safe",
            "aws_security_group_rule.r5432_v2",
            "from_port",
            None,
            "5432",
        ),
        MutationRow(
            1, "op_f5_db_sg_replacement_safe", "aws_security_group.db", "name", '"db"', '"db-v2"'
        ),
    )
    # Z: the monitoring group is new; the existing group db only gains an attribute (no CREATE)
    z_rows = (
        MutationRow(
            1, "op_f6_add_monitoring_sg_safe", "aws_security_group.mon", "name", None, '"mon"'
        ),
        MutationRow(
            1, "op_f6_add_monitoring_sg_safe", "aws_security_group.db", "description", None, '"x"'
        ),
    )
    return {
        "X": ScenarioLabels(
            "X",
            "F8",
            "repair",
            S,
            "controlled",
            "tpl-1",
            "safe",
            (_t(s=X_, f=P), _t(s=X_, f=P), _t(s=P, f=P)),
            (frozenset(), frozenset({F}), frozenset({S})),
            (),
            (_d(*BASE), _d(*BASE), _d(*BASE)),
        ),
        "Y": ScenarioLabels(
            "Y",
            "F5",
            "repair",
            S,
            "controlled",
            "tpl-2",
            "unsafe",
            (_t(s=X_, f=P), _t(s=P, f=X_)),
            (frozenset(), frozenset({S, F})),
            rename,
            (
                _d(*BASE, "aws_security_group_rule.r5432"),
                _d(*BASE, "aws_security_group_rule.r5432_v2"),
            ),
        ),
        "Z": ScenarioLabels(
            "Z",
            "F1",
            "change_request",
            None,
            "real_world",
            "lin-1",
            "safe",
            (_t(s=P, f=P), _t(s=P, f=P)),
            (frozenset(), frozenset()),
            z_rows,
            (_d(*BASE), _d(*BASE, "aws_security_group.mon")),
        ),
        "W": ScenarioLabels(
            "W",
            "F8",
            "repair",
            S,
            "controlled",
            "tpl-1",
            "unsafe",
            (_t(s=X_, f=P), _t(s=X_, f=X_), _t(s=P, f=X_)),
            (frozenset(), frozenset({F}), frozenset({S})),
            (MutationRow(1, "op_f5_count_each_safe", "aws_instance.app", "count", None, "1"),),
            (_d(*BASE), _d(*BASE), _d(*BASE)),
        ),
    }


GATES = (
    WorkRow("STRUCTURAL", "STRUCTURAL", "PASS", True, "gate", None),
    WorkRow("CONSISTENCY", "STRUCTURAL", "PASS", True, "gate", None),
)


def inv(name: str, origin: str, result: str, reason: str | None = None) -> WorkRow:
    version = 2 if name == S else 1
    chosen = reason or ("CONDITION_SCOPE" if origin == "condition" else "SCOPE_RESOURCE_CHANGED")
    return WorkRow(f"INVARIANT:{name}:{version}", "INVARIANT", result, True, origin, chosen)


def target(name: str) -> str:
    return f"INVARIANT:{name}:{2 if name == S else 1}"


def tr(
    condition: str,
    scenario: str,
    step: int,
    decision: str | None,
    work: Iterable[WorkRow] = (),
    *,
    carried: Iterable[str] = (),
    open_targets: Iterable[str] = (),
    affected: Iterable[str] = (),
    pairs: Iterable[tuple[str | None, str | None, str, bool]] = (),
    required: Iterable[str] | None = None,
) -> Transition:
    open_targets = tuple(open_targets)
    rows = tuple(work)
    if decision is None:
        return Transition(
            f"{condition}-{scenario}",
            scenario,
            condition,
            step,
            "TRUNCATED",
            None,
            (),
            (),
            (),
            frozenset(),
            (),
            None,
        )
    run = [w for w in rows if w.target_type == "INVARIANT"]
    wanted = [target(n) for n in required] if required is not None else [w.target_id for w in run]
    req = [("CONSISTENCY", "VERIFIED"), ("STRUCTURAL", "VERIFIED")]
    # as DAIL records it: VERIFIED only when the result proves the check (a PASS, or a FAIL on an
    # open target, C-196); an unproven check has no source
    results = {w.target_id: w.result for w in rows}
    opened = {target(n) for n in open_targets}
    req += [
        (
            t,
            (
                "VERIFIED"
                if results.get(t) == "PASS" or (results.get(t) == "FAIL" and t in opened)
                else None
            ),
        )
        for t in wanted
    ]
    req += [(target(n), "CARRIED_FORWARD") for n in carried]
    return Transition(
        f"{condition}-{scenario}",
        scenario,
        condition,
        step,
        "EVALUATED",
        decision,
        tuple(open_targets),
        tuple(sorted(req)),
        GATES + rows,
        frozenset(affected),
        tuple(pairs),
        0.5,
    )


NP = "NOT_PROTECTED_IN_PARENT"
Y_PAIRS_C = (
    ("aws_security_group_rule.r5432", "aws_security_group_rule.r5432_v2", "MODIFIED", True),
    ("aws_security_group.db", "aws_security_group.db", "MODIFIED", False),
)
Y_PAIRS_CP = (
    ("aws_security_group_rule.r5432", None, "DELETED", False),
    (None, "aws_security_group_rule.r5432_v2", "CREATED", False),
    ("aws_security_group.db", "aws_security_group.db", "REPLACED", False),
)


def transitions() -> list[Transition]:
    c_like = []
    for cond in ("C", "C_PRIME"):
        y_work = [inv(S, "impact", P)] + ([inv(F, "impact", P)] if cond == "C_PRIME" else [])
        c_like += [
            tr(
                cond,
                "X",
                1,
                "PROMOTE",
                [inv(S, "condition", X_, NP), inv(F, "impact", P)],
                open_targets=[S],
                affected=[F],
            ),
            tr(cond, "X", 2, "PROMOTE", [inv(S, "impact", P)], carried=[F], affected=[S]),
            tr(
                cond,
                "Y",
                1,
                "PROMOTE",
                y_work,
                carried=[] if cond == "C_PRIME" else [F],
                affected=[S],
                pairs=Y_PAIRS_CP if cond == "C_PRIME" else Y_PAIRS_C,
            ),
            tr(
                cond,
                "Z",
                1,
                "RETRY",
                [inv(F, "impact", "UNKNOWN")],
                carried=[S],
                affected=[F],
                pairs=[
                    (
                        None,
                        "aws_security_group.mon",
                        "UNCERTAIN" if cond == "C_PRIME" else "CREATED",
                        False,
                    )
                ],
            ),
            tr(
                cond,
                "W",
                1,
                "REJECT",
                [inv(S, "condition", X_, NP), inv(F, "impact", X_)],
                open_targets=[S],
                affected=[F],
            ),
            tr(cond, "W", 2, None),
        ]
    b = [
        tr(
            "B", "X", 1, "PROMOTE", [inv(S, "condition", X_), inv(F, "impact", P)], open_targets=[S]
        ),
        tr("B", "X", 2, "PROMOTE", [inv(S, "impact", P), inv(F, "condition", P)]),
        tr("B", "Y", 1, "REJECT", [inv(S, "impact", P), inv(F, "condition", X_)]),
        tr("B", "Z", 1, "PROMOTE", [inv(S, "condition", P), inv(F, "impact", P)]),
        tr(
            "B", "W", 1, "REJECT", [inv(S, "condition", X_), inv(F, "impact", X_)], open_targets=[S]
        ),
        tr("B", "W", 2, None),
    ]
    a = [
        tr("A", "X", 1, "PROMOTE", [inv(S, "condition", X_)], open_targets=[S]),
        tr("A", "X", 2, "PROMOTE", [inv(S, "impact", P)]),
        tr("A", "Y", 1, "PROMOTE", [inv(S, "impact", P)]),
        tr("A", "Z", 1, "PROMOTE", []),
        tr("A", "W", 1, "PROMOTE", [inv(S, "condition", X_)], open_targets=[S]),
        tr("A", "W", 2, "PROMOTE", [inv(S, "impact", P)]),
    ]
    return a + b + c_like


def baselines() -> dict[tuple[str, str], Mapping[str, str]]:
    """S0 results of DAIL under B, by (scenario, condition)."""
    return {
        ("X", "B"): {S: X_, F: P},
        ("Y", "B"): {S: X_, F: P},
        ("Z", "B"): {S: P, F: "UNKNOWN"},
        ("W", "B"): {S: X_, F: P},
    }
