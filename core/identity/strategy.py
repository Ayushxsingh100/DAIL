"""Identity strategies: how trusted and candidate resources are paired and classified (C-124/127).

``IdentityStrategy`` is the seam C-20 asks for. ``EvidenceIdentity`` is the full strategy: the
default of ``compare`` and the only one production code may use. ``AddressOnlyIdentity`` is the
labelled ablation for the pre-declared condition "DAIL minus identity" (hypothesis H3); it exists
only so that the experiment harness (P8) can run that condition. Whether it changes any result is
not known until it is measured. Neither is reachable from a configuration key or an environment
variable.

Both run the same decision order, with the rules the ablation removes switched off (``Rules``):

1. A **placeholder** (unknown number of instances) is always UNCERTAIN, paired or not.
2. A resource involved in a **conflicting move** (an occupied target, or a pair of two types) is
   UNCERTAIN.
3. **Pairing** by identical address after the moves (explicit, then implicit).
4. An unpaired instance whose counterpart block is a placeholder is UNCERTAIN, never CREATED or
   DELETED (missing knowledge is not proof of absence).
5. **AMB-1**: unpaired instances of one block that cannot be told apart are all UNCERTAIN.
6. The leftovers: unpaired trusted is DELETED, unpaired candidate CREATED.
7. A pair is UNCHANGED (equal fingerprints) or MODIFIED; **RT-1** may make it REPLACED or UNCERTAIN.

``UNSUPPORTED_TYPE`` and ``UNRESOLVED_CONTENT`` are flags, not identity evidence: they are attached
by both strategies, so the two differ only in identity decisions.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final, NamedTuple, Protocol

from core.domain.enums import ChangeType, ResourceSupport
from core.domain.identity import EvidenceSource, EvidenceType, IdentityEvidence
from core.domain.resource import Resource
from core.identity.addresses import block_of
from core.identity.findings import (
    Draft,
    Evidencer,
    ambiguous_blocks,
    is_placeholder,
    replace_trigger_verdict,
    sorted_resources,
)
from core.identity.moves import MovePlan, implicit_count_moves, plan_moves

IDENTITY_ALGORITHM_VERSION: Final = "dail-identity-1"
ADDRESS_ONLY_ALGORITHM_VERSION: Final = "dail-identity-addr-1"


class IdentityStrategy(Protocol):
    """Decides what happened to every resource; ``compare`` builds the report from the drafts."""

    @property
    def algorithm_version(self) -> str: ...

    def decide(
        self,
        trusted: Sequence[Resource],
        candidate: Sequence[Resource],
        candidate_moves: Sequence[tuple[str, str]],
    ) -> list[Draft]: ...


@dataclass(frozen=True)
class Rules:
    """Which parts of the decision order are on."""

    follow_moves: bool
    ambiguity: bool
    replace_triggers: bool
    indeterminate_leftovers: bool


FULL_RULES: Final = Rules(
    follow_moves=True, ambiguity=True, replace_triggers=True, indeterminate_leftovers=True
)
# The ablation (C-127): exact-address pairing only. It removes identity *evidence* (moves, AMB-1,
# RT-1), not the rule that unknown is not a pass: placeholders stay UNCERTAIN, and so do the
# unpaired instances of an indeterminate block (rule 4), which is the same rule.
ADDRESS_ONLY_RULES: Final = Rules(
    follow_moves=False, ambiguity=False, replace_triggers=False, indeterminate_leftovers=True
)


class _Reason(NamedTuple):
    kind: EvidenceType
    source: EvidenceSource
    observed: object
    text: str


# C-124: the first rule that applies decides, so the evidence of a placeholder comes first.
_PRIORITY: Final = {EvidenceType.INDETERMINATE_BLOCK: 0, EvidenceType.CONFLICTING_MOVE: 1}


class _Run:
    """One comparison: the state that the decision order passes along."""

    def __init__(
        self,
        version: str,
        rules: Rules,
        trusted: Sequence[Resource],
        candidate: Sequence[Resource],
        moves: Sequence[tuple[str, str]],
    ) -> None:
        self.rules = rules
        self.ev = Evidencer(version)
        self.trusted = {r.address: r for r in sorted_resources(trusted)}
        self.candidate = {r.address: r for r in sorted_resources(candidate)}
        self.moves = tuple(moves)
        self.t_placeholders = sorted(a for a, r in self.trusted.items() if is_placeholder(r))
        self.c_placeholders = sorted(a for a, r in self.candidate.items() if is_placeholder(r))
        self.plan: MovePlan | None = None
        self.final: dict[str, str] = {address: address for address in self.trusted}
        self.forced_t: dict[str, list[_Reason]] = defaultdict(list)
        self.forced_c: dict[str, list[_Reason]] = defaultdict(list)
        self.if_unpaired_t: dict[str, list[_Reason]] = defaultdict(list)
        self.if_unpaired_c: dict[str, list[_Reason]] = defaultdict(list)
        self.done_t: set[str] = set()
        self.done_c: set[str] = set()
        self.drafts: list[Draft] = []

    # --- the decision order ---------------------------------------------------------------------

    def run(self) -> list[Draft]:
        self.apply_moves()
        self.force_uncertain()
        self.pair()
        self.protect_indeterminate_blocks()
        if self.rules.ambiguity:
            self.ambiguity()
        self.leftovers()
        return self.drafts

    def apply_moves(self) -> None:
        if not self.rules.follow_moves:
            return
        implied = implicit_count_moves(
            self.trusted,
            self.candidate,
            self.moves,
            trusted_placeholders=self.t_placeholders,
            candidate_placeholders=self.c_placeholders,
        )
        self.plan = plan_moves(
            self.trusted, self.moves, placeholders=self.t_placeholders, implied=implied
        )
        self.final = dict(self.plan.final)

    def force_uncertain(self) -> None:
        """Rules 1 and 2: placeholders, then conflicting moves."""
        for address in self.t_placeholders:
            self.forced_t[address].append(self.indeterminate("trusted", address))
        for address in self.c_placeholders:
            self.forced_c[address].append(self.indeterminate("candidate", address))
        if self.plan is None:
            return
        for blocked in self.plan.blocked:
            reason = _Reason(
                EvidenceType.CONFLICTING_MOVE,
                EvidenceSource.MOVES,
                {
                    "reason": "the target is occupied, so Terraform skips the move",
                    "statement": [blocked.statement.source, blocked.statement.target],
                    "movers": list(blocked.movers),
                    "occupants": list(blocked.occupants),
                },
                "A move is skipped because its target already holds an object; which object ends "
                "where is not decided here (C-123).",
            )
            for origin in blocked.involved:
                self.forced_t[origin].append(reason)
            for intended in blocked.intended:
                if intended in self.candidate:
                    self.forced_c[intended].append(reason)
        for item in self.plan.undecidable:
            reason = _Reason(
                EvidenceType.INDETERMINATE_BLOCK,
                EvidenceSource.MOVES,
                {
                    "role": item.role,
                    "statement": [item.statement.source, item.statement.target],
                    "block": item.block,
                },
                "A move touches a block whose number of instances is unknown, so it can be "
                "neither applied nor refused (C-123).",
            )
            if item.role == "source" and item.statement.target in self.candidate:
                self.if_unpaired_c[item.statement.target].append(reason)
            for origin in item.subjects:
                self.if_unpaired_t[origin].append(reason)

    def pair(self) -> None:
        """Rule 3, and the forced matches of rules 1 and 2 that are not pairs."""
        for t_address, trusted in self.trusted.items():
            c_address = self.final[t_address]
            candidate = self.candidate.get(c_address)
            if candidate is None:
                continue
            reasons = [*self.forced_t.get(t_address, ()), *self.forced_c.get(c_address, ())]
            if trusted.resource_type != candidate.resource_type:
                reasons.append(
                    _Reason(
                        EvidenceType.CONFLICTING_MOVE,
                        EvidenceSource.BOTH,
                        {
                            "reason": "the types differ",
                            "trusted_type": trusted.resource_type,
                            "candidate_type": candidate.resource_type,
                        },
                        "The resources meet at one address but are of different types (C-124).",
                    )
                )
            self.done_t.add(t_address)
            self.done_c.add(c_address)
            if reasons:
                self.drafts.append(self.uncertain(trusted, candidate, reasons))
            else:
                self.drafts.append(self.classify(trusted, candidate))
        for t_address, trusted in self.trusted.items():
            if t_address not in self.done_t and t_address in self.forced_t:
                self.done_t.add(t_address)
                self.drafts.append(self.uncertain(trusted, None, self.forced_t[t_address]))
        for c_address, candidate in self.candidate.items():
            if c_address not in self.done_c and c_address in self.forced_c:
                self.done_c.add(c_address)
                self.drafts.append(self.uncertain(None, candidate, self.forced_c[c_address]))

    def protect_indeterminate_blocks(self) -> None:
        """Rule 4, and the instances a move could not place (C-123)."""
        counterpart_blocks = set(self.c_placeholders)
        moved_placeholders = {self.final[address] for address in self.t_placeholders}
        for t_address, trusted in self.trusted.items():
            if t_address in self.done_t:
                continue
            reasons = list(self.if_unpaired_t.get(t_address, ()))
            if self.rules.indeterminate_leftovers and block_of(self.final[t_address]) in (
                counterpart_blocks
            ):
                reasons.append(self.indeterminate("candidate", block_of(self.final[t_address])))
            if reasons:
                self.done_t.add(t_address)
                self.drafts.append(self.uncertain(trusted, None, reasons))
        for c_address, candidate in self.candidate.items():
            if c_address in self.done_c:
                continue
            reasons = list(self.if_unpaired_c.get(c_address, ()))
            if self.rules.indeterminate_leftovers and block_of(c_address) in moved_placeholders:
                reasons.append(self.indeterminate("trusted", block_of(c_address)))
            if reasons:
                self.done_c.add(c_address)
                self.drafts.append(self.uncertain(None, candidate, reasons))

    def ambiguity(self) -> None:
        """Rule 5 (AMB-1, C-125). Objects a move carried to an address nobody has are not part of
        it: the statement says where they went."""
        trusted = [a for a in self.trusted if a not in self.done_t and self.final[a] == a]
        candidate = [a for a in self.candidate if a not in self.done_c]
        for block, (t_members, c_members) in ambiguous_blocks(trusted, candidate).items():
            reason = _Reason(
                EvidenceType.AMBIGUOUS_CANDIDATES,
                EvidenceSource.BOTH,
                {"block": block, "trusted": list(t_members), "candidate": list(c_members)},
                "Several unpaired instances of one block could correspond; none is chosen "
                "(Doc 07 §11, AMB-1).",
            )
            for address in t_members:
                self.done_t.add(address)
                self.drafts.append(self.uncertain(self.trusted[address], None, [reason]))
            for address in c_members:
                self.done_c.add(address)
                self.drafts.append(self.uncertain(None, self.candidate[address], [reason]))

    def leftovers(self) -> None:
        """Rule 6."""
        for t_address, trusted in self.trusted.items():
            if t_address in self.done_t:
                continue
            self.done_t.add(t_address)
            evidence: list[IdentityEvidence] = []
            rule = EvidenceType.NO_COUNTERPART
            target = self.final[t_address]
            if target != t_address:
                rule = EvidenceType.EXPLICIT_MOVE
                evidence.append(
                    self.ev.about(
                        trusted,
                        None,
                        EvidenceType.EXPLICIT_MOVE,
                        EvidenceSource.MOVES,
                        {
                            "from": t_address,
                            "to": target,
                            "target_in_candidate": False,
                            "statements": self.statements(t_address),
                        },
                        "A moved block carries the resource to an address that the candidate does "
                        "not have: it is deleted there.",
                    )
                )
            evidence.append(
                self.ev.about(
                    trusted,
                    None,
                    EvidenceType.NO_COUNTERPART,
                    EvidenceSource.TRUSTED,
                    {"address": t_address},
                    "No candidate resource corresponds to this trusted resource.",
                )
            )
            self.drafts.append(
                self.flagged(Draft(trusted, None, ChangeType.DELETED, rule, evidence))
            )
        for c_address, candidate in self.candidate.items():
            if c_address in self.done_c:
                continue
            self.done_c.add(c_address)
            evidence = [
                self.ev.about(
                    None,
                    candidate,
                    EvidenceType.NO_COUNTERPART,
                    EvidenceSource.CANDIDATE,
                    {"address": c_address},
                    "No trusted resource corresponds to this candidate resource.",
                )
            ]
            self.drafts.append(
                self.flagged(
                    Draft(
                        None, candidate, ChangeType.CREATED, EvidenceType.NO_COUNTERPART, evidence
                    )
                )
            )

    # --- pieces ---------------------------------------------------------------------------------

    def indeterminate(self, side: str, address: str) -> _Reason:
        return _Reason(
            EvidenceType.INDETERMINATE_BLOCK,
            EvidenceSource.TRUSTED if side == "trusted" else EvidenceSource.CANDIDATE,
            {"side": side, "block": block_of(address)},
            "The number of instances of this block is unknown, so absence or equality cannot be "
            "concluded (C-114, C-124).",
        )

    def statements(self, address: str) -> list[list[str]]:
        steps = () if self.plan is None else self.plan.steps.get(address, ())
        return [[step.source, step.target] for step in steps]

    def uncertain(
        self, trusted: Resource | None, candidate: Resource | None, reasons: Sequence[_Reason]
    ) -> Draft:
        evidence: list[IdentityEvidence] = []
        seen: set[str] = set()
        ordered = sorted(reasons, key=lambda reason: _PRIORITY.get(reason.kind, len(_PRIORITY)))
        for reason in ordered:
            item = self.ev.about(
                trusted, candidate, reason.kind, reason.source, reason.observed, reason.text
            )
            if item.evidence_id not in seen:
                seen.add(item.evidence_id)
                evidence.append(item)
        return self.flagged(
            Draft(trusted, candidate, ChangeType.UNCERTAIN, ordered[0].kind, evidence)
        )

    def flagged(self, draft: Draft) -> Draft:
        """Attach ``UNSUPPORTED_TYPE`` and, for a pair, ``UNRESOLVED_CONTENT`` (C-124)."""
        flag = self.ev.unsupported(draft.trusted, draft.candidate)
        if flag is not None:
            draft.evidence.append(flag)
        if draft.trusted is not None and draft.candidate is not None:
            unresolved = self.ev.unresolved(draft.trusted, draft.candidate)
            if unresolved is not None:
                draft.evidence.append(unresolved)
        return draft

    def classify(self, trusted: Resource, candidate: Resource) -> Draft:
        """Rule 7 for a pair that no other rule has taken."""
        steps = () if self.plan is None else self.plan.steps.get(trusted.address, ())
        if steps:
            implied = all(step.implied for step in steps)
            via = self.ev.about(
                trusted,
                candidate,
                EvidenceType.IMPLICIT_COUNT_MOVE if implied else EvidenceType.EXPLICIT_MOVE,
                EvidenceSource.MOVES,
                {
                    "from": trusted.address,
                    "to": candidate.address,
                    "statements": self.statements(trusted.address),
                },
                (
                    "Terraform's implicit move when count is added or removed pairs the resources."
                    if implied
                    else "A moved block of the candidate maps the trusted address to this address."
                ),
            )
        else:
            via = self.ev.about(
                trusted,
                candidate,
                EvidenceType.EXACT_ADDRESS,
                EvidenceSource.BOTH,
                {"address": trusted.address, "resource_type": trusted.resource_type},
                "Same canonical address and type on both sides.",
            )
        observed = {"trusted": trusted.fingerprint, "candidate": candidate.fingerprint}
        if trusted.fingerprint == candidate.fingerprint:
            change, rule = ChangeType.UNCHANGED, EvidenceType.FINGERPRINT_EQUAL
            fingerprint = self.ev.about(
                trusted,
                candidate,
                rule,
                EvidenceSource.BOTH,
                observed,
                "The canonical content of the paired resources is identical.",
            )
            extra: list[IdentityEvidence] = []
        else:
            change, rule = ChangeType.MODIFIED, EvidenceType.FINGERPRINT_DIFFERENT
            fingerprint = self.ev.about(
                trusted,
                candidate,
                rule,
                EvidenceSource.BOTH,
                observed,
                "The canonical content of the paired resources differs.",
            )
            extra = []
            unsupported = ResourceSupport.UNSUPPORTED in (
                trusted.support_status,
                candidate.support_status,
            )
            if self.rules.replace_triggers and not unsupported:
                verdict, extra = replace_trigger_verdict(trusted, candidate, self.ev)
                if verdict is ChangeType.REPLACED:
                    change, rule = ChangeType.REPLACED, EvidenceType.REPLACE_TRIGGER_FIELD
                elif verdict is ChangeType.UNCERTAIN:
                    change, rule = ChangeType.UNCERTAIN, EvidenceType.REPLACE_TRIGGER_UNRESOLVED
        return self.flagged(Draft(trusted, candidate, change, rule, [via, fingerprint, *extra]))


def _decide(
    version: str,
    rules: Rules,
    trusted: Sequence[Resource],
    candidate: Sequence[Resource],
    moves: Sequence[tuple[str, str]],
) -> list[Draft]:
    return _Run(version, rules, trusted, candidate, moves).run()


@dataclass(frozen=True)
class EvidenceIdentity:
    """The full strategy (C-124 to C-126): moves, AMB-1, RT-1 and the protection of
    indeterminate blocks. The default of ``compare``."""

    @property
    def algorithm_version(self) -> str:
        return IDENTITY_ALGORITHM_VERSION

    def decide(
        self,
        trusted: Sequence[Resource],
        candidate: Sequence[Resource],
        candidate_moves: Sequence[tuple[str, str]],
    ) -> list[Draft]:
        return _decide(self.algorithm_version, FULL_RULES, trusted, candidate, candidate_moves)


@dataclass(frozen=True)
class AddressOnlyIdentity:
    """The ablation for the pre-declared condition "DAIL minus identity" (C-20, C-127, H3).

    Exact-address pairing only: no moves, no implicit moves, no RT-1, no AMB-1. Equal fingerprint
    is UNCHANGED, different is MODIFIED, unpaired is CREATED or DELETED. Placeholders and the
    instances of an indeterminate block are still UNCERTAIN. It exists only so that the experiment
    harness (P8) can run that condition; production code must not use it, no configuration key or
    environment variable selects it, and its report says ``dail-identity-addr-1``. Whether it
    changes any result is not known: it is hypothesis H3 until measured.
    """

    @property
    def algorithm_version(self) -> str:
        return ADDRESS_ONLY_ALGORITHM_VERSION

    def decide(
        self,
        trusted: Sequence[Resource],
        candidate: Sequence[Resource],
        candidate_moves: Sequence[tuple[str, str]],
    ) -> list[Draft]:
        return _decide(
            self.algorithm_version, ADDRESS_ONLY_RULES, trusted, candidate, candidate_moves
        )


DEFAULT_STRATEGY: Final[IdentityStrategy] = EvidenceIdentity()
