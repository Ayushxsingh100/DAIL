"""The identity engine: what changed between the trusted and the candidate state (Doc 07; C-121).

``compare`` is a pure, deterministic function. It takes the normalized resources of the trusted
and of the candidate state and the candidate's ``moves`` (canonical address pairs, validated and not
applied by P3a-2), and returns an ``IdentityReport``: one ``IdentityMatch`` per resource, with the
evidence behind it. Provider IDs, plan actions and similarity are not inputs (Doc 07 §7): before
P9 they are "simply unavailable, not negative evidence". A suggestion, whoever makes it, is not
identity evidence (Doc 07 §34).

Only the **candidate's** moves are applied. A ``moved`` block describes how objects of the previous
state reach new addresses, so the trusted configuration's own blocks are history and are not an
input (C-121). Both sides must carry the same ``normalization_version`` (Doc 07 §29).

Same inputs give the same ``content_hash``: resources are processed in address order, ties are
broken by address, and no dict or set order reaches the output (Doc 07 §28).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import datetime

from core.domain.identity import IdentityReport
from core.domain.resource import Resource
from core.identity.addresses import split_key
from core.identity.errors import IdentityInputError, IdentityStrategyError
from core.identity.findings import Draft, is_placeholder
from core.identity.moves import MoveStatement
from core.identity.strategy import DEFAULT_STRATEGY, IdentityStrategy

__all__ = ["IdentityInputError", "IdentityStrategyError", "compare"]


def _checked_side(resources: Iterable[Resource], side: str) -> list[Resource]:
    found = list(resources)
    for resource in found:
        if not isinstance(resource, Resource):
            raise IdentityInputError(f"{side}: {type(resource).__name__} is not a Resource")
    addresses = [resource.address for resource in found]
    if len(set(addresses)) != len(addresses):
        duplicates = sorted({a for a in addresses if addresses.count(a) > 1})
        raise IdentityInputError(f"{side}: addresses are not unique: {duplicates}")
    for resource in found:
        _, key = split_key(resource.address)
        if is_placeholder(resource) and key is not None:
            raise IdentityInputError(
                f"{side}: placeholder {resource.address} has an instance key (C-114 puts it at "
                "the key-less address)"
            )
    return found


def _check_normalization(trusted: Sequence[Resource], candidate: Sequence[Resource]) -> None:
    versions: set[str] = set()
    for side, resources in (("trusted", trusted), ("candidate", candidate)):
        for resource in resources:
            version = resource.provenance.normalization_version
            if version is None:
                raise IdentityInputError(
                    f"{side} resource {resource.address} has no normalization_version (Doc 07 §29)"
                )
            versions.add(version)
    if len(versions) > 1:
        raise IdentityInputError(
            f"the sides were normalized by different versions: {sorted(versions)}; a mixed "
            "comparison is refused (Doc 07 §29)"
        )


def _checked_moves(moves: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for pair in moves:
        if isinstance(pair, str) or len(pair) != 2:
            raise IdentityInputError(f"a move is a pair of addresses, not {pair!r}")
        statement = MoveStatement(pair[0], pair[1])
        found.append((statement.source, statement.target))
    return found


def _check_partition(
    trusted: Sequence[Resource], candidate: Sequence[Resource], drafts: Sequence[Draft]
) -> None:
    """Every input resource is in exactly one match, whatever the strategy (C-124 rule 11)."""
    seen_t = sorted(d.trusted_ref for d in drafts if d.trusted_ref is not None)
    seen_c = sorted(d.candidate_ref for d in drafts if d.candidate_ref is not None)
    if seen_t != sorted(r.address for r in trusted) or seen_c != sorted(
        r.address for r in candidate
    ):
        raise IdentityStrategyError(
            "the strategy's answer does not cover the input: a resource is in no match or in two"
        )


def compare(
    trusted: Iterable[Resource],
    candidate: Iterable[Resource],
    candidate_moves: Iterable[tuple[str, str]],
    *,
    parent_state_id: str,
    candidate_id: str,
    now: datetime,
    strategy: IdentityStrategy = DEFAULT_STRATEGY,
) -> IdentityReport:
    """What changed between ``trusted`` and ``candidate``, one match per resource (Doc 07 §30).

    ``strategy`` defaults to the full strategy; the address-only ablation of C-127 must be passed
    explicitly. Raises ``IdentityInputError`` for input it cannot compare: a resource that is not a
    ``Resource``, duplicate addresses on a side, resources of different normalization versions, a
    malformed move.
    """
    trusted_side = _checked_side(trusted, "trusted")
    candidate_side = _checked_side(candidate, "candidate")
    _check_normalization(trusted_side, candidate_side)
    moves = _checked_moves(candidate_moves)
    drafts = strategy.decide(trusted_side, candidate_side, moves)
    _check_partition(trusted_side, candidate_side, drafts)
    return IdentityReport.create(
        parent_state_id=parent_state_id,
        candidate_id=candidate_id,
        matches=[draft.match() for draft in drafts],
        evidence=[item for draft in drafts for item in draft.evidence],
        algorithm_version=strategy.algorithm_version,
        now=now,
    )
