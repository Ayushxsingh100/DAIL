"""Following ``moved`` blocks and the implicit ``count`` moves (Registry §2.3, §2.9; C-76, C-123).

The unit is Terraform's own: ``ApplyMoves`` (``internal/refactoring/move_execute.go``, tag
v1.15.8) takes the objects of the *previous* state and the statements of the *current*
configuration, orders the statements by dependency, and applies each one to the state as it is at
that moment. Here the previous state is the set of trusted addresses and the statements are the
candidate's ``moves`` (P3a-2, validated and not applied), plus the implied ones.

Rules, each with its source in C-123:

* **Level.** A statement is resource-level only when neither endpoint has an instance key
  (``UnifyMoveEndpoints``, ``move_endpoint.go`` L173-L215); then every instance of the source block
  moves to the target block with the same key. Otherwise it is instance-level and moves exactly the
  source address; a key-less side is the no-key instance.
* **Order.** A statement runs after the statements it chains from (its ``from`` is another
  statement's ``to``, at the same level) or nests with (a resource-level endpoint of one block and
  an instance-level endpoint of the same block): ``statementDependsOn``, ``move_execute.go``
  L247-L293. Ties are broken by address, never by the order of the input.
* **Occupied target.** A move is skipped, and recorded as *blocked*, when the target block (resource
  level) or the target address (instance level) already holds an object: "let the existing object
  take priority" (L157-L164, L182-L189). The caller decides what a blocked move means.
* **Nothing to move.** A statement whose source has no object is a no-op (history).
* **Implied moves** (``ImpliedMoveStatements``, ``move_statement.go`` L125-L209): the no-key
  instance of a block whose candidate has ``count`` moves to ``[0]``; a ``[0]`` instance whose
  candidate has neither ``count`` nor ``for_each`` moves to no-key; nothing else. A block that any
  explicit statement selects, as source or target, gets none (L176-L182).

A *placeholder* is a resource with an unknown number of instances (C-114). It lives at its key-less
block address, moves with its block under a resource-level statement, and makes everything that
depends on its instances undecidable: an instance-level statement whose source or target block is a
placeholder cannot be applied or refused, and is reported as such.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Collection, Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from core.identity.addresses import block_of, key_of, split_key
from core.identity.errors import IdentityInputError


@dataclass(frozen=True, order=True)
class MoveStatement:
    """One move: ``source`` to ``target``, canonical addresses. ``implied`` marks a count move."""

    source: str
    target: str
    implied: bool = False

    def __post_init__(self) -> None:
        for name, value in (("source", self.source), ("target", self.target)):
            split_key(value)  # also refuses a malformed address
            if value != value.strip():
                raise IdentityInputError(f"move {name} {value!r} has surrounding whitespace")
        if self.source == self.target:
            raise IdentityInputError(f"{self.source} is moved to itself")

    @property
    def source_block(self) -> str:
        return block_of(self.source)

    @property
    def target_block(self) -> str:
        return block_of(self.target)

    @property
    def resource_level(self) -> bool:
        return key_of(self.source) is None and key_of(self.target) is None


@dataclass(frozen=True)
class BlockedMove:
    """A statement that was skipped because its target is occupied (a conflict, C-123).

    ``movers`` and ``occupants`` are the *original* trusted addresses of the objects involved: the
    ones that wanted to move, and the ones already at the target.
    """

    statement: MoveStatement
    movers: tuple[str, ...]
    occupants: tuple[str, ...]

    @property
    def involved(self) -> tuple[str, ...]:
        return tuple(sorted({*self.movers, *self.occupants}))


@dataclass(frozen=True)
class UndecidableMove:
    """An instance-level statement that touches a placeholder block (unknown instances).

    ``role`` is ``source`` (the source instance may or may not exist: ``subjects`` is empty) or
    ``target`` (the target may or may not be occupied: ``subjects`` is the instance that wanted to
    move). ``block`` is the placeholder's block.
    """

    statement: MoveStatement
    role: str
    block: str
    subjects: tuple[str, ...]


@dataclass(frozen=True)
class MovePlan:
    """Where every trusted object ends after the statements (C-123).

    ``final`` has one entry per trusted address (the address itself when nothing moved it).
    ``steps`` has the statements applied to each moved object, in the order applied.
    """

    final: Mapping[str, str]
    steps: Mapping[str, tuple[MoveStatement, ...]]
    blocked: tuple[BlockedMove, ...]
    undecidable: tuple[UndecidableMove, ...]
    noops: tuple[MoveStatement, ...]
    statements: tuple[MoveStatement, ...] = field(default=())

    @property
    def moved(self) -> dict[str, str]:
        """Original address to final address, for the objects that moved."""
        return {old: new for old, new in sorted(self.final.items()) if old != new}

    @property
    def conflicted(self) -> frozenset[str]:
        """The original addresses of all objects involved in a blocked move."""
        return frozenset(address for item in self.blocked for address in item.involved)


@dataclass
class _Object:
    origin: str
    placeholder: bool
    steps: list[MoveStatement] = field(default_factory=list)


def _statements(
    moves: Iterable[tuple[str, str]], implied: Iterable[tuple[str, str]]
) -> list[MoveStatement]:
    found: dict[tuple[str, str], MoveStatement] = {}
    for implied_flag, pairs in ((False, moves), (True, implied)):
        for pair in pairs:
            if isinstance(pair, str) or len(pair) != 2:
                raise IdentityInputError(f"a move is a pair of addresses, not {pair!r}")
            statement = MoveStatement(pair[0], pair[1], implied_flag)
            found.setdefault((statement.source, statement.target), statement)
    statements = sorted(found.values())
    for first, second in zip(statements, statements[1:], strict=False):
        if first.source == second.source:
            raise IdentityInputError(
                f"{first.source} has two destinations: {first.target} and {second.target} "
                "(move_validate.go L120-L139)"
            )
    sources: dict[str, str] = {}
    for statement in statements:
        earlier = sources.setdefault(statement.target, statement.source)
        if earlier != statement.source:
            raise IdentityInputError(
                f"{statement.target} has two sources: {earlier} and {statement.source} "
                "(move_validate.go L141-L160)"
            )
    return statements


def _chains(later: MoveStatement, earlier: MoveStatement) -> bool:
    """``later.from`` can chain from ``earlier.to`` (``CanChainFrom``): same level and endpoint."""
    if later.resource_level != earlier.resource_level:
        return False
    if later.resource_level:
        return later.source_block == earlier.target_block
    return later.source == earlier.target


def _nested(inner: str, outer: str, outer_level: bool, inner_level: bool) -> bool:
    """``inner`` is an instance of the resource ``outer`` (``NestedWithin``)."""
    return outer_level and not inner_level and block_of(inner) == block_of(outer)


def _runs_after(later: MoveStatement, earlier: MoveStatement) -> bool:
    """``statementDependsOn(later, earlier)``: ``earlier`` must be executed first."""
    if _chains(later, earlier):
        return True
    late, early = later.resource_level, earlier.resource_level
    return (
        _nested(later.source, earlier.target, early, late)
        or _nested(later.target, earlier.target, early, late)
        or _nested(earlier.source, later.source, late, early)
        or _nested(earlier.target, later.source, late, early)
    )


def _in_dependency_order(statements: list[MoveStatement]) -> list[MoveStatement]:
    waiting = {
        statement: {
            other for other in statements if other != statement and _runs_after(statement, other)
        }
        for statement in statements
    }
    ordered: list[MoveStatement] = []
    while waiting:
        ready = sorted(statement for statement, needs in waiting.items() if not needs)
        if not ready:
            raise IdentityInputError(
                "chained move statements form a cycle (move_validate.go L179-L207)"
            )
        for statement in ready:
            del waiting[statement]
            ordered.append(statement)
        for needs in waiting.values():
            needs.difference_update(ready)
    return ordered


def plan_moves(
    trusted_addresses: Iterable[str],
    moves: Iterable[tuple[str, str]],
    *,
    placeholders: Collection[str] = frozenset(),
    implied: Iterable[tuple[str, str]] = (),
) -> MovePlan:
    """Apply the statements to the trusted objects as Terraform's ``ApplyMoves`` does (C-123).

    ``trusted_addresses`` are all addresses of the trusted side, placeholders included (at their
    key-less block address, named again in ``placeholders``). ``moves`` are the candidate's explicit
    pairs, ``implied`` the pairs from ``implicit_count_moves``. The result does not depend on the
    order of either.
    """
    addresses = list(trusted_addresses)
    if len(set(addresses)) != len(addresses):
        raise IdentityInputError("trusted addresses are not unique")
    for address in addresses:
        split_key(address)
    unknown = set(placeholders) - set(addresses)
    if unknown:
        raise IdentityInputError(f"placeholders that are not trusted addresses: {sorted(unknown)}")
    statements = _statements(moves, implied)
    current = {a: _Object(a, a in placeholders) for a in sorted(addresses)}
    by_block: dict[str, set[str]] = defaultdict(set)
    for address in current:
        by_block[block_of(address)].add(address)
    blocked: list[BlockedMove] = []
    undecidable: list[UndecidableMove] = []
    matched: set[MoveStatement] = set()

    def relocate(old: str, new: str, statement: MoveStatement) -> None:
        item = current.pop(old)
        by_block[block_of(old)].discard(old)
        item.steps.append(statement)
        current[new] = item
        by_block[block_of(new)].add(new)

    def placeholder_at(block: str) -> bool:
        item = current.get(block)
        return item is not None and item.placeholder

    for statement in _in_dependency_order(statements):
        if statement.resource_level:
            movers = sorted(by_block.get(statement.source_block, ()))
            if not movers:
                continue
            matched.add(statement)
            occupants = sorted(by_block.get(statement.target_block, ()))
            if occupants:
                blocked.append(
                    BlockedMove(
                        statement,
                        tuple(current[a].origin for a in movers),
                        tuple(current[a].origin for a in occupants),
                    )
                )
                continue
            for address in movers:
                relocate(address, statement.target_block + (key_of(address) or ""), statement)
            continue
        source = current.get(statement.source)
        if source is None or source.placeholder:
            if placeholder_at(statement.source_block):
                matched.add(statement)
                undecidable.append(UndecidableMove(statement, "source", statement.source_block, ()))
            continue
        matched.add(statement)
        occupant = current.get(statement.target)
        if occupant is not None and not occupant.placeholder:
            blocked.append(BlockedMove(statement, (source.origin,), (occupant.origin,)))
        elif placeholder_at(statement.target_block):
            undecidable.append(
                UndecidableMove(statement, "target", statement.target_block, (source.origin,))
            )
        else:
            relocate(statement.source, statement.target, statement)

    final = {item.origin: address for address, item in sorted(current.items())}
    steps = {item.origin: tuple(item.steps) for item in current.values() if item.steps}
    return MovePlan(
        final=MappingProxyType(dict(sorted(final.items()))),
        steps=MappingProxyType(dict(sorted(steps.items()))),
        blocked=tuple(sorted(blocked, key=lambda b: (b.statement, b.movers, b.occupants))),
        undecidable=tuple(sorted(undecidable, key=lambda u: (u.statement, u.role, u.subjects))),
        noops=tuple(s for s in statements if s not in matched),
        statements=tuple(statements),
    )


def implicit_count_moves(
    trusted_addresses: Iterable[str],
    candidate_addresses: Iterable[str],
    explicit_moves: Iterable[tuple[str, str]],
    *,
    trusted_placeholders: Collection[str] = frozenset(),
    candidate_placeholders: Collection[str] = frozenset(),
) -> tuple[tuple[str, str], ...]:
    """The implicit ``count`` moves between two configurations (C-76, C-123).

    A trusted no-key instance ``x`` moves to ``x[0]`` when the candidate has ``x[0]`` (so it has
    ``count``), and a trusted ``x[0]`` moves to ``x`` when the candidate has the no-key ``x`` (so it
    has neither ``count`` nor ``for_each``). Nothing else is implicit: not ``x[1]`` and above, and
    not into or out of ``for_each``. A block that an explicit statement selects as source or target
    gets none. Placeholders on either side are not instances, so they give none.
    """
    selected: set[str] = set()
    for source, target in explicit_moves:
        selected.add(block_of(source))
        selected.add(block_of(target))
    trusted = set(trusted_addresses) - set(trusted_placeholders)
    candidate = set(candidate_addresses) - set(candidate_placeholders)
    found: list[tuple[str, str]] = []
    for address in sorted(trusted):
        block, key = split_key(address)
        if block in selected:
            continue
        if key is None and block + "[0]" in candidate:
            found.append((address, block + "[0]"))
        elif key == "[0]" and block in candidate:
            found.append((address, block))
    return tuple(found)
