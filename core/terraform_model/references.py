"""Reference extraction (Doc 04 §16.2; Doc 07 §15; Doc 05 §5.3; C-115).

For every argument of every resource instance, ``references_of`` returns the
``core.domain.values.Reference`` objects it holds, so that no reference is silently discarded:

- **(a) values**: every ``Ref`` found in the evaluated value (target = the instance address);
- **(b) expressions**: every resource or data traversal in the argument's expression tree, followed
  transitively through ``local.*`` (a constant index gives the instance address, a non-constant
  index the key-less address as UNKNOWN, no index on a resource with ``count``/``for_each`` the
  key-less address as UNKNOWN unless (a) already gave its instances);
- ``depends_on`` entries (``DEPENDS_ON``), and the ``count``, ``for_each``, ``lifecycle``,
  ``provisioner`` and ``connection`` expressions (these are recorded, not evaluated, but they are
  dependencies Terraform follows).

``resolution_status`` (C-115): SUPPORTED for a configured determinate instance of a supported
type; UNSUPPORTED for an unsupported or tolerated type or a module; UNKNOWN for an indeterminate
or missing target, a data source, or a key that cannot be fixed. When (a) and (b) give the same
target with different statuses the more conservative one is kept (UNSUPPORTED over UNKNOWN over
SUPPORTED) and a diagnostic says so. Edge typing (Doc 07 §16) is P3c's.

The source attribute is the argument name, or a path through blocks such as
``ingress[0].security_groups`` (block order as in ``canonical.ordered_blocks``); the blocks of a
``dynamic`` block that expanded to nothing are written ``name[*]``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Final

from core.domain.enums import ReferenceResolution
from core.domain.values import Reference
from core.terraform_model.canonical import NO_POLICY, SetPolicy, ordered_blocks, policy_for
from core.terraform_model.config import (
    Diagnostic,
    DiagnosticSeverity,
    ParsedConfiguration,
    ResourceDecl,
)
from core.terraform_model.hcl.ast import (
    Attribute,
    AttrStep,
    BinaryOp,
    Block,
    Conditional,
    Expression,
    ForExpr,
    FunctionCall,
    GetAttr,
    Heredoc,
    IdentifierKey,
    Index,
    IndexStep,
    LegacyIndexStep,
    Literal,
    LiteralKind,
    Object,
    Parenthesized,
    ScopeTraversal,
    Splat,
    Template,
    TemplateFor,
    TemplateIf,
    TemplateInterpolation,
    TemplatePart,
    Tuple,
    UnaryOp,
)
from core.terraform_model.instances import (
    EvaluatedArgument,
    EvaluatedBlock,
    EvaluatedInstance,
    EvaluatedResource,
    instance_address,
)
from core.terraform_model.normalize import SUPPORTED_TYPES
from core.terraform_model.values import Ref, Value, walk

ATTRIBUTE_REFERENCE: Final = "ATTRIBUTE_REFERENCE"
DEPENDS_ON: Final = "DEPENDS_ON"

_IGNORED_ROOTS: Final = frozenset({"var", "each", "count", "path", "terraform", "self"})
_SEVERITY: Final = {
    ReferenceResolution.SUPPORTED: 0,
    ReferenceResolution.UNKNOWN: 1,
    ReferenceResolution.UNSUPPORTED: 2,
}

Key = int | str | None


@dataclass(frozen=True, slots=True)
class Candidate:
    """A resource, data source or module that an expression names."""

    kind: str  # resource, data or module
    type: str
    name: str
    mode: str  # "none" (no index), "const" (a constant index) or "unknown" (any other index)
    key: Key = None


def _constant_key(step: IndexStep | LegacyIndexStep) -> tuple[bool, Key]:
    if isinstance(step, LegacyIndexStep):
        return True, step.index
    key = step.key
    if isinstance(key, Literal):
        if key.kind is LiteralKind.STRING:
            return True, str(key.value)
        if key.kind is LiteralKind.NUMBER and isinstance(key.value, int):
            return True, key.value
    return False, None


def _traversal_candidates(node: ScopeTraversal) -> list[Candidate]:
    root, steps = node.root, node.steps
    if root in _IGNORED_ROOTS or not steps or not isinstance(steps[0], AttrStep):
        return []
    if root == "module":
        return [Candidate("module", "module", steps[0].name, "none")]
    if root == "data":
        if len(steps) < 2 or not isinstance(steps[1], AttrStep):
            return []
        kind, type_, name, rest = "data", steps[0].name, steps[1].name, steps[2:]
    else:
        kind, type_, name, rest = "resource", root, steps[0].name, steps[1:]
    if rest and isinstance(rest[0], IndexStep | LegacyIndexStep):
        constant, key = _constant_key(rest[0])
        if constant:
            return [Candidate(kind, type_, name, "const", key)]
        return [Candidate(kind, type_, name, "unknown")]
    return [Candidate(kind, type_, name, "none")]


def _parts(parts: Iterable[TemplatePart]) -> list[Expression]:
    found: list[Expression] = []
    for part in parts:
        if isinstance(part, TemplateInterpolation):
            found.append(part.expr)
        elif isinstance(part, TemplateIf):
            found.append(part.condition)
            found.extend(_parts(part.true_parts))
            found.extend(_parts(part.false_parts or ()))
        elif isinstance(part, TemplateFor):
            found.append(part.collection)  # the loop variables are bound in the body only
            found.extend(_parts(part.parts))
    return found


def _is_resource_name(node: Expression) -> bool:
    return (
        isinstance(node, ScopeTraversal)
        and node.root not in _IGNORED_ROOTS
        and node.root not in ("local", "module")
        and len(node.steps) == 1
        and isinstance(node.steps[0], AttrStep)
    )


def expression_candidates(
    expression: Expression, locals_: Mapping[str, Expression], bound: frozenset[str] = frozenset()
) -> list[Candidate]:
    """Every resource, data source and module the expression names, through locals too."""
    found: list[Candidate] = []
    stack: list[tuple[Expression, frozenset[str], frozenset[str]]] = [
        (expression, bound, frozenset())
    ]
    while stack:
        node, names, visiting = stack.pop()
        if isinstance(node, ScopeTraversal):
            if node.root in names:
                continue
            if node.root == "local" and node.steps and isinstance(node.steps[0], AttrStep):
                local = node.steps[0].name
                if local in locals_ and local not in visiting:
                    stack.append((locals_[local], frozenset(), visiting | {local}))
                continue
            found.extend(_traversal_candidates(node))
        elif isinstance(node, Parenthesized):
            stack.append((node.expr, names, visiting))
        elif isinstance(node, Tuple):
            stack.extend((e, names, visiting) for e in node.elements)
        elif isinstance(node, Object):
            for item in node.items:
                if not isinstance(item.key, IdentifierKey):
                    stack.append((item.key, names, visiting))
                stack.append((item.value, names, visiting))
        elif isinstance(node, Template | Heredoc):
            stack.extend((e, names, visiting) for e in _parts(node.parts))
        elif isinstance(node, FunctionCall):
            stack.extend((e, names, visiting) for e in node.args)
        elif isinstance(node, Conditional):
            stack.extend(
                (e, names, visiting) for e in (node.condition, node.true_expr, node.false_expr)
            )
        elif isinstance(node, BinaryOp):
            stack.extend((e, names, visiting) for e in (node.left, node.right))
        elif isinstance(node, UnaryOp):
            stack.append((node.operand, names, visiting))
        elif isinstance(node, ForExpr):
            inner = names | {v for v in (node.key_var, node.value_var) if v is not None}
            stack.append((node.collection, names, visiting))
            for part in (node.key_expr, node.value_expr, node.condition):
                if part is not None:
                    stack.append((part, inner, visiting))
        elif isinstance(node, Splat):
            stack.append((node.source, names, visiting))
            for step in node.steps:
                if isinstance(step, IndexStep):
                    stack.append((step.key, names, visiting))
        elif isinstance(node, Index):
            collection = node.collection
            while isinstance(collection, Parenthesized):
                collection = collection.expr
            if _is_resource_name(collection):
                assert isinstance(collection, ScopeTraversal)
                kind = "data" if collection.root == "data" else "resource"
                found.append(Candidate(kind, collection.root, collection.steps[0].name, "unknown"))  # type: ignore[union-attr]
            else:
                stack.append((node.collection, names, visiting))
            stack.append((node.key, names, visiting))
        elif isinstance(node, GetAttr):
            stack.append((node.target, names, visiting))
    return found


# --- Context -------------------------------------------------------------------------------------


@dataclass
class ReferenceContext:
    """What the targets of references are: the configuration and its evaluation."""

    parsed: ParsedConfiguration
    instances: Mapping[str, EvaluatedInstance]
    indeterminate: Mapping[str, EvaluatedResource]
    locals_: Mapping[str, Expression] = field(init=False)
    _cache: dict[int, list[Candidate]] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self.locals_ = {name: decl.attribute.expr for name, decl in self.parsed.locals.items()}

    def candidates(
        self, expression: Expression, bound: frozenset[str] = frozenset()
    ) -> list[Candidate]:
        key = id(expression)
        if bound or key not in self._cache:
            result = expression_candidates(expression, self.locals_, bound)
            if bound:
                return result
            self._cache[key] = result
        return self._cache[key]

    def decl_of(self, kind: str, type_: str, name: str) -> ResourceDecl | None:
        table = self.parsed.resources if kind == "resource" else self.parsed.data_sources
        return table.get((type_, name))

    def status_of_instance(self, address: str) -> ReferenceResolution:
        instance = self.instances.get(address)
        if instance is None:
            return ReferenceResolution.UNKNOWN
        if instance.type not in SUPPORTED_TYPES:
            return ReferenceResolution.UNSUPPORTED
        if not instance.determinate:
            return ReferenceResolution.UNKNOWN
        return ReferenceResolution.SUPPORTED

    def resolve(self, candidate: Candidate) -> tuple[str, ReferenceResolution]:
        """The target address and status of a candidate (C-115)."""
        if candidate.kind == "module":
            return f"module.{candidate.name}", ReferenceResolution.UNSUPPORTED
        keyless = instance_address(candidate.kind, candidate.type, candidate.name)
        if candidate.kind == "data":
            address = (
                instance_address("data", candidate.type, candidate.name, candidate.key)
                if candidate.mode == "const" and candidate.key is not None
                else keyless
            )
            return address, ReferenceResolution.UNKNOWN
        decl = self.decl_of("resource", candidate.type, candidate.name)
        if decl is None or keyless in self.indeterminate or candidate.mode == "unknown":
            return keyless, ReferenceResolution.UNKNOWN
        if candidate.mode == "const":
            assert candidate.key is not None
            address = instance_address("resource", candidate.type, candidate.name, candidate.key)
            return address, self.status_of_instance(address)
        if decl.count is not None or decl.for_each is not None:
            return keyless, ReferenceResolution.UNKNOWN
        return keyless, self.status_of_instance(keyless)

    def triple_of_address(self, address: str) -> tuple[str, str, str] | None:
        instance = self.instances.get(address)
        return None if instance is None else (instance.kind, instance.type, instance.name)


# --- Collecting ----------------------------------------------------------------------------------


class _Collector:
    def __init__(self, source_address: str, ctx: ReferenceContext) -> None:
        self.source_address = source_address
        self.ctx = ctx
        self.found: dict[tuple[str, str, str], ReferenceResolution] = {}
        self.diagnostics: list[Diagnostic] = []
        self._covered: dict[str, set[tuple[str, str, str]]] = {}

    def _add(self, path: str, target: str, kind: str, status: ReferenceResolution) -> None:
        key = (path, target, kind)
        previous = self.found.get(key)
        if previous is None:
            self.found[key] = status
        elif previous is not status:
            kept = status if _SEVERITY[status] > _SEVERITY[previous] else previous
            self.found[key] = kept
            self.diagnostics.append(
                Diagnostic(
                    DiagnosticSeverity.UNSUPPORTED_CONSTRUCT,
                    "norm.reference_status_conflict",
                    f"{self.source_address} {path} -> {target}: {previous.value} and "
                    f"{status.value}; kept {kept.value}",
                )
            )

    def values(self, path: str, value: Value) -> None:
        """(a): every ``Ref`` in the evaluated value."""
        for item in walk(value):
            if isinstance(item, Ref):
                status = self.ctx.status_of_instance(item.address)
                self._add(path, item.address, ATTRIBUTE_REFERENCE, status)
                triple = self.ctx.triple_of_address(item.address)
                if triple is not None:
                    self._covered.setdefault(path, set()).add(triple)

    def expression(
        self,
        path: str,
        expression: Expression,
        kind: str = ATTRIBUTE_REFERENCE,
        bound: frozenset[str] = frozenset(),
    ) -> None:
        """(b): every resource or data traversal in the expression."""
        for candidate in self.ctx.candidates(expression, bound):
            if candidate.mode == "none" and candidate.kind == "resource":
                triple = (candidate.kind, candidate.type, candidate.name)
                decl = self.ctx.decl_of(*triple)
                counted = decl is not None and (decl.count is not None or decl.for_each is not None)
                if counted and triple in self._covered.get(path, set()):
                    continue
            target, status = self.ctx.resolve(candidate)
            self._add(path, target, kind, status)

    def references(self) -> list[Reference]:
        return [
            Reference(self.source_address, path, target, kind, status)
            for (path, target, kind), status in sorted(self.found.items())
        ]


def _iterator_name(block: Block) -> str:
    for item in block.body.items:
        if (
            isinstance(item, Attribute)
            and item.name == "iterator"
            and isinstance(item.expr, ScopeTraversal)
            and not item.expr.steps
        ):
            return item.expr.root
    return block.labels[0].value if block.labels else ""


def _walk_body(
    collector: _Collector,
    items: Iterable[Attribute | Block],
    evaluated: Mapping[str, EvaluatedArgument],
    prefix: str,
    bound: frozenset[str],
    policy: SetPolicy,
    top: bool,
) -> None:
    """Pair the tree of a body with its evaluated arguments, to name every source attribute."""
    groups: dict[str, list[Attribute | Block]] = {}
    for item in items:
        if isinstance(item, Attribute):
            name = item.name
        elif item.type == "dynamic" and item.labels:
            name = item.labels[0].value
        else:
            name = item.type
        groups.setdefault(name, []).append(item)
    for name, members in groups.items():
        argument = evaluated.get(name)
        eval_blocks = [] if argument is None else ordered_blocks(argument, policy, top=top)
        for member in members:
            if isinstance(member, Attribute):
                path = f"{prefix}{name}"
                if argument is not None and argument.value is not None:
                    collector.values(path, argument.value)  # (a) first: it covers instances
                collector.expression(path, member.expr, bound=bound)
            elif member.type == "dynamic":
                _dynamic(collector, member, name, eval_blocks, prefix, bound, policy)
            else:
                _static(collector, member, name, eval_blocks, prefix, bound, policy)


def _static(
    collector: _Collector,
    block: Block,
    name: str,
    eval_blocks: list[EvaluatedBlock],
    prefix: str,
    bound: frozenset[str],
    policy: SetPolicy,
) -> None:
    for rank, evaluated in enumerate(eval_blocks):
        if not evaluated.from_dynamic and evaluated.source_range == block.range:
            path = f"{prefix}{name}[{rank}]."
            _walk_body(collector, block.body.items, evaluated.arguments, path, bound, policy, False)
            return
    _walk_body(collector, block.body.items, {}, f"{prefix}{name}[*].", bound, policy, False)


def _dynamic(
    collector: _Collector,
    block: Block,
    name: str,
    eval_blocks: list[EvaluatedBlock],
    prefix: str,
    bound: frozenset[str],
    policy: SetPolicy,
) -> None:
    iterator = _iterator_name(block)
    content: Block | None = None
    for item in block.body.items:
        if isinstance(item, Attribute) and item.name in ("for_each", "labels"):
            collector.expression(f"{prefix}{name}.{item.name}", item.expr, bound=bound)
        elif isinstance(item, Block) and item.type == "content":
            content = item
    if content is None:
        return
    inner = bound | {iterator}
    expansions = [
        (rank, evaluated)
        for rank, evaluated in enumerate(eval_blocks)
        if evaluated.from_dynamic and evaluated.source_range == content.range
    ]
    if not expansions:
        path = f"{prefix}{name}[*]."
        _walk_body(collector, content.body.items, {}, path, inner, policy, False)
    for rank, evaluated in expansions:
        path = f"{prefix}{name}[{rank}]."
        _walk_body(collector, content.body.items, evaluated.arguments, path, inner, policy, False)


def _walk_plain(collector: _Collector, items: Iterable[Attribute | Block], prefix: str) -> None:
    """Expressions that are recorded and not evaluated (lifecycle, provisioner, connection)."""
    for item in items:
        if isinstance(item, Attribute):
            if item.name != "ignore_changes":
                collector.expression(f"{prefix}{item.name}", item.expr)
        else:
            _walk_plain(collector, item.body.items, f"{prefix}{item.type}.")


def _collect(
    decl: ResourceDecl,
    source_address: str,
    arguments: Mapping[str, EvaluatedArgument],
    ctx: ReferenceContext,
    policy: SetPolicy,
) -> _Collector:
    collector = _Collector(source_address, ctx)
    for name, attribute in (("count", decl.count), ("for_each", decl.for_each)):
        if attribute is not None:
            collector.expression(name, attribute.expr)
    if decl.depends_on is not None:
        collector.expression("depends_on", decl.depends_on.expr, DEPENDS_ON)
    _walk_body(collector, decl.body.items, arguments, "", frozenset(), policy, True)
    for block in decl.lifecycle:
        _walk_plain(collector, block.body.items, "lifecycle.")
    for index, block in enumerate(decl.provisioners):
        _walk_plain(collector, block.body.items, f"provisioner[{index}].")
    for index, block in enumerate(decl.connections):
        _walk_plain(collector, block.body.items, f"connection[{index}].")
    return collector


def references_of(
    instance: EvaluatedInstance, ctx: ReferenceContext
) -> tuple[list[Reference], list[Diagnostic]]:
    """The references of one resource instance, sorted, and the diagnostics about them."""
    decl = ctx.decl_of("resource", instance.type, instance.name)
    assert decl is not None
    collector = _collect(decl, instance.address, instance.arguments, ctx, policy_for(instance.type))
    return collector.references(), collector.diagnostics


def references_of_indeterminate(
    resource: EvaluatedResource, ctx: ReferenceContext
) -> tuple[list[Reference], list[Diagnostic]]:
    """The references of a resource that has no instances: from its expressions only."""
    decl = ctx.decl_of("resource", resource.type, resource.name)
    assert decl is not None
    collector = _collect(decl, resource.address, {}, ctx, NO_POLICY)
    return collector.references(), collector.diagnostics


__all__ = [
    "ATTRIBUTE_REFERENCE",
    "DEPENDS_ON",
    "Candidate",
    "ReferenceContext",
    "expression_candidates",
    "references_of",
    "references_of_indeterminate",
]
