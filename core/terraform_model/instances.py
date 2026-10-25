"""Instance expansion and evaluated instances (Doc 04 §4, §17; registry §2.3, §2.6; C-84, C-100,
C-105).

A ``resource`` or ``data`` block expands into instances: one at the bare address without ``count``
and ``for_each``, ``count`` of them at ``addr[0]`` to ``addr[n-1]``, or one per key of a map or
element of a set of strings at ``addr["key"]``. Each instance has its arguments evaluated with
that instance's ``count.index`` or ``each.key`` / ``each.value``. If the expansion cannot be fixed
(an unknown ``count`` or ``for_each``) the resource is **indeterminate**: one ``EvaluatedResource``
record with the reason and no instances (registry §2.3). Nothing is guessed.

Argument forms (registry §2.6, C-84, C-100): for every argument name an instance keeps whether it
was written as an attribute (``ATTRIBUTE``), as static blocks (``BLOCKS``), as ``dynamic`` blocks
(``DYNAMIC``), or as both kinds of blocks (``MIXED``, each block records whether it came from
``dynamic``). An attribute together with a block of the same name is INVALID (Terraform rejects
it, C-100) and is reported, never resolved to one form. Absent arguments are simply absent.

Canonical addresses follow Terraform's: ``type.name``, ``type.name[0]``, ``type.name["key"]``
and ``data.type.name``. A string key is written as Terraform's ``toHCLQuotedString`` writes it
(``internal/addrs/instance_key.go`` at tag v1.15.8): newline, carriage return, tab, double quote
and backslash as backslash escapes; ``${`` and ``%{`` with the first character doubled; any
character that Go's ``unicode.IsPrint`` rejects as a four-digit (u) or eight-digit (U) hex
escape. The printable table is frozen (``print_table.py``); the Unicode version of Terraform
1.15.8 was measured (see ``scripts/generate_print_table.py``).

Rules for ``count`` and ``for_each`` follow Terraform 1.15.8 (``terraform validate`` on scratch
directories outside the repository, builtin ``terraform_data`` resources, no credentials):
``count`` together with ``for_each`` is rejected (INVALID); a ``count`` that is negative, not a
whole number, null or a bool is an error, a numeric string such as ``"2"`` is accepted; a
``for_each`` that is a list or tuple, null, or a set of numbers is an error; a map or object (of
any values, null included) and a set of strings are accepted. A value that Terraform rejects only
while planning is unsupported here, never INVALID (C-103).

Limits (C-105): at most 1,000 instances per resource; the 10,000 per configuration are checked by
``evaluation.py``. A ``dynamic`` block expands at most 1,000 blocks.

Terraform documentation: ``hashicorp/web-unified-docs`` commit
``fefc7502dba86c70716f0109c324c85829229b2f``, ``content/terraform/v1.15.x/docs/``:
``language/meta-arguments/count.mdx``, ``language/meta-arguments/for_each.mdx``,
``language/expressions/dynamic-blocks.mdx``, ``cli/state/resource-addressing.mdx``.
"""

from __future__ import annotations

import bisect
import enum
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from core.terraform_model.config import Diagnostic, DiagnosticSeverity, ResourceDecl
from core.terraform_model.convert import Fail, as_int, as_string, kind_of
from core.terraform_model.evaluate import Scope, evaluate_expression
from core.terraform_model.hcl.ast import (
    Attribute,
    AttrStep,
    Block,
    Body,
    Expression,
    ScopeTraversal,
    SourceRange,
    Tuple,
)
from core.terraform_model.print_table import PRINTABLE
from core.terraform_model.values import (
    Known,
    Ref,
    Unknown,
    Unsupported,
    Value,
    first_problem_value,
    known_object,
)

MAX_INSTANCES_PER_RESOURCE: Final = 1_000
MAX_INSTANCES_PER_CONFIGURATION: Final = 10_000
MAX_DYNAMIC_BLOCKS: Final = 1_000

# Reason codes of the Unsupported and Unknown values made here.
REASONS: Final[dict[str, str]] = {
    "count.invalid": "A count that is not a whole number of 0 or more (Terraform: error).",
    "count.null": "A null count (Terraform: error).",
    "for_each.list": "A for_each over a list or tuple (Terraform: error).",
    "for_each.null": "A null for_each (Terraform: error).",
    "for_each.type": "A for_each that is not a map, object or set of strings.",
    "for_each.set_element": "A for_each set with an element that is not a string.",
    "expansion.count_and_for_each": "A resource with both count and for_each (INVALID).",
    "expansion.key_surrogate": "An instance key with a lone surrogate (not valid text).",
    "limit.instances_per_resource": "More than 1,000 instances for one resource (C-105).",
    "limit.dynamic_blocks": "A dynamic block that expands to more than 1,000 blocks.",
    "dynamic.malformed": "A dynamic block that is not for_each + content (+ iterator, labels).",
    "dynamic.for_each": "A dynamic for_each that is not a collection.",
    "resource.cycle": "A resource argument or expansion that depends on itself.",
    "resource.block_argument": "A reference to an argument that is written as blocks.",
}
UNKNOWN_REASONS: Final[dict[str, str]] = {
    "expansion.count_unknown": "A count that is unknown (the code carries ':<reason>').",
    "expansion.for_each_unknown": "A for_each that is unknown (the code carries ':<reason>').",
    "resource.computed": "A provider-computed attribute (the code carries ':<attribute>').",
}
DIAGNOSTICS: Final[dict[str, str]] = {
    "eval.count_and_for_each": "count and for_each in one resource (INVALID).",
    "eval.attribute_and_block": "An attribute and a block with one name (INVALID, C-100).",
    "eval.resource_cycle": "A cycle between resource arguments (INVALID).",
    "eval.provisioner": "A provisioner block: recorded, not evaluated.",
    "eval.connection": "A connection block: recorded, not evaluated.",
    "eval.dynamic_malformed": "A dynamic block that DAIL cannot read (its blocks are unknown).",
    "limit.instances_per_resource": "More than 1,000 instances for one resource (UNSUPPORTED).",
}


# --- Canonical addresses -------------------------------------------------------------------------

_PRINT_LOWS: Final = tuple(low for low, _ in PRINTABLE)


def is_print(code_point: int) -> bool:
    """Go's ``unicode.IsPrint`` for Unicode 15.0.0 (frozen table)."""
    index = bisect.bisect_right(_PRINT_LOWS, code_point) - 1
    return index >= 0 and PRINTABLE[index][0] <= code_point <= PRINTABLE[index][1]


_SIMPLE_ESCAPES: Final = {"\n": "\\n", "\r": "\\r", "\t": "\\t", '"': '\\"', "\\": "\\\\"}


def quote_key(text: str) -> str:
    """Terraform's ``toHCLQuotedString`` (``internal/addrs/instance_key.go``)."""
    if text == "":
        return '""'
    out = ['"']
    for index, char in enumerate(text):
        if char in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[char])
        elif char in "$%":
            out.append(char)
            if text[index + 1 : index + 2] == "{":
                out.append(char)  # doubled: it would start an interpolation or a directive
        elif is_print(ord(char)):
            out.append(char)
        elif ord(char) < 0x10000:
            out.append(f"\\u{ord(char):04x}")
        else:
            out.append(f"\\U{ord(char):08x}")
    out.append('"')
    return "".join(out)


def format_key(key: int | str) -> str:
    """``[0]`` or ``["key"]``."""
    return f"[{key}]" if isinstance(key, int) else f"[{quote_key(key)}]"


def instance_address(kind: str, type_: str, name: str, key: int | str | None = None) -> str:
    base = f"{type_}.{name}" if kind == "resource" else f"data.{type_}.{name}"
    return base if key is None else base + format_key(key)


# --- Evaluated records ---------------------------------------------------------------------------


class ArgumentForm(enum.StrEnum):
    ATTRIBUTE = "ATTRIBUTE"  # written as ``name = value``
    BLOCKS = "BLOCKS"  # written as one or more ``name { }`` blocks
    DYNAMIC = "DYNAMIC"  # written as ``dynamic "name" { }`` blocks only
    MIXED = "MIXED"  # both static and dynamic blocks (C-100)


def _freeze(arguments: Mapping[str, EvaluatedArgument]) -> Mapping[str, EvaluatedArgument]:
    return MappingProxyType(dict(sorted(arguments.items())))


@dataclass(frozen=True, slots=True)
class EvaluatedBlock:
    """One nested block with its arguments evaluated. ``labels`` are the block labels (for a
    ``dynamic`` block, the values of ``labels``; a label that cannot be fixed is unknown)."""

    type: str
    labels: tuple[Value, ...]
    arguments: Mapping[str, EvaluatedArgument]
    from_dynamic: bool
    source_range: SourceRange

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", _freeze(self.arguments))


@dataclass(frozen=True, slots=True)
class EvaluatedArgument:
    """One argument name of an instance or of a block, with the form it was written in.

    ``value`` is set for ``ATTRIBUTE`` only. ``blocks`` holds the blocks of the other forms in
    source order (``dynamic`` blocks at the place of their ``dynamic`` block). ``indeterminate``
    holds one reason for every ``dynamic`` block whose expansion cannot be fixed: the number of
    blocks it produces is unknown (registry §2.3).
    """

    name: str
    form: ArgumentForm
    value: Value | None
    blocks: tuple[EvaluatedBlock, ...]
    indeterminate: tuple[Unknown | Unsupported, ...]
    source_range: SourceRange


@dataclass(frozen=True, slots=True)
class MetaArguments:
    """The meta-arguments of a resource, recorded and not interpreted (except as noted)."""

    count: Expression | None
    for_each: Expression | None
    provider: str | None  # ``aws`` or ``aws.west``; None when absent or not a plain reference
    depends_on: tuple[str, ...] | None  # references as written; None when absent or not static
    create_before_destroy: Value | None
    prevent_destroy: Value | None
    lifecycle: tuple[Block, ...]
    provisioners: tuple[Block, ...]  # flagged, not evaluated
    connections: tuple[Block, ...]  # flagged, not evaluated


@dataclass(frozen=True, slots=True)
class EvaluatedInstance:
    """One expanded instance of a resource or data source.

    ``determinate`` is False when a ``dynamic`` block of the instance is indeterminate (its
    reason is on the argument, under the argument name).
    """

    address: str
    kind: str  # "resource" or "data"
    type: str
    name: str
    key: int | str | None
    determinate: bool
    arguments: Mapping[str, EvaluatedArgument]
    meta: MetaArguments
    source_range: SourceRange
    diagnostics: tuple[Diagnostic, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", _freeze(self.arguments))


@dataclass(frozen=True, slots=True)
class EvaluatedResource:
    """A resource whose expansion cannot be fixed: no instances, only the reason."""

    address: str  # without a key
    kind: str
    type: str
    name: str
    determinate: bool  # always False
    reason: Unknown | Unsupported
    meta: MetaArguments
    source_range: SourceRange
    diagnostics: tuple[Diagnostic, ...]


@dataclass(frozen=True, slots=True)
class Expansion:
    """The result of expanding one block: instances, or the indeterminate resource."""

    instances: tuple[EvaluatedInstance, ...]
    indeterminate: EvaluatedResource | None


# --- Evaluating a body ---------------------------------------------------------------------------


def _diagnostic(
    severity: DiagnosticSeverity, code: str, message: str, where: SourceRange
) -> Diagnostic:
    return Diagnostic(severity, code, message, where.file, where.start_line, where.start_column)


class _BodyEvaluator:
    """Evaluates the arguments and nested blocks of one body in one scope."""

    def __init__(self, diagnostics: list[Diagnostic]) -> None:
        self.diagnostics = diagnostics
        self.indeterminate_seen = False

    def evaluate(
        self,
        body: Body,
        scope: Scope,
        configured: Callable[[str], Value] | None = None,
    ) -> dict[str, EvaluatedArgument]:
        """The arguments of ``body``. ``configured`` gives the value of a top-level attribute
        (the instance evaluates each once and detects cycles); nested bodies are evaluated here."""
        groups: dict[str, list[Attribute | Block]] = {}
        for item in body.items:
            if isinstance(item, Attribute):
                name = item.name
            elif item.type == "dynamic":
                if len(item.labels) != 1:
                    self._malformed(item, "a dynamic block has exactly one label")
                    continue
                name = item.labels[0].value
            else:
                name = item.type
            groups.setdefault(name, []).append(item)
        arguments: dict[str, EvaluatedArgument] = {}
        for name, items in groups.items():
            argument = self._argument(name, items, scope, configured)
            if argument is not None:
                arguments[name] = argument
        return arguments

    def _argument(
        self,
        name: str,
        items: list[Attribute | Block],
        scope: Scope,
        configured: Callable[[str], Value] | None,
    ) -> EvaluatedArgument | None:
        attributes = [i for i in items if isinstance(i, Attribute)]
        blocks = [i for i in items if isinstance(i, Block)]
        if attributes and blocks:
            self.diagnostics.append(
                _diagnostic(
                    DiagnosticSeverity.INVALID,
                    "eval.attribute_and_block",
                    f"{name} is written as an attribute and as a block",
                    blocks[0].range,
                )
            )
            return None
        if attributes:
            attribute = attributes[0]
            value = (
                configured(name)
                if configured is not None
                else evaluate_expression(attribute.expr, scope)
            )
            return EvaluatedArgument(name, ArgumentForm.ATTRIBUTE, value, (), (), attribute.range)
        evaluated: list[EvaluatedBlock] = []
        indeterminate: list[Unknown | Unsupported] = []
        has_static = has_dynamic = False
        for block in blocks:
            if block.type == "dynamic":
                has_dynamic = True
                produced, problem = self._dynamic(block, scope, name)
                evaluated.extend(produced)
                if problem is not None:
                    indeterminate.append(problem)
                    self.indeterminate_seen = True
            else:
                has_static = True
                evaluated.append(self._static(block, scope))
        form = (
            ArgumentForm.MIXED
            if has_static and has_dynamic
            else ArgumentForm.DYNAMIC if has_dynamic else ArgumentForm.BLOCKS
        )
        return EvaluatedArgument(
            name, form, None, tuple(evaluated), tuple(indeterminate), blocks[0].range
        )

    def _static(self, block: Block, scope: Scope) -> EvaluatedBlock:
        return EvaluatedBlock(
            block.type,
            tuple(Known(label.value) for label in block.labels),
            self.evaluate(block.body, scope),
            False,
            block.range,
        )

    # -- dynamic blocks --

    def _malformed(self, block: Block, why: str) -> Unsupported:
        self.diagnostics.append(
            _diagnostic(
                DiagnosticSeverity.UNSUPPORTED_CONSTRUCT,
                "eval.dynamic_malformed",
                why,
                block.range,
            )
        )
        return Unsupported("dynamic.malformed")

    def _dynamic(
        self, block: Block, scope: Scope, generated: str
    ) -> tuple[list[EvaluatedBlock], Unknown | Unsupported | None]:
        parts: dict[str, Attribute | Block] = {}
        for item in block.body.items:
            key = item.name if isinstance(item, Attribute) else item.type
            if key in parts or key not in ("for_each", "iterator", "labels", "content"):
                return [], self._malformed(block, f"unexpected or repeated {key}")
            if (key == "content") != isinstance(item, Block):
                return [], self._malformed(block, f"{key} has the wrong form")
            parts[key] = item
        if "for_each" not in parts or "content" not in parts:
            return [], self._malformed(block, "a dynamic block needs for_each and content")
        iterator = generated
        if "iterator" in parts:
            expr = parts["iterator"]
            assert isinstance(expr, Attribute)
            if not (isinstance(expr.expr, ScopeTraversal) and not expr.expr.steps):
                return [], self._malformed(block, "iterator must be a plain name")
            iterator = expr.expr.root
        for_each = parts["for_each"]
        content = parts["content"]
        assert isinstance(for_each, Attribute) and isinstance(content, Block)
        collection = evaluate_expression(for_each.expr, scope)
        pairs = _dynamic_pairs(collection)
        if not isinstance(pairs, list):
            return [], pairs
        if len(pairs) > MAX_DYNAMIC_BLOCKS:
            return [], Unsupported("limit.dynamic_blocks")
        produced: list[EvaluatedBlock] = []
        labels_attribute = parts.get("labels")
        for element_key, element_value in pairs:
            iteration = known_object({"key": element_key, "value": element_value})
            inner = scope.with_binding(iterator, iteration)
            labels: tuple[Value, ...] = ()
            if isinstance(labels_attribute, Attribute):
                labels = _labels(evaluate_expression(labels_attribute.expr, inner))
            produced.append(
                EvaluatedBlock(
                    generated, labels, self.evaluate(content.body, inner), True, content.range
                )
            )
        return produced, None


def _dynamic_pairs(collection: Value) -> list[tuple[Value, Value]] | Unknown | Unsupported:
    if isinstance(collection, Unknown | Unsupported):
        return collection
    if isinstance(collection, Ref):
        return Unknown(f"ref.derived:{collection.address}.{collection.attribute}")
    kind = kind_of(collection)
    assert isinstance(collection, Known)
    payload = collection.value
    if kind == "tuple":
        return [(Known(i), v) for i, v in enumerate(payload)]
    if kind == "set":
        problem = first_problem_value(collection)
        if problem is not None:
            return problem
        return [(v, v) for v in payload.elements]
    if kind == "object":
        return [(Known(k), v) for k, v in payload.items()]
    return Unsupported("dynamic.for_each")


def _labels(value: Value) -> tuple[Value, ...]:
    if isinstance(value, Unknown | Unsupported):
        return (value,)
    if isinstance(value, Known) and isinstance(value.value, tuple):
        out: list[Value] = []
        for item in value.value:
            if isinstance(item, Unknown | Unsupported):
                out.append(item)
            else:
                try:
                    out.append(Known(as_string(item)))
                except Fail as failure:
                    out.append(Unsupported(failure.reason))
        return tuple(out)
    return (Unsupported("dynamic.malformed"),)


# --- Expansion -----------------------------------------------------------------------------------


def _traversal_text(expr: Expression) -> str | None:
    if not isinstance(expr, ScopeTraversal):
        return None
    if not all(isinstance(step, AttrStep) for step in expr.steps):
        return None
    return ".".join([expr.root, *(step.name for step in expr.steps if isinstance(step, AttrStep))])


def _meta(decl: ResourceDecl, scope: Scope) -> MetaArguments:
    depends: tuple[str, ...] | None = None
    if decl.depends_on is not None and isinstance(decl.depends_on.expr, Tuple):
        texts = [_traversal_text(e) for e in decl.depends_on.expr.elements]
        if all(t is not None for t in texts):
            depends = tuple(t for t in texts if t is not None)
    values: dict[str, Value] = {}
    for block in decl.lifecycle:
        for item in block.body.items:
            if isinstance(item, Attribute) and item.name in (
                "create_before_destroy",
                "prevent_destroy",
            ):
                values[item.name] = evaluate_expression(item.expr, scope)
    return MetaArguments(
        decl.count.expr if decl.count else None,
        decl.for_each.expr if decl.for_each else None,
        _traversal_text(decl.provider.expr) if decl.provider else None,
        depends,
        values.get("create_before_destroy"),
        values.get("prevent_destroy"),
        decl.lifecycle,
        decl.provisioners,
        decl.connections,
    )


@dataclass(slots=True)
class _Key:
    """One instance to create: its key and the values that ``each`` / ``count`` take."""

    key: int | str | None
    each: tuple[Value, Value] | None
    count_index: Value | None


@dataclass(slots=True)
class _Plan:
    keys: tuple[_Key, ...]
    problem: Unknown | Unsupported | None
    diagnostics: tuple[Diagnostic, ...]


def _has_lone_surrogate(text: str) -> bool:
    return any(0xD800 <= ord(char) <= 0xDFFF for char in text)


class InstanceRuntime:
    """One instance of a resource: evaluates its arguments lazily, once each.

    ``attribute`` and ``attributes`` implement ``evaluate.InstanceView`` for references from other
    expressions. Evaluating an argument that depends on itself is a cycle: Terraform rejects it
    (``validate``: "Cycle"), so it is INVALID and the value is unsupported (``resource.cycle``).
    """

    def __init__(self, runtime: ResourceRuntime, key: _Key) -> None:
        self.runtime = runtime
        self._key = key
        self.address = instance_address(
            runtime.decl.kind, runtime.decl.type, runtime.decl.name, key.key
        )
        self.scope = runtime.scope.with_instance(each=key.each, count_index=key.count_index)
        self._values: dict[str, Value] = {}
        self._active: set[str] = set()
        self._attributes = {
            item.name: item for item in runtime.decl.body.items if isinstance(item, Attribute)
        }
        self._blocks = {
            (item.labels[0].value if item.type == "dynamic" and item.labels else item.type)
            for item in runtime.decl.body.items
            if isinstance(item, Block)
        }

    @property
    def key(self) -> Value | None:
        raw = self._key.key
        return None if raw is None else Known(raw)

    def configured(self, name: str) -> Value:
        """The value of the attribute ``name`` of this instance, evaluated once."""
        if name in self._values:
            return self._values[name]
        if name in self._active:
            where = self._attributes[name].range
            self.scope.report("eval.resource_cycle", f"Cycle: {self.address}.{name}", where)
            return Unsupported("resource.cycle")
        self._active.add(name)
        try:
            value = evaluate_expression(self._attributes[name].expr, self.scope)
        finally:
            self._active.discard(name)
        self._values[name] = value
        return value

    def attribute(self, name: str) -> Value:
        if name == "id":
            return Ref(self.address, "id")
        if name in self._attributes and name not in self._blocks:
            return self.configured(name)
        if name in self._blocks:
            return Unsupported("resource.block_argument")
        return Unknown(f"resource.computed:{name}")

    def attributes(self) -> Mapping[str, Value]:
        result: dict[str, Value] = {"id": Ref(self.address, "id")}
        for name in self._attributes:
            if name != "id" and name not in self._blocks:
                result[name] = self.configured(name)
        return result

    def evaluate(self) -> EvaluatedInstance:
        decl = self.runtime.decl
        diagnostics: list[Diagnostic] = []
        body = _BodyEvaluator(diagnostics)
        arguments = body.evaluate(decl.body, self.scope, self.configured)
        for provisioner in decl.provisioners:
            diagnostics.append(
                _diagnostic(
                    DiagnosticSeverity.UNSUPPORTED_CONSTRUCT,
                    "eval.provisioner",
                    "a provisioner block is recorded, not evaluated",
                    provisioner.range,
                )
            )
        for connection in decl.connections:
            diagnostics.append(
                _diagnostic(
                    DiagnosticSeverity.UNSUPPORTED_CONSTRUCT,
                    "eval.connection",
                    "a connection block is recorded, not evaluated",
                    connection.range,
                )
            )
        return EvaluatedInstance(
            self.address,
            decl.kind,
            decl.type,
            decl.name,
            self._key.key,
            not body.indeterminate_seen,
            arguments,
            self.runtime.meta(self.scope),
            decl.block.range,
            tuple(sorted(set(diagnostics), key=lambda d: d.sort_key + (d.message,))),
        )


class ResourceRuntime:
    """Lazy expansion and evaluation of one ``resource`` or ``data`` block.

    Implements ``evaluate.ResourceView``: ``instances`` is the plan (which instances exist);
    arguments are evaluated per instance, on demand.
    """

    def __init__(self, decl: ResourceDecl, scope: Scope) -> None:
        self.decl = decl
        self.scope = scope.with_owner((decl.kind, decl.type, decl.name))
        self._plan: _Plan | None = None
        self._planning = False
        self._instances: tuple[InstanceRuntime, ...] | None = None
        self._meta: MetaArguments | None = None

    @property
    def mode(self) -> str:
        if self.decl.count is not None and self.decl.for_each is None:
            return "count"
        if self.decl.for_each is not None and self.decl.count is None:
            return "for_each"
        return "single"

    @property
    def address(self) -> str:
        return instance_address(self.decl.kind, self.decl.type, self.decl.name)

    def meta(self, scope: Scope) -> MetaArguments:
        if self._meta is None:
            self._meta = _meta(self.decl, scope)
        return self._meta

    # -- the plan: which instances exist --

    def plan(self) -> _Plan:
        if self._plan is not None:
            return self._plan
        if self._planning:
            self.scope.report(
                "eval.resource_cycle", f"Cycle: {self.address}", self.decl.block.range
            )
            return _Plan((), Unsupported("resource.cycle"), ())
        self._planning = True
        try:
            self._plan = self._compute_plan()
        finally:
            self._planning = False
        return self._plan

    def _compute_plan(self) -> _Plan:
        decl = self.decl
        if decl.count is not None and decl.for_each is not None:
            problem = _diagnostic(
                DiagnosticSeverity.INVALID,
                "eval.count_and_for_each",
                "count and for_each cannot be used together",
                decl.block.range,
            )
            return _Plan((), Unsupported("expansion.count_and_for_each"), (problem,))
        if decl.count is not None:
            return self._count(decl.count)
        if decl.for_each is not None:
            return self._for_each(decl.for_each)
        return _Plan((_Key(None, None, None),), None, ())

    def _too_many(self, where: SourceRange) -> _Plan:
        problem = _diagnostic(
            DiagnosticSeverity.UNSUPPORTED,
            "limit.instances_per_resource",
            f"more than {MAX_INSTANCES_PER_RESOURCE} instances",
            where,
        )
        return _Plan((), Unsupported("limit.instances_per_resource"), (problem,))

    def _count(self, attribute: Attribute) -> _Plan:
        value = evaluate_expression(attribute.expr, self.scope)
        if isinstance(value, Unsupported):
            return _Plan((), value, ())
        if isinstance(value, Unknown | Ref):
            reason = value.reason if isinstance(value, Unknown) else value.address
            return _Plan((), Unknown(f"expansion.count_unknown:{reason}"), ())
        if kind_of(value) == "null":
            return _Plan((), Unsupported("count.null"), ())
        try:
            if kind_of(value) in ("bool", "tuple", "set", "object"):
                raise Fail("count.invalid", "not a number")
            count = as_int(value)
            if count < 0:
                raise Fail("count.invalid", "negative")
        except Fail:
            return _Plan((), Unsupported("count.invalid"), ())
        if count > MAX_INSTANCES_PER_RESOURCE:
            return self._too_many(attribute.range)
        return _Plan(tuple(_Key(i, None, Known(i)) for i in range(count)), None, ())

    def _for_each(self, attribute: Attribute) -> _Plan:
        value = evaluate_expression(attribute.expr, self.scope)
        if isinstance(value, Unsupported):
            return _Plan((), value, ())
        if isinstance(value, Unknown):
            return _Plan((), Unknown(f"expansion.for_each_unknown:{value.reason}"), ())
        if isinstance(value, Ref):
            reason = f"ref.derived:{value.address}.{value.attribute}"
            return _Plan((), Unknown(f"expansion.for_each_unknown:{reason}"), ())
        kind = kind_of(value)
        assert isinstance(value, Known)
        payload = value.value
        if kind == "null":
            return _Plan((), Unsupported("for_each.null"), ())
        if kind == "tuple":
            return _Plan((), Unsupported("for_each.list"), ())
        if kind not in ("object", "set"):
            return _Plan((), Unsupported("for_each.type"), ())
        if kind == "object":
            keys = [_Key(k, (Known(k), v), None) for k, v in payload.items()]
        else:
            problem = first_problem_value(value)
            if isinstance(problem, Unsupported):
                return _Plan((), problem, ())
            if problem is not None:
                return _Plan((), Unknown(f"expansion.for_each_unknown:{problem.reason}"), ())
            elements = payload.elements
            for element in elements:
                if isinstance(element, Ref):
                    ref = f"ref.derived:{element.address}.{element.attribute}"
                    return _Plan((), Unknown(f"expansion.for_each_unknown:{ref}"), ())
            if any(kind_of(element) != "string" for element in elements):
                return _Plan((), Unsupported("for_each.set_element"), ())
            keys = [_Key(str(e.value), (e, e), None) for e in elements if isinstance(e, Known)]
        if any(isinstance(k.key, str) and _has_lone_surrogate(k.key) for k in keys):
            return _Plan((), Unsupported("expansion.key_surrogate"), ())
        if len(keys) > MAX_INSTANCES_PER_RESOURCE:
            return self._too_many(attribute.range)
        return _Plan(tuple(keys), None, ())

    # -- ResourceView --

    def instances(self) -> tuple[InstanceRuntime, ...] | Unknown | Unsupported:
        plan = self.plan()
        if plan.problem is not None:
            return plan.problem
        if self._instances is None:
            self._instances = tuple(InstanceRuntime(self, key) for key in plan.keys)
        return self._instances

    # -- the final records --

    def expand(self) -> Expansion:
        """Expand the block: its instances with every argument evaluated, or the indeterminate
        resource."""
        plan = self.plan()
        found = self.instances()
        if isinstance(found, Unknown | Unsupported):
            decl = self.decl
            return Expansion(
                (),
                EvaluatedResource(
                    self.address,
                    decl.kind,
                    decl.type,
                    decl.name,
                    False,
                    found,
                    self.meta(self.scope),
                    decl.block.range,
                    plan.diagnostics,
                ),
            )
        return Expansion(tuple(instance.evaluate() for instance in found), None)


def expand_resource(decl: ResourceDecl, scope: Scope) -> Expansion:
    """Expand one ``resource`` or ``data`` block in ``scope`` (variables, locals, and the
    resources it can refer to)."""
    return ResourceRuntime(decl, scope).expand()
