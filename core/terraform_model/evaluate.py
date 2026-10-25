"""The expression evaluator (Doc 04 §17; C-102, C-103, C-105).

``evaluate_expression(expression, scope)`` turns one syntax tree of ``core.terraform_model.hcl``
into a value of ``values.py``. It is pure: the same expression, scope and variable values give the
same value, and it reads no file, environment variable, clock or network.

What it evaluates: literals, templates and heredocs (with ``%{if}`` and ``%{for}``), tuples,
objects, operators, conditionals, ``for`` expressions, splats, indexes, attribute access and the
function subset of ``functions.py``; references to ``var.*``, ``local.*``, ``each.*``,
``count.index``, resources (``.id`` is a ``Ref``, a configured argument is its value, any other
attribute is unknown) and data sources (always unknown).

Propagation (C-102): an operation on an unknown or unsupported operand is unknown or unsupported,
never known, and unsupported beats unknown. A construct DAIL does not implement, or an error that
Terraform raises while evaluating, is ``Unsupported`` with a reason code, never INVALID (C-103).
The one INVALID finding made here is a reference that ``terraform validate`` rejects: an
undeclared variable, local, resource or data source, ``each`` or ``count.index`` outside a
resource that has ``for_each`` or ``count``, and a cycle between locals. It is recorded as a
diagnostic on the scope, and the value is unsupported.

Limits (C-105): at most 10,000 evaluation steps per expression, at most 1,000 elements in the
result of one ``for`` expression, and a nesting depth of 150 (expression nesting plus references
followed). Exceeding one gives ``Unsupported`` (``limit.*``), never an exception.

A conditional evaluates the branch it does not take only to learn its type (Terraform: HCL
``ConditionalExpr.Value``); an error in that branch is ignored, as Terraform ignores it.

Terraform documentation: ``hashicorp/web-unified-docs`` commit
``fefc7502dba86c70716f0109c324c85829229b2f``, ``content/terraform/v1.15.x/docs/language/``:
``expressions/operators.mdx``, ``expressions/conditionals.mdx``, ``expressions/for.mdx``,
``expressions/splat.mdx``, ``expressions/strings.mdx``, ``expressions/references.mdx``,
``expressions/type-constraints.mdx``, ``meta-arguments/count.mdx``, ``meta-arguments/for_each.mdx``.
Behaviour that the pages do not state was measured with ``terraform console`` and
``terraform validate`` of Terraform 1.15.8 (listed in the P3a-2 report).
"""

from __future__ import annotations

import contextlib
import decimal
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Protocol

from core.terraform_model.config import Diagnostic, DiagnosticSeverity
from core.terraform_model.convert import (
    Fail,
    as_bool,
    as_elements,
    as_int,
    as_number,
    as_string,
    kind_of,
    make_number,
    unify_pair,
)
from core.terraform_model.functions import (
    FUNCTIONS,
    call_function,
    equal3,
    scalar_problem,
)
from core.terraform_model.hcl.ast import (
    AttrStep,
    BinaryOp,
    BinaryOperator,
    Conditional,
    Expression,
    ForExpr,
    ForKind,
    FunctionCall,
    GetAttr,
    Heredoc,
    IdentifierKey,
    Index,
    LegacyIndexStep,
    Literal,
    LiteralKind,
    Object,
    Parenthesized,
    ScopeTraversal,
    SourceRange,
    Splat,
    Template,
    TemplateFor,
    TemplateIf,
    TemplateInterpolation,
    TemplateLiteral,
    TraversalStep,
    Tuple,
    UnaryOp,
    UnaryOperator,
)
from core.terraform_model.values import (
    FALSE,
    NULL,
    TRUE,
    Known,
    Ref,
    SetValue,
    Unknown,
    Unsupported,
    Value,
    known_object,
    number_context,
)

# C-105
MAX_STEPS: Final = 10_000
MAX_FOR_ELEMENTS: Final = 1_000
# Expression nesting plus references followed. Each level costs a few Python frames, so this stays
# far below the interpreter's recursion limit.
MAX_DEPTH: Final = 150

# Reason codes of the Unsupported values made here (the others are in convert.py and functions.py).
REASONS: Final[dict[str, str]] = {
    "limit.eval_steps": "More than 10,000 evaluation steps for one expression (C-105).",
    "limit.depth": "Expressions nested, or references followed, deeper than the limit.",
    "limit.for_elements": "A for expression with more than 1,000 result elements (C-105).",
    "reference.undeclared": "A reference to something the configuration does not declare.",
    "reference.context": "each or count.index outside a resource that has for_each or count.",
    "local.cycle": "A local value that depends on itself.",
    "template.directive": "A %{if} or %{for} template directive (not implemented in v1).",
    "reference.shape": "A reference that is not var.NAME, local.NAME, each.key and so on.",
    "reference.path": "path.module, path.root or path.cwd (depend on the machine).",
    "reference.terraform": "terraform.workspace and the other terraform.* values.",
    "reference.module": "module.* (a module call makes the whole configuration unsupported).",
    "reference.self": "self.* (provisioner and connection blocks).",
    "reference.missing_key": "A resource with count or for_each referenced without an index.",
    "eval.invalid_index": "An index outside a list, or a key an object does not have.",
    "eval.missing_attribute": "An attribute an object does not have.",
    "eval.attribute_type": "An attribute of something that is not an object.",
    "eval.index_type": "An index into something that cannot be indexed, or of the wrong type.",
    "eval.not_iterable": "A for expression over something that is not a collection.",
    "eval.duplicate_key": "Two for iterations that produce the same object key.",
    "number.inexact": "A result Terraform rounds and DAIL cannot keep exactly.",
    "number.divide_by_zero": "A division or remainder by zero.",
}
UNKNOWN_REASONS: Final[dict[str, str]] = {
    "data_source": "A data source (its attributes are never known, registry 2.2).",
    "resource.computed": "A provider-computed attribute (the code carries ':<attribute>').",
    "ref.derived": "A value computed from a reference whose ID is not known.",
    "operator.undecided": "An equality that cannot be decided.",
    "function.contains_undecided": "contains() that cannot be decided.",
    "variable.no_value": "A variable with no value and no default.",
    "expansion.unknown": "A count or for_each that is unknown.",
}
DIAGNOSTICS: Final[dict[str, str]] = {
    "eval.undeclared_reference": "A reference to an undeclared variable, local, resource or data.",
    "eval.each_context": "each used where the resource has no for_each.",
    "eval.count_context": "count.index used where the resource has no count.",
    "eval.cycle": "A cycle between local values.",
}


class _Abort(Exception):
    """A limit was reached; the expression's value is ``Unsupported(reason)``."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --- What the evaluator needs to know about resources --------------------------------------------


class InstanceView(Protocol):
    """One expanded instance of a resource, as another expression can see it."""

    @property
    def address(self) -> str: ...

    @property
    def key(self) -> Value | None:
        """The count index or for_each key (a ``Known`` number or string); None for a single
        instance."""
        ...

    def attribute(self, name: str) -> Value:
        """``Ref`` for ``id``; the configured value of an argument; unknown for anything else
        (reason ``resource.computed:<attribute>``)."""
        ...

    def attributes(self) -> Mapping[str, Value]:
        """``id`` and every argument configured on the instance, for a whole-instance value."""
        ...


class ResourceView(Protocol):
    @property
    def mode(self) -> str:
        """``single``, ``count`` or ``for_each``."""
        ...

    def instances(self) -> tuple[InstanceView, ...] | Unknown | Unsupported:
        """The instances in order, or why they cannot be known."""
        ...


class ResourceResolver(Protocol):
    def resource(self, kind: str, type_: str, name: str) -> ResourceView | None:
        """The declared ``resource`` (kind ``resource``) or ``data`` block, or None."""
        ...


@dataclass(slots=True)
class _Resource:
    """A resource with count or for_each, referenced without an instance key."""

    mode: str
    instances: tuple[InstanceView, ...]


@dataclass(slots=True)
class _Instance:
    view: InstanceView


Raw = Value | _Resource | _Instance


# --- Scope ---------------------------------------------------------------------------------------


class _Shared:
    """State shared by a scope and the scopes made from it with ``with_instance``."""

    def __init__(
        self,
        variables: Mapping[str, Value],
        locals_: Mapping[str, Expression],
        resources: ResourceResolver | None,
    ) -> None:
        self.variables = variables
        self.locals = locals_
        self.resources = resources
        self.local_values: dict[str, Value] = {}
        self.resolving: list[str] = []
        self.diagnostics: list[Diagnostic] = []
        self.depth = 0
        self.base: Scope | None = None


class Scope:
    """What an expression can refer to. Evaluating never changes the variables, locals or
    resources; the scope only caches the value of each local and collects diagnostics."""

    def __init__(
        self,
        variables: Mapping[str, Value] | None = None,
        locals: Mapping[str, Expression] | None = None,  # noqa: A002 (the Terraform word)
        resources: ResourceResolver | None = None,
        *,
        each: tuple[Value, Value] | None = None,
        count_index: Value | None = None,
        _shared: _Shared | None = None,
    ) -> None:
        if _shared is None:
            _shared = _Shared(variables or {}, locals or {}, resources)
            _shared.base = self
        self._shared = _shared
        self.each = each
        self.count_index = count_index

    def with_instance(
        self, *, each: tuple[Value, Value] | None = None, count_index: Value | None = None
    ) -> Scope:
        """The scope of one instance of a resource: ``each.key``/``each.value`` or
        ``count.index``. Shares variables, locals, resources and diagnostics with this scope."""
        return Scope(each=each, count_index=count_index, _shared=self._shared)

    @property
    def diagnostics(self) -> tuple[Diagnostic, ...]:
        return tuple(self._shared.diagnostics)

    def report(self, code: str, message: str, where: SourceRange) -> None:
        self._shared.diagnostics.append(
            Diagnostic(
                DiagnosticSeverity.INVALID,
                code,
                message,
                where.file,
                where.start_line,
                where.start_column,
            )
        )


def evaluate_expression(expression: Expression, scope: Scope) -> Value:
    """Evaluate one expression. Never raises for any expression the parser can produce."""
    try:
        return _Evaluator(scope).value(expression)
    except Fail as failure:
        return Unsupported(failure.reason)
    except _Abort as limit:
        return Unsupported(limit.reason)
    except RecursionError:  # pragma: no cover - the depth guard keeps us far from the limit
        return Unsupported("limit.depth")


# --- The evaluator -------------------------------------------------------------------------------

_COMPARISON: Final = {
    BinaryOperator.GT,
    BinaryOperator.GE,
    BinaryOperator.LT,
    BinaryOperator.LE,
}


class _Evaluator:
    def __init__(self, scope: Scope) -> None:
        self.scope = scope
        self.shared = scope._shared
        self.steps = 0
        self.frames: list[dict[str, Raw]] = []
        self._dispatch: dict[type, Callable[[Any], Raw]] = {
            Literal: self._literal,
            Template: self._template,
            Heredoc: self._template,
            Tuple: self._tuple,
            Object: self._object,
            ScopeTraversal: self._traversal,
            FunctionCall: self._function,
            Conditional: self._conditional,
            BinaryOp: self._binary,
            UnaryOp: self._unary,
            ForExpr: self._for,
            Splat: self._splat,
            Index: self._index_node,
            GetAttr: self._get_attr,
            Parenthesized: self._parenthesized,
        }

    # -- Plumbing --

    def tick(self) -> None:
        self.steps += 1
        if self.steps > MAX_STEPS:
            raise _Abort("limit.eval_steps")

    def value(self, expression: Expression) -> Value:
        return self._finish(self.raw(expression))

    @staticmethod
    def _finish(result: Raw) -> Value:
        """A resource used as a value: an object (single instance), a tuple of objects (count) or
        an object of objects (for_each), as the "References to Named Values" page says. An instance
        object holds ``id`` and the arguments configured on it; Terraform's other attributes are
        not in it, so reading one from the object is unsupported (a direct ``aws_x.y.arn`` is
        unknown instead)."""
        if isinstance(result, _Instance):
            return known_object(dict(result.view.attributes()))
        if isinstance(result, _Resource):
            objects = [known_object(dict(i.attributes())) for i in result.instances]
            if result.mode == "count":
                return Known(tuple(objects))
            keyed: dict[str, Value] = {}
            for instance, instance_object in zip(result.instances, objects, strict=True):
                if instance.key is None:
                    raise Fail("reference.shape", "an instance of for_each without a key")
                keyed[as_string(instance.key)] = instance_object
            return known_object(keyed)
        return result

    def raw(self, expression: Expression) -> Raw:
        self.tick()
        if self.shared.depth >= MAX_DEPTH:
            raise _Abort("limit.depth")
        self.shared.depth += 1
        try:
            return self._dispatch[type(expression)](expression)
        finally:
            self.shared.depth -= 1

    # -- Literals and templates --

    def _literal(self, expr: Literal) -> Raw:
        if expr.kind is LiteralKind.NULL:
            return NULL
        return Known(expr.value)

    def _template(self, expr: Template | Heredoc) -> Raw:
        parts = expr.parts
        if any(isinstance(part, TemplateIf | TemplateFor) for part in parts):
            # %{if} and %{for} are not implemented in v1 (the work package, Step 3)
            return Unsupported("template.directive")
        if (
            isinstance(expr, Template)
            and len(parts) == 1
            and isinstance(parts[0], TemplateInterpolation)
        ):
            # a template that is one interpolation is the value itself, not a string
            return self.value(parts[0].expr)
        out: list[str] = []
        problems: list[Value] = []
        for part in parts:
            self.tick()
            if isinstance(part, TemplateLiteral):
                out.append(part.text)
            elif isinstance(part, TemplateInterpolation):
                value = self.value(part.expr)
                problem = scalar_problem(value)
                if problem is not None:
                    problems.append(problem)
                else:
                    out.append(self._piece(value))
        for pending in problems:
            if isinstance(pending, Unsupported):
                return pending
        if problems:
            return problems[0]
        return Known("".join(out))

    @staticmethod
    def _piece(value: Value) -> str:
        if kind_of(value) in ("tuple", "set", "object"):
            raise Fail("type.conversion", "a collection cannot be put into a string")
        return as_string(value)

    # -- Collections --

    def _tuple(self, expr: Tuple) -> Raw:
        return Known(tuple(self.value(element) for element in expr.elements))

    def _object(self, expr: Object) -> Raw:
        items: dict[str, Value] = {}
        problems: list[Value] = []
        for item in expr.items:
            if isinstance(item.key, IdentifierKey):
                name: str | None = item.key.name
            else:
                key = self.value(item.key)
                problem = scalar_problem(key)
                if problem is not None:
                    problems.append(problem)
                    name = None
                else:
                    name = as_string(key)
            value = self.value(item.value)
            if name is not None:
                items[name] = value  # a later duplicate key wins, as in Terraform
        for pending in problems:
            if isinstance(pending, Unsupported):
                return pending
        if problems:
            return problems[0]
        return known_object(items)

    # -- References --

    def _frame_binding(self, name: str) -> Raw | None:
        for frame in reversed(self.frames):
            if name in frame:
                return frame[name]
        return None

    def _traversal(self, expr: ScopeTraversal) -> Raw:
        bound = self._frame_binding(expr.root)
        if bound is not None:
            current: Raw = bound
            steps: Sequence[TraversalStep] = expr.steps
        else:
            resolved = self._root(expr)
            if not isinstance(resolved, tuple):
                return resolved
            current, steps = resolved
        for step in steps:
            self.tick()
            current = self._apply(current, step)
        return current

    def _name_step(self, expr: ScopeTraversal, what: str) -> str:
        if not expr.steps or not isinstance(expr.steps[0], AttrStep):
            raise Fail("reference.shape", f"{expr.root} must be followed by {what}")
        return expr.steps[0].name

    def _undeclared(self, expr: ScopeTraversal, what: str) -> Fail:
        self.scope.report(
            "eval.undeclared_reference", f"Reference to undeclared {what}", expr.range
        )
        return Fail("reference.undeclared", what)

    def _root(self, expr: ScopeTraversal) -> tuple[Raw, Sequence[TraversalStep]] | Value:
        root = expr.root
        if root == "var":
            name = self._name_step(expr, "a variable name")
            if name not in self.shared.variables:
                raise self._undeclared(expr, f"input variable var.{name}")
            return self.shared.variables[name], expr.steps[1:]
        if root == "local":
            name = self._name_step(expr, "a local value name")
            return self._local(name, expr), expr.steps[1:]
        if root == "each":
            attribute = self._name_step(expr, "key or value")
            if self.scope.each is None:
                self.scope.report("eval.each_context", "each used without for_each", expr.range)
                raise Fail("reference.context", "each outside for_each")
            if attribute not in ("key", "value"):
                raise Fail("reference.shape", f"each.{attribute}")
            return self.scope.each[0 if attribute == "key" else 1], expr.steps[1:]
        if root == "count":
            attribute = self._name_step(expr, "index")
            if self.scope.count_index is None:
                self.scope.report(
                    "eval.count_context", "count.index used without count", expr.range
                )
                raise Fail("reference.context", "count.index outside count")
            if attribute != "index":
                raise Fail("reference.shape", f"count.{attribute}")
            return self.scope.count_index, expr.steps[1:]
        if root in _OTHER_ROOTS:
            raise Fail(_OTHER_ROOTS[root], f"{root}.* is not evaluated")
        if root == "data":
            return self._data(expr)
        return self._resource(expr)

    def _local(self, name: str, expr: ScopeTraversal) -> Value:
        shared = self.shared
        if name in shared.local_values:
            return shared.local_values[name]
        if name not in shared.locals:
            raise self._undeclared(expr, f"local value local.{name}")
        if name in shared.resolving:
            self.scope.report("eval.cycle", f"Cycle: local.{name}", expr.range)
            raise Fail("local.cycle", f"local.{name} depends on itself")
        shared.resolving.append(name)
        try:
            assert shared.base is not None
            result = evaluate_expression(shared.locals[name], shared.base)
        finally:
            shared.resolving.pop()
        shared.local_values[name] = result
        return result

    def _data(self, expr: ScopeTraversal) -> Value:
        if len(expr.steps) < 2 or not all(isinstance(s, AttrStep) for s in expr.steps[:2]):
            raise Fail("reference.shape", "data must be followed by a type and a name")
        type_ = expr.steps[0].name  # type: ignore[union-attr]
        name = expr.steps[1].name  # type: ignore[union-attr]
        resources = self.shared.resources
        if resources is None or resources.resource("data", type_, name) is None:
            raise self._undeclared(expr, f"data source data.{type_}.{name}")
        return Unknown("data_source")

    def _resource(self, expr: ScopeTraversal) -> tuple[Raw, Sequence[TraversalStep]] | Value:
        type_ = expr.root
        name = self._name_step(expr, "a resource name")
        resources = self.shared.resources
        view = None if resources is None else resources.resource("resource", type_, name)
        if view is None:
            raise self._undeclared(expr, f"resource {type_}.{name}")
        instances = view.instances()
        if isinstance(instances, Unknown | Unsupported):
            return instances
        if view.mode == "single":
            if len(instances) != 1:
                raise Fail("reference.shape", f"{type_}.{name} has no single instance")
            return _Instance(instances[0]), expr.steps[1:]
        return _Resource(view.mode, instances), expr.steps[1:]

    def _apply(self, current: Raw, step: TraversalStep) -> Raw:
        if isinstance(step, AttrStep):
            return self._attribute(current, step.name)
        if isinstance(step, LegacyIndexStep):
            return self._index(current, Known(step.index))
        return self._index(current, self.value(step.key))

    def _attribute(self, current: Raw, name: str) -> Raw:
        if isinstance(current, _Instance):
            return current.view.attribute(name)
        if isinstance(current, _Resource):
            raise Fail("reference.missing_key", "a resource with count or for_each needs an index")
        if isinstance(current, Unknown | Unsupported):
            return current
        if isinstance(current, Ref):
            raise Fail("eval.attribute_type", "an attribute of a reference")
        if isinstance(current.value, Mapping):
            if name in current.value:
                attribute: Value = current.value[name]
                return attribute
            raise Fail("eval.missing_attribute", f"the object has no attribute {name[:30]!r}")
        if current.value is None:
            raise Fail("value.null", "an attribute of null")
        raise Fail("eval.attribute_type", f"an attribute of a {kind_of(current)}")

    def _index(self, current: Raw, key: Value) -> Raw:
        if isinstance(current, _Instance):
            raise Fail("reference.shape", "an index on a single resource instance")
        if isinstance(current, _Resource):
            return self._instance_at(current, key)
        problem = scalar_problem(current, key)
        if problem is not None:
            return problem
        assert not isinstance(current, Ref) and isinstance(current, Known)
        payload = current.value
        if payload is None:
            raise Fail("value.null", "an index into null")
        if isinstance(payload, tuple):
            position = as_int(key)
            if 0 <= position < len(payload):
                element: Value = payload[position]
                return element
            raise Fail("eval.invalid_index", "an index outside the list")
        if isinstance(payload, Mapping):
            name = as_string(key)
            if name in payload:
                member: Value = payload[name]
                return member
            raise Fail("eval.invalid_index", f"the object has no key {name[:30]!r}")
        if isinstance(payload, SetValue):
            raise Fail("eval.index_type", "the elements of a set have no index")
        raise Fail("eval.index_type", f"a {kind_of(current)} cannot be indexed")

    def _instance_at(self, resource: _Resource, key: Value) -> Raw:
        problem = scalar_problem(key)
        if problem is not None:
            return problem
        if resource.mode == "count":
            position = as_int(key)
            if 0 <= position < len(resource.instances):
                return _Instance(resource.instances[position])
            raise Fail("eval.invalid_index", "an instance index outside count")
        name = as_string(key)
        for instance in resource.instances:
            if instance.key == Known(name):
                return _Instance(instance)
        raise Fail("eval.invalid_index", f"no instance with the key {name[:30]!r}")

    # -- Index, attribute, splat, parentheses --

    def _index_node(self, expr: Index) -> Raw:
        collection = self.raw(expr.collection)
        return self._index(collection, self.value(expr.key))

    def _get_attr(self, expr: GetAttr) -> Raw:
        return self._attribute(self.raw(expr.target), expr.name)

    def _parenthesized(self, expr: Parenthesized) -> Raw:
        return self.raw(expr.expr)

    def _splat(self, expr: Splat) -> Raw:
        source = self.raw(expr.source)
        if isinstance(source, _Resource):
            elements: list[Raw] = [_Instance(i) for i in source.instances]
        elif isinstance(source, _Instance):
            elements = [source]
        elif isinstance(source, Unknown | Unsupported):
            return source
        elif isinstance(source, Known) and source.value is None:
            elements = []
        elif isinstance(source, Known) and isinstance(source.value, tuple):
            elements = list(source.value)
        elif isinstance(source, Known) and isinstance(source.value, SetValue):
            elements = list(source.value.elements)
        else:
            elements = [source]  # a single value is treated as a one-element list
        results: list[Value] = []
        for element in elements:
            self.tick()
            current = element
            for step in expr.steps:
                current = self._apply(current, step)
            results.append(self._finish(current))
        return Known(tuple(results))

    # -- Operators --

    def _unary(self, expr: UnaryOp) -> Raw:
        operand = self.value(expr.operand)
        problem = scalar_problem(operand)
        if problem is not None:
            return problem
        if expr.op is UnaryOperator.NOT:
            return FALSE if as_bool(operand) else TRUE
        number = as_number(operand)
        if number == 0:
            raise Fail("number.negative_zero", "Terraform prints -0")
        with number_context() as context:
            return Known(make_number(context.minus(decimal.Decimal(number))))

    def _binary(self, expr: BinaryOp) -> Raw:
        spine: list[BinaryOp] = []
        node: Expression = expr
        while isinstance(node, BinaryOp):
            spine.append(node)
            node = node.left
            self.tick()
        accumulated = self.value(node)
        for operation in reversed(spine):
            self.tick()
            decided = self._decides(operation.op, accumulated)
            if decided is not None:
                # Terraform 1.15.8 does not evaluate the right operand when the left one decides
                # (probe: `false && [1][5]` is false), so an error there is not an error.
                try:
                    right = self.value(operation.right)
                except Fail:
                    accumulated = decided
                    continue
            else:
                right = self.value(operation.right)
            accumulated = self._operate(operation.op, accumulated, right)
        return accumulated

    @staticmethod
    def _decides(op: BinaryOperator, left: Value) -> Value | None:
        if op not in (BinaryOperator.AND, BinaryOperator.OR):
            return None
        if not isinstance(left, Known) or kind_of(left) not in ("bool", "string"):
            return None
        try:
            flag = as_bool(left)
        except Fail:
            return None
        if op is BinaryOperator.AND and not flag:
            return FALSE
        if op is BinaryOperator.OR and flag:
            return TRUE
        return None

    def _operate(self, op: BinaryOperator, left: Value, right: Value) -> Value:
        if op in (BinaryOperator.EQ, BinaryOperator.NE):
            return self._equality(op, left, right)
        problem = scalar_problem(left, right)
        if problem is not None:
            return problem
        if op in (BinaryOperator.AND, BinaryOperator.OR):
            first, second = as_bool(left), as_bool(right)
            return Known(first and second if op is BinaryOperator.AND else first or second)
        a, b = as_number(left), as_number(right)
        if op in _COMPARISON:
            return Known(_compare(op, a, b))
        return Known(_arithmetic(op, a, b))

    @staticmethod
    def _equality(op: BinaryOperator, left: Value, right: Value) -> Value:
        for operand in (left, right):
            if isinstance(operand, Unsupported):
                return operand
        answer = equal3(left, right)
        if answer is None:
            for operand in (left, right):
                if isinstance(operand, Unknown):
                    return operand
            return Unknown("operator.undecided")
        return Known(answer if op is BinaryOperator.EQ else not answer)

    def _conditional(self, expr: Conditional) -> Raw:
        condition = self.value(expr.condition)
        problem = scalar_problem(condition)
        if problem is not None:
            # still look at both branches, so that undeclared references are reported
            for branch in (expr.true_expr, expr.false_expr):
                with contextlib.suppress(Fail):
                    self.value(branch)
            return problem
        taken, other = (
            (expr.true_expr, expr.false_expr)
            if as_bool(condition)
            else (expr.false_expr, expr.true_expr)
        )
        chosen = self.value(taken)
        try:
            alternative: Value | None = self.value(other)
        except Fail:
            alternative = None  # Terraform reports only the diagnostics of the branch it takes
        if alternative is None or isinstance(chosen, Unknown | Unsupported):
            return chosen
        if isinstance(alternative, Unknown | Unsupported):
            return chosen
        return unify_pair(chosen, alternative)

    # -- for expressions --

    def _pairs(self, collection: Raw) -> list[tuple[Raw, Raw]] | Value:
        """The (key, value) pairs a ``for`` expression iterates, or the problem value."""
        if isinstance(collection, _Resource):
            if collection.mode == "count":
                return [(Known(i), _Instance(v)) for i, v in enumerate(collection.instances)]
            return [
                (v.key if v.key is not None else NULL, _Instance(v)) for v in collection.instances
            ]
        if isinstance(collection, _Instance):
            collection = self._finish(collection)
        if isinstance(collection, Unknown | Unsupported):
            return collection
        if isinstance(collection, Ref):
            raise Fail("eval.not_iterable", "a reference")
        payload = collection.value
        if payload is None:
            raise Fail("value.null", "a for expression over null")
        if isinstance(payload, tuple):
            return [(Known(i), v) for i, v in enumerate(payload)]
        if isinstance(payload, SetValue):
            return [(v, v) for v in payload.elements]  # a set's key is the element itself
        if isinstance(payload, Mapping):
            return [(Known(k), v) for k, v in payload.items()]
        raise Fail("eval.not_iterable", f"a {kind_of(collection)}")

    def _for(self, expr: ForExpr) -> Raw:
        pairs = self._pairs(self.raw(expr.collection))
        if not isinstance(pairs, list):
            return pairs
        items: list[Value] = []
        keyed: dict[str, list[Value]] = {}
        unknown: Unknown | None = None
        for key, element in pairs:
            self.tick()
            frame: dict[str, Raw] = {expr.value_var: element}
            if expr.key_var is not None:
                frame[expr.key_var] = key
            self.frames.append(frame)
            try:
                if expr.condition is not None:
                    condition = self.value(expr.condition)
                    problem = scalar_problem(condition)
                    if isinstance(problem, Unsupported):
                        return problem
                    if problem is not None:
                        unknown = unknown or _as_unknown(problem)
                        continue
                    if not as_bool(condition):
                        continue
                if expr.kind is ForKind.TUPLE:
                    items.append(self.value(expr.value_expr))
                else:
                    assert expr.key_expr is not None
                    name_value = self.value(expr.key_expr)
                    problem = scalar_problem(name_value)
                    produced = self.value(expr.value_expr)
                    if isinstance(problem, Unsupported):
                        return problem
                    if problem is not None:
                        unknown = unknown or _as_unknown(problem)
                        continue
                    name = as_string(name_value)
                    if name in keyed and not expr.group:
                        raise Fail(
                            "eval.duplicate_key", f"two iterations make the key {name[:30]!r}"
                        )
                    keyed.setdefault(name, []).append(produced)
            finally:
                self.frames.pop()
            if len(items) > MAX_FOR_ELEMENTS or len(keyed) > MAX_FOR_ELEMENTS:
                raise Fail("limit.for_elements", "more than 1,000 elements")
        if unknown is not None:
            return unknown
        if expr.kind is ForKind.TUPLE:
            return Known(tuple(items))
        if expr.group:
            return known_object({k: Known(tuple(v)) for k, v in keyed.items()})
        return known_object({k: v[0] for k, v in keyed.items()})

    # -- Function calls --

    def _function(self, expr: FunctionCall) -> Raw:
        arguments: list[Value] = []
        for argument in expr.args:
            arguments.append(self.value(argument))
        if expr.expand_final:
            last = arguments[-1] if arguments else NULL
            problem = scalar_problem(last)
            if problem is not None:
                return problem
            arguments[-1:] = list(as_elements(last, sets=False))
        if expr.name not in FUNCTIONS:
            return Unsupported(f"function.not_implemented:{expr.name}")
        return call_function(expr.name, arguments)


_OTHER_ROOTS: Final = {
    "path": "reference.path",
    "terraform": "reference.terraform",
    "module": "reference.module",
    "self": "reference.self",
}


def _as_unknown(problem: Unknown | Unsupported) -> Unknown:
    return problem if isinstance(problem, Unknown) else Unknown(problem.reason)


def _compare(op: BinaryOperator, a: int | decimal.Decimal, b: int | decimal.Decimal) -> bool:
    if op is BinaryOperator.GT:
        return a > b
    if op is BinaryOperator.GE:
        return a >= b
    if op is BinaryOperator.LT:
        return a < b
    return a <= b


def _arithmetic(
    op: BinaryOperator, a: int | decimal.Decimal, b: int | decimal.Decimal
) -> int | decimal.Decimal:
    if op in (BinaryOperator.DIV, BinaryOperator.MOD) and b == 0:
        raise Fail("number.divide_by_zero", "division by zero")
    x, y = decimal.Decimal(a), decimal.Decimal(b)
    try:
        with number_context() as context:
            if op is BinaryOperator.ADD:
                result = context.add(x, y)
            elif op is BinaryOperator.SUB:
                result = context.subtract(x, y)
            elif op is BinaryOperator.MUL:
                result = context.multiply(x, y)
            elif op is BinaryOperator.DIV:
                result = context.divide(x, y)
            else:
                result = context.remainder(x, y)
    except ArithmeticError as error:
        raise Fail("number.inexact", "the result is not exactly representable") from error
    if result.is_zero():
        if op in (BinaryOperator.MUL, BinaryOperator.DIV) and (x < 0) != (y < 0):
            raise Fail("number.negative_zero", "Terraform prints -0")
        return 0
    return make_number(result)


__all__ = [
    "MAX_DEPTH",
    "MAX_FOR_ELEMENTS",
    "MAX_STEPS",
    "InstanceView",
    "ResourceResolver",
    "ResourceView",
    "Scope",
    "evaluate_expression",
]
