"""Configuration evaluation: variables, locals, instances and moves (Doc 04 §4, §17; registry §2.2,
§2.3; C-92, C-100 to C-105).

``evaluate_configuration(parsed, variables)`` takes the root module that ``load_configuration``
parsed (status OK) and the scenario's variable values, and returns an ``EvaluationOutcome``:

- ``variables``: every declared variable's value (the scenario value, else the declared default,
  else ``Unknown("variable.no_value")``), converted to its type constraint;
- ``locals``: every local value, evaluated lazily with cycle detection;
- ``instances`` and ``indeterminate``: the expansion of every ``resource`` and ``data`` block
  (``instances.py``);
- ``moves``: the ``moved`` blocks as canonical address pairs, validated and **not applied**.

The status follows C-92 and fails closed: INVALID when Terraform 1.15.8 itself rejects the input
(an undeclared reference, ``each`` or ``count.index`` outside their resource, a cycle, ``count``
with ``for_each``, an attribute and a block with one name); UNSUPPORTED when the configuration is
valid but outside what DAIL evaluates, for the whole configuration (a ``module`` block, C-104;
more than 10,000 instances, C-105; a scenario value for an undeclared variable; a ``moved`` block
that is not a static pair or a move table that is not well-formed) or for one value (per-value
``Unknown`` / ``Unsupported``, which leave the status OK). INVALID wins over UNSUPPORTED. Data is
present only when the status is OK.

A scenario value for an undeclared variable is UNSUPPORTED, not INVALID. Measured on Terraform
1.15.8 (``terraform plan`` with the builtin ``terraform_data`` resource, scratch directory outside
the repository, no credentials): ``-var nope=1`` is an error, a ``-var-file`` with ``nope`` is a
warning, and ``TF_VAR_nope`` is ignored, so whether Terraform rejects it depends on how the
harness passes the value.

``moved`` blocks: the checks are those of ``ValidateMoves`` in Terraform v1.15.8
(``internal/refactoring/move_validate.go``): a move to the same address, a ``from`` that is still
declared, two destinations for one source, two sources for one destination, and a cycle. Terraform
runs them while planning, not in ``validate``, so a violation is UNSUPPORTED here. DAIL cannot
tell whether a move between two resource types is one the provider supports, so it is
UNSUPPORTED too. Implicit ``count`` moves and applying moves are P3b's.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import InitVar, dataclass
from types import MappingProxyType
from typing import Final

from core.domain.errors import DomainValidationError, UnauthorizedConstructionError
from core.domain.hashing import content_hash
from core.terraform_model.config import (
    PARSER_VERSION,
    Declaration,
    Diagnostic,
    DiagnosticSeverity,
    MovedDecl,
    ParsedConfiguration,
    ParseStatus,
)
from core.terraform_model.convert import ANY, Fail, TypeSpec, convert_to, parse_type
from core.terraform_model.evaluate import Scope, evaluate_expression
from core.terraform_model.hcl.ast import (
    Attribute,
    AttrStep,
    Block,
    Expression,
    IndexStep,
    LegacyIndexStep,
    Literal,
    LiteralKind,
    ScopeTraversal,
    SourceRange,
)
from core.terraform_model.instances import (
    MAX_INSTANCES_PER_CONFIGURATION,
    EvaluatedInstance,
    EvaluatedResource,
    ResourceRuntime,
    instance_address,
)
from core.terraform_model.values import (
    NULL,
    Known,
    Unknown,
    Unsupported,
    Value,
    from_json,
)

EVALUATOR_VERSION: Final = "dail-tf-eval-1"
_OUTCOME_TOKEN: Final = object()

# Reason codes of the Unsupported values made here.
REASONS: Final[dict[str, str]] = {
    "variable.type_constraint": "A variable type constraint DAIL cannot read.",
    "variable.type_mismatch": "A variable value that does not convert to its type constraint.",
    "variable.nullable": "A nullable argument that is not a literal bool.",
    "variable.null_not_allowed": "A null for a variable with nullable = false and no default.",
}
DIAGNOSTICS: Final[dict[str, str]] = {
    "eval.module_call": "A module block: the whole configuration is unsupported (C-104).",
    "eval.undeclared_variable_value": "A scenario value for a variable the configuration lacks.",
    "eval.variable_validation": "A validation block on a variable that is used (not evaluated).",
    "limit.instances_per_configuration": "More than 10,000 instances in the configuration.",
    "eval.move_not_static": "A moved block whose from or to is not a static resource address.",
    "eval.move_type_change": "A move between two resource types.",
    "eval.move_redundant": "A move to the same address.",
    "eval.move_from_exists": "A move from an address that is still declared.",
    "eval.move_undecidable": "A move from an instance of a resource with unknown expansion.",
    "eval.move_ambiguous": "Two destinations for one source, or two sources for one destination.",
    "eval.move_cycle": "Chained moves that form a cycle.",
}


# --- Outcome -------------------------------------------------------------------------------------


def _status_of(diagnostics: tuple[Diagnostic, ...]) -> ParseStatus:
    severities = {d.severity for d in diagnostics}
    if DiagnosticSeverity.INVALID in severities:
        return ParseStatus.INVALID
    if DiagnosticSeverity.UNSUPPORTED in severities:
        return ParseStatus.UNSUPPORTED
    return ParseStatus.OK


@dataclass(frozen=True)
class EvaluationOutcome:
    """The result of evaluating a configuration. Built only by ``evaluate_configuration``.

    ``instances``, ``indeterminate``, ``variables``, ``locals`` and ``moves`` are present only
    when ``status`` is OK, and ``status`` is the one the diagnostics imply (INVALID, else
    UNSUPPORTED, else OK). ``instances`` is sorted by address.
    """

    status: ParseStatus
    diagnostics: tuple[Diagnostic, ...]
    instances: Mapping[str, EvaluatedInstance]
    indeterminate: Mapping[str, EvaluatedResource]
    variables: Mapping[str, Value]
    locals: Mapping[str, Value]
    moves: tuple[tuple[str, str], ...]
    configuration_hash: str
    variables_hash: str
    parser_version: str
    evaluator_version: str
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _OUTCOME_TOKEN:
            raise UnauthorizedConstructionError(
                "EvaluationOutcome can be created only by evaluate_configuration (C-92)"
            )
        if not isinstance(self.status, ParseStatus):
            raise DomainValidationError("EvaluationOutcome.status must be a ParseStatus")
        if self.status is not _status_of(self.diagnostics):
            raise DomainValidationError(
                "EvaluationOutcome.status does not follow from its diagnostics"
            )
        keys = [d.sort_key for d in self.diagnostics]
        if keys != sorted(keys):
            raise DomainValidationError("EvaluationOutcome.diagnostics must be sorted")
        if self.status is not ParseStatus.OK and (
            self.instances or self.indeterminate or self.variables or self.locals or self.moves
        ):
            raise DomainValidationError("data is present only when the status is OK")
        for address, instance in self.instances.items():
            if address != instance.address:
                raise DomainValidationError("an instance is stored under another address")
        if list(self.instances) != sorted(self.instances):
            raise DomainValidationError("EvaluationOutcome.instances must be sorted by address")
        for name in ("instances", "indeterminate", "variables", "locals"):
            object.__setattr__(self, name, MappingProxyType(dict(getattr(self, name))))


# --- Variables -----------------------------------------------------------------------------------


class _Variables(Mapping[str, Value]):
    """The variable values of a scope. Reading a variable whose declaration has a ``validation``
    block records that the block was not evaluated."""

    def __init__(
        self,
        values: Mapping[str, Value],
        validations: Mapping[str, Block],
        notes: list[Diagnostic],
    ) -> None:
        self._values = values
        self._validations = validations
        self._notes = notes

    def __getitem__(self, name: str) -> Value:
        block = self._validations.get(name)
        if block is not None:
            self._notes.append(
                _diagnostic(
                    DiagnosticSeverity.UNSUPPORTED_CONSTRUCT,
                    "eval.variable_validation",
                    f"the validation block of variable {name} is not evaluated",
                    block.range,
                )
            )
        return self._values[name]

    def __contains__(self, name: object) -> bool:
        return name in self._values

    def __iter__(self) -> Iterator[str]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)


def _diagnostic(
    severity: DiagnosticSeverity, code: str, message: str, where: SourceRange
) -> Diagnostic:
    return Diagnostic(severity, code, message, where.file, where.start_line, where.start_column)


def _variable_value(declaration: Declaration, supplied: Mapping[str, Value], empty: Scope) -> Value:
    """The value of one variable (registry §2.2: provided value, else declared default, else
    unresolved), converted to its type constraint (``expressions/type-constraints.mdx``)."""
    name = declaration.name
    attributes = {
        item.name: item for item in declaration.block.body.items if isinstance(item, Attribute)
    }
    spec: TypeSpec = ANY
    if "type" in attributes:
        try:
            spec = parse_type(attributes["type"].expr)
        except Fail:
            return Unsupported("variable.type_constraint")
    nullable = True
    if "nullable" in attributes:
        flag = evaluate_expression(attributes["nullable"].expr, empty)
        if not (isinstance(flag, Known) and isinstance(flag.value, bool)):
            return Unsupported("variable.nullable")
        nullable = flag.value
    default: Value | None = None
    if "default" in attributes:
        default = evaluate_expression(attributes["default"].expr, empty)
    if name in supplied:
        chosen = supplied[name]
        if chosen == NULL and not nullable:
            if default is None or default == NULL:
                return Unsupported("variable.null_not_allowed")
            chosen = default
    elif default is not None:
        chosen = default
    else:
        return Unknown("variable.no_value")
    try:
        return convert_to(chosen, spec)
    except Fail:
        return Unsupported("variable.type_mismatch")


# --- Moves ---------------------------------------------------------------------------------------

_NOT_RESOURCE_ROOTS: Final = frozenset(
    {"data", "module", "var", "local", "each", "count", "path", "terraform", "self"}
)


def _move_address(expr: Expression) -> tuple[str, str, int | str | None] | None:
    """(type, name, key) of a static resource address such as ``aws_x.a`` or ``aws_x.a["k"]``."""
    if not isinstance(expr, ScopeTraversal) or expr.root in _NOT_RESOURCE_ROOTS:
        return None
    steps = expr.steps
    if not steps or not isinstance(steps[0], AttrStep) or len(steps) > 2:
        return None
    key: int | str | None = None
    if len(steps) == 2:
        step = steps[1]
        if isinstance(step, LegacyIndexStep):
            key = step.index
        elif isinstance(step, IndexStep) and isinstance(step.key, Literal):
            literal = step.key
            if literal.kind is LiteralKind.STRING:
                key = str(literal.value)
            elif literal.kind is LiteralKind.NUMBER and isinstance(literal.value, int):
                key = literal.value
            else:
                return None
        else:
            return None
        if isinstance(key, int) and key < 0:
            return None
    return expr.root, steps[0].name, key


@dataclass(frozen=True, slots=True)
class _Move:
    source: str
    target: str
    resource_type: tuple[str, str]  # (from type, to type)
    from_parts: tuple[str, str, int | str | None]
    declaration: MovedDecl


def _overlap(first: str, second: str) -> bool:
    """Equal, or one is the resource and the other an instance of it."""
    return first == second or first.startswith(second + "[") or second.startswith(first + "[")


def _moves(
    parsed: ParsedConfiguration,
    instances: Mapping[str, EvaluatedInstance],
    indeterminate: Mapping[str, EvaluatedResource],
    diagnostics: list[Diagnostic],
) -> tuple[tuple[str, str], ...]:
    found: list[_Move] = []
    for declaration in parsed.moved:
        source = _move_address(declaration.from_expr)
        target = _move_address(declaration.to_expr)
        where = declaration.block.range
        if source is None or target is None:
            diagnostics.append(
                _diagnostic(
                    DiagnosticSeverity.UNSUPPORTED,
                    "eval.move_not_static",
                    "from and to must be static resource addresses",
                    where,
                )
            )
            continue
        found.append(
            _Move(
                instance_address("resource", source[0], source[1], source[2]),
                instance_address("resource", target[0], target[1], target[2]),
                (source[0], target[0]),
                source,
                declaration,
            )
        )
    problems = len(diagnostics)
    seen_from: dict[str, _Move] = {}
    seen_to: dict[str, _Move] = {}

    def report(code: str, message: str, where: SourceRange) -> None:
        diagnostics.append(_diagnostic(DiagnosticSeverity.UNSUPPORTED, code, message, where))

    for move in found:
        where = move.declaration.block.range
        if move.resource_type[0] != move.resource_type[1]:
            report(
                "eval.move_type_change", f"{move.source} to {move.target} changes the type", where
            )
        if move.source == move.target:
            report("eval.move_redundant", f"{move.source} is moved to itself", where)
            continue
        type_, name, key = move.from_parts
        if key is None:
            exists = (type_, name) in parsed.resources
        elif instance_address("resource", type_, name) in indeterminate:
            report("eval.move_undecidable", f"the expansion of {type_}.{name} is unknown", where)
            exists = False
        else:
            exists = move.source in instances
        if exists:
            report("eval.move_from_exists", f"{move.source} is still declared", where)
        earlier = seen_from.setdefault(move.source, move)
        if earlier.target != move.target:
            report("eval.move_ambiguous", f"{move.source} has two destinations", where)
        earlier = seen_to.setdefault(move.target, move)
        if earlier.source != move.source:
            report("eval.move_ambiguous", f"{move.target} has two sources", where)
    if len(diagnostics) == problems and _has_cycle(found):
        diagnostics.append(
            _diagnostic(
                DiagnosticSeverity.UNSUPPORTED,
                "eval.move_cycle",
                "chained move statements form a cycle",
                found[0].declaration.block.range,
            )
        )
    return tuple((move.source, move.target) for move in found)


def _has_cycle(moves: list[_Move]) -> bool:
    """A move depends on another when its target overlaps the other's source; a cycle in that
    graph has no final location (``validateMoveStatementGraph``)."""
    edges = {
        i: [j for j, other in enumerate(moves) if i != j and _overlap(move.target, other.source)]
        for i, move in enumerate(moves)
    }
    state: dict[int, int] = {}  # 1 on the stack, 2 done
    for start in edges:
        if start in state:
            continue
        stack = [(start, iter(edges[start]))]
        state[start] = 1
        while stack:
            node, successors = stack[-1]
            advanced = False
            for successor in successors:
                if state.get(successor) == 1:
                    return True
                if successor not in state:
                    state[successor] = 1
                    stack.append((successor, iter(edges[successor])))
                    advanced = True
                    break
            if not advanced:
                state[node] = 2
                stack.pop()
    return False


# --- The entry point -----------------------------------------------------------------------------


def evaluate_configuration(
    parsed: ParsedConfiguration, variables: Mapping[str, object] | None = None
) -> EvaluationOutcome:
    """Evaluate a parsed root module with the scenario's variable values.

    ``variables`` maps names to JSON values (``None``, bool, int, str, list, dict). A float is
    refused with ``ValueModelError`` (pass an integer or a string); that is a caller error, not a
    property of the configuration. Never raises for any configuration ``load_configuration``
    accepted.
    """
    scenario_raw = dict(variables or {})
    supplied = {name: from_json(value) for name, value in scenario_raw.items()}
    variables_hash = content_hash(scenario_raw)
    diagnostics: list[Diagnostic] = []
    notes: list[Diagnostic] = []

    for name, module in sorted(parsed.modules.items()):
        diagnostics.append(
            _diagnostic(
                DiagnosticSeverity.UNSUPPORTED,
                "eval.module_call",
                f"module {name}: module calls are not supported in v1 (C-104)",
                module.block.range,
            )
        )
    for name in sorted(set(supplied) - set(parsed.variables)):
        diagnostics.append(
            Diagnostic(
                DiagnosticSeverity.UNSUPPORTED,
                "eval.undeclared_variable_value",
                f"a value was provided for variable {name}, which is not declared",
            )
        )

    empty = Scope()
    values = {
        name: _variable_value(declaration, supplied, empty)
        for name, declaration in sorted(parsed.variables.items())
    }
    diagnostics.extend(empty.diagnostics)
    validations = {
        name: block
        for name, declaration in parsed.variables.items()
        for block in (
            item
            for item in declaration.block.body.items
            if isinstance(item, Block) and item.type == "validation"
        )
    }

    class _Resolver:
        def __init__(self) -> None:
            self.runtimes: dict[tuple[str, str, str], ResourceRuntime] = {}

        def resource(self, kind: str, type_: str, name: str) -> ResourceRuntime | None:
            return self.runtimes.get((kind, type_, name))

    resolver = _Resolver()
    scope = Scope(
        variables=_Variables(values, validations, notes),
        locals={name: decl.attribute.expr for name, decl in parsed.locals.items()},
        resources=resolver,
    )
    for (type_, name), decl in parsed.resources.items():
        resolver.runtimes[("resource", type_, name)] = ResourceRuntime(decl, scope)
    for (type_, name), decl in parsed.data_sources.items():
        resolver.runtimes[("data", type_, name)] = ResourceRuntime(decl, scope)
    ordered = [resolver.runtimes[key] for key in sorted(resolver.runtimes)]

    # phase 1: which instances exist (cheap), so the configuration limit is checked before any
    # argument is evaluated
    total = 0
    for runtime in ordered:
        found = runtime.instances()
        if not isinstance(found, Unknown | Unsupported):
            total += len(found)
    over = total > MAX_INSTANCES_PER_CONFIGURATION
    if over:
        diagnostics.append(
            Diagnostic(
                DiagnosticSeverity.UNSUPPORTED,
                "limit.instances_per_configuration",
                f"{total} instances; at most {MAX_INSTANCES_PER_CONFIGURATION} are evaluated",
            )
        )

    instances: dict[str, EvaluatedInstance] = {}
    indeterminate: dict[str, EvaluatedResource] = {}
    local_values: dict[str, Value] = {}
    if not over:
        # phase 2: the arguments of every instance
        for runtime in ordered:
            expansion = runtime.expand()
            for instance in expansion.instances:
                instances[instance.address] = instance
                diagnostics.extend(instance.diagnostics)
            if expansion.indeterminate is not None:
                indeterminate[expansion.indeterminate.address] = expansion.indeterminate
                diagnostics.extend(expansion.indeterminate.diagnostics)
        for name in sorted(parsed.locals):
            local_values[name] = scope.local_value(name)
    instances = dict(sorted(instances.items()))
    moves = _moves(parsed, instances, indeterminate, diagnostics) if not over else ()

    diagnostics.extend(scope.diagnostics)
    diagnostics.extend(notes)
    ordered_diagnostics = tuple(sorted(set(diagnostics), key=lambda d: d.sort_key + (d.message,)))
    status = _status_of(ordered_diagnostics)
    ok = status is ParseStatus.OK
    return EvaluationOutcome(
        status,
        ordered_diagnostics,
        instances if ok else {},
        indeterminate if ok else {},
        values if ok else {},
        local_values if ok else {},
        moves if ok else (),
        parsed.configuration_hash,
        variables_hash,
        PARSER_VERSION,
        EVALUATOR_VERSION,
        _OUTCOME_TOKEN,
    )
