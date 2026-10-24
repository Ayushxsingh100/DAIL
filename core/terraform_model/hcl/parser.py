"""Recursive-descent parser for the HCL native syntax (Doc 04 §4; C-91, C-93).

Grammar source: ``hclsyntax/spec.md`` of ``hashicorp/hcl`` at tag ``v2.25.0``
(commit 00057cf06d7b38a3f89e6e54d622eee98322b314, SHA-256 of the file
a99da24e075391fd097654dc6bf4da8ed8820d52b282ba9e44612f0f1f6feb14); see ADR-003. Section names
below are the headings of that file, and line numbers are lines of that file.

The parser accepts the whole native expression grammar (parse widely; semantic support is decided
in P3a-2). It never guesses: anything it does not fully understand raises ``HclSyntaxError``
(not valid HCL) or ``HclLimitError`` (valid so far, beyond a limit of C-93). Behaviours that the
specification leaves open and that were settled against Terraform 1.15.8 are marked "C-95".

``parse_file`` is pure and deterministic. It does no I/O.
"""

from __future__ import annotations

from collections import deque
from decimal import Decimal

from core.terraform_model.hcl.ast import (
    Attribute,
    AttrStep,
    BinaryOp,
    BinaryOperator,
    Block,
    Body,
    Conditional,
    Expression,
    ForExpr,
    ForKind,
    FunctionCall,
    GetAttr,
    Heredoc,
    IdentifierKey,
    Index,
    IndexStep,
    Label,
    LegacyIndexStep,
    Literal,
    LiteralKind,
    Object,
    ObjectItem,
    Parenthesized,
    ScopeTraversal,
    SourceRange,
    Splat,
    SplatKind,
    Strip,
    Template,
    TemplateFor,
    TemplateIf,
    TemplateInterpolation,
    TemplateLiteral,
    TemplatePart,
    TraversalStep,
    Tuple,
    UnaryOp,
    UnaryOperator,
)
from core.terraform_model.hcl.errors import HclLimitError, HclSyntaxError
from core.terraform_model.hcl.lexer import Lexer, SourceMap, T, Token

# C-93: nesting deeper than this is UNSUPPORTED. Nesting counts blocks, tuples, objects, for
# expressions, parentheses, function-call and index brackets, template sequences and directives,
# unary operators and conditional branches.
MAX_NESTING_DEPTH = 64

# Binary operator precedence, copied from the specification ("Operations", lines 641-657):
#
#   "The unary operators have the highest precedence."
#   Level    Operators
#     6      * / %
#     5      + -
#     4      > >= < <=
#     3      == !=
#     2      &&
#     1      ||
#   "Higher values of 'level' bind tighter. Operators within the same precedence level have
#   left-to-right associativity. For example, `x / y * z` is equivalent to `(x / y) * z`."
#
# The conditional operator ``? :`` binds weaker than every level ("Conditional Operator",
# lines 722-729: Conditional = Expression "?" Expression ":" Expression) and is right-associative
# because each branch is a full Expression.
_BINARY: dict[T, tuple[BinaryOperator, int]] = {
    T.STAR: (BinaryOperator.MUL, 6),
    T.SLASH: (BinaryOperator.DIV, 6),
    T.PERCENT: (BinaryOperator.MOD, 6),
    T.PLUS: (BinaryOperator.ADD, 5),
    T.MINUS: (BinaryOperator.SUB, 5),
    T.GT: (BinaryOperator.GT, 4),
    T.GE: (BinaryOperator.GE, 4),
    T.LT: (BinaryOperator.LT, 4),
    T.LE: (BinaryOperator.LE, 4),
    T.EQEQ: (BinaryOperator.EQ, 3),
    T.NE: (BinaryOperator.NE, 3),
    T.AND: (BinaryOperator.AND, 2),
    T.OR: (BinaryOperator.OR, 1),
}

_DIGITS = frozenset("0123456789")
# Unicode White_Space, for the strip markers ("Space characters are interpreted as per
# Unicode's definition", line 804). Python's str.isspace also accepts U+001C..U+001F, which
# are not White_Space.
_WHITE_SPACE = frozenset("\t\n\x0b\x0c\r \x85\xa0          " "      　")


def _lstrip(text: str) -> str:
    i = 0
    while i < len(text) and text[i] in _WHITE_SPACE:
        i += 1
    return text[i:]


def _rstrip(text: str) -> str:
    j = len(text)
    while j > 0 and text[j - 1] in _WHITE_SPACE:
        j -= 1
    return text[:j]


def number_value(text: str) -> int | Decimal | None:
    """Exact value of a numeric literal: ``int`` when integral and small, else ``Decimal``.

    Returns None when the exponent is outside what ``Decimal`` can represent. Never a float.
    """
    if text.isascii() and text.isdigit() and len(text) <= 4000:
        return int(text)
    try:
        value = Decimal(text)
    except ArithmeticError:
        return None
    if value.adjusted() < 4000 and value == value.to_integral_value():
        return int(value)
    return value


def _is_constant_step(step: TraversalStep) -> bool:
    """Whether a step can join a plain traversal: a name, a legacy index or a literal key."""
    if isinstance(step, IndexStep):
        return isinstance(step.key, Literal) and step.key.kind in (
            LiteralKind.NUMBER,
            LiteralKind.STRING,
        )
    return True


class _PartsBuilder:
    """Collects the parts of one template body and applies the ``~`` strip markers.

    A strip marker acts on the adjacent literal token only ("Template Literals", lines 794-811);
    the tokens of a heredoc are its lines, so a marker does not reach past one line. Adjacent
    literals are merged and empty ones dropped when the parts are finished.
    """

    def __init__(self) -> None:
        self.items: list[TemplatePart] = []
        self.lstrip_next = False

    def literal(self, text: str, rng: SourceRange) -> None:
        if text == "":
            return
        if self.lstrip_next:
            self.lstrip_next = False
            text = _lstrip(text)
            if text == "":
                return
        self.items.append(TemplateLiteral(text, rng))

    def rstrip_previous(self) -> None:
        last = self.items[-1] if self.items else None
        if isinstance(last, TemplateLiteral):
            self.items.pop()
            text = _rstrip(last.text)
            if text != "":
                self.items.append(TemplateLiteral(text, last.range))

    def add(self, part: TemplatePart) -> None:
        self.lstrip_next = False
        self.items.append(part)

    def finish(self) -> tuple[TemplatePart, ...]:
        merged: list[TemplatePart] = []
        for part in self.items:
            previous = merged[-1] if merged else None
            if isinstance(part, TemplateLiteral) and isinstance(previous, TemplateLiteral):
                merged.pop()
                end = part.range
                merged.append(
                    TemplateLiteral(
                        previous.text + part.text,
                        SourceRange(
                            previous.range.file,
                            previous.range.start_line,
                            previous.range.start_column,
                            end.end_line,
                            end.end_column,
                            previous.range.start_byte,
                            end.end_byte,
                        ),
                    )
                )
            else:
                merged.append(part)
        return tuple(merged)


class _Parser:
    def __init__(self, text: str, filename: str) -> None:
        self._text = text
        self._smap = SourceMap(text, filename)
        self._lexer = Lexer(text, filename, self._smap)
        self._buffer: deque[Token] = deque()
        self._ignore_newlines: list[bool] = [False]
        self._depth = 0
        self._last_end = 0

    # -- token plumbing ----------------------------------------------------------------------

    def _fill(self, index: int) -> None:
        while len(self._buffer) <= index:
            self._buffer.append(self._lexer.next_token())

    def _peek(self, k: int = 0) -> Token:
        """The k-th upcoming token, skipping newlines where they are not significant."""
        ignore = self._ignore_newlines[-1]
        index = 0
        seen = 0
        while True:
            self._fill(index)
            token = self._buffer[index]
            if ignore and token.kind is T.NEWLINE:
                index += 1
                continue
            if seen == k or token.kind is T.EOF:
                return token
            seen += 1
            index += 1

    def _next(self) -> Token:
        if self._ignore_newlines[-1]:
            while True:
                self._fill(0)
                if self._buffer[0].kind is T.NEWLINE:
                    self._buffer.popleft()
                else:
                    break
        self._fill(0)
        token = self._buffer.popleft()
        self._last_end = token.end
        return token

    def _push_newlines(self, ignore: bool) -> None:
        self._ignore_newlines.append(ignore)

    def _pop_newlines(self) -> None:
        self._ignore_newlines.pop()

    def _range(self, start: int, end: int | None = None) -> SourceRange:
        return self._smap.range(start, self._last_end if end is None else end)

    def _error(self, code: str, token: Token, message: str) -> HclSyntaxError:
        return HclSyntaxError(code, self._smap.range(token.start, token.end), message)

    def _describe(self, token: Token) -> str:
        if token.kind is T.EOF:
            return "the end of the file"
        if token.kind is T.NEWLINE:
            return "a line break"
        if token.kind is T.IDENT:
            return f"identifier {token.value!r}"
        if token.kind is T.NUMBER:
            return f"number {token.value}"
        return self._text[token.start : token.end] or token.kind.name

    def _enter(self, token: Token) -> None:
        self._depth += 1
        if self._depth > MAX_NESTING_DEPTH:
            raise HclLimitError(
                "limit.nesting_depth",
                self._smap.range(token.start, token.end),
                f"nesting is deeper than {MAX_NESTING_DEPTH}",
            )

    def _leave(self) -> None:
        self._depth -= 1

    def _expect(self, kind: T, code: str, what: str) -> Token:
        token = self._peek()
        if token.kind is not kind:
            raise self._error(code, token, f"expected {what}, found {self._describe(token)}")
        return self._next()

    def _is_keyword(self, token: Token, word: str) -> bool:
        return token.kind is T.IDENT and token.value == word

    def _close(self, kind: T, opener: Token, code: str, what: str) -> Token:
        """Consume the closing delimiter of a construct, then leave its newline context."""
        token = self._peek()
        if token.kind is T.EOF:
            raise self._error(
                "parse.unclosed_bracket",
                opener,
                f"{self._text[opener.start : opener.end]} is not closed before the end of the file",
            )
        if token.kind is not kind:
            raise self._error(code, token, f"expected {what}, found {self._describe(token)}")
        closing = self._next()
        self._pop_newlines()
        return closing

    # -- structure ---------------------------------------------------------------------------

    def parse(self) -> Body:
        items = self._parse_body(None)
        return Body(tuple(items), self._smap.range(0, len(self._text)))

    def _parse_body(self, opener: Token | None) -> list[Attribute | Block]:
        """Body = (Attribute | Block | OneLineBlock)* (lines 159-165)."""
        items: list[Attribute | Block] = []
        while True:
            token = self._peek()
            if token.kind is T.NEWLINE:
                self._next()
                continue
            if token.kind is T.EOF:
                if opener is not None:
                    raise self._error(
                        "parse.unclosed_block",
                        opener,
                        "block is not closed before the end of the file",
                    )
                return items
            if token.kind is T.CBRACE:
                if opener is None:
                    raise self._error("parse.unexpected_token", token, "unmatched }")
                return items
            if token.kind is not T.IDENT:
                raise self._error(
                    "parse.expected_argument_or_block",
                    token,
                    f"expected an argument or block definition, found {self._describe(token)}",
                )
            items.append(self._parse_item())

    def _parse_item(self) -> Attribute | Block:
        name = self._next()
        following = self._peek()
        if following.kind is T.EQ:
            return self._parse_attribute(name)
        return self._parse_block(name)

    def _end_of_line(self, code: str, what: str) -> None:
        token = self._peek()
        if token.kind is T.NEWLINE:
            self._next()
        elif token.kind is not T.EOF:
            raise self._error(
                code, token, f"{what} must end with a line break, found {self._describe(token)}"
            )

    def _parse_attribute(self, name: Token) -> Attribute:
        """Attribute = Identifier "=" Expression Newline."""
        self._next()  # "="
        expr = self._parse_expression()
        end = self._last_end
        self._end_of_line("parse.missing_newline_after_argument", "an argument definition")
        return Attribute(
            name.value,
            expr,
            self._smap.range(name.start, name.end),
            self._smap.range(name.start, end),
        )

    def _parse_block(self, type_token: Token) -> Block:
        """Block and OneLineBlock (lines 163-164)."""
        labels: list[Label] = []
        while True:
            token = self._peek()
            if token.kind is T.OBRACE:
                break
            if token.kind is T.IDENT:
                self._next()
                labels.append(Label(token.value, False, self._smap.range(token.start, token.end)))
            elif token.kind is T.OQUOTE:
                labels.append(self._parse_string_label())
            else:
                raise self._error(
                    "parse.invalid_block_definition",
                    token,
                    "a block definition must have block content delimited by { and }, starting "
                    f"on the same line as its header; found {self._describe(token)}",
                )
        opener = self._next()
        first = self._peek()
        if first.kind is T.NEWLINE:
            self._next()
            self._enter(opener)
            items = self._parse_body(opener)
            self._leave()
            self._next()  # "}"
            one_line = False
        else:
            items = self._parse_one_line_body(opener)
            one_line = True
        end = self._last_end
        self._end_of_line("parse.missing_newline_after_block", "a block definition")
        body_range = self._smap.range(opener.start, end)
        return Block(
            type_token.value,
            tuple(labels),
            Body(tuple(items), body_range),
            one_line,
            self._smap.range(type_token.start, type_token.end),
            self._smap.range(type_token.start, end),
        )

    def _parse_one_line_body(self, opener: Token) -> list[Attribute | Block]:
        """The part of OneLineBlock after "{": (Identifier "=" Expression)? "}"."""
        token = self._peek()
        if token.kind is T.CBRACE:
            self._next()
            return []
        if token.kind is T.IDENT and self._peek(1).kind is T.EQ:
            name = self._next()
            self._next()  # "="
            expr = self._parse_expression()
            end = self._last_end
            closing = self._peek()
            if closing.kind is not T.CBRACE:
                raise self._error(
                    "parse.single_line_block",
                    closing,
                    "a one-line block holds one argument and must be closed on the same line; "
                    f"found {self._describe(closing)}",
                )
            self._next()
            return [
                Attribute(
                    name.value,
                    expr,
                    self._smap.range(name.start, name.end),
                    self._smap.range(name.start, end),
                )
            ]
        if token.kind is T.EOF:
            raise self._error("parse.unclosed_block", opener, "block is not closed")
        raise self._error(
            "parse.single_line_block",
            token,
            "a one-line block can hold only a single argument definition; found "
            f"{self._describe(token)}",
        )

    def _parse_string_label(self) -> Label:
        """A quoted block label is a StringLit: no interpolation and no directive (line 369)."""
        opener = self._next()
        pieces: list[str] = []
        while True:
            token = self._next()
            if token.kind is T.TPL_LITERAL:
                pieces.append(token.value)
            elif token.kind is T.CQUOTE:
                return Label("".join(pieces), True, self._smap.range(opener.start, token.end))
            else:
                raise self._error(
                    "parse.template_in_label",
                    token,
                    "template sequences are not allowed in a block label; to write a literal "
                    '"$" or "%", double it ($${ or %%{)',
                )

    # -- expressions -------------------------------------------------------------------------

    def _parse_expression(self) -> Expression:
        """Expression = ExprTerm | Operation | Conditional (lines 199-205)."""
        start = self._peek().start
        condition = self._parse_binary(1)
        if self._peek().kind is not T.QUESTION:
            return condition
        question = self._next()
        self._enter(question)
        true_expr = self._parse_expression()
        colon = self._peek()
        if colon.kind is not T.COLON:
            raise self._error(
                "parse.missing_conditional_colon",
                colon,
                "the conditional operator requires a false expression after a colon; found "
                f"{self._describe(colon)}",
            )
        self._next()
        false_expr = self._parse_expression()
        self._leave()
        return Conditional(condition, true_expr, false_expr, self._range(start))

    def _parse_binary(self, min_level: int) -> Expression:
        start = self._peek().start
        left = self._parse_unary()
        links = 0
        while True:
            token = self._peek()
            entry = _BINARY.get(token.kind)
            if entry is None or entry[1] < min_level:
                self._depth -= links
                return left
            self._next()
            # Every operator of a left-associative chain deepens the tree by one level, so a
            # chain counts toward the nesting limit (C-93) like any other nesting.
            self._enter(token)
            links += 1
            right = self._parse_binary(entry[1] + 1)
            left = BinaryOp(entry[0], left, right, self._range(start))

    def _parse_unary(self) -> Expression:
        token = self._peek()
        if token.kind is T.MINUS or token.kind is T.BANG:
            self._next()
            self._enter(token)
            operand = self._parse_unary()
            self._leave()
            op = UnaryOperator.NEG if token.kind is T.MINUS else UnaryOperator.NOT
            return UnaryOp(op, operand, self._range(token.start))
        return self._parse_postfix()

    def _parse_postfix(self) -> Expression:
        """ExprTerm Index | ExprTerm GetAttr | ExprTerm Splat (lines 221-233).

        Attribute accesses and constant indexes directly after a variable are collected into one
        ``ScopeTraversal`` (a flat list, so a long chain is cheap); any other postfix operation
        wraps the expression built so far and counts toward the nesting limit.
        """
        start = self._peek().start
        expr = self._parse_term()
        base = expr if isinstance(expr, ScopeTraversal) else None
        pending: list[TraversalStep] = []
        pending_end = self._last_end
        links = 0
        while True:
            token = self._peek()
            step: TraversalStep
            if token.kind is T.DOT:
                following = self._peek(1)
                if following.kind is T.IDENT:
                    self._next()
                    name = self._next()
                    step = AttrStep(name.value, self._smap.range(name.start, name.end))
                elif following.kind is T.NUMBER:
                    self._next()
                    step = self._legacy_step(self._next())
                elif following.kind is T.STAR:
                    self._next()
                    self._next()
                    expr = self._close_traversal(base, pending, pending_end, start, expr)
                    base, pending = None, []
                    self._enter(token)
                    links += 1
                    expr = self._parse_attribute_splat(expr, start)
                    continue
                else:
                    self._next()
                    raise self._error(
                        "parse.invalid_attribute_name",
                        following,
                        "an attribute name is required after a dot; found "
                        f"{self._describe(following)}",
                    )
            elif token.kind is T.OBRACKET:
                if self._peek(1).kind is T.STAR and self._peek(2).kind is T.CBRACKET:
                    self._next()
                    self._next()
                    self._next()
                    expr = self._close_traversal(base, pending, pending_end, start, expr)
                    base, pending = None, []
                    self._enter(token)
                    links += 1
                    expr = self._parse_full_splat(expr, start)
                    continue
                step = self._parse_index_step()
            else:
                break
            if base is not None and _is_constant_step(step):
                pending.append(step)
                pending_end = self._last_end
                continue
            expr = self._close_traversal(base, pending, pending_end, start, expr)
            base, pending = None, []
            self._enter(token)
            links += 1
            expr = self._wrap(expr, step, start)
        expr = self._close_traversal(base, pending, pending_end, start, expr)
        self._depth -= links
        return expr

    def _close_traversal(
        self,
        base: ScopeTraversal | None,
        pending: list[TraversalStep],
        end: int,
        start: int,
        expr: Expression,
    ) -> Expression:
        """The expression so far, with the collected steps folded into one ``ScopeTraversal``."""
        if base is not None and pending:
            return ScopeTraversal(base.root, (*base.steps, *pending), self._smap.range(start, end))
        return expr

    def _wrap(self, expr: Expression, step: TraversalStep, start: int) -> Expression:
        rng = self._range(start)
        if isinstance(step, AttrStep):
            return GetAttr(expr, step.name, rng)
        if isinstance(step, LegacyIndexStep):
            key = Literal(LiteralKind.NUMBER, step.index, str(step.index), step.range)
            return Index(expr, key, True, rng)
        return Index(expr, step.key, False, rng)

    def _legacy_step(self, number: Token) -> LegacyIndexStep:
        """LegacyIndex = '.' digit+ (lines 547-561); ``foo.0.0`` lexes as a number literal."""
        if not (number.value.isascii() and number.value.isdigit()):
            raise self._error(
                "parse.invalid_legacy_index",
                number,
                f"the legacy index syntax needs a plain integer, found {number.value}; "
                "chaining two legacy indexes is not permitted",
            )
        return LegacyIndexStep(int(number.value), self._smap.range(number.start, number.end))

    def _parse_index_step(self) -> IndexStep:
        """Index = "[" Expression "]" (lines 518-520)."""
        opener = self._next()
        self._enter(opener)
        self._push_newlines(True)
        key = self._parse_expression()
        closing = self._close(T.CBRACKET, opener, "parse.unclosed_bracket", "a closing ]")
        self._leave()
        return IndexStep(key, self._smap.range(opener.start, closing.end))

    def _parse_attribute_splat(self, source: Expression, start: int) -> Expression:
        """attrSplat = "." "*" GetAttr* (line 596)."""
        steps: list[TraversalStep] = []
        while self._peek().kind is T.DOT:
            following = self._peek(1)
            if following.kind is T.IDENT:
                self._next()
                name = self._next()
                steps.append(AttrStep(name.value, self._smap.range(name.start, name.end)))
            elif following.kind is T.STAR:
                self._next()
                raise self._error(
                    "parse.nested_splat",
                    self._next(),
                    "a splat cannot be used inside another attribute-only splat",
                )
            else:
                break
        return Splat(source, SplatKind.ATTRIBUTE, tuple(steps), self._range(start))

    def _parse_full_splat(self, source: Expression, start: int) -> Expression:
        """fullSplat = "[" "*" "]" (GetAttr | Index)* (line 597)."""
        steps: list[TraversalStep] = []
        while True:
            token = self._peek()
            if token.kind is T.DOT:
                following = self._peek(1)
                if following.kind is T.IDENT:
                    self._next()
                    name = self._next()
                    steps.append(AttrStep(name.value, self._smap.range(name.start, name.end)))
                elif following.kind is T.NUMBER:
                    self._next()
                    steps.append(self._legacy_step(self._next()))
                else:
                    break
            elif token.kind is T.OBRACKET and not (
                self._peek(1).kind is T.STAR and self._peek(2).kind is T.CBRACKET
            ):
                steps.append(self._parse_index_step())
            else:
                break
        return Splat(source, SplatKind.FULL, tuple(steps), self._range(start))

    def _parse_term(self) -> Expression:
        token = self._peek()
        kind = token.kind
        if kind is T.NUMBER:
            self._next()
            value = number_value(token.value)
            if value is None:
                raise HclLimitError(
                    "limit.number_range",
                    self._smap.range(token.start, token.end),
                    "the exponent of this number literal is out of range",
                )
            return Literal(LiteralKind.NUMBER, value, token.value, self._range(token.start))
        if kind is T.IDENT:
            return self._parse_identifier_term(token)
        if kind is T.OQUOTE:
            return self._parse_quoted_template()
        if kind is T.HEREDOC_OPEN:
            return self._parse_heredoc()
        if kind is T.OBRACKET:
            return self._parse_tuple_or_for()
        if kind is T.OBRACE:
            return self._parse_object_or_for()
        if kind is T.OPAREN:
            return self._parse_parenthesized()
        raise self._error(
            "parse.expected_expression",
            token,
            f"expected the start of an expression, found {self._describe(token)}",
        )

    def _parse_identifier_term(self, token: Token) -> Expression:
        following = self._peek(1)
        if following.kind is T.OPAREN or following.kind is T.DCOLON:
            return self._parse_function_call()
        self._next()
        rng = self._range(token.start)
        if token.value == "true" or token.value == "false":
            return Literal(LiteralKind.BOOL, token.value == "true", token.value, rng)
        if token.value == "null":
            return Literal(LiteralKind.NULL, None, token.value, rng)
        return ScopeTraversal(token.value, (), rng)

    def _parse_function_call(self) -> Expression:
        """FunctionCall = Identifier "(" arguments ")" (lines 411-417).

        A name may be namespaced with ``::`` (``provider::p::f``); the specification does not
        mention it but Terraform 1.15.8 accepts it (C-95).
        """
        first = self._next()
        name = first.value
        while self._peek().kind is T.DCOLON:
            self._next()
            part = self._peek()
            if part.kind is not T.IDENT:
                raise self._error(
                    "parse.invalid_function_name",
                    part,
                    "a :: in a function name must be followed by a name; found "
                    f"{self._describe(part)}",
                )
            self._next()
            name += "::" + part.value
        opener = self._peek()
        if opener.kind is not T.OPAREN:
            raise self._error(
                "parse.invalid_function_name",
                opener,
                f"a namespaced name must be a function call; found {self._describe(opener)}",
            )
        self._next()
        self._enter(opener)
        self._push_newlines(True)
        args: list[Expression] = []
        expand = False
        if self._peek().kind is not T.CPAREN:
            while True:
                args.append(self._parse_expression())
                token = self._peek()
                if token.kind is T.ELLIPSIS:
                    self._next()
                    expand = True
                    after = self._peek()
                    if after.kind is not T.CPAREN and after.kind is not T.EOF:
                        raise self._error(
                            "parse.expand_not_last",
                            after,
                            "an expanded function argument (with ...) must be immediately "
                            "followed by the closing parenthesis",
                        )
                    break
                if token.kind is T.COMMA:
                    self._next()
                    if self._peek().kind is T.CPAREN:
                        break
                    continue
                if token.kind is T.CPAREN or token.kind is T.EOF:
                    break
                raise self._error(
                    "parse.missing_argument_separator",
                    token,
                    "a comma is required to separate each function argument from the next; "
                    f"found {self._describe(token)}",
                )
        self._close(T.CPAREN, opener, "parse.unclosed_bracket", "a closing )")
        self._leave()
        return FunctionCall(name, tuple(args), expand, self._range(first.start))

    def _parse_parenthesized(self) -> Expression:
        opener = self._next()
        self._enter(opener)
        self._push_newlines(True)
        expr = self._parse_expression()
        self._close(T.CPAREN, opener, "parse.unclosed_bracket", "a closing )")
        self._leave()
        return Parenthesized(expr, self._range(opener.start))

    # -- collections and for expressions -----------------------------------------------------

    def _parse_tuple_or_for(self) -> Expression:
        """tuple = "[" ((Expression (("," | Newline) Expression)* ","?)?) "]" (lines 270-272).

        Newlines are ignored inside the brackets (lines 292-293), so items need commas; the
        grammar's "Newline" alternative is overruled by the prose ("prose has priority", line 49;
        Terraform 1.15.8 rejects ``[1\\n2]``).
        """
        opener = self._next()
        self._enter(opener)
        self._push_newlines(True)
        if self._is_keyword(self._peek(), "for"):
            expr = self._parse_for(opener, ForKind.TUPLE)
            self._leave()
            return expr
        elements: list[Expression] = []
        while self._peek().kind is not T.CBRACKET:
            if self._peek().kind is T.EOF:
                break
            elements.append(self._parse_expression())
            token = self._peek()
            if token.kind is T.COMMA:
                self._next()
            elif token.kind is not T.CBRACKET and token.kind is not T.EOF:
                raise self._error(
                    "parse.missing_item_separator",
                    token,
                    "expected a comma to mark the beginning of the next item; found "
                    f"{self._describe(token)}",
                )
        self._close(T.CBRACKET, opener, "parse.missing_item_separator", "a closing ]")
        self._leave()
        return Tuple(tuple(elements), self._range(opener.start))

    def _parse_object_or_for(self) -> Expression:
        """object = "{" ((objectelem (("," | Newline) objectelem)* ","?)?) "}" (lines 273-276)."""
        opener = self._next()
        self._enter(opener)
        self._push_newlines(True)  # to look past line breaks for the keyword "for"
        if self._is_keyword(self._peek(), "for"):
            expr = self._parse_for(opener, ForKind.OBJECT)
            self._leave()
            return expr
        self._pop_newlines()
        self._push_newlines(False)  # in an object a line break separates items
        items: list[ObjectItem] = []
        while True:
            token = self._peek()
            if token.kind is T.NEWLINE:
                self._next()
                continue
            if token.kind is T.CBRACE or token.kind is T.EOF:
                break
            items.append(self._parse_object_item())
            after = self._peek()
            if after.kind is T.COMMA or after.kind is T.NEWLINE:
                self._next()
            elif after.kind is not T.CBRACE and after.kind is not T.EOF:
                raise self._error(
                    "parse.missing_attribute_separator",
                    after,
                    "expected a line break or a comma to mark the beginning of the next "
                    f"attribute; found {self._describe(after)}",
                )
        self._close(T.CBRACE, opener, "parse.missing_attribute_separator", "a closing }")
        self._leave()
        return Object(tuple(items), self._range(opener.start))

    def _parse_object_item(self) -> ObjectItem:
        """objectelem = (Identifier | Expression) ("=" | ":") Expression (line 276).

        A lone identifier before the separator is a literal attribute name, not a variable
        (lines 284-290); anything else is an expression (``(a)``, ``"a"``, ``a.b``, ``1``).
        """
        start_token = self._peek()
        key: IdentifierKey | Expression
        if start_token.kind is T.IDENT and self._peek(1).kind in (T.EQ, T.COLON):
            self._next()
            key = IdentifierKey(
                start_token.value, self._smap.range(start_token.start, start_token.end)
            )
        else:
            key = self._parse_expression()
        separator = self._peek()
        if separator.kind is not T.EQ and separator.kind is not T.COLON:
            raise self._error(
                "parse.missing_attribute_value",
                separator,
                'expected an attribute value, introduced by an equals sign ("=") or a colon; '
                f"found {self._describe(separator)}",
            )
        self._next()
        value = self._parse_expression()
        return ObjectItem(key, value, self._range(start_token.start))

    def _parse_for(self, opener: Token, kind: ForKind) -> Expression:
        """ForExpr (lines 438-444); the opening bracket is consumed and newlines are ignored.

        forIntro = "for" Identifier ("," Identifier)? "in" Expression ":"
        """
        self._next()  # "for"
        first = self._peek()
        if first.kind is not T.IDENT:
            raise self._error(
                "parse.invalid_for",
                first,
                "a for expression requires a variable name after 'for'; found "
                f"{self._describe(first)}",
            )
        self._next()
        key_var: str | None = None
        value_var = first.value
        if self._peek().kind is T.COMMA:
            self._next()
            second = self._peek()
            if second.kind is not T.IDENT:
                raise self._error(
                    "parse.invalid_for",
                    second,
                    f"expected a second variable name; found {self._describe(second)}",
                )
            self._next()
            key_var, value_var = first.value, second.value
        keyword = self._peek()
        if not self._is_keyword(keyword, "in"):
            raise self._error(
                "parse.invalid_for",
                keyword,
                "a for expression requires the 'in' keyword after its variable names; found "
                f"{self._describe(keyword)}",
            )
        self._next()
        collection = self._parse_expression()
        colon = self._peek()
        if colon.kind is not T.COLON:
            raise self._error(
                "parse.invalid_for",
                colon,
                "a for expression requires a colon after the collection expression; found "
                f"{self._describe(colon)}",
            )
        self._next()
        key_expr: Expression | None = None
        group = False
        if kind is ForKind.OBJECT:
            key_expr = self._parse_expression()
            arrow = self._peek()
            if arrow.kind is not T.ARROW:
                raise self._error(
                    "parse.invalid_for",
                    arrow,
                    "a key expression is required when building an object: expected =>; "
                    f"found {self._describe(arrow)}",
                )
            self._next()
        value_expr = self._parse_expression()
        after = self._peek()
        if after.kind is T.ELLIPSIS:
            if kind is ForKind.TUPLE:
                raise self._error(
                    "parse.invalid_for",
                    after,
                    "the grouping ellipsis cannot be used to build a tuple",
                )
            self._next()
            group = True
        elif after.kind is T.ARROW and kind is ForKind.TUPLE:
            raise self._error(
                "parse.invalid_for", after, "a key expression is not valid when building a tuple"
            )
        condition: Expression | None = None
        if self._is_keyword(self._peek(), "if"):
            self._next()
            condition = self._parse_expression()
        closer = T.CBRACKET if kind is ForKind.TUPLE else T.CBRACE
        self._close(closer, opener, "parse.invalid_for", "the end of the for expression")
        return ForExpr(
            kind,
            key_var,
            value_var,
            collection,
            key_expr,
            value_expr,
            condition,
            group,
            self._range(opener.start),
        )

    # -- templates ---------------------------------------------------------------------------

    def _parse_quoted_template(self) -> Expression:
        """quotedTemplate; a template with only literal text is a string Literal (lines 361-367)."""
        opener = self._next()
        builder = _PartsBuilder()
        self._parse_parts(builder)
        closing = self._peek()
        if closing.kind is T.CQUOTE:
            self._next()
        else:
            raise self._unbalanced(closing)
        parts = builder.finish()
        rng = self._range(opener.start)
        if not parts:
            return Literal(LiteralKind.STRING, "", self._text[opener.start : closing.end], rng)
        if len(parts) == 1 and isinstance(parts[0], TemplateLiteral):
            return Literal(
                LiteralKind.STRING, parts[0].text, self._text[opener.start : closing.end], rng
            )
        return Template(parts, rng)

    def _parse_heredoc(self) -> Expression:
        opener = self._next()
        builder = _PartsBuilder()
        self._parse_parts(builder)
        closing = self._peek()
        if closing.kind is T.HEREDOC_CLOSE:
            self._next()
        else:
            raise self._unbalanced(closing)
        return Heredoc(opener.value, opener.flag == 1, builder.finish(), self._range(opener.start))

    def _unbalanced(self, token: Token) -> HclSyntaxError:
        if token.kind is T.TPL_CONTROL_OPEN:
            keyword = self._peek(1)
            return self._error(
                "parse.unbalanced_directive",
                token,
                f"unexpected {keyword.value!r} directive: the control directives within this "
                "template are unbalanced",
            )
        return self._error(
            "parse.unexpected_token", token, f"unexpected {self._describe(token)} in a template"
        )

    def _parse_parts(self, builder: _PartsBuilder) -> None:
        """Parse template parts until the end of the template or an else/endif/endfor tag."""
        while True:
            token = self._peek()
            kind = token.kind
            if kind is T.TPL_LITERAL:
                self._next()
                builder.literal(token.value, self._smap.range(token.start, token.end))
            elif kind is T.TPL_INTERP_OPEN:
                self._parse_interpolation(builder)
            elif kind is T.TPL_CONTROL_OPEN:
                keyword = self._peek(1)
                if keyword.kind is not T.IDENT:
                    raise self._error(
                        "parse.invalid_template_directive",
                        keyword,
                        f"expected a template directive keyword; found {self._describe(keyword)}",
                    )
                if keyword.value == "if":
                    self._parse_if(builder)
                elif keyword.value == "for":
                    self._parse_template_for(builder)
                elif keyword.value in ("else", "endif", "endfor"):
                    return
                else:
                    raise self._error(
                        "parse.invalid_template_directive",
                        keyword,
                        f"{keyword.value!r} is not a valid template control keyword",
                    )
            else:
                return

    def _parse_interpolation(self, builder: _PartsBuilder) -> None:
        """TemplateInterpolation = ("${" | "${~") Expression ("}" | "~}") (line 820)."""
        opener = self._next()
        if opener.flag:
            builder.rstrip_previous()
        self._enter(opener)
        self._push_newlines(True)
        expr = self._parse_expression()
        closing = self._close(
            T.TPL_SEQ_CLOSE,
            opener,
            "parse.invalid_template_directive",
            "the end of the interpolation",
        )
        self._leave()
        builder.add(
            TemplateInterpolation(
                expr,
                Strip(bool(opener.flag), bool(closing.flag)),
                self._range(opener.start),
            )
        )
        builder.lstrip_next = bool(closing.flag)

    def _open_directive(self) -> Token:
        """Consume ``%{`` and the keyword that follows (checked by the caller)."""
        opener = self._next()
        self._next()
        return opener

    def _bare_tag_close(self, opener: Token, word: str) -> Token:
        """The ``}`` of a tag that takes no expression (``%{ else }``, ``%{ endif }``)."""
        self._push_newlines(True)
        token = self._peek()
        if token.kind is not T.TPL_SEQ_CLOSE:
            raise self._error(
                "parse.invalid_template_directive",
                token,
                f"the {word} directive takes no arguments; found {self._describe(token)}",
            )
        return self._close(
            T.TPL_SEQ_CLOSE, opener, "parse.invalid_template_directive", f"the end of {word}"
        )

    def _parse_if(self, outer: _PartsBuilder) -> None:
        """TemplateIf (lines 833-841)."""
        opener = self._open_directive()
        if opener.flag:
            outer.rstrip_previous()
        self._enter(opener)
        self._push_newlines(True)
        condition = self._parse_expression()
        close_if = self._close(
            T.TPL_SEQ_CLOSE,
            opener,
            "parse.invalid_template_directive",
            "the end of the if directive",
        )
        true_builder = _PartsBuilder()
        true_builder.lstrip_next = bool(close_if.flag)
        self._parse_parts(true_builder)
        tag = self._peek()
        keyword = self._peek(1)
        strip_else: Strip | None = None
        false_builder: _PartsBuilder | None = None
        if tag.kind is T.TPL_CONTROL_OPEN and keyword.value == "else":
            else_open = self._open_directive()
            if else_open.flag:
                true_builder.rstrip_previous()
            close_else = self._bare_tag_close(else_open, "else")
            strip_else = Strip(bool(else_open.flag), bool(close_else.flag))
            false_builder = _PartsBuilder()
            false_builder.lstrip_next = bool(close_else.flag)
            self._parse_parts(false_builder)
            tag = self._peek()
            keyword = self._peek(1)
        if not (tag.kind is T.TPL_CONTROL_OPEN and keyword.value == "endif"):
            raise self._error(
                "parse.unbalanced_directive",
                tag if tag.kind is not T.EOF else opener,
                "an if directive needs a matching endif",
            )
        end_open = self._open_directive()
        if end_open.flag:
            (false_builder or true_builder).rstrip_previous()
        close_end = self._bare_tag_close(end_open, "endif")
        self._leave()
        outer.add(
            TemplateIf(
                condition,
                true_builder.finish(),
                None if false_builder is None else false_builder.finish(),
                Strip(bool(opener.flag), bool(close_if.flag)),
                strip_else,
                Strip(bool(end_open.flag), bool(close_end.flag)),
                self._range(opener.start),
            )
        )
        outer.lstrip_next = bool(close_end.flag)

    def _parse_template_for(self, outer: _PartsBuilder) -> None:
        """TemplateFor (lines 859-863); the second variable is optional, as in a for expression
        (the grammar line omits the "?", Terraform 1.15.8 accepts one variable; C-95)."""
        opener = self._open_directive()
        if opener.flag:
            outer.rstrip_previous()
        self._enter(opener)
        self._push_newlines(True)
        first = self._peek()
        if first.kind is not T.IDENT:
            raise self._error(
                "parse.invalid_template_directive",
                first,
                f"a for directive requires a variable name; found {self._describe(first)}",
            )
        self._next()
        key_var: str | None = None
        value_var = first.value
        if self._peek().kind is T.COMMA:
            self._next()
            second = self._peek()
            if second.kind is not T.IDENT:
                raise self._error(
                    "parse.invalid_template_directive",
                    second,
                    f"expected a second variable name; found {self._describe(second)}",
                )
            self._next()
            key_var, value_var = first.value, second.value
        keyword = self._peek()
        if not self._is_keyword(keyword, "in"):
            raise self._error(
                "parse.invalid_template_directive",
                keyword,
                f"a for directive requires the 'in' keyword; found {self._describe(keyword)}",
            )
        self._next()
        collection = self._parse_expression()
        close_for = self._close(
            T.TPL_SEQ_CLOSE,
            opener,
            "parse.invalid_template_directive",
            "the end of the for directive",
        )
        body = _PartsBuilder()
        body.lstrip_next = bool(close_for.flag)
        self._parse_parts(body)
        tag = self._peek()
        keyword = self._peek(1)
        if not (tag.kind is T.TPL_CONTROL_OPEN and keyword.value == "endfor"):
            raise self._error(
                "parse.unbalanced_directive",
                tag if tag.kind is not T.EOF else opener,
                "a for directive needs a matching endfor",
            )
        end_open = self._open_directive()
        if end_open.flag:
            body.rstrip_previous()
        close_end = self._bare_tag_close(end_open, "endfor")
        self._leave()
        outer.add(
            TemplateFor(
                key_var,
                value_var,
                collection,
                body.finish(),
                Strip(bool(opener.flag), bool(close_for.flag)),
                Strip(bool(end_open.flag), bool(close_end.flag)),
                self._range(opener.start),
            )
        )
        outer.lstrip_next = bool(close_end.flag)


def parse_file(text: str, filename: str) -> Body:
    """Parse the text of one configuration file into an immutable syntax tree.

    Pure and deterministic; no I/O. Raises ``HclSyntaxError`` when ``text`` is not valid HCL and
    ``HclLimitError`` when it exceeds the nesting limit (C-93). Never raises ``RecursionError``.
    """
    return _Parser(text, filename).parse()
