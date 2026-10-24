"""Lexer for the HCL native syntax (Doc 04 §4; C-91, C-93).

Grammar source: ``hclsyntax/spec.md`` of ``hashicorp/hcl`` at tag ``v2.25.0``
(commit 00057cf06d7b38a3f89e6e54d622eee98322b314); see ADR-003. Section names below are the
headings of that file.

The lexer is a hand-written state machine over a stack of frames (the top-level body, a ``{``
in an expression, a template sequence ``${ }`` / ``%{ }``, a quoted template and a heredoc), so
it knows which text is a template literal and which is an expression, and which ``}`` closes an
interpolation. It is lazy: the parser pulls one token at a time. Newlines are tokens; the parser
decides where they are significant.

Behaviours that the specification leaves open and that were settled against the reference
behaviour of Terraform 1.15.8 (``terraform validate`` / ``terraform console`` on scratch files)
are listed in the register row C-95 and marked "C-95" below.

Not done here: evaluation, normalization (P3a-2), and no regular expressions.
"""

from __future__ import annotations

import enum
import unicodedata
from array import array
from bisect import bisect_right
from collections import deque

from core.terraform_model.hcl.ast import SourceRange
from core.terraform_model.hcl.errors import HclLimitError, HclSyntaxError


class T(enum.Enum):
    """Token kinds."""

    EOF = enum.auto()
    NEWLINE = enum.auto()
    IDENT = enum.auto()
    NUMBER = enum.auto()
    PLUS = enum.auto()
    MINUS = enum.auto()
    STAR = enum.auto()
    SLASH = enum.auto()
    PERCENT = enum.auto()
    BANG = enum.auto()
    LT = enum.auto()
    GT = enum.auto()
    LE = enum.auto()
    GE = enum.auto()
    EQEQ = enum.auto()
    NE = enum.auto()
    AND = enum.auto()
    OR = enum.auto()
    QUESTION = enum.auto()
    COLON = enum.auto()
    DCOLON = enum.auto()
    COMMA = enum.auto()
    DOT = enum.auto()
    ELLIPSIS = enum.auto()
    EQ = enum.auto()
    ARROW = enum.auto()
    OPAREN = enum.auto()
    CPAREN = enum.auto()
    OBRACKET = enum.auto()
    CBRACKET = enum.auto()
    OBRACE = enum.auto()
    CBRACE = enum.auto()
    OQUOTE = enum.auto()
    CQUOTE = enum.auto()
    HEREDOC_OPEN = enum.auto()
    HEREDOC_CLOSE = enum.auto()
    TPL_LITERAL = enum.auto()
    TPL_INTERP_OPEN = enum.auto()
    TPL_CONTROL_OPEN = enum.auto()
    TPL_SEQ_CLOSE = enum.auto()


# Values of ``Token.flag`` on a TPL_LITERAL token.
LIT_QUOTED = 0  # literal of a quoted template (or already processed)
LIT_HEREDOC = 1  # heredoc literal that does not start a line
LIT_HEREDOC_LINE = 2  # heredoc literal that starts a line


class Token:
    """One lexical token. ``start`` and ``end`` are character offsets (end exclusive).

    ``value`` is the identifier name, the number text, the cooked literal text or the heredoc
    marker. ``flag`` is the strip marker (``~``) of a template sequence token, the ``<<-`` flag of
    HEREDOC_OPEN, or the LIT_* value of a TPL_LITERAL.
    """

    __slots__ = ("end", "flag", "kind", "start", "value")

    def __init__(self, kind: T, start: int, end: int, value: str = "", flag: int = 0) -> None:
        self.kind = kind
        self.start = start
        self.end = end
        self.value = value
        self.flag = flag

    def __repr__(self) -> str:
        return f"Token({self.kind.name}, {self.start}:{self.end}, {self.value!r}, {self.flag})"


class SourceMap:
    """Converts character offsets of one text into ``SourceRange`` values."""

    def __init__(self, text: str, filename: str) -> None:
        self.text = text
        self.filename = filename
        starts = [0]
        pos = text.find("\n")
        while pos != -1:
            starts.append(pos + 1)
            pos = text.find("\n", pos + 1)
        self._starts = starts
        self._bytes: array[int] | None = None
        if not text.isascii():
            offsets: array[int] = array("Q")
            acc = 0
            for ch in text:
                offsets.append(acc)
                cp = ord(ch)
                acc += 1 if cp < 0x80 else 2 if cp < 0x800 else 3 if cp < 0x10000 else 4
            offsets.append(acc)
            self._bytes = offsets

    def _byte(self, offset: int) -> int:
        return offset if self._bytes is None else self._bytes[offset]

    def range(self, start: int, end: int) -> SourceRange:
        starts = self._starts
        start_line = bisect_right(starts, start) - 1
        end_line = bisect_right(starts, end) - 1
        return SourceRange(
            self.filename,
            start_line + 1,
            start - starts[start_line] + 1,
            end_line + 1,
            end - starts[end_line] + 1,
            self._byte(start),
            self._byte(end),
        )


# --- Identifiers (spec, "Identifiers"; UAX #31) ------------------------------------------------
#
# Identifier = ID_Start (ID_Continue | '-')*. Python 3.12 carries Unicode 15.0 tables. ID_Start is
# the categories L* and Nl plus Other_ID_Start; ID_Continue adds Mn, Mc, Nd, Pc and
# Other_ID_Continue. Terraform 1.15.8 also accepts a leading '_' (C-95), and the Terraform
# documentation ("Identifiers") only forbids a leading digit, so '_' starts an identifier here.
# A code point that Unicode 15.0 does not assign cannot be classified exactly (R2); it gives
# UNSUPPORTED (limit.unicode_table), never a silent acceptance.

_ID_START_CATEGORIES = frozenset({"Lu", "Ll", "Lt", "Lm", "Lo", "Nl"})
_ID_CONTINUE_CATEGORIES = frozenset({"Mn", "Mc", "Nd", "Pc"})
_OTHER_ID_START = frozenset({0x1885, 0x1886, 0x2118, 0x212E, 0x309B, 0x309C})
_OTHER_ID_CONTINUE = frozenset({0x00B7, 0x0387, 0x19DA, *range(0x1369, 0x1372)})
_ASCII_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_DIGITS = frozenset("0123456789")
_ASCII_ID_START = _ASCII_LETTERS | {"_"}
_ASCII_ID_CONTINUE = _ASCII_LETTERS | _DIGITS | {"_", "-"}
_HEX = frozenset("0123456789abcdefABCDEF")

UNICODE_VERSION = unicodedata.unidata_version


def is_id_start(ch: str) -> bool:
    if ch < "\x80":
        return ch in _ASCII_ID_START
    return unicodedata.category(ch) in _ID_START_CATEGORIES or ord(ch) in _OTHER_ID_START


def is_id_continue(ch: str) -> bool:
    if ch < "\x80":
        return ch in _ASCII_ID_CONTINUE
    cp = ord(ch)
    return (
        unicodedata.category(ch) in _ID_START_CATEGORIES | _ID_CONTINUE_CATEGORIES
        or cp in _OTHER_ID_START
        or cp in _OTHER_ID_CONTINUE
    )


def _is_noncharacter(cp: int) -> bool:
    return 0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE


# --- Frames ------------------------------------------------------------------------------------

_TOP = 0  # the file body
_BRACE = 1  # a '{' inside an expression or a block
_SEQ = 2  # an interpolation or directive: after '${' or '%{', until '}' or '~}'
_QUOTED = 3  # text of a quoted template
_HEREDOC = 4  # text of a heredoc


class _Frame:
    __slots__ = ("at_line_start", "buffered", "dash", "kind", "marker")

    def __init__(
        self, kind: int, marker: str = "", dash: bool = False, buffered: bool = False
    ) -> None:
        self.kind = kind
        self.marker = marker
        self.dash = dash
        self.buffered = buffered
        self.at_line_start = True


_SINGLE: dict[str, T] = {
    "+": T.PLUS,
    "-": T.MINUS,
    "*": T.STAR,
    "%": T.PERCENT,
    "?": T.QUESTION,
    ",": T.COMMA,
    "(": T.OPAREN,
    ")": T.CPAREN,
    "[": T.OBRACKET,
    "]": T.CBRACKET,
}

_QUOTED_SPECIAL = frozenset('"\\$%\n\r')
_HEREDOC_SPECIAL = frozenset("$%\n\r")
_SIMPLE_ESCAPES = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}


class Lexer:
    """Pulls tokens from ``text`` one at a time; after the last token it returns EOF forever."""

    def __init__(self, text: str, filename: str, smap: SourceMap | None = None) -> None:
        self.smap = smap if smap is not None else SourceMap(text, filename)
        self._text = text
        self._n = len(text)
        self._i = 0
        self._frames: list[_Frame] = [_Frame(_TOP)]
        self._queue: deque[Token] = deque()
        self._buffers: list[list[Token]] = []
        self._done = False
        try:
            text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise self._error(
                "lex.invalid_utf8", exc.start, exc.start + 1, "lone surrogate code point"
            ) from None

    # -- plumbing ----------------------------------------------------------------------------

    def _error(self, code: str, start: int, end: int, message: str) -> HclSyntaxError:
        return HclSyntaxError(code, self.smap.range(start, end), message)

    def _emit(self, token: Token) -> None:
        if self._buffers:
            self._buffers[-1].append(token)
        else:
            self._queue.append(token)

    def next_token(self) -> Token:
        while not self._queue:
            if self._done:
                return Token(T.EOF, self._n, self._n)
            self._step()
        return self._queue.popleft()

    # -- dispatch ----------------------------------------------------------------------------

    def _step(self) -> None:
        kind = self._frames[-1].kind
        if kind == _QUOTED:
            self._step_quoted()
        elif kind == _HEREDOC:
            self._step_heredoc()
        else:
            self._step_expression()

    def _at_end(self) -> None:
        """End of input: fine only when no template is open."""
        for frame in reversed(self._frames):
            if frame.kind == _HEREDOC:
                raise self._error(
                    "lex.unterminated_heredoc", self._n, self._n, "heredoc is not closed"
                )
            if frame.kind == _QUOTED:
                raise self._error(
                    "lex.unterminated_string", self._n, self._n, "quoted template is not closed"
                )
        self._queue.append(Token(T.EOF, self._n, self._n))
        self._done = True

    # -- expression mode ---------------------------------------------------------------------

    def _step_expression(self) -> None:
        text = self._text
        n = self._n
        i = self._i
        while i < n and (text[i] == " " or text[i] == "\t"):
            i += 1
        if i >= n:
            self._i = i
            self._at_end()
            return
        c = text[i]
        start = i
        if c == "\n":
            self._emit(Token(T.NEWLINE, i, i + 1))
            i += 1
        elif c == "\r":
            if text.startswith("\r\n", i):
                self._emit(Token(T.NEWLINE, i, i + 2))
                i += 2
            else:
                raise self._error(
                    "lex.invalid_character", i, i + 1, "a carriage return outside a line break"
                )
        elif c == "#" or (c == "/" and text.startswith("//", i)):
            # A line comment is equivalent to a newline sequence (spec, "Comments and
            # Whitespace"). At the end of the file the end of input plays that role.
            j = text.find("\n", i)
            if j == -1:
                i = n
            else:
                self._emit(Token(T.NEWLINE, j, j + 1))
                i = j + 1
        elif c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            if j == -1:
                raise self._error(
                    "lex.unterminated_comment", i, n, "inline comment is not closed by */"
                )
            i = j + 2  # an inline comment is equivalent to whitespace, even across lines
        elif c in _ASCII_ID_START or (c > "\x7f" and is_id_start(c)):
            i += 1
            while i < n:
                d = text[i]
                if d in _ASCII_ID_CONTINUE or (d > "\x7f" and is_id_continue(d)):
                    i += 1
                else:
                    break
            self._emit(Token(T.IDENT, start, i, text[start:i]))
        elif c in _DIGITS:
            i = self._scan_number(i)
            self._emit(Token(T.NUMBER, start, i, text[start:i]))
        elif c in _SINGLE:
            self._emit(Token(_SINGLE[c], i, i + 1))
            i += 1
        else:
            i = self._step_operator(c, i)
        self._i = i

    def _scan_number(self, i: int) -> int:
        """NumericLit = decimal+ ("." decimal+)? (expmark decimal+)? (spec, "Numeric Literals")."""
        text = self._text
        n = self._n
        while i < n and text[i] in _DIGITS:
            i += 1
        if i + 1 < n and text[i] == "." and text[i + 1] in _DIGITS:
            i += 1
            while i < n and text[i] in _DIGITS:
                i += 1
        if i < n and text[i] in "eE":
            k = i + 1
            if k < n and text[k] in "+-":
                k += 1
            if k < n and text[k] in _DIGITS:
                while k < n and text[k] in _DIGITS:
                    k += 1
                i = k
        return i

    def _step_operator(self, c: str, i: int) -> int:
        text = self._text
        two = text[i : i + 2]
        if c == "=":
            if two == "==":
                self._emit(Token(T.EQEQ, i, i + 2))
                return i + 2
            if two == "=>":
                self._emit(Token(T.ARROW, i, i + 2))
                return i + 2
            self._emit(Token(T.EQ, i, i + 1))
            return i + 1
        if c == "!":
            if two == "!=":
                self._emit(Token(T.NE, i, i + 2))
                return i + 2
            self._emit(Token(T.BANG, i, i + 1))
            return i + 1
        if c == "<":
            if two == "<<":
                return self._heredoc_intro(i)
            if two == "<=":
                self._emit(Token(T.LE, i, i + 2))
                return i + 2
            self._emit(Token(T.LT, i, i + 1))
            return i + 1
        if c == ">":
            if two == ">=":
                self._emit(Token(T.GE, i, i + 2))
                return i + 2
            self._emit(Token(T.GT, i, i + 1))
            return i + 1
        if c == "&" and two == "&&":
            self._emit(Token(T.AND, i, i + 2))
            return i + 2
        if c == "|" and two == "||":
            self._emit(Token(T.OR, i, i + 2))
            return i + 2
        if c == "/":
            self._emit(Token(T.SLASH, i, i + 1))
            return i + 1
        if c == ".":
            if text.startswith("...", i):
                self._emit(Token(T.ELLIPSIS, i, i + 3))
                return i + 3
            self._emit(Token(T.DOT, i, i + 1))
            return i + 1
        if c == ":":
            if two == "::":
                self._emit(Token(T.DCOLON, i, i + 2))
                return i + 2
            self._emit(Token(T.COLON, i, i + 1))
            return i + 1
        if c == "{":
            self._frames.append(_Frame(_BRACE))
            self._emit(Token(T.OBRACE, i, i + 1))
            return i + 1
        if c == "}":
            top = self._frames[-1]
            if top.kind == _SEQ:
                self._frames.pop()
                self._emit(Token(T.TPL_SEQ_CLOSE, i, i + 1, "", 0))
            else:
                if top.kind == _BRACE:
                    self._frames.pop()
                self._emit(Token(T.CBRACE, i, i + 1))
            return i + 1
        if c == "~" and two == "~}" and self._frames[-1].kind == _SEQ:
            self._frames.pop()
            self._emit(Token(T.TPL_SEQ_CLOSE, i, i + 2, "", 1))
            return i + 2
        if c == '"':
            self._frames.append(_Frame(_QUOTED))
            self._emit(Token(T.OQUOTE, i, i + 1))
            return i + 1
        return self._invalid_character(c, i)

    def _invalid_character(self, c: str, i: int) -> int:
        cp = ord(c)
        if unicodedata.category(c) == "Cn" and not _is_noncharacter(cp):
            raise HclLimitError(
                "limit.unicode_table",
                self.smap.range(i, i + 1),
                f"U+{cp:04X} is unassigned in Unicode {UNICODE_VERSION}, so it cannot be "
                "classified exactly",
            )
        raise self._error("lex.invalid_character", i, i + 1, f"invalid character U+{cp:04X}")

    # -- heredoc introduction ----------------------------------------------------------------

    def _heredoc_intro(self, i: int) -> int:
        """``<<`` or ``<<-`` Identifier Newline (spec, "Template Expressions")."""
        text = self._text
        n = self._n
        j = i + 2
        dash = j < n and text[j] == "-"
        if dash:
            j += 1
        if not (
            j < n and (text[j] in _ASCII_ID_START or (text[j] > "\x7f" and is_id_start(text[j])))
        ):
            raise self._error(
                "lex.invalid_heredoc_intro",
                i,
                min(j + 1, n),
                "<< must be followed by an identifier",
            )
        k = j + 1
        while k < n and (
            text[k] in _ASCII_ID_CONTINUE or (text[k] > "\x7f" and is_id_continue(text[k]))
        ):
            k += 1
        if text.startswith("\n", k):
            end = k + 1
        elif text.startswith("\r\n", k):
            end = k + 2
        else:
            raise self._error(
                "lex.invalid_heredoc_intro", i, k, "the heredoc marker must end the line"
            )
        marker = text[j:k]
        self._frames.append(_Frame(_HEREDOC, marker, dash, buffered=dash))
        if dash:
            self._buffers.append([])
        self._emit(Token(T.HEREDOC_OPEN, i, end, marker, 1 if dash else 0))
        return end

    # -- quoted templates --------------------------------------------------------------------

    def _step_quoted(self) -> None:
        text = self._text
        n = self._n
        i = self._i
        pieces: list[str] = []
        lit_start = i
        while True:
            j = i
            while j < n and text[j] not in _QUOTED_SPECIAL:
                j += 1
            if j > i:
                pieces.append(text[i:j])
                i = j
            if i >= n:
                raise self._error(
                    "lex.unterminated_string", lit_start, n, "quoted template is not closed"
                )
            c = text[i]
            if c == '"':
                self._flush_literal(pieces, lit_start, i, LIT_QUOTED)
                self._emit(Token(T.CQUOTE, i, i + 1))
                self._frames.pop()
                self._i = i + 1
                return
            if c == "\\":
                cooked, i = self._escape(i)
                pieces.append(cooked)
            elif c == "$" or c == "%":
                opened = self._template_sequence(c, i, pieces, lit_start, LIT_QUOTED)
                if opened:
                    self._i = i + opened
                    return
                if text.startswith(c + c + "{", i):
                    pieces.append(c + "{")
                    i += 3
                else:
                    pieces.append(c)
                    i += 1
            else:  # a line break
                raise self._error(
                    "lex.newline_in_string", i, i + 1, "quoted templates cannot span lines"
                )

    def _escape(self, i: int) -> tuple[str, int]:
        """Escape sequences of a quoted template (spec, "Template Expressions")."""
        text = self._text
        n = self._n
        if i + 1 >= n:
            raise self._error("lex.invalid_escape", i, n, "backslash at the end of the file")
        c = text[i + 1]
        simple = _SIMPLE_ESCAPES.get(c)
        if simple is not None:
            return simple, i + 2
        if c == "u" or c == "U":
            width = 4 if c == "u" else 8
            digits = text[i + 2 : i + 2 + width]
            if len(digits) != width or any(d not in _HEX for d in digits):
                raise self._error(
                    "lex.invalid_escape", i, i + 2 + len(digits), f"\\{c} needs {width} hex digits"
                )
            cp = int(digits, 16)
            if cp > 0x10FFFF or 0xD800 <= cp <= 0xDFFF:
                raise self._error(
                    "lex.invalid_escape", i, i + 2 + width, f"U+{cp:04X} is not a Unicode scalar"
                )
            return chr(cp), i + 2 + width
        raise self._error("lex.invalid_escape", i, i + 2, f"\\{c} is not an escape sequence")

    def _template_sequence(
        self, c: str, i: int, pieces: list[str], lit_start: int, lit_flag: int
    ) -> int:
        """Open ``${`` / ``%{`` at ``i`` unless it is escaped (``$${``, ``%%{``).

        Returns the number of characters consumed (0 when no sequence opens here). The marker
        ``~`` after the brace is a strip marker (spec, "Template Literals").
        """
        text = self._text
        if not text.startswith("{", i + 1):
            return 0
        strip = 1 if text.startswith("~", i + 2) else 0
        width = 3 if strip else 2
        self._flush_literal(pieces, lit_start, i, lit_flag)
        kind = T.TPL_INTERP_OPEN if c == "$" else T.TPL_CONTROL_OPEN
        self._emit(Token(kind, i, i + width, "", strip))
        self._frames.append(_Frame(_SEQ))
        return width

    def _flush_literal(self, pieces: list[str], start: int, end: int, flag: int) -> None:
        if pieces:
            self._emit(Token(T.TPL_LITERAL, start, end, "".join(pieces), flag))
            pieces.clear()

    # -- heredoc bodies ----------------------------------------------------------------------

    def _heredoc_terminator(self, i: int, marker: str) -> int:
        """End offset of a closing marker line starting at ``i``, or -1.

        The marker may be preceded and followed by spaces and tabs for both ``<<`` and ``<<-``
        and must be followed by a line break (C-95; spec: "on a line of its own").
        """
        text = self._text
        n = self._n
        j = i
        while j < n and (text[j] == " " or text[j] == "\t"):
            j += 1
        if not text.startswith(marker, j):
            return -1
        k = j + len(marker)
        while k < n and (text[k] == " " or text[k] == "\t"):
            k += 1
        if text.startswith("\n", k):
            return k + 1
        if text.startswith("\r\n", k):
            return k + 2
        return -1

    def _step_heredoc(self) -> None:
        text = self._text
        n = self._n
        frame = self._frames[-1]
        i = self._i
        if i >= n:
            raise self._error("lex.unterminated_heredoc", n, n, "heredoc is not closed")
        if frame.at_line_start:
            end = self._heredoc_terminator(i, frame.marker)
            if end != -1:
                newline_len = 2 if text.startswith("\r\n", end - 2) else 1
                self._emit(Token(T.HEREDOC_CLOSE, i, end - newline_len, frame.marker))
                self._emit(Token(T.NEWLINE, end - newline_len, end))
                self._frames.pop()
                if frame.buffered:
                    self._finish_buffer()
                self._i = end
                return
        pieces: list[str] = []
        lit_start = i
        flag = LIT_QUOTED
        if frame.dash:  # only a <<- heredoc needs to know which literals start a line
            flag = LIT_HEREDOC_LINE if frame.at_line_start else LIT_HEREDOC
        while True:
            j = i
            while j < n and text[j] not in _HEREDOC_SPECIAL:
                j += 1
            if j > i:
                pieces.append(text[i:j])
                i = j
            if i >= n:
                raise self._error("lex.unterminated_heredoc", n, n, "heredoc is not closed")
            c = text[i]
            if c == "\n" or c == "\r":
                if c == "\r" and not text.startswith("\r\n", i):
                    pieces.append("\r")
                    i += 1
                    continue
                newline = "\r\n" if c == "\r" else "\n"
                pieces.append(newline)
                i += len(newline)
                self._flush_literal(pieces, lit_start, i, flag)
                frame.at_line_start = True
                self._i = i
                return
            opened = self._template_sequence(c, i, pieces, lit_start, flag)
            if opened:
                if frame.dash and frame.at_line_start and i == lit_start:
                    # A line that starts with a sequence has indentation 0 (C-95): record it
                    # with an empty line-leading literal.
                    self._emit_empty_line_literal(i)
                frame.at_line_start = False
                self._i = i + opened
                return
            if text.startswith(c + c + "{", i):
                pieces.append(c + "{")
                i += 3
            else:
                pieces.append(c)
                i += 1

    def _emit_empty_line_literal(self, i: int) -> None:
        # The sequence tokens were already emitted by _template_sequence; put the empty literal
        # before them so that the order of tokens follows the text.
        target = self._buffers[-1] if self._buffers else self._queue
        open_token = target.pop()
        target.append(Token(T.TPL_LITERAL, i, i, "", LIT_HEREDOC_LINE))
        target.append(open_token)

    def _finish_buffer(self) -> None:
        """Apply ``<<-`` indentation stripping to the tokens of a finished heredoc.

        Spec, "Template Expressions": "any literal string at the start of each line is analyzed
        to find the minimum number of leading spaces, and then that number of prefix spaces is
        removed from all line-leading literal strings". Settled details (C-95): a tab counts as
        one space; a line that holds only whitespace is ignored and left unchanged; a line that
        starts with a sequence has indentation 0.
        """
        tokens = self._buffers.pop()
        indent: int | None = None
        for token in tokens:
            if token.kind is T.TPL_LITERAL and token.flag == LIT_HEREDOC_LINE:
                if _is_blank_line(token.value):
                    continue
                count = _leading_blanks(token.value)
                indent = count if indent is None else min(indent, count)
        for token in tokens:
            if token.kind is T.TPL_LITERAL:
                if indent and token.flag == LIT_HEREDOC_LINE and not _is_blank_line(token.value):
                    token.value = token.value[indent:]
                token.flag = LIT_QUOTED
        if self._buffers:
            self._buffers[-1].extend(tokens)
        else:
            self._queue.extend(tokens)


def _is_blank_line(value: str) -> bool:
    return value.endswith("\n") and value.strip(" \t\r\n") == ""


def _leading_blanks(value: str) -> int:
    count = 0
    for ch in value:
        if ch == " " or ch == "\t":
            count += 1
        else:
            break
    return count


def tokenize(text: str, filename: str) -> list[Token]:
    """All tokens of ``text`` up to and including EOF (for tests and tools)."""
    lexer = Lexer(text, filename)
    tokens: list[Token] = []
    while True:
        token = lexer.next_token()
        tokens.append(token)
        if token.kind is T.EOF:
            return tokens
