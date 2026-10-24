"""Internal errors of the HCL lexer and parser, and the registry of their rule codes (C-92).

``HclSyntaxError`` means the input is not valid HCL (the loader reports INVALID).
``HclLimitError`` means the input is valid so far but exceeds a limit of C-93 or a table DAIL
does not have (the loader reports UNSUPPORTED). Neither is a crash: the loader turns both into
diagnostics. ``RecursionError`` must never escape; the nesting limit is checked explicitly.
"""

from __future__ import annotations

from core.terraform_model.hcl.ast import SourceRange

# Rule code -> what it means. A code raised anywhere in this package must be listed here
# (tests/unit/test_hcl_lexer.py checks this against the source).
RULES: dict[str, str] = {
    # Lexical rules
    "lex.invalid_character": "A character that is not part of the HCL native syntax.",
    "lex.invalid_utf8": "The text is not valid Unicode (a lone surrogate code point).",
    "lex.unterminated_comment": "A /* comment is not closed by */.",
    "lex.unterminated_string": "A quoted template is not closed before the end of the file.",
    "lex.newline_in_string": "A quoted template contains a line break.",
    "lex.invalid_escape": "An escape sequence that the specification does not define.",
    "lex.invalid_heredoc_intro": "<< is not followed by an identifier and a line break.",
    "lex.unterminated_heredoc": "The closing marker line of a heredoc was not found.",
    # Parse rules
    "parse.unexpected_token": "A token that cannot appear here.",
    "parse.expected_argument_or_block": "An attribute or block definition was expected.",
    "parse.expected_expression": "An expression was expected.",
    "parse.invalid_block_definition": "A block header is not followed by { on the same line.",
    "parse.template_in_label": "A block label contains a template sequence.",
    "parse.missing_newline_after_argument": "An attribute must end with a line break.",
    "parse.missing_newline_after_block": "A block must end with a line break.",
    "parse.single_line_block": "A one-line block holds at most one attribute and must close.",
    "parse.unclosed_block": "A block is not closed before the end of the file.",
    "parse.unclosed_bracket": "A bracket, brace or parenthesis is not closed.",
    "parse.missing_item_separator": "Tuple items must be separated by commas.",
    "parse.missing_attribute_value": "An object key is not followed by = or :.",
    "parse.missing_attribute_separator": "Object items must be separated by a comma or a line.",
    "parse.missing_argument_separator": "Function arguments must be separated by commas.",
    "parse.expand_not_last": "The ... after a function argument must be followed by ).",
    "parse.invalid_function_name": "A :: in a function name is not followed by an identifier.",
    "parse.invalid_attribute_name": "A . is not followed by an attribute name, a digit or *.",
    "parse.invalid_legacy_index": "A legacy .N index is not a plain integer.",
    "parse.nested_splat": "A splat inside an attribute-only splat.",
    "parse.missing_conditional_colon": "A conditional ? is not followed by :.",
    "parse.invalid_for": "A malformed for expression.",
    "parse.invalid_template_directive": "A malformed template directive.",
    "parse.unbalanced_directive": "A template directive without its partner.",
    # Limits and tables (the loader reports UNSUPPORTED)
    "limit.nesting_depth": "Nesting deeper than the limit of C-93.",
    "limit.unicode_table": "A code point that Unicode 15.0 (the tables of Python 3.12) lacks.",
}


class HclError(Exception):
    """Base of the internal errors: a rule code, where it happened and a message."""

    def __init__(self, code: str, range: SourceRange, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.range = range
        self.message = message


class HclSyntaxError(HclError):
    """The input is not valid HCL."""


class HclLimitError(HclError):
    """The input exceeds a limit or a table of this implementation (UNSUPPORTED, C-93)."""
