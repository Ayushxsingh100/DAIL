"""Lexer of the HCL native syntax (P3a-1 step 2; Doc 04 §4, §23; C-91, C-93).

Expected values are written by hand from ``hclsyntax/spec.md`` (hashicorp/hcl v2.25.0, ADR-003).
The cases marked "C-95" follow behaviour that the specification leaves open and that was settled
against Terraform 1.15.8 when the lexer was written (see the register row C-95).
Every error path of the lexer has its own test.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

from core.terraform_model.hcl.ast import SourceRange
from core.terraform_model.hcl.errors import RULES, HclLimitError, HclSyntaxError
from core.terraform_model.hcl.lexer import (
    SourceMap,
    T,
    is_id_continue,
    is_id_start,
    tokenize,
)

F = "t.tf"


def kinds(src: str) -> list[T]:
    return [t.kind for t in tokenize(src, F)]


def pairs(src: str) -> list[tuple[T, str]]:
    return [(t.kind, t.value) for t in tokenize(src, F) if t.kind is not T.EOF]


def error_code(src: str) -> str:
    try:
        tokenize(src, F)
    except (HclSyntaxError, HclLimitError) as exc:
        return exc.code
    raise AssertionError(f"no error for {src!r}")


class TestTokens(unittest.TestCase):
    def test_punctuation_and_operators_of_the_spec_table(self) -> None:
        # Spec, "Operators and Delimiters"; ``${`` and ``%{`` belong to templates.
        table = {
            "+": T.PLUS,
            "-": T.MINUS,
            "*": T.STAR,
            "/": T.SLASH,
            "%": T.PERCENT,
            "&&": T.AND,
            "||": T.OR,
            "!": T.BANG,
            "==": T.EQEQ,
            "!=": T.NE,
            "<": T.LT,
            ">": T.GT,
            "<=": T.LE,
            ">=": T.GE,
            ":": T.COLON,
            "?": T.QUESTION,
            "=": T.EQ,
            "=>": T.ARROW,
            "{": T.OBRACE,
            "}": T.CBRACE,
            "[": T.OBRACKET,
            "]": T.CBRACKET,
            "(": T.OPAREN,
            ")": T.CPAREN,
            ".": T.DOT,
            ",": T.COMMA,
            "...": T.ELLIPSIS,
        }
        for text, kind in table.items():
            with self.subTest(text=text):
                self.assertEqual(kinds(text), [kind, T.EOF])

    def test_longest_operator_wins(self) -> None:
        self.assertEqual(kinds("==="), [T.EQEQ, T.EQ, T.EOF])
        self.assertEqual(kinds("!=="), [T.NE, T.EQ, T.EOF])
        self.assertEqual(kinds(">=="), [T.GE, T.EQ, T.EOF])
        self.assertEqual(kinds("<=>"), [T.LE, T.GT, T.EOF])
        self.assertEqual(kinds("=>="), [T.ARROW, T.EQ, T.EOF])
        self.assertEqual(kinds("...."), [T.ELLIPSIS, T.DOT, T.EOF])
        self.assertEqual(kinds("a::b"), [T.IDENT, T.DCOLON, T.IDENT, T.EOF])

    def test_numeric_literals(self) -> None:
        # NumericLit = decimal+ ("." decimal+)? (expmark decimal+)?
        for text in ("0", "12", "1.5", "1e3", "1E+3", "1.5e-3", "007"):
            with self.subTest(text=text):
                self.assertEqual(pairs(text), [(T.NUMBER, text)])

    def test_number_edges_split_into_tokens(self) -> None:
        self.assertEqual(pairs("1."), [(T.NUMBER, "1"), (T.DOT, "")])
        self.assertEqual(pairs(".5"), [(T.DOT, ""), (T.NUMBER, "5")])
        self.assertEqual(pairs("1e"), [(T.NUMBER, "1"), (T.IDENT, "e")])
        self.assertEqual(pairs("1e+"), [(T.NUMBER, "1"), (T.IDENT, "e"), (T.PLUS, "")])
        self.assertEqual(pairs("0x10"), [(T.NUMBER, "0"), (T.IDENT, "x10")])
        # "foo.0.0.bar": the number literal 0.0 takes priority (spec, "Index Operator").
        self.assertEqual(
            pairs("foo.0.0.bar"),
            [(T.IDENT, "foo"), (T.DOT, ""), (T.NUMBER, "0.0"), (T.DOT, ""), (T.IDENT, "bar")],
        )

    def test_identifiers_may_contain_dashes_and_underscores(self) -> None:
        for name in ("a", "a-b", "a--", "a_b", "_a", "_", "a1", "a-1", "AbC"):
            with self.subTest(name=name):
                self.assertEqual(pairs(name), [(T.IDENT, name)])
        # A dash cannot start an identifier: it is the minus operator.
        self.assertEqual(pairs("-a"), [(T.MINUS, ""), (T.IDENT, "a")])
        # A digit cannot start an identifier.
        self.assertEqual(pairs("1a"), [(T.NUMBER, "1"), (T.IDENT, "a")])

    def test_unicode_identifiers_follow_uax31(self) -> None:
        for name in ("é", "é", "α", "中", "aʰ", "a٣", "a·b", "℘"):
            with self.subTest(name=name):
                self.assertEqual(pairs(name), [(T.IDENT, name)])

    def test_characters_outside_id_continue_end_or_break_an_identifier(self) -> None:
        # ZERO WIDTH JOINER is not in ID_Continue of Unicode 9.0 (C-101); an emoji is neither.
        self.assertEqual(error_code("a‍b"), "lex.invalid_character")
        self.assertEqual(error_code("\U0001f600"), "lex.invalid_character")
        self.assertFalse(is_id_start("1"))
        self.assertTrue(is_id_continue("1"))
        self.assertFalse(is_id_continue(" "))

    def test_text_is_not_normalized(self) -> None:
        # A precombined letter and a letter with a combining accent stay distinct (spec,
        # "Source Code Representation").
        self.assertEqual(pairs("é")[0][1], "é")
        self.assertEqual(pairs("é")[0][1], "é")

    def test_keywords_are_plain_identifiers(self) -> None:
        # Spec, "Keywords": no globally-reserved words.
        for word in ("true", "false", "null", "for", "in", "if", "else", "endif", "endfor"):
            with self.subTest(word=word):
                self.assertEqual(pairs(word), [(T.IDENT, word)])


class TestWhitespaceNewlinesAndComments(unittest.TestCase):
    def test_spaces_and_tabs_are_whitespace(self) -> None:
        self.assertEqual(kinds(" \t a \t"), [T.IDENT, T.EOF])

    def test_newline_sequences(self) -> None:
        self.assertEqual(kinds("a\nb"), [T.IDENT, T.NEWLINE, T.IDENT, T.EOF])
        self.assertEqual(kinds("a\r\nb"), [T.IDENT, T.NEWLINE, T.IDENT, T.EOF])
        newline = tokenize("a\r\n", F)[1]
        self.assertEqual((newline.start, newline.end), (1, 3))

    def test_a_lone_carriage_return_is_not_a_newline(self) -> None:
        self.assertEqual(error_code("a\rb"), "lex.invalid_character")

    def test_other_unicode_spaces_are_not_whitespace(self) -> None:
        for ch in (" ", "\x0b", "\x0c", " ", "　"):
            with self.subTest(ch=hex(ord(ch))):
                self.assertEqual(error_code(f"a{ch}b"), "lex.invalid_character")

    def test_line_comments_act_as_a_newline(self) -> None:
        self.assertEqual(kinds("a # c\nb"), [T.IDENT, T.NEWLINE, T.IDENT, T.EOF])
        self.assertEqual(kinds("a // c\nb"), [T.IDENT, T.NEWLINE, T.IDENT, T.EOF])
        self.assertEqual(kinds("a # c\r\nb"), [T.IDENT, T.NEWLINE, T.IDENT, T.EOF])

    def test_a_line_comment_at_the_end_of_the_file_needs_no_newline(self) -> None:
        self.assertEqual(kinds("a # c"), [T.IDENT, T.EOF])
        self.assertEqual(kinds("# only"), [T.EOF])

    def test_a_comment_may_hold_any_character(self) -> None:
        self.assertEqual(kinds("# a\x00b‮c \r d\n"), [T.NEWLINE, T.EOF])

    def test_inline_comments_act_as_whitespace_even_across_lines(self) -> None:
        self.assertEqual(kinds("a /* c */ b"), [T.IDENT, T.IDENT, T.EOF])
        self.assertEqual(kinds("a /* c\nd */ b"), [T.IDENT, T.IDENT, T.EOF])
        self.assertEqual(kinds("a /**/ b"), [T.IDENT, T.IDENT, T.EOF])

    def test_comments_do_not_nest(self) -> None:
        # "/* a /* b */" ends at the first "*/"; the rest "*/" is then lexed as "*" and "/".
        self.assertEqual(kinds("/* a /* b */ */"), [T.STAR, T.SLASH, T.EOF])

    def test_comment_markers_inside_strings_are_text(self) -> None:
        self.assertEqual(
            pairs('"a # b /* c */ // d"'),
            [(T.OQUOTE, ""), (T.TPL_LITERAL, "a # b /* c */ // d"), (T.CQUOTE, "")],
        )

    def test_unterminated_inline_comment(self) -> None:
        self.assertEqual(error_code("a /* never closed"), "lex.unterminated_comment")
        self.assertEqual(error_code("/*/"), "lex.unterminated_comment")


class TestQuotedTemplates(unittest.TestCase):
    def test_empty_and_plain_strings(self) -> None:
        self.assertEqual(pairs('""'), [(T.OQUOTE, ""), (T.CQUOTE, "")])
        self.assertEqual(pairs('"abc"'), [(T.OQUOTE, ""), (T.TPL_LITERAL, "abc"), (T.CQUOTE, "")])

    def test_every_escape_sequence_of_the_spec(self) -> None:
        cases = {
            r"\n": "\n",
            r"\r": "\r",
            r"\t": "\t",
            r"\"": '"',
            r"\\": "\\",
            r"A": "A",
            r"é": "é",
            r"€": "€",
            r"\U0001F600": "\U0001f600",
            r"\U00000041": "A",
            r"\u0000": "\x00",
        }
        for escape, expected in cases.items():
            with self.subTest(escape=escape):
                tokens = tokenize(f'"{escape}"', F)
                self.assertEqual(tokens[1].value, expected)

    def test_escapes_and_text_form_one_literal(self) -> None:
        tokens = tokenize(r'"a\tbAc"', F)
        self.assertEqual([t.kind for t in tokens][:3], [T.OQUOTE, T.TPL_LITERAL, T.CQUOTE])
        self.assertEqual(tokens[1].value, "a\tbAc")

    def test_interpolation_and_directive_tokens(self) -> None:
        self.assertEqual(
            kinds('"a${b}c%{if}d"'),
            [
                T.OQUOTE,
                T.TPL_LITERAL,
                T.TPL_INTERP_OPEN,
                T.IDENT,
                T.TPL_SEQ_CLOSE,
                T.TPL_LITERAL,
                T.TPL_CONTROL_OPEN,
                T.IDENT,
                T.TPL_SEQ_CLOSE,
                T.TPL_LITERAL,
                T.CQUOTE,
                T.EOF,
            ],
        )

    def test_dollar_and_percent_escapes(self) -> None:
        # "The ${ sequence is escaped as $${ and the %{ sequence is escaped as %%{".
        self.assertEqual(tokenize('"$${x}"', F)[1].value, "${x}")
        self.assertEqual(tokenize('"%%{x}"', F)[1].value, "%{x}")
        self.assertEqual(tokenize('"a$${"', F)[1].value, "a${")

    def test_a_dollar_or_percent_without_a_brace_is_text(self) -> None:
        for text in ("$", "$$", "%", "%%", "$x", "%x", "$$x", "a$", "a%"):
            with self.subTest(text=text):
                self.assertEqual(tokenize(f'"{text}"', F)[1].value, text)

    def test_overlapping_escapes_resolve_left_to_right(self) -> None:
        # "$$${x}": a literal "$" and then the escape "$${" -> "$" + "${" + "x}".
        self.assertEqual(tokenize('"$$${x}"', F)[1].value, "$${x}")

    def test_strip_markers_are_flags_on_the_sequence_tokens(self) -> None:
        tokens = tokenize('"${~ a ~}%{~ b ~}${c}"', F)
        flags = [
            (t.kind, t.flag)
            for t in tokens
            if t.kind in (T.TPL_INTERP_OPEN, T.TPL_CONTROL_OPEN, T.TPL_SEQ_CLOSE)
        ]
        self.assertEqual(
            flags,
            [
                (T.TPL_INTERP_OPEN, 1),
                (T.TPL_SEQ_CLOSE, 1),
                (T.TPL_CONTROL_OPEN, 1),
                (T.TPL_SEQ_CLOSE, 1),
                (T.TPL_INTERP_OPEN, 0),
                (T.TPL_SEQ_CLOSE, 0),
            ],
        )

    def test_a_tilde_outside_a_sequence_is_not_a_token(self) -> None:
        self.assertEqual(tokenize('"~}"', F)[1].value, "~}")
        self.assertEqual(error_code("~"), "lex.invalid_character")
        self.assertEqual(error_code("a ~}"), "lex.invalid_character")

    def test_braces_inside_an_interpolation_are_matched(self) -> None:
        self.assertEqual(
            kinds('"${ {a = 1}.a }x"'),
            [
                T.OQUOTE,
                T.TPL_INTERP_OPEN,
                T.OBRACE,
                T.IDENT,
                T.EQ,
                T.NUMBER,
                T.CBRACE,
                T.DOT,
                T.IDENT,
                T.TPL_SEQ_CLOSE,
                T.TPL_LITERAL,
                T.CQUOTE,
                T.EOF,
            ],
        )

    def test_braces_in_template_text_are_text(self) -> None:
        self.assertEqual(tokenize('"{ } ${1} { }"', F)[1].value, "{ } ")

    def test_templates_nest_inside_interpolations(self) -> None:
        got = kinds('"a${"b${1}"}"')
        self.assertEqual(got.count(T.OQUOTE), 2)
        self.assertEqual(got.count(T.CQUOTE), 2)
        self.assertEqual(got.count(T.TPL_SEQ_CLOSE), 2)

    def test_newlines_and_comments_are_allowed_inside_an_interpolation(self) -> None:
        self.assertEqual(
            kinds('"${\n1 /* c */\n}"'),
            [
                T.OQUOTE,
                T.TPL_INTERP_OPEN,
                T.NEWLINE,
                T.NUMBER,
                T.NEWLINE,
                T.TPL_SEQ_CLOSE,
                T.CQUOTE,
                T.EOF,
            ],
        )

    def test_raw_tab_and_non_ascii_text_in_strings(self) -> None:
        self.assertEqual(tokenize('"a\tb‮cé"', F)[1].value, "a\tb‮cé")

    # -- error paths ------------------------------------------------------------------------

    def test_error_unterminated_string_at_the_end_of_the_file(self) -> None:
        self.assertEqual(error_code('"abc'), "lex.unterminated_string")
        self.assertEqual(error_code('"'), "lex.unterminated_string")

    def test_error_unterminated_interpolation(self) -> None:
        self.assertEqual(error_code('"${1'), "lex.unterminated_string")
        self.assertEqual(error_code('"%{ if x '), "lex.unterminated_string")

    def test_error_newline_in_string(self) -> None:
        self.assertEqual(error_code('"a\nb"'), "lex.newline_in_string")
        self.assertEqual(error_code('"a\r\nb"'), "lex.newline_in_string")
        self.assertEqual(error_code('"a\rb"'), "lex.newline_in_string")

    def test_error_unknown_escape(self) -> None:
        for escape in (r"\q", r"\$", r"\%", r"\0", r"\x41", r"\ ", "\\\n"):
            with self.subTest(escape=escape):
                self.assertEqual(error_code(f'"{escape}"'), "lex.invalid_escape")

    def test_error_backslash_at_the_end_of_the_file(self) -> None:
        self.assertEqual(error_code('"\\'), "lex.invalid_escape")

    def test_error_short_or_non_hex_unicode_escapes(self) -> None:
        for escape in (
            r"\u",
            r"\u12",
            r"\u12G4",
            r"\u+123",
            r"\u 123",
            r"\U1234567",
            r"\U0000000G",
        ):
            with self.subTest(escape=escape):
                self.assertEqual(error_code(f'"{escape}"'), "lex.invalid_escape")

    def test_error_escape_that_is_not_a_unicode_scalar(self) -> None:
        for escape in (r"\uD800", r"\uDFFF", r"\U0000D800", r"\U00110000", r"\UFFFFFFFF"):
            with self.subTest(escape=escape):
                self.assertEqual(error_code(f'"{escape}"'), "lex.invalid_escape")

    def test_boundary_scalars_are_accepted(self) -> None:
        self.assertEqual(tokenize(r'"퟿"', F)[1].value, "퟿")
        self.assertEqual(tokenize(r'""', F)[1].value, "")
        self.assertEqual(tokenize(r'"\U0010FFFF"', F)[1].value, "\U0010ffff")


class TestHeredocs(unittest.TestCase):
    def values(self, src: str) -> list[str]:
        return [t.value for t in tokenize(src, F) if t.kind is T.TPL_LITERAL]

    def test_plain_heredoc_keeps_every_line_break(self) -> None:
        self.assertEqual(
            kinds("<<EOT\nhi\nthere\nEOT\n"),
            [T.HEREDOC_OPEN, T.TPL_LITERAL, T.TPL_LITERAL, T.HEREDOC_CLOSE, T.NEWLINE, T.EOF],
        )
        self.assertEqual(self.values("<<EOT\nhi\nthere\nEOT\n"), ["hi\n", "there\n"])

    def test_heredoc_token_values(self) -> None:
        tokens = tokenize("<<-EOT\nx\nEOT\n", F)
        self.assertEqual(
            (tokens[0].kind, tokens[0].value, tokens[0].flag), (T.HEREDOC_OPEN, "EOT", 1)
        )
        plain = tokenize("<<EOT\nx\nEOT\n", F)
        self.assertEqual((plain[0].value, plain[0].flag), ("EOT", 0))

    def test_empty_heredoc(self) -> None:
        self.assertEqual(kinds("<<EOT\nEOT\n"), [T.HEREDOC_OPEN, T.HEREDOC_CLOSE, T.NEWLINE, T.EOF])

    def test_no_escape_processing_inside_a_heredoc(self) -> None:
        self.assertEqual(self.values('<<EOT\na \\n \\" "q"\nEOT\n'), ['a \\n \\" "q"\n'])

    def test_template_escapes_and_sequences_work_inside_a_heredoc(self) -> None:
        self.assertEqual(self.values("<<EOT\na$${b} %%{c}\nEOT\n"), ["a${b} %{c}\n"])
        got = kinds("<<EOT\na ${b} %{if c}\nEOT\n")
        self.assertIn(T.TPL_INTERP_OPEN, got)
        self.assertIn(T.TPL_CONTROL_OPEN, got)

    def test_crlf_line_breaks_are_kept(self) -> None:
        self.assertEqual(self.values("<<EOT\r\nhi\r\nthere\r\nEOT\r\n"), ["hi\r\n", "there\r\n"])

    def test_closing_marker_may_have_surrounding_blanks(self) -> None:
        # C-95: both forms accept blanks around the closing marker; "on a line of its own".
        for src in (
            "<<EOT\nhi\n  EOT\n",
            "<<EOT\nhi\nEOT  \n",
            "<<EOT\nhi\n\tEOT\t\n",
            "<<-EOT\nhi\n  EOT\n",
        ):
            with self.subTest(src=src):
                self.assertEqual(self.values(src), ["hi\n"])

    def test_a_marker_followed_by_text_is_content(self) -> None:
        self.assertEqual(
            self.values("<<EOT\nEOTX\nXEOT\nEOT x\nEOT\n"), ["EOTX\n", "XEOT\n", "EOT x\n"]
        )

    def test_the_marker_is_case_sensitive_and_may_contain_dashes(self) -> None:
        self.assertEqual(self.values("<<eot\nEOT\neot\n"), ["EOT\n"])
        self.assertEqual(self.values("<<E-T\nx\nE-T\n"), ["x\n"])

    def test_an_interpolation_inside_a_heredoc_may_span_lines(self) -> None:
        got = self.values("<<EOT\na ${\n1\n} b\nEOT\n")
        self.assertEqual(got, ["a ", " b\n"])

    def test_a_marker_line_inside_an_interpolation_is_not_a_terminator(self) -> None:
        got = self.values("<<EOT\n${\nEOT\n}\nEOT\n")
        self.assertEqual(got, ["\n"])

    def test_heredocs_nest_inside_interpolations(self) -> None:
        got = kinds("<<A\n${<<B\nz\nB\n}\nA\n")
        self.assertEqual(got.count(T.HEREDOC_OPEN), 2)
        self.assertEqual(got.count(T.HEREDOC_CLOSE), 2)

    def test_the_closing_line_break_is_a_newline_token_that_ends_the_attribute(self) -> None:
        got = pairs("x = <<EOT\nhi\nEOT\ny = 1\n")
        self.assertEqual(
            [kind for kind, _ in got],
            [
                T.IDENT,
                T.EQ,
                T.HEREDOC_OPEN,
                T.TPL_LITERAL,
                T.HEREDOC_CLOSE,
                T.NEWLINE,
                T.IDENT,
                T.EQ,
                T.NUMBER,
                T.NEWLINE,
            ],
        )

    # -- <<- indentation (spec, "Template Expressions"; C-95 for the settled details) -------

    def test_dash_heredoc_removes_the_smallest_indentation(self) -> None:
        self.assertEqual(
            self.values("<<-EOT\n      a\n    b\n      c\n    EOT\n"), ["  a\n", "b\n", "  c\n"]
        )

    def test_dash_heredoc_ignores_blank_lines_when_measuring_and_leaves_them_alone(self) -> None:
        self.assertEqual(self.values("<<-EOT\n    a\n\n    b\n    EOT\n"), ["a\n", "\n", "b\n"])
        self.assertEqual(
            self.values("<<-EOT\n    a\n        \n    b\n    EOT\n"), ["a\n", "        \n", "b\n"]
        )
        self.assertEqual(self.values("<<-EOT\n    a\n  \n    b\n    EOT\n"), ["a\n", "  \n", "b\n"])

    def test_dash_heredoc_counts_a_tab_as_one(self) -> None:
        self.assertEqual(self.values("<<-EOT\n\t\ta\n\t\t\tb\n\t\tEOT\n"), ["a\n", "\tb\n"])
        self.assertEqual(self.values("<<-EOT\n\ttab\n    sp\n    EOT\n"), ["tab\n", "   sp\n"])

    def test_dash_heredoc_counts_a_line_that_starts_with_a_sequence_as_indent_zero(self) -> None:
        self.assertEqual(
            self.values("<<-EOT\n      a\n${b}\n      c\n    EOT\n"),
            ["      a\n", "", "\n", "      c\n"],
        )

    def test_dash_heredoc_counts_blanks_before_a_sequence(self) -> None:
        # The smallest indentation is the 2 blanks before ${b}.
        self.assertEqual(
            self.values("<<-EOT\n      a\n  ${b}\n      c\n    EOT\n"),
            ["    a\n", "", "\n", "    c\n"],
        )

    def test_dash_heredoc_keeps_text_after_the_first_sequence_on_a_line(self) -> None:
        self.assertEqual(self.values("<<-EOT\n  a ${b}\n    c\n  EOT\n"), ["a ", "\n", "  c\n"])
        self.assertEqual(
            self.values("<<-EOT\n    a\n      x ${b}   y\n    EOT\n"), ["a\n", "  x ", "   y\n"]
        )

    def test_dash_heredoc_does_not_touch_nested_quoted_literals(self) -> None:
        values = self.values('<<-EOT\n  a ${"   q"}\n  EOT\n')
        self.assertEqual(values, ["a ", "   q", "\n"])

    def test_plain_heredoc_is_not_dedented(self) -> None:
        self.assertEqual(self.values("<<EOT\n  a\n    b\nEOT\n"), ["  a\n", "    b\n"])

    def test_a_plain_heredoc_inside_a_dash_heredoc_keeps_its_indentation(self) -> None:
        src = "<<-A\n  x ${<<B\n    y\nB\n}\n  A\n"
        values = self.values(src)
        self.assertIn("    y\n", values)
        self.assertEqual(values[0], "x ")

    def test_a_dash_heredoc_inside_a_dash_heredoc_is_measured_on_its_own(self) -> None:
        src = "<<-A\n    x ${<<-B\n      y\n        z\n      B\n}\n    A\n"
        values = self.values(src)
        self.assertEqual(values[0], "x ")
        self.assertIn("y\n", values)
        self.assertIn("  z\n", values)

    # -- error paths ------------------------------------------------------------------------

    def test_error_marker_missing(self) -> None:
        self.assertEqual(error_code("<<\n"), "lex.invalid_heredoc_intro")
        self.assertEqual(error_code("<<-\n"), "lex.invalid_heredoc_intro")
        self.assertEqual(error_code("<<"), "lex.invalid_heredoc_intro")
        self.assertEqual(error_code("<< EOT\nx\nEOT\n"), "lex.invalid_heredoc_intro")
        self.assertEqual(error_code("<<1A\nx\n1A\n"), "lex.invalid_heredoc_intro")

    def test_error_marker_not_followed_by_a_line_break(self) -> None:
        self.assertEqual(error_code("<<EOT x\nx\nEOT\n"), "lex.invalid_heredoc_intro")
        self.assertEqual(error_code("<<EOT  \nx\nEOT\n"), "lex.invalid_heredoc_intro")
        self.assertEqual(error_code("<<EOT # c\nx\nEOT\n"), "lex.invalid_heredoc_intro")
        self.assertEqual(error_code("<<EOT"), "lex.invalid_heredoc_intro")

    def test_error_closing_marker_missing(self) -> None:
        self.assertEqual(error_code("<<EOT\nhi\n"), "lex.unterminated_heredoc")
        self.assertEqual(error_code("<<EOT\n"), "lex.unterminated_heredoc")
        self.assertEqual(error_code("<<EOT\nhi\nEOTX\n"), "lex.unterminated_heredoc")

    def test_error_closing_marker_without_a_line_break_at_the_end_of_the_file(self) -> None:
        self.assertEqual(error_code("<<EOT\nhi\nEOT"), "lex.unterminated_heredoc")

    def test_error_text_ends_in_the_middle_of_a_heredoc_line(self) -> None:
        self.assertEqual(error_code("<<EOT\nhi"), "lex.unterminated_heredoc")

    def test_error_interpolation_open_at_the_end_of_a_heredoc(self) -> None:
        self.assertEqual(error_code("<<EOT\n${a\n"), "lex.unterminated_heredoc")


class TestErrorsOutsideTemplates(unittest.TestCase):
    def test_error_invalid_characters(self) -> None:
        for ch in (";", "@", "`", "'", "\\", "$", "&", "|", "~", "^", "\x00", "﻿", "�", "￿"):
            with self.subTest(ch=hex(ord(ch))):
                self.assertEqual(error_code(f"a {ch} b"), "lex.invalid_character")

    def test_error_lone_surrogate(self) -> None:
        self.assertEqual(error_code("a = \ud800\n"), "lex.invalid_utf8")
        self.assertEqual(error_code('"\udfff"'), "lex.invalid_utf8")
        self.assertEqual(error_code("# \ud800\n"), "lex.invalid_utf8")

    def test_unassigned_code_point_is_invalid(self) -> None:
        # U+0378 is unassigned in every Unicode version. Terraform 1.15.8 uses Unicode 9.0 for
        # identifiers (U+1E900, assigned in 9.0, is accepted; U+11A00, assigned in 10.0, is not),
        # so it rejects every code point that 9.0 leaves unassigned: INVALID (C-92 rule).
        for text in ("a ͸ b", "a͸ = 1", "͸a = 1", "a = 1 \U0002ebf0"):
            with self.subTest(text=text):
                self.assertEqual(error_code(text), "lex.invalid_character")

    def test_unassigned_code_points_inside_strings_and_comments_are_text(self) -> None:
        self.assertEqual(tokenize('"͸"', F)[1].value, "͸")
        self.assertEqual(kinds("# ͸\n"), [T.NEWLINE, T.EOF])


def raw(data: bytes) -> str:
    """Decode as the loader does for a file that is not valid UTF-8."""
    return data.decode("utf-8", "surrogateescape")


class TestUndecodableBytes(unittest.TestCase):
    """C-92 rule: INVALID only when Terraform 1.15.8 rejects the input.

    Terraform accepts non-UTF-8 bytes inside comments, and inside strings and heredocs when they
    form a lead byte C0..F7 plus the right number of continuation bytes 80..BF (even overlong,
    above U+10FFFF or a surrogate). It rejects every other stray byte and any byte in code.
    """

    # Valid for Terraform 1.15.8 inside a string, undecodable for Python.
    SHAPES = {
        "overlong two-byte": b"\xc0\xaf",
        "overlong C1": b"\xc1\xbf",
        "overlong three-byte": b"\xe0\x80\x80",
        "overlong four-byte": b"\xf0\x80\x80\x80",
        "above U+10FFFF": b"\xf4\x90\x80\x80",
        "lead F5": b"\xf5\x80\x80\x80",
        "surrogate D800": b"\xed\xa0\x80",
        "surrogate DFFF": b"\xed\xbf\xbf",
        "surrogate pair": b"\xed\xa0\x80\xed\xb0\x80",
    }
    # Rejected by Terraform 1.15.8 everywhere outside a comment.
    MALFORMED = {
        "lone continuation": b"\x80",
        "lone continuation BF": b"\xbf",
        "truncated two-byte": b"\xc2",
        "truncated three-byte": b"\xe2\x82",
        "five-byte lead": b"\xf8\x88\x80\x80\x80",
        "FE": b"\xfe",
        "FF": b"\xff",
        "lead then ASCII": b"\xe2a\x82",
    }

    def test_everything_is_text_inside_a_comment(self) -> None:
        for name, data in {**self.SHAPES, **self.MALFORMED}.items():
            for comment in (b"# %s\n", b"// %s\n", b"/* %s */\n"):
                with self.subTest(case=name, comment=comment[:2]):
                    tokenize(raw(comment % data), F)

    def test_well_formed_shapes_are_text_inside_strings_and_heredocs(self) -> None:
        for name, data in self.SHAPES.items():
            with self.subTest(case=name):
                tokenize(raw(b'"a%sb"' % data), F)
                tokenize(raw(b"<<EOT\na%sb\nEOT\n" % data), F)
                tokenize(raw(b"<<-EOT\n  a%sb\n  EOT\n" % data), F)

    def test_malformed_bytes_in_strings_and_heredocs_are_invalid(self) -> None:
        for name, data in self.MALFORMED.items():
            for template in (b'"a%sb"', b"<<EOT\na%sb\nEOT\n", b"<<-EOT\n  a%sb\n  EOT\n"):
                with self.subTest(case=name, template=template[:3]):
                    self.assertEqual(error_code(raw(template % data)), "lex.invalid_utf8")

    def test_every_byte_in_code_is_invalid(self) -> None:
        for name, data in {**self.SHAPES, **self.MALFORMED}.items():
            for template in (b"a = 1 %s\n", b"%s\n", b"a = [1, %s]\n", b"a = (%s)\n"):
                with self.subTest(case=name, template=template[:5]):
                    self.assertEqual(error_code(raw(template % data)), "lex.invalid_utf8")

    def test_a_stray_byte_beside_an_identifier_is_invalid_unless_terraform_tolerates_it(
        self,
    ) -> None:
        # Terraform 1.15.8 tolerates some stray lead bytes next to identifier characters (found by
        # trying every byte); DAIL cannot reproduce the rule exactly, so those are UNSUPPORTED.
        tolerated = (b"\xc4", b"\xcb", b"\xd6", b"\xdb", b"\xe4", b"\xed")
        rejected = (
            b"\xc0",
            b"\xc2",
            b"\xc3",
            b"\xcc",
            b"\xd7",
            b"\xe0",
            b"\xe3",
            b"\xee",
            b"\xf0",
            b"\xff",
            b"\x80",
        )
        for template in (b"locals {\n  a%ss = 1\n}\n", b"locals {\n  %sa = 1\n}\n"):
            for data in tolerated:
                with self.subTest(template=template[:14], byte=data):
                    with self.assertRaises(HclLimitError) as caught:
                        tokenize(raw(template % data), F)
                    self.assertEqual(caught.exception.code, "limit.undecodable_in_identifier")
            for data in rejected:
                with self.subTest(template=template[:14], byte=data):
                    self.assertEqual(error_code(raw(template % data)), "lex.invalid_utf8")

    def test_a_tolerated_lead_byte_away_from_identifiers_is_invalid(self) -> None:
        for data in (b"\xc4", b"\xcb", b"\xe4", b"\xed"):
            for template in (b"locals { a = 1 %s }\n", b"locals {\n  a = 1\n  %s\n}\n"):
                with self.subTest(template=template[:12], byte=data):
                    self.assertEqual(error_code(raw(template % data)), "lex.invalid_utf8")

    def test_a_shape_cut_off_at_the_end_of_the_string_is_invalid(self) -> None:
        self.assertEqual(error_code(raw(b'"a\xe2\x82"')), "lex.invalid_utf8")
        self.assertEqual(error_code(raw(b'"a\xe2\x82$${"')), "lex.invalid_utf8")

    def test_a_valid_character_beside_a_shape_is_unaffected(self) -> None:
        tokens = tokenize(raw('"é'.encode() + b"\xc0\xaf" + '€"'.encode()), F)
        self.assertEqual(tokens[1].kind, T.TPL_LITERAL)

    def test_other_lone_surrogates_are_still_rejected(self) -> None:
        for text in ("a = \ud800\n", '"\udbff"', "# \udc7f\n", "# \udd00\n"):
            with self.subTest(text=text):
                self.assertEqual(error_code(text), "lex.invalid_utf8")

    def test_an_undecodable_byte_counts_as_one_byte_in_ranges(self) -> None:
        smap = SourceMap(raw(b"# \xff\xff\n\xc3\xa9 = \xe2\x82\xac"), F)
        # "# " + 2 bytes + newline = 5 bytes; "é" is 2 bytes
        self.assertEqual(smap.range(0, 4).end_byte, 4)
        self.assertEqual(smap.range(5, 6).start_byte, 5)
        self.assertEqual(smap.range(5, 6).end_byte, 7)


class TestNulByte(unittest.TestCase):
    """A NUL byte, checked against Terraform 1.15.8 (`terraform validate`, scratch directory):
    accepted inside a quoted string, a heredoc and a comment; rejected in code ("Invalid
    character"); in a block label the label is not a valid name (see the loader tests)."""

    def test_nul_is_text_in_strings_heredocs_and_comments(self) -> None:
        self.assertEqual(tokenize('"x\x00y"', F)[1].value, "x\x00y")
        values = [t.value for t in tokenize("<<EOT\nx\x00y\nEOT\n", F) if t.kind is T.TPL_LITERAL]
        self.assertEqual(values, ["x\x00y\n"])
        self.assertEqual(kinds("# x\x00y\n"), [T.NEWLINE, T.EOF])
        self.assertEqual(kinds("/* x\x00y */"), [T.EOF])

    def test_nul_in_code_is_invalid(self) -> None:
        for text in ("a = 1 \x00\n", "a\x00 = 1\n", "\x00", "a = [1,\x00]\n"):
            with self.subTest(text=text):
                self.assertEqual(error_code(text), "lex.invalid_character")


class TestSourceRanges(unittest.TestCase):
    def test_lines_columns_and_bytes_of_ascii_text(self) -> None:
        smap = SourceMap("ab\ncd\n", F)
        self.assertEqual(smap.range(0, 2), SourceRange(F, 1, 1, 1, 3, 0, 2))
        self.assertEqual(smap.range(3, 5), SourceRange(F, 2, 1, 2, 3, 3, 5))
        self.assertEqual(smap.range(5, 6), SourceRange(F, 2, 3, 3, 1, 5, 6))

    def test_columns_count_code_points_and_bytes_count_utf8(self) -> None:
        text = "é\t\U0001f600x"  # 2 + 1 + 4 + 1 bytes; 4 code points
        smap = SourceMap(text, F)
        self.assertEqual(smap.range(3, 4), SourceRange(F, 1, 4, 1, 5, 7, 8))
        self.assertEqual(smap.range(0, 1), SourceRange(F, 1, 1, 1, 2, 0, 2))

    def test_crlf_counts_as_one_line_break(self) -> None:
        smap = SourceMap("a\r\nb", F)
        self.assertEqual(smap.range(3, 4), SourceRange(F, 2, 1, 2, 2, 3, 4))

    def test_token_ranges_follow_the_text(self) -> None:
        tokens = tokenize("ab = 1\n", F)
        self.assertEqual([(t.start, t.end) for t in tokens[:3]], [(0, 2), (3, 4), (5, 6)])

    def test_errors_carry_the_range_of_the_problem(self) -> None:
        try:
            tokenize('a = 1\nb = "x\\q"\n', F)
        except HclSyntaxError as exc:
            self.assertEqual(exc.code, "lex.invalid_escape")
            self.assertEqual(
                (exc.range.file, exc.range.start_line, exc.range.start_column), (F, 2, 7)
            )
        else:
            self.fail("no error")


class TestRuleRegistry(unittest.TestCase):
    def test_every_rule_code_in_the_package_is_registered_and_every_registered_code_is_used(
        self,
    ) -> None:
        package = Path(__file__).resolve().parents[2] / "core" / "terraform_model" / "hcl"
        used: set[str] = set()
        for name in ("lexer.py", "parser.py"):
            text = (package / name).read_text("utf-8")
            used |= set(re.findall(r'"((?:lex|parse|limit)\.[a-z0-9_]+)"', text))
        self.assertLessEqual(used, set(RULES), "a rule code is raised but not registered")
        self.assertEqual(set(RULES) - used, set(), "a registered rule code is never raised")
        lexer_codes = {code for code in RULES if code.startswith("lex.")}
        lexer_used = set(
            re.findall(r'"(lex\.[a-z0-9_]+)"', (package / "lexer.py").read_text("utf-8"))
        )
        self.assertEqual(lexer_codes, lexer_used)


if __name__ == "__main__":
    unittest.main()
