"""Frozen identifier tables (P3a-2 step 1; C-101).

Terraform 1.15.8 is built with hashicorp/hcl v2.24.0 (go.mod of hashicorp/terraform at tag v1.15.8,
line 36), whose ``hclsyntax/unicode_derived.rl`` was generated from Unicode 9.0.0. The lexer reads
the committed tables in ``unicode_tables.py`` and never the interpreter's ``unicodedata``, so a
result cannot depend on the Python version.
"""

from __future__ import annotations

import ast
import importlib.util
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from core.terraform_model.hcl import lexer, unicode_tables
from core.terraform_model.hcl.errors import HclSyntaxError
from core.terraform_model.hcl.lexer import T, is_id_continue, is_id_start, tokenize

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "core" / "terraform_model"

# Counts of ID_Start and ID_Continue code points in the Unicode 9.0.0 DerivedCoreProperties.txt
# (https://www.unicode.org/Public/9.0.0/ucd/DerivedCoreProperties.txt, read on 25 Oct 2026). The
# generator's result was compared with that file code point by code point: no difference.
UCD_9_ID_START_COUNT = 117_007
UCD_9_ID_CONTINUE_COUNT = 119_691


def load_generator():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location(
        "generate_unicode_tables", ROOT / "scripts" / "generate_unicode_tables.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def count(ranges: tuple[tuple[int, int], ...]) -> int:
    return sum(high - low + 1 for low, high in ranges)


class TestTheLexerDoesNotUseTheInterpretersUnicode(unittest.TestCase):
    def test_no_module_of_the_package_imports_unicodedata(self) -> None:
        for path in sorted(PACKAGE.rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names: list[str] = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom):
                    names = [node.module or ""]
                with self.subTest(file=path.name):
                    self.assertNotIn("unicodedata", names)
            with self.subTest(file=path.name, attribute="unidata_version"):
                self.assertNotIn("unidata_version", path.read_text(encoding="utf-8"))

    def test_results_do_not_change_with_the_interpreters_unicode_version(self) -> None:
        samples = [chr(c) for c in (0xE9, 0x3B1, 0x1E900, 0x870, 0x11A00)] + [
            "a" + chr(0x301),
            "x" + chr(0x1E900) + "y",
            "a" + chr(0xB7) + "b",
        ]
        before = [self.outcome(text) for text in samples]
        with (
            mock.patch.object(unicodedata, "unidata_version", "1.0.0"),
            mock.patch.object(unicodedata, "category", side_effect=AssertionError("used")),
            mock.patch.object(unicodedata, "name", side_effect=AssertionError("used")),
        ):
            after = [self.outcome(text) for text in samples]
        self.assertEqual(before, after)

    @staticmethod
    def outcome(text: str) -> object:
        try:
            return [(t.kind, t.value) for t in tokenize(text, "t.tf")]
        except HclSyntaxError as exc:
            return exc.code


class TestTheFrozenTables(unittest.TestCase):
    def test_header_names_the_source_and_its_hash(self) -> None:
        header = Path(unicode_tables.__file__).read_text(encoding="utf-8").split('"""')[1]
        for fragment in (
            "github.com/hashicorp/hcl",
            "v2.24.0",
            "hclsyntax/unicode_derived.rl",
            "9.0.0",
            "hclsyntax/scan_tokens.rl line 46",
            unicode_tables.SOURCE_SHA256,
        ):
            self.assertIn(fragment, header)
        self.assertEqual(
            unicode_tables.SOURCE_SHA256,
            "c519389245d3f319479d8e262994d98cb055db657a486b83d7d99b3656c1e561",
        )
        self.assertEqual(unicode_tables.SOURCE_UNICODE_VERSION, "9.0.0")

    def test_the_generator_pins_the_same_source(self) -> None:
        generator = load_generator()
        self.assertEqual(generator.EXPECTED_SHA256, unicode_tables.SOURCE_SHA256)
        self.assertEqual(generator.SOURCE_TAG, "v2.24.0")

    def test_the_ranges_are_sorted_disjoint_and_inside_unicode(self) -> None:
        for name in ("ID_START", "ID_CONTINUE"):
            ranges = getattr(unicode_tables, name)
            with self.subTest(table=name):
                for low, high in ranges:
                    self.assertLessEqual(low, high)
                    self.assertLessEqual(high, 0x10FFFF)
                    self.assertFalse(0xD800 <= low <= 0xDFFF or 0xD800 <= high <= 0xDFFF)
                for (_, previous_high), (low, _) in zip(ranges, ranges[1:], strict=False):
                    self.assertLess(previous_high + 1, low, "adjacent ranges must be merged")

    def test_id_start_is_inside_id_continue(self) -> None:
        for low, high in unicode_tables.ID_START:
            for point in (low, high):
                self.assertTrue(
                    any(a <= point <= b for a, b in unicode_tables.ID_CONTINUE), hex(point)
                )

    def test_the_counts_equal_those_of_the_unicode_9_data_file(self) -> None:
        self.assertEqual(count(unicode_tables.ID_START), UCD_9_ID_START_COUNT)
        self.assertEqual(count(unicode_tables.ID_CONTINUE), UCD_9_ID_CONTINUE_COUNT)

    def test_characters_added_after_unicode_9_are_not_identifier_characters(self) -> None:
        # Measured on Terraform 1.15.8 with `terraform validate` (scratch directory): the first two
        # are accepted, the others are rejected.
        accepted = (0x1E900, 0x11700, 0x10B00)
        rejected = (0x11A00, 0x10D00, 0x1E100, 0x10E80, 0x30000, 0x0870, 0x11F04, 0x0378)
        for point in accepted:
            with self.subTest(accepted=hex(point)):
                self.assertTrue(is_id_start(chr(point)))
                self.assertTrue(is_id_continue(chr(point)))
        for point in rejected:
            with self.subTest(rejected=hex(point)):
                self.assertFalse(is_id_start(chr(point)))
                self.assertFalse(is_id_continue(chr(point)))
                with self.assertRaises(HclSyntaxError) as caught:
                    tokenize(f"a{chr(point)} = 1", "t.tf")
                self.assertEqual(caught.exception.code, "lex.invalid_character")

    def test_ascii_rules_of_the_scanner(self) -> None:
        # scan_tokens.rl line 46: Ident = (ID_Start | '_') (ID_Continue | '-')*
        for ch in ("a", "Z", "_"):
            self.assertTrue(is_id_start(ch))
        for ch in ("0", "9", "-", ".", " ", "$"):
            self.assertFalse(is_id_start(ch))
        for ch in ("a", "0", "_", "-"):
            self.assertTrue(is_id_continue(ch))
        for ch in (".", " ", "$", "~"):
            self.assertFalse(is_id_continue(ch))

    def test_marks_and_digits_continue_but_do_not_start(self) -> None:
        for point in (0x0301, 0x0663, 0x00B7, 0x0387):  # Mn, Nd, and two Other_ID_Continue
            with self.subTest(point=hex(point)):
                self.assertFalse(is_id_start(chr(point)))
                self.assertTrue(is_id_continue(chr(point)))

    def test_the_lexer_reads_the_table_not_a_copy(self) -> None:
        self.assertIs(lexer.ID_START, unicode_tables.ID_START)
        self.assertEqual(lexer.tokenize("\U0001e900x", "t.tf")[0].kind, T.IDENT)


class TestTheGenerator(unittest.TestCase):
    def setUp(self) -> None:
        self.generator = load_generator()

    def test_single_byte_and_multi_byte_alternatives(self) -> None:
        g = self.generator
        self.assertEqual(g.code_points([(0x41, 0x5A)]), set(range(0x41, 0x5B)))
        self.assertEqual(g.code_points([(0xC2, 0xC2), (0xAA, 0xAA)]), {0xAA})
        self.assertEqual(g.code_points([(0xE2, 0xE2), (0x84, 0x84), (0x98, 0x98)]), {0x2118})
        self.assertEqual(
            g.code_points([(0xF0, 0xF0), (0x90, 0x90), (0x80, 0x80), (0x80, 0x8B)]),
            set(range(0x10000, 0x1000C)),
        )

    def test_loose_trailing_ranges_keep_only_well_formed_sequences(self) -> None:
        g = self.generator
        # 0xC4..0xC5 0x00..0xFF is U+0100..U+017F once only continuation bytes are kept.
        self.assertEqual(g.code_points([(0xC4, 0xC5), (0x00, 0xFF)]), set(range(0x100, 0x180)))

    def test_overlong_and_surrogate_forms_are_not_characters(self) -> None:
        g = self.generator
        self.assertEqual(
            g.code_points([(0xE0, 0xE0), (0x00, 0xFF), (0x00, 0xFF)]), set(range(0x800, 0x1000))
        )
        points = g.code_points([(0xED, 0xED), (0x00, 0xFF), (0x00, 0xFF)])
        self.assertEqual(points, set(range(0xD000, 0xD800)))
        self.assertEqual(g.code_points([(0xC0, 0xC1), (0x80, 0xBF)]), set())
        self.assertEqual(
            g.code_points([(0xF4, 0xF4), (0x90, 0xBF), (0x80, 0xBF), (0x80, 0xBF)]), set()
        )

    def test_ranges_are_merged(self) -> None:
        self.assertEqual(self.generator.to_ranges({1, 2, 3, 7, 9, 10}), [(1, 3), (7, 7), (9, 10)])

    def test_machine_text_is_parsed_with_comments_and_bars(self) -> None:
        text = (
            "    ID_Start = \n"
            "        0x41..0x5A              #L&  [26] LATIN\n"
            "      | 0xC2 0xAA               #Lo       FEMININE\n"
            "      ;\n"
            "    ID_Continue = \n"
            "        0x30..0x39              #Nd\n"
            "      ;\n"
        )
        g = self.generator
        self.assertEqual(
            g.machine_lines(text, "ID_Start"), [[(0x41, 0x5A)], [(0xC2, 0xC2), (0xAA, 0xAA)]]
        )
        self.assertEqual(g.machine_lines(text, "ID_Continue"), [[(0x30, 0x39)]])

    def test_a_different_source_file_is_refused(self) -> None:
        import tempfile

        g = self.generator
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "unicode_derived.rl")
            path.write_bytes(b"not the file")
            self.assertEqual(g.main([str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
