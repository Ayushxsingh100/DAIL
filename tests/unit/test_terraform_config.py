"""Configuration loader and structural validation (P3a-1 step 4; Doc 04 §4, §17, §18; C-92 to C-94).

Expected values are written by hand from the register rows C-92 to C-94 and the Terraform 1.15.x
documentation pages that the loader cites. Every structural rule has a negative test.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import tempfile
import unittest
from collections.abc import Callable, Iterator
from decimal import Decimal
from pathlib import Path
from typing import Any
from unittest import mock

from core.domain.errors import DomainValidationError, UnauthorizedConstructionError
from core.terraform_model import config as cfg
from core.terraform_model.config import (
    MAX_BLOCKS,
    MAX_FILE_BYTES,
    PARSER_VERSION,
    Declaration,
    Diagnostic,
    DiagnosticSeverity,
    ParsedConfiguration,
    ParseOutcome,
    ParseStatus,
    ResourceDecl,
    load_configuration,
)
from core.terraform_model.hcl.ast import (
    Attribute,
    Block,
    FunctionCall,
    Literal,
    LiteralKind,
    ScopeTraversal,
    Template,
    Tuple,
)
from core.terraform_model.hcl.parser import MAX_NESTING_DEPTH

OK = ParseStatus.OK
INVALID = ParseStatus.INVALID
UNSUPPORTED = ParseStatus.UNSUPPORTED


class DirectoryCase(unittest.TestCase):
    """Builds a scratch directory from {name: text-or-bytes} and loads it."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)

    def write(self, files: dict[str, str | bytes]) -> Path:
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
        return self.root

    def load(self, files: dict[str, str | bytes]) -> ParseOutcome:
        return load_configuration(self.write(files))

    def codes(self, outcome: ParseOutcome) -> list[str]:
        return [d.code for d in outcome.diagnostics]

    def config(self, outcome: ParseOutcome) -> ParsedConfiguration:
        self.assertEqual(outcome.status, OK, outcome.diagnostics)
        assert outcome.configuration is not None
        return outcome.configuration


MAIN = 'resource "aws_vpc" "main" {\n  cidr_block = "10.0.0.0/16"\n}\n'


class TestOutcomeModel(DirectoryCase):
    def test_ok_outcome(self) -> None:
        outcome = self.load({"main.tf": MAIN})
        self.assertEqual(outcome.status, OK)
        self.assertEqual(outcome.diagnostics, ())
        self.assertIsNotNone(outcome.configuration)
        self.assertEqual(outcome.parser_version, PARSER_VERSION)

    def test_status_values_equal_their_names(self) -> None:
        for status in ParseStatus:
            self.assertEqual(status.value, status.name)
        self.assertEqual({s.name for s in ParseStatus}, {"OK", "INVALID", "UNSUPPORTED"})

    def test_a_syntax_error_is_invalid_and_has_no_configuration(self) -> None:
        outcome = self.load({"main.tf": 'resource "a" "b" {\n  x = (\n}\n'})
        self.assertEqual(outcome.status, INVALID)
        self.assertIsNone(outcome.configuration)
        (diagnostic,) = outcome.diagnostics
        self.assertEqual(diagnostic.severity, DiagnosticSeverity.INVALID)
        self.assertEqual((diagnostic.file, diagnostic.line), ("main.tf", 3))
        self.assertTrue(diagnostic.code.startswith("parse."))

    def test_diagnostics_carry_file_line_column_and_a_rule_code(self) -> None:
        outcome = self.load({"main.tf": "locals {\n  a = 1 +\n}\n"})
        (diagnostic,) = outcome.diagnostics
        self.assertEqual(
            (diagnostic.file, diagnostic.line, diagnostic.column, diagnostic.code),
            ("main.tf", 2, 10, "parse.expected_expression"),
        )

    def test_no_partial_configuration_when_one_file_fails(self) -> None:
        outcome = self.load({"a.tf": MAIN, "b.tf": "x = (\n"})
        self.assertEqual(outcome.status, INVALID)
        self.assertIsNone(outcome.configuration)

    def test_invalid_takes_precedence_over_unsupported(self) -> None:
        outcome = self.load({"a.tf": MAIN, "b.tf": "locals {\n a = (\n}\n", "x.tf.json": "{}"})
        self.assertEqual(outcome.status, INVALID)
        self.assertIsNone(outcome.configuration)
        severities = {d.severity for d in outcome.diagnostics}
        self.assertEqual(severities, {DiagnosticSeverity.INVALID, DiagnosticSeverity.UNSUPPORTED})

    def test_a_structural_error_beside_a_limit_is_still_invalid(self) -> None:
        text = "locals {}\n" * (MAX_BLOCKS + 1) + 'variable "v" {}\nvariable "v" {}\n'
        outcome = self.load({"main.tf": text})
        self.assertEqual(outcome.status, INVALID)
        self.assertIn("limit.block_count", self.codes(outcome))
        self.assertIn("struct.duplicate_address", self.codes(outcome))

    def test_diagnostics_are_sorted_by_file_line_column_code(self) -> None:
        outcome = self.load(
            {
                "b.tf": 'variable "v" {}\nvariable "v" {}\nvariable "w" {}\nvariable "w" {}\n',
                "a.tf": 'output "o" {}\noutput "o" {}\n',
            }
        )
        keys = [(d.file, d.line, d.column, d.code) for d in outcome.diagnostics]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual([d.file for d in outcome.diagnostics], ["a.tf", "b.tf", "b.tf"])
        self.assertEqual([d.line for d in outcome.diagnostics], [2, 2, 4])

    def test_a_directory_that_does_not_exist_is_invalid_not_an_exception(self) -> None:
        outcome = load_configuration(self.root / "missing")
        self.assertEqual(outcome.status, INVALID)
        self.assertEqual(self.codes(outcome), ["input.directory_unreadable"])

    def test_a_file_given_as_the_directory_is_invalid(self) -> None:
        self.write({"main.tf": MAIN})
        outcome = load_configuration(self.root / "main.tf")
        self.assertEqual(outcome.status, INVALID)

    def test_an_empty_directory_is_invalid(self) -> None:
        outcome = load_configuration(self.root)
        self.assertEqual(outcome.status, INVALID)
        self.assertEqual(self.codes(outcome), ["input.no_configuration_files"])

    def test_a_directory_with_no_tf_files_is_invalid(self) -> None:
        outcome = self.load({"README.md": "x", "sub/main.tf": MAIN})
        self.assertEqual(outcome.status, INVALID)
        self.assertEqual(self.codes(outcome), ["input.no_configuration_files"])

    def test_an_unreadable_file_is_invalid(self) -> None:
        self.write({"main.tf": MAIN})
        original = Path.open

        def failing(self: Path, *args: Any, **kwargs: Any) -> Any:
            if self.name == "main.tf":
                raise PermissionError(13, "Permission denied")
            return original(self, *args, **kwargs)

        with mock.patch.object(Path, "open", failing):
            outcome = load_configuration(self.root)
        self.assertEqual(outcome.status, INVALID)
        self.assertEqual(self.codes(outcome), ["input.file_unreadable"])

    def test_an_unexpected_error_inside_the_parser_is_never_ok_and_never_raised(self) -> None:
        self.write({"main.tf": MAIN})
        with mock.patch.object(cfg, "parse_file", side_effect=ValueError("boom")):
            outcome = load_configuration(self.root)
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertEqual(self.codes(outcome), ["internal.loader_error"])
        self.assertIsNone(outcome.configuration)

    def test_stack_and_memory_exhaustion_are_unsupported_not_crashes(self) -> None:
        self.write({"main.tf": MAIN})
        for error, code in (
            (RecursionError(), "limit.nesting_depth"),
            (MemoryError(), "limit.memory"),
        ):
            with self.subTest(error=type(error).__name__):
                with mock.patch.object(cfg, "parse_file", side_effect=error):
                    outcome = load_configuration(self.root)
                self.assertEqual(outcome.status, UNSUPPORTED)
                self.assertEqual(self.codes(outcome), [code])
                self.assertIsNone(outcome.configuration)


class TestConstructionGuard(DirectoryCase):
    """``OK`` is a trust claim: only the loader can make an outcome or a configuration."""

    def test_direct_construction_of_an_outcome_is_refused(self) -> None:
        good = self.load({"main.tf": MAIN})
        with self.assertRaises(UnauthorizedConstructionError):
            ParseOutcome(OK, (), good.configuration, PARSER_VERSION)
        with self.assertRaises(UnauthorizedConstructionError):
            ParseOutcome(OK, (), good.configuration, PARSER_VERSION, object())  # type: ignore[call-arg]

    def test_direct_construction_of_a_configuration_is_refused(self) -> None:
        good = self.config(self.load({"main.tf": MAIN}))
        fields = {f.name: getattr(good, f.name) for f in dataclasses.fields(good)}
        with self.assertRaises(UnauthorizedConstructionError):
            ParsedConfiguration(**fields)

    def test_replace_cannot_forge_an_outcome(self) -> None:
        bad = self.load({"main.tf": "x = (\n"})
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(bad, status=OK)
        good = self.load({"main.tf": MAIN})
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(good, configuration=None)

    def test_an_outcome_cannot_be_changed_in_place(self) -> None:
        outcome = self.load({"main.tf": MAIN})
        with self.assertRaises(dataclasses.FrozenInstanceError):
            outcome.status = INVALID  # type: ignore[misc]
        with self.assertRaises(dataclasses.FrozenInstanceError):
            outcome.configuration = None  # type: ignore[misc]

    def test_the_outcome_checks_its_own_consistency_even_with_the_token(self) -> None:
        # Defence in depth: even code that holds the token cannot build an outcome that claims
        # OK without a configuration, a configuration with a failure, or a status that the
        # diagnostics do not imply.
        token = cfg._LOADER_TOKEN
        good = self.config(self.load({"main.tf": MAIN}))
        failure = Diagnostic(
            DiagnosticSeverity.INVALID, "parse.expected_expression", "x", "a.tf", 1, 1
        )
        unsupported = Diagnostic(DiagnosticSeverity.UNSUPPORTED, "limit.file_size", "x", "a.tf")
        construct = Diagnostic(
            DiagnosticSeverity.UNSUPPORTED_CONSTRUCT, "construct.provisioner", "x"
        )
        cases: list[Callable[[], ParseOutcome]] = [
            lambda: ParseOutcome(OK, (), None, PARSER_VERSION, token),
            lambda: ParseOutcome(OK, (failure,), good, PARSER_VERSION, token),
            lambda: ParseOutcome(INVALID, (failure,), good, PARSER_VERSION, token),
            lambda: ParseOutcome(UNSUPPORTED, (failure,), None, PARSER_VERSION, token),
            lambda: ParseOutcome(INVALID, (unsupported,), None, PARSER_VERSION, token),
            lambda: ParseOutcome(INVALID, (), None, PARSER_VERSION, token),
            lambda: ParseOutcome("OK", (), good, PARSER_VERSION, token),  # type: ignore[arg-type]
            lambda: ParseOutcome(INVALID, (failure, unsupported), None, PARSER_VERSION, token),
        ]
        for index, build in enumerate(cases):
            with self.subTest(case=index), self.assertRaises(DomainValidationError):
                build()
        # An UNSUPPORTED_CONSTRUCT finding does not change an OK outcome.
        ok = ParseOutcome(OK, (construct,), good, PARSER_VERSION, token)
        self.assertEqual(ok.status, OK)

    def test_mappings_of_a_configuration_are_immutable(self) -> None:
        config = self.config(self.load({"main.tf": MAIN + 'variable "v" {}\n'}))
        for name in (
            "files",
            "bodies",
            "resources",
            "data_sources",
            "variables",
            "locals",
            "outputs",
            "modules",
        ):
            with self.subTest(name=name), self.assertRaises(TypeError):
                getattr(config, name)["x"] = 1
        with self.assertRaises(dataclasses.FrozenInstanceError):
            config.files = {}  # type: ignore[misc]


class TestFilesHashesAndOrder(DirectoryCase):
    def test_files_are_read_in_byte_wise_sorted_order(self) -> None:
        names = ["b.tf", "a.tf", "C.tf", "_x.tf", "é.tf", "a1.tf", "a.tf.tf"]
        outcome = self.load(
            {name: f'variable "{name[0:1].lower()}{i}" {{}}\n' for i, name in enumerate(names)}
        )
        config = self.config(outcome)
        self.assertEqual(
            list(config.files),
            ["C.tf", "_x.tf", "a.tf", "a.tf.tf", "a1.tf", "b.tf", "é.tf"],
        )

    def test_only_tf_files_directly_in_the_directory_are_read(self) -> None:
        outcome = self.load(
            {
                "main.tf": MAIN,
                "notes.md": "x = (",
                "main.tf.bak": "x = (",
                "UPPER.TF": "x = (",
                "sub/inner.tf": "x = (",
                "dir.tf/inner.tf": "x = (",
                "main.tfvars": "x = 1",
            }
        )
        self.assertEqual(list(self.config(outcome).files), ["main.tf"])

    def test_file_hash_is_the_sha256_of_the_raw_bytes(self) -> None:
        raw = b'variable "a" {}\r\n# \xc3\xa9\r\n'
        config = self.config(self.load({"main.tf": raw}))
        self.assertEqual(config.files["main.tf"], hashlib.sha256(raw).hexdigest())

    def test_crlf_and_lf_copies_hash_differently(self) -> None:
        crlf = self.config(self.load({"main.tf": 'variable "a" {}\r\n'}))
        with tempfile.TemporaryDirectory() as other:
            Path(other, "main.tf").write_bytes(b'variable "a" {}\n')
            lf = self.config(load_configuration(Path(other)))
        self.assertNotEqual(crlf.files["main.tf"], lf.files["main.tf"])
        self.assertNotEqual(crlf.configuration_hash, lf.configuration_hash)

    def test_configuration_hash_is_the_hash_of_the_sorted_name_hash_pairs(self) -> None:
        config = self.config(self.load({"b.tf": 'variable "b" {}\n', "a.tf": 'variable "a" {}\n'}))
        pairs = [
            ["a.tf", hashlib.sha256(b'variable "a" {}\n').hexdigest()],
            ["b.tf", hashlib.sha256(b'variable "b" {}\n').hexdigest()],
        ]
        canonical = json.dumps(pairs, sort_keys=True, separators=(",", ":"))
        self.assertEqual(config.configuration_hash, hashlib.sha256(canonical.encode()).hexdigest())

    def test_configuration_hash_changes_with_any_file(self) -> None:
        one = self.config(self.load({"a.tf": 'variable "a" {}\n'}))
        with tempfile.TemporaryDirectory() as other:
            Path(other, "a.tf").write_bytes(b'variable "a" {}\n')
            Path(other, "b.tf").write_bytes(b"\n")
            two = self.config(load_configuration(Path(other)))
        self.assertNotEqual(one.configuration_hash, two.configuration_hash)
        with tempfile.TemporaryDirectory() as renamed:
            Path(renamed, "z.tf").write_bytes(b'variable "a" {}\n')
            three = self.config(load_configuration(Path(renamed)))
        self.assertEqual(one.files["a.tf"], three.files["z.tf"])
        self.assertNotEqual(one.configuration_hash, three.configuration_hash)


class TestInputSubset(DirectoryCase):
    """C-93: *.tf.json, override files and files that are not valid UTF-8 are UNSUPPORTED."""

    def test_tf_json_files_are_unsupported_and_named(self) -> None:
        outcome = self.load({"main.tf": MAIN, "extra.tf.json": "{}"})
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertIsNone(outcome.configuration)
        (diagnostic,) = outcome.diagnostics
        self.assertEqual((diagnostic.code, diagnostic.file), ("input.tf_json", "extra.tf.json"))
        self.assertIn("extra.tf.json", diagnostic.message)

    def test_only_a_tf_json_file_is_unsupported_not_empty(self) -> None:
        outcome = self.load({"main.tf.json": "{}"})
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertEqual(self.codes(outcome), ["input.tf_json"])

    def test_override_files_are_unsupported_and_named(self) -> None:
        for name in (
            "override.tf",
            "x_override.tf",
            "_override.tf",
            "override.tf.json",
            "x_override.tf.json",
        ):
            with self.subTest(name=name):
                with tempfile.TemporaryDirectory() as directory:
                    Path(directory, "main.tf").write_text(MAIN, encoding="utf-8")
                    Path(directory, name).write_text(
                        "{}" if name.endswith("json") else MAIN, "utf-8"
                    )
                    outcome = load_configuration(Path(directory))
                self.assertEqual(outcome.status, UNSUPPORTED)
                self.assertIsNone(outcome.configuration)
                (diagnostic,) = outcome.diagnostics
                self.assertEqual((diagnostic.code, diagnostic.file), ("input.override_file", name))

    def test_names_that_only_look_like_override_files_are_ordinary(self) -> None:
        outcome = self.load(
            {
                "overrides.tf": 'variable "a" {}\n',
                "my_override_x.tf": 'variable "b" {}\n',
                "override_.tf": 'variable "c" {}\n',
            }
        )
        self.assertEqual(outcome.status, OK)

    def test_a_byte_order_mark_is_invalid(self) -> None:
        # The pinned spec: "UTF-8 encoded Unicode byte order marks are not permitted" (C-93).
        outcome = self.load({"main.tf": b"\xef\xbb\xbf" + MAIN.encode()})
        self.assertEqual(outcome.status, INVALID)
        (diagnostic,) = outcome.diagnostics
        self.assertEqual((diagnostic.code, diagnostic.file), ("input.byte_order_mark", "main.tf"))
        self.assertEqual((diagnostic.line, diagnostic.column), (1, 1))

    def test_invalid_utf8_is_unsupported_with_its_position(self) -> None:
        outcome = self.load({"main.tf": b'# ok\nlocals {\n  a = "\xff"\n}\n'})
        self.assertEqual(outcome.status, UNSUPPORTED)
        (diagnostic,) = outcome.diagnostics
        self.assertEqual(diagnostic.code, "input.invalid_utf8")
        self.assertEqual((diagnostic.file, diagnostic.line, diagnostic.column), ("main.tf", 3, 8))

    def test_other_invalid_encodings_are_unsupported(self) -> None:
        for raw in (b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82", b"\x80"):
            with self.subTest(raw=raw):
                with tempfile.TemporaryDirectory() as directory:
                    Path(directory, "main.tf").write_bytes(b"# " + raw + b"\n")
                    outcome = load_configuration(Path(directory))
                self.assertEqual(outcome.status, UNSUPPORTED)
                self.assertEqual(self.codes(outcome), ["input.invalid_utf8"])

    def test_utf16_text_is_not_accepted(self) -> None:
        outcome = self.load({"main.tf": MAIN.encode("utf-16")})
        self.assertNotEqual(outcome.status, OK)
        self.assertIsNone(outcome.configuration)

    def test_non_ascii_text_is_read_as_utf8(self) -> None:
        config = self.config(self.load({"main.tf": 'variable "é" {}\n# €\n'.encode()}))
        self.assertIn("é", config.variables)


class TestLimits(DirectoryCase):
    """C-93: each limit passes exactly at the limit and is UNSUPPORTED one beyond it."""

    def test_file_size_limit(self) -> None:
        at_limit = "locals {}\n" + "#" * (MAX_FILE_BYTES - len("locals {}\n"))
        self.assertEqual(len(at_limit.encode()), MAX_FILE_BYTES)
        self.assertEqual(self.load({"main.tf": at_limit}).status, OK)
        beyond = at_limit + "#"
        with tempfile.TemporaryDirectory() as directory:
            # write_bytes: text mode would turn the newline into CRLF on Windows (one byte more)
            Path(directory, "main.tf").write_bytes(beyond.encode("utf-8"))
            outcome = load_configuration(Path(directory))
        self.assertEqual(len(beyond.encode("utf-8")), MAX_FILE_BYTES + 1)
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertIsNone(outcome.configuration)
        self.assertEqual(self.codes(outcome), ["limit.file_size"])

    def test_the_file_size_limit_counts_bytes_not_characters(self) -> None:
        text = "locals {}\n# " + "é" * ((MAX_FILE_BYTES - 12) // 2) + "\n"
        self.assertLessEqual(len(text), MAX_FILE_BYTES)
        self.assertGreater(len(text.encode()), MAX_FILE_BYTES - 2)
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "main.tf").write_bytes(text.encode() + b"##")
            outcome = load_configuration(Path(directory))
        self.assertEqual(outcome.status, UNSUPPORTED)

    def test_nesting_depth_limit(self) -> None:
        def nested(depth: int) -> str:
            return "locals { a = " + "[" * depth + "1" + "]" * depth + " }\n"

        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "main.tf").write_text(nested(MAX_NESTING_DEPTH), encoding="utf-8")
            self.assertEqual(load_configuration(Path(directory)).status, OK)
            Path(directory, "main.tf").write_text(nested(MAX_NESTING_DEPTH + 1), encoding="utf-8")
            outcome = load_configuration(Path(directory))
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertIsNone(outcome.configuration)
        self.assertEqual(self.codes(outcome), ["limit.nesting_depth"])

    def test_nesting_depth_limit_for_blocks(self) -> None:
        def nested(depth: int) -> str:
            return 'resource "t" "n" {\n' + "x {\n" * (depth - 1) + "}\n" * (depth - 1) + "}\n"

        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "main.tf").write_text(nested(MAX_NESTING_DEPTH), encoding="utf-8")
            self.assertEqual(load_configuration(Path(directory)).status, OK)
            Path(directory, "main.tf").write_text(nested(MAX_NESTING_DEPTH + 1), encoding="utf-8")
            self.assertEqual(load_configuration(Path(directory)).status, UNSUPPORTED)

    def test_block_count_limit_across_files(self) -> None:
        half = MAX_BLOCKS // 2
        files = {"a.tf": "locals {}\n" * half, "b.tf": "locals {}\n" * half}
        self.assertEqual(self.load(files).status, OK)
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "a.tf").write_text("locals {}\n" * half, encoding="utf-8")
            Path(directory, "b.tf").write_text("locals {}\n" * (half + 1), encoding="utf-8")
            outcome = load_configuration(Path(directory))
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertIsNone(outcome.configuration)
        self.assertEqual(self.codes(outcome), ["limit.block_count"])
        self.assertEqual(outcome.diagnostics[0].file, "b.tf")

    def test_block_count_includes_nested_blocks(self) -> None:
        # 2,500 resources x (1 + 3 nested blocks) = 10,000 blocks; one more block is too many.
        body = 'resource "t" "n%d" {\n  a {}\n  b {}\n  c {}\n}\n'
        text = "".join(body % i for i in range(MAX_BLOCKS // 4))
        self.assertEqual(self.load({"main.tf": text}).status, OK)
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "main.tf").write_text(text + "locals {}\n", encoding="utf-8")
            outcome = load_configuration(Path(directory))
        self.assertEqual(outcome.status, UNSUPPORTED)
        self.assertEqual(self.codes(outcome), ["limit.block_count"])

    def test_a_limit_in_one_file_does_not_hide_a_syntax_error_in_another(self) -> None:
        outcome = self.load({"a.tf": "locals { a = " + "[" * 100 + " }\n", "b.tf": "x = (\n"})
        self.assertEqual(outcome.status, INVALID)
        self.assertEqual(sorted(self.codes(outcome))[0], "limit.nesting_depth")


class TestStructuralRules(DirectoryCase):
    """C-94 (and C-96): each rule with a negative test."""

    def invalid_code(self, text: str, expected: str, **others: str) -> None:
        outcome = self.load({"main.tf": text, **others})
        self.assertEqual(outcome.status, INVALID, outcome.diagnostics)
        self.assertIn(expected, self.codes(outcome))
        self.assertIsNone(outcome.configuration)

    def test_unknown_top_level_block_types_are_invalid(self) -> None:
        for kind in ("foo", "list", "dynamic", "lifecycle", "providers", "Resource", "resources"):
            with self.subTest(kind=kind):
                self.invalid_code(f'{kind} "a" {{\n}}\n', "struct.unknown_block_type")

    def test_the_terraform_block_types_are_accepted(self) -> None:
        text = (
            'resource "t" "a" {}\ndata "t" "a" {}\nvariable "v" {}\noutput "o" {}\n'
            'module "m" {}\nprovider "p" {}\nlocals {}\nterraform {}\n'
            "moved {\n from = a.b\n to = a.c\n}\n"
            'ephemeral "t" "e" {}\naction "t" "x" {}\ncheck "c" {}\nimport {}\nremoved {}\n'
        )
        self.assertEqual(self.load({"main.tf": text}).status, OK)

    def test_label_counts(self) -> None:
        expected = {
            "resource": 2,
            "data": 2,
            "variable": 1,
            "output": 1,
            "module": 1,
            "provider": 1,
            "locals": 0,
            "terraform": 0,
            "moved": 0,
            "ephemeral": 2,
            "action": 2,
            "check": 1,
            "import": 0,
            "removed": 0,
        }
        for kind, count in expected.items():
            for given in (count - 1, count + 1, count + 2):
                if given < 0:
                    continue
                labels = " ".join(f'"l{i}"' for i in range(given))
                with self.subTest(kind=kind, labels=given):
                    self.invalid_code(f"{kind} {labels} {{\n}}\n", "struct.label_count")
            labels = " ".join(f'"l{i}"' for i in range(count))
            with self.subTest(kind=kind, labels=count):
                body = "  from = a.b\n  to = a.c\n" if kind == "moved" else ""
                outcome = self.load({"main.tf": f"{kind} {labels} {{\n{body}}}\n"})
                self.assertEqual(outcome.status, OK, outcome.diagnostics)

    def test_labels_may_be_quoted_or_bare_identifiers(self) -> None:
        config = self.config(self.load({"main.tf": 'resource aws_vpc "main" {}\nvariable v {}\n'}))
        self.assertIn(("aws_vpc", "main"), config.resources)
        self.assertIn("v", config.variables)

    def test_a_top_level_argument_is_invalid(self) -> None:
        self.invalid_code("a = 1\n", "struct.top_level_attribute")

    def test_duplicate_attribute_in_a_block(self) -> None:
        self.invalid_code('resource "t" "n" {\n  a = 1\n  a = 2\n}\n', "struct.duplicate_attribute")

    def test_duplicate_attribute_in_a_nested_block(self) -> None:
        text = 'resource "t" "n" {\n  lifecycle {\n    x = 1\n    x = 2\n  }\n}\n'
        self.invalid_code(text, "struct.duplicate_attribute")

    def test_duplicate_attribute_in_a_deeply_nested_block(self) -> None:
        text = (
            'resource "t" "n" {\n  a {\n    b {\n      c {\n'
            "        d = 1\n        d = 2\n      }\n    }\n  }\n}\n"
        )
        self.invalid_code(text, "struct.duplicate_attribute")

    def test_duplicate_attribute_in_a_one_line_block(self) -> None:
        # A one-line block holds one argument, so this is a syntax error; the rule still holds
        # for the multi-line spelling.
        self.invalid_code(
            'resource "t" "n" {\n  a { x = 1 }\n  a = 1\n  a = 2\n}\n', "struct.duplicate_attribute"
        )

    def test_duplicate_attribute_is_reported_at_the_second_definition(self) -> None:
        outcome = self.load({"main.tf": 'resource "t" "n" {\n  a = 1\n  b = 1\n  a = 2\n}\n'})
        (diagnostic,) = outcome.diagnostics
        self.assertEqual((diagnostic.line, diagnostic.column), (4, 3))
        self.assertIn("line 2", diagnostic.message)

    def test_same_name_in_different_bodies_is_not_a_duplicate(self) -> None:
        text = 'resource "t" "n" {\n  a = 1\n  x {\n    a = 1\n  }\n  y {\n    a = 1\n  }\n}\n'
        self.assertEqual(self.load({"main.tf": text}).status, OK)

    def test_a_block_and_an_argument_of_the_same_name_are_both_kept(self) -> None:
        # Registry §2.6 / C-84: ingress { } and ingress = [] are different forms; the loader
        # does not decide between them.
        text = 'resource "aws_security_group" "g" {\n  ingress = []\n  ingress {\n  }\n}\n'
        self.assertEqual(self.load({"main.tf": text}).status, OK)

    def test_duplicate_object_keys_are_not_a_structural_error(self) -> None:
        self.assertEqual(self.load({"main.tf": "locals {\n  a = { k = 1, k = 2 }\n}\n"}).status, OK)

    def test_duplicate_addresses(self) -> None:
        cases = {
            "resource": 'resource "t" "n" {}\nresource "t" "n" {}\n',
            "data": 'data "t" "n" {}\ndata "t" "n" {}\n',
            "variable": 'variable "v" {}\nvariable "v" {}\n',
            "output": 'output "o" {}\noutput "o" {}\n',
            "module": 'module "m" {}\nmodule "m" {}\n',
            "local across blocks": "locals {\n  a = 1\n}\nlocals {\n  a = 2\n}\n",
        }
        for kind, text in cases.items():
            with self.subTest(kind=kind):
                self.invalid_code(text, "struct.duplicate_address")

    def test_duplicate_addresses_across_files(self) -> None:
        self.invalid_code(
            'variable "v" {}\n', "struct.duplicate_address", **{"b.tf": 'variable "v" {}\n'}
        )
        outcome = self.load({"a.tf": 'resource "t" "n" {}\n', "b.tf": 'resource "t" "n" {}\n'})
        (diagnostic,) = outcome.diagnostics
        self.assertEqual((diagnostic.file, diagnostic.line), ("b.tf", 1))
        self.assertIn("a.tf:1", diagnostic.message)

    def test_a_local_defined_twice_in_one_block_is_reported_once(self) -> None:
        outcome = self.load({"main.tf": "locals {\n  a = 1\n  a = 2\n}\n"})
        self.assertEqual(self.codes(outcome), ["struct.duplicate_attribute"])

    def test_names_that_differ_are_not_duplicates(self) -> None:
        text = (
            'resource "t" "n" {}\nresource "t" "m" {}\nresource "u" "n" {}\nresource "t" "N" {}\n'
            'data "t" "n" {}\nvariable "n" {}\noutput "n" {}\nmodule "n" {}\nlocals {\n  n = 1\n}\n'
            'provider "p" {}\nprovider "p" {}\nterraform {}\nterraform {}\n'
        )
        self.assertEqual(self.load({"main.tf": text}).status, OK)

    def test_locals_hold_arguments_only(self) -> None:
        self.invalid_code("locals {\n  a = 1\n  b {\n  }\n}\n", "struct.unexpected_block")

    def test_moved_needs_from_and_to(self) -> None:
        self.invalid_code("moved {\n  to = a.b\n}\n", "struct.moved_missing_argument")
        self.invalid_code("moved {\n  from = a.b\n}\n", "struct.moved_missing_argument")
        self.invalid_code("moved {\n}\n", "struct.moved_missing_argument")
        self.invalid_code(
            "moved {\n  from = a.b\n  to = a.c\n  x {\n  }\n}\n", "struct.unexpected_block"
        )

    def test_every_finding_is_reported_not_just_the_first(self) -> None:
        text = (
            'foo "a" {}\nvariable {}\nvariable "v" {}\nvariable "v" {}\n'
            'resource "t" "n" {\n a = 1\n a = 2\n}\n'
        )
        outcome = self.load({"main.tf": text})
        self.assertEqual(
            sorted(self.codes(outcome)),
            sorted(
                [
                    "struct.unknown_block_type",
                    "struct.label_count",
                    "struct.duplicate_address",
                    "struct.duplicate_attribute",
                ]
            ),
        )


class TestProvisioners(DirectoryCase):
    TEXT = (
        'resource "aws_instance" "app" {\n'
        '  ami = "x"\n'
        '  provisioner "local-exec" {\n'
        '    command = "echo hi"\n'
        "  }\n"
        '  connection {\n    type = "ssh"\n  }\n'
        "}\n"
    )

    def test_a_provisioner_is_kept_and_flagged_without_changing_the_outcome(self) -> None:
        outcome = self.load({"main.tf": self.TEXT})
        self.assertEqual(outcome.status, OK)
        (diagnostic,) = outcome.diagnostics
        self.assertEqual(diagnostic.severity, DiagnosticSeverity.UNSUPPORTED_CONSTRUCT)
        self.assertEqual(diagnostic.code, "construct.provisioner")
        self.assertEqual((diagnostic.file, diagnostic.line, diagnostic.column), ("main.tf", 3, 3))
        resource = self.config(outcome).resources[("aws_instance", "app")]
        self.assertEqual(len(resource.provisioners), 1)
        self.assertEqual(resource.provisioners[0].labels[0].value, "local-exec")
        self.assertEqual(len(resource.connections), 1)

    def test_each_provisioner_is_flagged(self) -> None:
        text = self.TEXT.replace("  connection", '  provisioner "remote-exec" {\n  }\n  connection')
        outcome = self.load({"main.tf": text})
        self.assertEqual(self.codes(outcome), ["construct.provisioner"] * 2)

    def test_a_flagged_construct_does_not_hide_a_failure(self) -> None:
        outcome = self.load({"main.tf": self.TEXT + 'variable "v" {}\nvariable "v" {}\n'})
        self.assertEqual(outcome.status, INVALID)
        self.assertIn("construct.provisioner", self.codes(outcome))
        self.assertIn("struct.duplicate_address", self.codes(outcome))


class TestParsedConfigurationShape(DirectoryCase):
    TEXT = """\
terraform {
  required_version = "~> 1.15.0"
}

provider "aws" {
  region = "us-east-1"
}

provider "aws" {
  alias = "other"
}

variable "env" {
  default = "dev"
}

locals {
  a = 1
  b = local.a + 1
}

locals {
  c = "x"
}

output "vpc" {
  value = aws_vpc.main.id
}

module "child" {
  source = "./child"
}

moved {
  from = aws_vpc.old
  to   = aws_vpc.main
}

check "c" {
  assert {
    condition     = true
    error_message = "x"
  }
}

resource "aws_vpc" "main" {
  count      = 2
  provider   = aws.other
  depends_on = [module.child]
  cidr_block = "10.0.0.0/16"
  lifecycle {
    prevent_destroy = true
  }
  dynamic "tag" {
    for_each = []
    content {}
  }
  tags = {}
}

resource "aws_subnet" "s" {
  for_each = toset(["a", "b"])
}

data "aws_ami" "latest" {
  most_recent = true
}
"""

    def setUp(self) -> None:
        super().setUp()
        self.cfg = self.config(self.load({"main.tf": self.TEXT}))

    def test_top_level_blocks_are_sorted_into_their_collections(self) -> None:
        cfg_ = self.cfg
        self.assertEqual(list(cfg_.resources), [("aws_vpc", "main"), ("aws_subnet", "s")])
        self.assertEqual(list(cfg_.data_sources), [("aws_ami", "latest")])
        self.assertEqual(list(cfg_.variables), ["env"])
        self.assertEqual(list(cfg_.locals), ["a", "b", "c"])
        self.assertEqual(list(cfg_.outputs), ["vpc"])
        self.assertEqual(list(cfg_.modules), ["child"])
        self.assertEqual(len(cfg_.providers), 2)
        self.assertEqual(len(cfg_.terraform_blocks), 1)
        self.assertEqual([d.kind for d in cfg_.other_blocks], ["check"])
        self.assertEqual(len(cfg_.moved), 1)

    def test_resource_labels_and_meta_arguments_are_split_out(self) -> None:
        vpc = self.cfg.resources[("aws_vpc", "main")]
        self.assertEqual(
            (vpc.kind, vpc.type, vpc.name, vpc.file), ("resource", "aws_vpc", "main", "main.tf")
        )
        self.assertEqual([label.value for label in vpc.labels], ["aws_vpc", "main"])
        self.assertIsNotNone(vpc.count)
        self.assertIsNotNone(vpc.provider)
        self.assertIsNotNone(vpc.depends_on)
        self.assertIsNone(vpc.for_each)
        assert vpc.count is not None
        self.assertEqual(vpc.count.expr, Literal(LiteralKind.NUMBER, 2, "2", vpc.count.range))
        self.assertEqual(len(vpc.lifecycle), 1)
        self.assertEqual(vpc.provisioners, ())
        self.assertEqual(vpc.connections, ())

    def test_nothing_is_dropped_from_a_resource(self) -> None:
        vpc = self.cfg.resources[("aws_vpc", "main")]
        kept = [
            item
            for item in (vpc.count, vpc.for_each, vpc.provider, vpc.depends_on)
            if item is not None
        ]
        everything = len(kept) + len(vpc.lifecycle) + len(vpc.provisioners) + len(vpc.connections)
        self.assertEqual(everything + len(vpc.body.items), len(vpc.block.body.items))
        self.assertEqual(
            [item.name for item in vpc.body.items if isinstance(item, Attribute)],
            ["cidr_block", "tags"],
        )

    def test_dynamic_blocks_stay_visible(self) -> None:
        vpc = self.cfg.resources[("aws_vpc", "main")]
        (dynamic,) = vpc.dynamic_blocks
        self.assertEqual(dynamic.type, "dynamic")
        self.assertEqual(dynamic.labels[0].value, "tag")
        self.assertIn(dynamic, vpc.body.items)

    def test_for_each_is_a_meta_argument(self) -> None:
        subnet = self.cfg.resources[("aws_subnet", "s")]
        assert subnet.for_each is not None
        self.assertIsInstance(subnet.for_each.expr, FunctionCall)
        self.assertIsNone(subnet.count)

    def test_data_sources_split_meta_arguments_too(self) -> None:
        ami = self.cfg.data_sources[("aws_ami", "latest")]
        self.assertEqual(ami.kind, "data")
        self.assertEqual(
            [i.name for i in ami.body.items if isinstance(i, Attribute)], ["most_recent"]
        )

    def test_locals_keep_their_expressions(self) -> None:
        local = self.cfg.locals["b"]
        self.assertEqual((local.name, local.file, local.attribute.name), ("b", "main.tf", "b"))
        expr = self.cfg.locals["c"].attribute.expr
        assert isinstance(expr, Literal)
        self.assertEqual((expr.value, expr.text), ("x", '"x"'))

    def test_moved_blocks_keep_from_and_to_as_trees(self) -> None:
        (moved,) = self.cfg.moved
        self.assertIsInstance(moved.from_expr, ScopeTraversal)
        self.assertIsInstance(moved.to_expr, ScopeTraversal)
        assert isinstance(moved.from_expr, ScopeTraversal) and isinstance(
            moved.to_expr, ScopeTraversal
        )
        self.assertEqual(moved.from_expr.root, "aws_vpc")
        self.assertEqual([step.name for step in moved.from_expr.steps], ["old"])  # type: ignore[union-attr]
        self.assertEqual([step.name for step in moved.to_expr.steps], ["main"])  # type: ignore[union-attr]

    def test_declarations_expose_their_name_and_block(self) -> None:
        env = self.cfg.variables["env"]
        self.assertIsInstance(env, Declaration)
        self.assertEqual((env.kind, env.name, env.file), ("variable", "env", "main.tf"))
        self.assertIsInstance(env.block, Block)
        self.assertEqual(self.cfg.terraform_blocks[0].name, "")
        self.assertEqual([d.name for d in self.cfg.providers], ["aws", "aws"])

    def test_the_syntax_trees_of_the_files_are_kept(self) -> None:
        self.assertEqual(list(self.cfg.bodies), ["main.tf"])
        self.assertEqual(len(self.cfg.bodies["main.tf"].items), 13)

    def test_resources_from_several_files_are_combined_in_file_order(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, "b.tf").write_text('resource "t" "b" {}\n', encoding="utf-8")
            Path(directory, "a.tf").write_text('resource "t" "a" {}\n', encoding="utf-8")
            config = self.config(load_configuration(Path(directory)))
        self.assertEqual(list(config.resources), [("t", "a"), ("t", "b")])
        self.assertEqual(config.resources[("t", "a")].file, "a.tf")

    def test_resource_declarations_are_frozen(self) -> None:
        vpc = self.cfg.resources[("aws_vpc", "main")]
        self.assertIsInstance(vpc, ResourceDecl)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            vpc.name = "x"  # type: ignore[misc]


class TestDeterminism(DirectoryCase):
    FILES: dict[str, str | bytes] = {
        "main.tf": MAIN,
        "b.tf": 'variable "b" {}\n',
        "a.tf": 'variable "a" {}\nlocals {\n  x = <<-EOT\n    hi\n    EOT\n}\n',
        "z.tf": 'output "z" {\n  value = [for v in var.l : "${v}"]\n}\n',
    }

    def test_loading_twice_gives_equal_outcomes_and_hashes(self) -> None:
        directory = self.write(self.FILES)
        first = load_configuration(directory)
        second = load_configuration(directory)
        self.assertEqual(first.status, OK)
        self.assertEqual(first, second)
        self.assertEqual(repr(first), repr(second))
        assert first.configuration is not None and second.configuration is not None
        self.assertEqual(
            first.configuration.configuration_hash, second.configuration.configuration_hash
        )

    def test_creation_order_of_the_files_is_irrelevant(self) -> None:
        results = []
        for order in (list(self.FILES), list(reversed(self.FILES)), sorted(self.FILES, key=len)):
            with tempfile.TemporaryDirectory() as directory:
                for name in order:
                    content = self.FILES[name]
                    Path(directory, name).write_bytes(
                        content if isinstance(content, bytes) else content.encode()
                    )
                results.append(load_configuration(Path(directory)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0], results[2])
        self.assertEqual(repr(results[0]), repr(results[1]))
        assert results[0].configuration is not None
        self.assertEqual(list(results[0].configuration.files), ["a.tf", "b.tf", "main.tf", "z.tf"])

    def test_the_directory_name_does_not_matter(self) -> None:
        a = tempfile.TemporaryDirectory(prefix="aaa")
        b = tempfile.TemporaryDirectory(prefix="zzz_longer_name")
        self.addCleanup(a.cleanup)
        self.addCleanup(b.cleanup)
        for directory in (a, b):
            for name, content in self.FILES.items():
                Path(directory.name, name).write_text(str(content), encoding="utf-8")
        self.assertEqual(load_configuration(Path(a.name)), load_configuration(Path(b.name)))

    def test_a_changed_file_changes_the_hashes_and_nothing_else_in_the_hash_set(self) -> None:
        directory = self.write(self.FILES)
        before = self.config(load_configuration(directory))
        Path(directory, "b.tf").write_text('variable "b" {}\n# changed\n', encoding="utf-8")
        after = self.config(load_configuration(directory))
        self.assertNotEqual(before.configuration_hash, after.configuration_hash)
        self.assertEqual(before.files["a.tf"], after.files["a.tf"])
        self.assertNotEqual(before.files["b.tf"], after.files["b.tf"])


def _walk(value: object) -> Iterator[object]:
    """Every value reachable from a syntax tree or configuration (iterative)."""
    stack = [value]
    while stack:
        item = stack.pop()
        yield item
        if dataclasses.is_dataclass(item) and not isinstance(item, type):
            stack.extend(getattr(item, f.name) for f in dataclasses.fields(item))
        elif isinstance(item, tuple | list | set | frozenset):
            stack.extend(item)
        elif isinstance(item, dict) or hasattr(item, "items"):
            for key, member in item.items():  # type: ignore[attr-defined]
                stack.append(key)
                stack.append(member)


class TestNoFloats(DirectoryCase):
    def test_no_float_anywhere_in_a_tree(self) -> None:
        text = (
            "locals {\n  a = 1.5\n  b = 1e3\n  c = 0.1\n  d = 1e-3\n  e = [2.5, 3, {k = 1.25}]\n"
            '  f = "${1.5}"\n  g = f(0.5, 1E+2)\n}\n'
        )
        config = self.config(self.load({"main.tf": text}))
        values = [
            v
            for v in _walk(config)
            if isinstance(v, int | float | Decimal) and not isinstance(v, bool)
        ]
        self.assertTrue(values, "the walk must reach the numbers")
        self.assertEqual([v for v in values if isinstance(v, float)], [])

    def test_decimal_and_int_values(self) -> None:
        config = self.config(self.load({"main.tf": "locals {\n  a = 1.5\n  b = 1e3\n}\n"}))
        a = config.locals["a"].attribute.expr
        b = config.locals["b"].attribute.expr
        assert isinstance(a, Literal) and isinstance(b, Literal)
        self.assertEqual((a.value, type(a.value)), (Decimal("1.5"), Decimal))
        self.assertEqual((b.value, type(b.value)), (1000, int))
        self.assertEqual((a.text, b.text), ("1.5", "1e3"))

    def test_templates_and_tuples_are_reachable_by_the_walker(self) -> None:
        config = self.config(self.load({"main.tf": 'locals {\n  a = "x${1}"\n  b = []\n}\n'}))
        kinds = {type(v) for v in _walk(config)}
        self.assertIn(Template, kinds)
        self.assertIn(Tuple, kinds)


if __name__ == "__main__":
    unittest.main()
