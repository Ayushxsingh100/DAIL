"""Parser and loader fuzzing (P3a-1 step 5; Doc 12 §22 "Parser fuzzing"; Doc 14 §2; C-92, C-93).

Doc 12 §22: "Terraform/HCL ... parsers should receive malformed and boundary inputs: truncated
documents, unexpected nesting, duplicate fields, very large strings, Unicode edge cases, invalid
references, unexpected block types, null/missing fields, deeply nested structures."

Cases start from the canonical fixtures and from small programs and apply those mutations. The
generators are deterministic: they use ``random.Random`` with the fixed seeds in ``SEEDS`` (printed
when the module runs), so a failure names a seed and a case index that reproduce it.

Properties checked for every case:
- ``load_configuration`` returns a ``ParseOutcome`` with a valid status; it never raises
  (``RecursionError`` included) and never hangs: each case runs under a time budget, and a
  watchdog (``faulthandler``) turns an endless loop into a traceback and exit;
- ``configuration`` is present exactly when the status is OK;
- no diagnostic has an ``internal.`` code (an unexpected exception inside the loader);
- when the expected class of the input is known, the status is inside it, in particular an input
  that is certainly INVALID never comes back OK.
"""

from __future__ import annotations

import faulthandler
import os
import random
import tempfile
import time
import unittest
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

from core.terraform_model.config import (
    MAX_FILE_BYTES,
    DiagnosticSeverity,
    ParseOutcome,
    ParseStatus,
    load_configuration,
)
from core.terraform_model.hcl.errors import RULES
from core.terraform_model.hcl.lexer import tokenize
from core.terraform_model.hcl.parser import MAX_NESTING_DEPTH
from tests import fixture_catalog as fc

SEEDS = (20261024, 1, 7, 424242, 99991)
CASE_BUDGET_SECONDS = 20.0
WATCHDOG_SECONDS = 900

OK, INVALID, UNSUPPORTED = ParseStatus.OK, ParseStatus.INVALID, ParseStatus.UNSUPPORTED
NOT_OK = frozenset({INVALID, UNSUPPORTED})
ONLY_INVALID = frozenset({INVALID})
ONLY_UNSUPPORTED = frozenset({UNSUPPORTED})
ONLY_OK = frozenset({OK})

ROOT = fc.REPO_ROOT
FOLDERS = sorted(
    {
        fixture.data[role]
        for fixture in fc.load_all().values()
        for role in ("config", "parent")
        if fixture.data[role] is not None
    }
)


def _read_lf(path: Path) -> bytes:
    """The file with LF line endings, whatever the checkout (git autocrlf) made of it."""
    return path.read_bytes().replace(b"\r\n", b"\n")


MAINS = {folder: _read_lf(ROOT / folder / "main.tf") for folder in FOLDERS}
VERSIONS = _read_lf(ROOT / FOLDERS[0] / "versions.tf")
RICH_FOLDER = "fixtures/identity/ambiguous_identity_uncertain_v1"  # for_each and a template string


@dataclass(frozen=True)
class Case:
    label: str
    files: dict[str, bytes]
    expected: frozenset[ParseStatus] | None = None  # None: any valid status


def with_versions(main: bytes) -> dict[str, bytes]:
    return {"main.tf": main, "versions.tf": VERSIONS}


def text_of(folder: str) -> str:
    return MAINS[folder].decode("utf-8")


# --- generators --------------------------------------------------------------------------------


def truncation_cases() -> list[Case]:
    """Truncation at every token boundary of one fixture (start and end of every token)."""
    text = text_of(RICH_FOLDER)
    offsets = {0, len(text)}
    for token in tokenize(text, "main.tf"):
        offsets.add(token.start)
        offsets.add(token.end)
    cases = []
    for offset in sorted(offsets):
        prefix = text[:offset]
        # An unclosed `{` (the fixture has no braces in comments) can never be valid.
        unclosed = prefix.count("{") > prefix.count("}")
        expected = ONLY_INVALID if unclosed else None
        cases.append(Case(f"truncate@{offset}", with_versions(prefix.encode()), expected))
    return cases


def _body_lines(text: str) -> list[tuple[int, int]]:
    """(line index, brace depth before the line) for lines of a fixture file."""
    out = []
    depth = 0
    for index, line in enumerate(text.split("\n")):
        out.append((index, depth))
        code = line.split("#", 1)[0]
        depth += code.count("{") - code.count("}")
    return out


def _simple_attribute_lines(text: str) -> list[int]:
    lines = text.split("\n")
    picked = []
    for index, depth in _body_lines(text):
        line = lines[index].strip()
        if depth >= 1 and " = " in line and not line.endswith(("{", "[", "(", ",", "<<EOT")):
            picked.append(index)
    return picked


def duplicate_attribute_cases(seed: int, count: int = 20) -> list[Case]:
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        folder = rng.choice(FOLDERS)
        text = text_of(folder)
        lines = text.split("\n")
        index = rng.choice(_simple_attribute_lines(text))
        lines.insert(index + 1, lines[index])
        cases.append(
            Case(
                f"seed{seed}#{i} dup-attribute {folder}:{index + 1}",
                with_versions("\n".join(lines).encode()),
                ONLY_INVALID,
            )
        )
    return cases


def duplicate_block_cases(seed: int, count: int = 10) -> list[Case]:
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        folder = rng.choice(FOLDERS)
        lines = text_of(folder).split("\n")
        starts = [n for n, line in enumerate(lines) if line.startswith("resource ")]
        start = rng.choice(starts)
        end = next(n for n in range(start, len(lines)) if lines[n] == "}")
        block = lines[start : end + 1]
        lines[end + 1 : end + 1] = ["", *block]
        cases.append(
            Case(
                f"seed{seed}#{i} dup-block {folder}:{start + 1}",
                with_versions("\n".join(lines).encode()),
                ONLY_INVALID,
            )
        )
    return cases


UNEXPECTED_TOP_LEVEL = (
    'foo "x" "y" {\n}\n',
    'resources "x" "y" {\n}\n',
    'Resource "x" "y" {\n}\n',
    'dynamic "x" {\n  content {}\n}\n',
    "lifecycle {\n  prevent_destroy = true\n}\n",
    'list "x" "y" {\n}\n',
    'resource "only_one_label" {\n}\n',
    'resource "a" "b" "c" {\n}\n',
    "variable {\n}\n",
    'locals "x" {\n}\n',
    'data "x" {\n}\n',
    "x = 1\n",
    "locals {\n  y {\n  }\n}\n",
    "moved {\n}\n",
)


def unexpected_block_cases(seed: int, count: int = 20) -> list[Case]:
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        folder = rng.choice(FOLDERS)
        lines = text_of(folder).split("\n")
        boundaries = [n for n, depth in _body_lines("\n".join(lines)) if depth == 0]
        at = rng.choice(boundaries)
        lines.insert(at, rng.choice(UNEXPECTED_TOP_LEVEL))
        cases.append(
            Case(
                f"seed{seed}#{i} unexpected-block {folder}:{at + 1}",
                with_versions("\n".join(lines).encode()),
                ONLY_INVALID,
            )
        )
    return cases


NESTING_KINDS: dict[str, Callable[[int], str]] = {
    "tuple": lambda n: "locals { a = " + "[" * n + "1" + "]" * n + " }\n",
    "object": lambda n: "locals { a = " + "{k = " * n + "1" + "}" * n + " }\n",
    "paren": lambda n: "locals { a = " + "(" * n + "1" + ")" * n + " }\n",
    "call": lambda n: "locals { a = " + "f(" * n + "1" + ")" * n + " }\n",
    "unary": lambda n: "locals { a = " + "!" * n + "x }\n",
    "conditional": lambda n: "locals { a = " + "x ? y : " * n + "z }\n",
    "interpolation": lambda n: 'locals { a = "'
    + '${"' * (n - 1)
    + "${1}"
    + '"}' * (n - 1)
    + '" }\n',
    "for": lambda n: "locals { a = " + "[for v in " * n + "x" + " : v]" * n + " }\n",
    "operator chain": lambda n: "locals { a = 1" + " + 1" * n + " }\n",
    "postfix chain": lambda n: "locals { a = f(x)" + ".b" * n + " }\n",
    "block": lambda n: 'resource "t" "n" {\n' + "x {\n" * (n - 1) + "}\n" * (n - 1) + "}\n",
}
NESTING_DEPTHS = (1, 2, 32, 63, 64, 65, 66, 100, 1000, 5000)


def nesting_cases() -> list[Case]:
    cases = []
    for name, build in NESTING_KINDS.items():
        for depth in NESTING_DEPTHS:
            expected = ONLY_OK if depth <= MAX_NESTING_DEPTH else ONLY_UNSUPPORTED
            cases.append(
                Case(f"nesting {name} x{depth}", with_versions(build(depth).encode()), expected)
            )
    return cases


def large_cases() -> list[Case]:
    mib = 1024 * 1024
    pad = "x" * mib
    return [
        Case("1 MiB string", with_versions(f'locals {{ a = "{pad}" }}\n'.encode()), ONLY_OK),
        Case("1 MiB comment", with_versions(f"# {pad}\nlocals {{}}\n".encode()), ONLY_OK),
        Case(
            "1 MiB heredoc line",
            with_versions(f"locals {{\n  a = <<EOT\n{pad}\nEOT\n}}\n".encode()),
            ONLY_OK,
        ),
        Case("1 MiB identifier", with_versions(f"locals {{\n  {pad} = 1\n}}\n".encode()), ONLY_OK),
        Case(
            "exactly 2 MiB",
            with_versions(("locals {}\n" + "#" * (MAX_FILE_BYTES - 10)).encode()),
            ONLY_OK,
        ),
        Case(
            "2 MiB plus one byte",
            with_versions(("locals {}\n" + "#" * (MAX_FILE_BYTES - 9)).encode()),
            ONLY_UNSUPPORTED,
        ),
        Case(
            "1 MiB unterminated string",
            with_versions(f'locals {{ a = "{pad}'.encode()),
            ONLY_INVALID,
        ),
        Case(
            "1 MiB of open brackets",
            with_versions(("locals { a = " + "[" * mib).encode()),
            ONLY_UNSUPPORTED,
        ),
    ]


# (character, expected status when it is inside a string or a comment, in code, after a letter)
UNICODE_CHARS: list[tuple[str, str, frozenset[ParseStatus], frozenset[ParseStatus]]] = [
    ("\x00", "NUL", ONLY_INVALID, ONLY_INVALID),
    ("‮", "bidi override", ONLY_INVALID, ONLY_INVALID),
    ("‍", "zero width joiner", ONLY_INVALID, ONLY_INVALID),
    ("\U0001f600", "emoji", ONLY_INVALID, ONLY_INVALID),
    ("͸", "unassigned", ONLY_UNSUPPORTED, ONLY_UNSUPPORTED),
    ("﻿", "byte order mark", ONLY_INVALID, ONLY_INVALID),
    ("￿", "noncharacter", ONLY_INVALID, ONLY_INVALID),
    (" ", "no-break space", ONLY_INVALID, ONLY_INVALID),
    (" ", "line separator", ONLY_INVALID, ONLY_INVALID),
    ("\u0085", "next line", ONLY_INVALID, ONLY_INVALID),
    ("́", "combining acute", ONLY_INVALID, ONLY_OK),
]


def unicode_cases() -> list[Case]:
    cases = []
    for char, name, in_code, after_letter in UNICODE_CHARS:
        cases.append(
            Case(
                f"unicode {name} in a string",
                with_versions(f'locals {{ a = "x{char}y" }}\n'.encode()),
                ONLY_OK,
            )
        )
        cases.append(
            Case(
                f"unicode {name} in a comment",
                with_versions(f"# x{char}y\nlocals {{}}\n".encode()),
                ONLY_OK,
            )
        )
        cases.append(
            Case(
                f"unicode {name} in a heredoc",
                with_versions(f"locals {{\n a = <<EOT\nx{char}y\nEOT\n}}\n".encode()),
                ONLY_OK,
            )
        )
        cases.append(
            Case(
                f"unicode {name} in code",
                with_versions(f"locals {{ a = 1 {char} }}\n".encode()),
                in_code,
            )
        )
        cases.append(
            Case(
                f"unicode {name} after a letter",
                with_versions(f"locals {{ a{char}b = 1 }}\n".encode()),
                after_letter,
            )
        )
    for escape in (
        r"\uD800",
        r"\uDBFF",
        r"\uDC00",
        r"\uDFFF",
        r"\U0000D800",
        r"\U00110000",
        r"\UFFFFFFFF",
        r"\u12",
        r"\q",
    ):
        cases.append(
            Case(
                f"escape {escape}",
                with_versions(f'locals {{ a = "{escape}" }}\n'.encode()),
                ONLY_INVALID,
            )
        )
    for escape in (r"\u0000", r"퟿", r"", r"￿", r"\U0010FFFF", r"\U00000041"):
        cases.append(
            Case(
                f"escape {escape} is a scalar",
                with_versions(f'locals {{ a = "{escape}" }}\n'.encode()),
                ONLY_OK,
            )
        )
    cases.append(
        Case("lone CR in a string", with_versions(b'locals { a = "x\ry" }\n'), ONLY_INVALID)
    )
    cases.append(
        Case("lone CR as a line end", with_versions(b"locals {\r a = 1\r}\r"), ONLY_INVALID)
    )
    cases.append(
        Case(
            "BOM before a valid file",
            with_versions(b"\xef\xbb\xbf" + MAINS[FOLDERS[0]]),
            ONLY_INVALID,
        )
    )
    return cases


def embedded_unicode_cases(seed: int, count: int = 40) -> list[Case]:
    """Unicode characters dropped into the comment or string positions of a fixture."""
    rng = random.Random(seed)
    cases = []
    safe = [char for char, _, _, _ in UNICODE_CHARS]
    for i in range(count):
        folder = rng.choice(FOLDERS)
        lines = text_of(folder).split("\n")
        comment_lines = [n for n, line in enumerate(lines) if line.startswith("#")]
        n = rng.choice(comment_lines)
        lines[n] = lines[n] + "".join(rng.choice(safe) for _ in range(rng.randint(1, 4)))
        cases.append(
            Case(
                f"seed{seed}#{i} unicode-in-comment {folder}:{n + 1}",
                with_versions("\n".join(lines).encode()),
                ONLY_OK,
            )
        )
    return cases


INVALID_BYTES = [*range(0x80, 0xC2), *range(0xF5, 0x100)]  # no valid lead byte among them


def invalid_utf8_cases(seed: int, count: int = 40) -> list[Case]:
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        folder = rng.choice(FOLDERS)
        data = bytearray(MAINS[folder])
        for _ in range(rng.randint(1, 3)):
            data.insert(rng.randrange(len(data) + 1), rng.choice(INVALID_BYTES))
        cases.append(
            Case(
                f"seed{seed}#{i} invalid-utf8 {folder}",
                with_versions(bytes(data)),
                ONLY_UNSUPPORTED,
            )
        )
    return cases


def byte_flip_cases(seed: int, count: int = 60) -> list[Case]:
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        folder = rng.choice(FOLDERS)
        data = bytearray(MAINS[folder])
        mode = rng.choice(("flip", "delete", "insert", "swap"))
        for _ in range(rng.randint(1, 5)):
            position = rng.randrange(len(data))
            if mode == "flip":
                data[position] ^= rng.randint(1, 255)
            elif mode == "delete":
                del data[position]
            elif mode == "insert":
                data.insert(position, rng.choice(b"{}[]()\"'$%#/*=,.:?!<>&|~\\\n\t "))
            else:
                other = rng.randrange(len(data))
                data[position], data[other] = data[other], data[position]
        cases.append(Case(f"seed{seed}#{i} {mode} {folder}", with_versions(bytes(data))))
    return cases


VOCABULARY = [
    "resource", "data", "variable", "locals", "module", "output", "terraform", "moved", "provider",
    "aws_vpc", "main", "x", "for", "in", "if", "else", "endif", "true", "false", "null", "each",
    "=", "==", "=>", "!=", "<=", ">=", "&&", "||", "?", ":", "::", ",", ".", "...", ".*", "[*]",
    "(", ")", "[", "]", "{", "}", "${", "%{", "~}", "$${", "%%{", '"', '"abc"', "<<EOT", "EOT",
    "<<-X", "X", "1", "1.5", "1e3", "007", "-", "+", "*", "/", "%", "!", "#", "//", "/*", "*/",
    "\n", "\n", "\n", " ", " ", "\t", "\r\n", "é", "‮", "\x00",
]  # fmt: skip


def garbage_cases(seed: int, count: int = 30) -> list[Case]:
    rng = random.Random(seed)
    cases = []
    for i in range(count):
        pieces = [rng.choice(VOCABULARY) for _ in range(rng.randint(1, 80))]
        cases.append(Case(f"seed{seed}#{i} garbage", with_versions("".join(pieces).encode())))
    return cases


def directory_cases() -> list[Case]:
    good = MAINS[FOLDERS[0]]
    return [
        Case(
            "tf.json beside a valid file",
            {**with_versions(good), "extra.tf.json": b"{}"},
            ONLY_UNSUPPORTED,
        ),
        Case(
            "override beside a valid file",
            {**with_versions(good), "override.tf": good},
            ONLY_UNSUPPORTED,
        ),
        Case(
            "_override beside a valid file",
            {**with_versions(good), "x_override.tf": good},
            ONLY_UNSUPPORTED,
        ),
        Case(
            "tf.json beside a broken file",
            {"main.tf": b"x = (\n", "extra.tf.json": b"{}"},
            ONLY_INVALID,
        ),
        Case(
            "override beside a broken file",
            {"main.tf": b"x = (\n", "override.tf": good},
            ONLY_INVALID,
        ),
        Case(
            "invalid utf8 beside a broken file", {"a.tf": b"\xff", "b.tf": b"x = (\n"}, ONLY_INVALID
        ),
        Case(
            "limit beside a broken file",
            {"a.tf": b"locals { a = " + b"[" * 100, "b.tf": b"x = (\n"},
            ONLY_INVALID,
        ),
        Case(
            "same resource in two files",
            {"a.tf": b'resource "t" "n" {}\n', "b.tf": b'resource "t" "n" {}\n'},
            ONLY_INVALID,
        ),
        Case("empty file beside a valid one", {**with_versions(good), "empty.tf": b""}, ONLY_OK),
        Case("only an empty file", {"empty.tf": b""}, ONLY_OK),
        Case("only comments", {"c.tf": b"# nothing\n/* here */\n"}, ONLY_OK),
        Case(
            "unrelated files only",
            {"README.md": b"x", "terraform.tfvars": b"a = 1\n"},
            ONLY_INVALID,
        ),
    ]


def crlf_cases() -> list[Case]:
    cases = []
    for folder in FOLDERS:
        data = MAINS[folder].replace(b"\n", b"\r\n")
        cases.append(Case(f"crlf {folder}", with_versions(data), ONLY_OK))
    return cases


def all_case_groups() -> dict[str, list[Case]]:
    groups: dict[str, list[Case]] = {
        "truncation": truncation_cases(),
        "nesting": nesting_cases(),
        "large": large_cases(),
        "unicode": unicode_cases(),
        "directory": directory_cases(),
        "crlf": crlf_cases(),
    }
    for name, make in (
        ("duplicate attributes", duplicate_attribute_cases),
        ("duplicate blocks", duplicate_block_cases),
        ("unexpected blocks", unexpected_block_cases),
        ("embedded unicode", embedded_unicode_cases),
        ("invalid utf8", invalid_utf8_cases),
        ("byte flips", byte_flip_cases),
        ("garbage", garbage_cases),
    ):
        groups[name] = [case for seed in SEEDS for case in make(seed)]
    return groups


# --- the property ------------------------------------------------------------------------------

KNOWN_PREFIXES = ("input.", "struct.", "construct.", "limit.")


def check_outcome(outcome: object) -> str | None:
    """Why ``outcome`` breaks a loader invariant, or None."""
    if not isinstance(outcome, ParseOutcome):
        return f"not a ParseOutcome: {type(outcome).__name__}"
    if outcome.status not in ParseStatus:
        return f"invalid status {outcome.status!r}"
    if (outcome.status is OK) != (outcome.configuration is not None):
        return "configuration present exactly when OK is violated"
    failing = [
        d for d in outcome.diagnostics if d.severity is not DiagnosticSeverity.UNSUPPORTED_CONSTRUCT
    ]
    if outcome.status is OK and failing:
        return "OK with a failing diagnostic"
    if outcome.status is not OK and not failing:
        return "not OK without a failing diagnostic"
    for diagnostic in outcome.diagnostics:
        if diagnostic.code.startswith("internal."):
            return f"unexpected exception inside the loader: {diagnostic.message}"
        if diagnostic.code not in RULES and not diagnostic.code.startswith(KNOWN_PREFIXES):
            return f"unregistered rule code {diagnostic.code!r}"
    return None


class FuzzCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        print(f"hcl-fuzz seeds: {SEEDS}")
        faulthandler.dump_traceback_later(WATCHDOG_SECONDS, exit=True)

    @classmethod
    def tearDownClass(cls) -> None:
        faulthandler.cancel_dump_traceback_later()

    def run_group(self, cases: list[Case]) -> None:
        failures: list[str] = []
        statuses: dict[ParseStatus, int] = {}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for case in cases:
                for entry in os.listdir(root):
                    (root / entry).unlink()
                for name, data in case.files.items():
                    (root / name).write_bytes(data)
                started = time.monotonic()
                try:
                    outcome = load_configuration(root)
                except BaseException as exc:  # the loader must never raise
                    failures.append(f"{case.label}: raised {type(exc).__name__}: {exc}")
                    continue
                elapsed = time.monotonic() - started
                if elapsed > CASE_BUDGET_SECONDS:
                    failures.append(f"{case.label}: took {elapsed:.1f}s")
                problem = check_outcome(outcome)
                if problem is not None:
                    failures.append(f"{case.label}: {problem}")
                    continue
                statuses[outcome.status] = statuses.get(outcome.status, 0) + 1
                if case.expected is not None and outcome.status not in case.expected:
                    codes = [d.code for d in outcome.diagnostics][:3]
                    failures.append(
                        f"{case.label}: status {outcome.status.value}, expected one of "
                        f"{sorted(s.value for s in case.expected)} ({codes})"
                    )
        self.assertEqual(failures[:15], [], f"{len(failures)} of {len(cases)} cases failed")
        self.assertEqual(sum(statuses.values()), len(cases))


class TestHclFuzz(FuzzCase):
    GROUPS = all_case_groups()

    def test_the_corpus_has_at_least_two_thousand_cases(self) -> None:
        total = sum(len(cases) for cases in self.GROUPS.values())
        print(f"hcl-fuzz cases: {total} ({ {k: len(v) for k, v in self.GROUPS.items()} })")
        self.assertGreaterEqual(total, 2000)

    def test_case_labels_are_unique_so_a_failure_names_one_input(self) -> None:
        labels = [case.label for cases in self.GROUPS.values() for case in cases]
        self.assertEqual(len(labels), len(set(labels)))

    def test_truncation_at_every_token_boundary(self) -> None:
        self.run_group(self.GROUPS["truncation"])

    def test_deeply_nested_structures_up_to_the_limit_plus_one(self) -> None:
        self.run_group(self.GROUPS["nesting"])

    def test_very_large_inputs(self) -> None:
        self.run_group(self.GROUPS["large"])

    def test_unicode_edge_cases(self) -> None:
        self.run_group(self.GROUPS["unicode"])

    def test_directory_level_mixes(self) -> None:
        self.run_group(self.GROUPS["directory"])

    def test_crlf_copies_of_every_fixture(self) -> None:
        self.run_group(self.GROUPS["crlf"])

    def test_duplicated_attributes(self) -> None:
        self.run_group(self.GROUPS["duplicate attributes"])

    def test_duplicated_blocks(self) -> None:
        self.run_group(self.GROUPS["duplicate blocks"])

    def test_unexpected_block_types_and_labels(self) -> None:
        self.run_group(self.GROUPS["unexpected blocks"])

    def test_unicode_in_comment_positions_of_fixtures(self) -> None:
        self.run_group(self.GROUPS["embedded unicode"])

    def test_invalid_utf8_bytes(self) -> None:
        self.run_group(self.GROUPS["invalid utf8"])

    def test_random_byte_flips_deletions_insertions_and_swaps(self) -> None:
        self.run_group(self.GROUPS["byte flips"])

    def test_random_token_soup(self) -> None:
        self.run_group(self.GROUPS["garbage"])


class TestTheFuzzerCanFail(unittest.TestCase):
    """The harness must reject a loader that breaks its invariants (otherwise it proves nothing)."""

    def test_check_outcome_flags_broken_outcomes(self) -> None:
        self.assertIsNotNone(check_outcome(None))
        self.assertIsNotNone(check_outcome("OK"))

    def test_an_expected_class_that_is_wrong_is_reported(self) -> None:
        case = Case("valid file claimed invalid", with_versions(MAINS[FOLDERS[0]]), ONLY_INVALID)
        with self.assertRaises(AssertionError):
            FuzzCase("run_group").run_group([case])

    def test_a_loader_that_raises_is_reported(self) -> None:
        case = Case("any", with_versions(MAINS[FOLDERS[0]]))
        patched = mock.patch(f"{__name__}.load_configuration", side_effect=KeyError("boom"))
        with patched, self.assertRaises(AssertionError) as caught:
            FuzzCase("run_group").run_group([case])
        self.assertIn("raised KeyError", str(caught.exception))

    def test_a_slow_case_is_reported(self) -> None:
        case = Case("any", with_versions(MAINS[FOLDERS[0]]))
        patched = mock.patch(f"{__name__}.CASE_BUDGET_SECONDS", -1.0)
        with patched, self.assertRaises(AssertionError) as caught:
            FuzzCase("run_group").run_group([case])
        self.assertIn("took", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
