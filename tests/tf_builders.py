"""Builders for the Terraform normalization tests (P3a-3): configuration text to parsed,
evaluated and normalized form. Standard library plus ``core.terraform_model``. Not a test module.
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

from core.terraform_model.config import ParsedConfiguration, ParseStatus, load_configuration
from core.terraform_model.evaluation import EvaluationOutcome, evaluate_configuration

NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=UTC)
LATER = datetime(2027, 1, 2, 3, 4, 5, tzinfo=UTC)


def parse_files(files: Mapping[str, str]) -> ParsedConfiguration:
    """Load a directory made from ``{file name: text}``; the status must be OK."""
    with tempfile.TemporaryDirectory() as directory:
        for name, text in files.items():
            (Path(directory) / name).write_text(text, encoding="utf-8", newline="\n")
        outcome = load_configuration(Path(directory))
    assert outcome.status is ParseStatus.OK, outcome.diagnostics
    assert outcome.configuration is not None
    return outcome.configuration


def parse_text(text: str) -> ParsedConfiguration:
    return parse_files({"main.tf": text})


def evaluate_text(
    text: str, variables: Mapping[str, object] | None = None
) -> tuple[ParsedConfiguration, EvaluationOutcome]:
    parsed = parse_text(text)
    return parsed, evaluate_configuration(parsed, variables)


def evaluate_ok(
    text: str, variables: Mapping[str, object] | None = None
) -> tuple[ParsedConfiguration, EvaluationOutcome]:
    parsed, outcome = evaluate_text(text, variables)
    assert outcome.status is ParseStatus.OK, outcome.diagnostics
    return parsed, outcome
