"""Model keys that gitleaks' generic secret rule does not flag (P10c-1, C-229; P10b verdict limit
5).

P10b verdict limit 5: "``.gitleaksignore`` keeps growing with model-key fingerprints; rename the
keys instead." P10c-1: "a key format that does not match gitleaks' generic secret pattern (... check
it against the rule), applied to new records only. Old frozen records keep their keys."

The rule is gitleaks 8.24.3's ``generic-api-key`` (the version DAIL's CI runs), read unchanged from
``tests/fixtures/gitleaks/generic_api_key_8.24.3.json`` (extracted from the release's
``config/gitleaks.toml``, whose SHA-256 the fixture keeps). ``flagged`` reproduces how gitleaks
applies it to one line: the regex; the secret's Shannon entropy must exceed the rule's ``entropy``;
then the rule's allowlists (a regex on the secret, on the whole match or on the line; stopwords
contained in the secret) and the global allowlist. Two Go regex forms are translated: ``\\z`` and a
``(?i)`` flag group in the middle of a pattern. The reproduction is calibrated against what CI
flagged in P10b: the granite keys were flagged, the qwen and phi4-mini keys in the same files were
not.
"""

from __future__ import annotations

import json
import math
import re
import unittest
from collections import Counter
from typing import Any

from tests.fixture_catalog import REPO_ROOT

RULE_FILE = REPO_ROOT / "tests" / "fixtures" / "gitleaks" / "generic_api_key_8.24.3.json"
# the pins of frozen records (P10a, P10b): they keep their keys
FROZEN_KEYS = frozenset(
    {
        "qwen2_5-coder-1_5b",
        "qwen2_5-coder-7b",
        "granite3_3-8b",
        "phi4-mini-3_8b",
        "qwen2_5-coder-7b-k3",
        "granite3_3-8b-k3",
        "phi4-mini-3_8b-k3",
    }
)
NEW_KEYS = (
    "model-qwen2.5-coder-7b",
    "model-granite-3.3-8b",
    "model-phi4-mini-3.8b",
    "model-qwen2.5-coder-7b-sample",
    "model-granite-3.3-8b-sample",
    "model-phi4-mini-3.8b-sample",
)


# The flagged values are built at run time, so this file holds no line the rule matches (gitleaks
# scans the source; CLAUDE.md: fake secrets in tests are built at run time).
GRANITE = "granite" + "3_3-8b"
EXAMPLE = "granite" + "-3.3-8b"


def record(indent: int, field: str, value: str) -> str:
    """A JSON record line as DAIL writes it."""
    return " " * indent + '"' + field + '": "' + value + '",'


def _go(pattern: str) -> str:
    pattern = pattern.replace(r"\z", r"\Z")
    i = pattern.find("(?i)")
    if i > 0:  # Go allows a flag group mid-pattern; it applies to the rest
        pattern = pattern[:i] + "(?i:" + pattern[i + 4 :] + ")"
    return pattern


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def load_rule() -> dict[str, Any]:
    return json.loads(RULE_FILE.read_text(encoding="utf-8"))


def flagged(line: str, doc: dict[str, Any] | None = None) -> list[str]:
    """The secrets the rule reports in ``line``."""
    doc = doc or load_rule()
    rule, glob = doc["rule"], doc["global_allowlist"]
    found = []
    for m in re.finditer(_go(rule["regex"]), line):
        secret = m.group(1)
        if entropy(secret) <= rule["entropy"]:
            continue
        allowed = False
        for allow in rule["allowlists"]:
            if allow.get("condition") == "AND":  # bound to .bb/.inc paths
                continue
            target = {"match": m.group(0), "line": line}.get(allow.get("regexTarget", ""), secret)
            if any(re.search(_go(r), target) for r in allow.get("regexes", [])):
                allowed = True
            if any(w in secret.lower() for w in allow.get("stopwords", [])):
                allowed = True
        if any(re.search(_go(r), secret) for r in glob.get("regexes", [])):
            allowed = True
        if any(w in secret.lower() for w in glob.get("stopwords", [])):
            allowed = True
        if not allowed:
            found.append(secret)
    return found


class TestTheReproductionMatchesCI(unittest.TestCase):
    """What gitleaks 8.24.3 reported on DAIL's PR #33 (docs/P10B_MODEL_PILOT.json and
    P10B_INTERRUPTIONS.json): the granite keys, and none of the qwen or phi4-mini keys beside them.
    """

    def test_the_fixture_is_the_release_rule(self) -> None:
        doc = load_rule()
        self.assertEqual(doc["gitleaks_version"], "8.24.3")
        self.assertEqual(
            doc["source_sha256"], "8f393899dbdc67e4eae580909e496acab9cf3a75aacfb6fac56b6eb16bb9e051"
        )
        self.assertEqual(doc["rule"]["id"], "generic-api-key")
        self.assertEqual(doc["rule"]["entropy"], 3.5)

    def test_flagged_and_not_flagged_as_ci_reported(self) -> None:
        for line in (
            record(4, "key", GRANITE),
            record(5, "key", GRANITE + "-k3"),
            record(3, "model_key", GRANITE + "-k3"),
        ):
            with self.subTest(line=line.strip()):
                self.assertTrue(flagged(line))
        for line in (
            '    "key": "qwen2_5-coder-7b",',
            '    "key": "phi4-mini-3_8b",',
            '     "key": "qwen2_5-coder-7b-k3",',
            '     "key": "phi4-mini-3_8b-k3",',
        ):
            with self.subTest(line=line.strip()):
                self.assertEqual(flagged(line), [])

    def test_the_work_packages_example_is_still_flagged(self) -> None:
        # why C-229 does not use it: entropy 3.522 > 3.5 and no stopword
        self.assertTrue(flagged(record(0, "model_key", EXAMPLE)))


class TestNewKeys(unittest.TestCase):
    def test_no_new_key_is_flagged_in_a_record(self) -> None:
        for key in NEW_KEYS:
            for line in (f'"model_key": "{key}",', f'   "key": "{key}",', f'"model_key": "{key}"'):
                with self.subTest(line=line):
                    self.assertEqual(flagged(line), [])

    def test_every_pin_for_new_records_has_a_new_key(self) -> None:
        from experiments.generation.models import load_pins

        pins = load_pins()
        self.assertLessEqual(set(NEW_KEYS), set(pins))
        new = set(pins) - FROZEN_KEYS
        self.assertEqual(new, set(NEW_KEYS))
        for key in new:
            with self.subTest(key=key):
                self.assertEqual(flagged(f'"model_key": "{key}",'), [])

    def test_the_new_pins_are_the_frozen_models(self) -> None:
        from experiments.generation.models import load_pins

        pins = load_pins()
        for old, new in (
            ("qwen2_5-coder-7b", "model-qwen2.5-coder-7b"),
            ("granite3_3-8b", "model-granite-3.3-8b"),
            ("phi4-mini-3_8b", "model-phi4-mini-3.8b"),
            ("qwen2_5-coder-7b-k3", "model-qwen2.5-coder-7b-sample"),
            ("granite3_3-8b-k3", "model-granite-3.3-8b-sample"),
            ("phi4-mini-3_8b-k3", "model-phi4-mini-3.8b-sample"),
        ):
            with self.subTest(new=new):
                a, b = pins[old].to_dict(), pins[new].to_dict()
                a.pop("key")
                b.pop("key")
                self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
