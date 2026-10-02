"""Repository ports (Doc 05 §26, §32; Doc 06 §30; C-43; P1b step 3).

The expected method lists come from the P1b prompt's Section 7 Step 3 (which extends Doc 05 §26),
not from the implementation.
"""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path
from typing import Any

from core.domain import repositories
from core.domain.errors import (
    DomainValidationError,
    IllegalTransitionError,
    PersistenceError,
    StaleParentError,
)

EXPECTED: dict[str, set[str]] = {
    "TrustedStateRepository": {
        "get",
        "get_current",
        "assert_current",
        "save_baseline",
        "save_promoted",
        "lineage",
    },
    "CandidateRepository": {"create", "get", "save_transition"},
    "PatchRepository": {"save", "get"},
    "InvariantRepository": {"register_definition", "get_definition", "get_state_refs"},
    "UnitOfWork": {"trusted_states", "candidates", "patches", "invariants"},
}

# Doc 06 §30: "Do not permit persistence-layer convenience methods to bypass lifecycle validation."
CONVENIENCE_NAMES = {
    "update",
    "set",
    "delete",
    "remove",
    "upsert",
    "set_status",
    "update_status",
    "save",  # allowed only on PatchRepository, checked below
}


def public_names(cls: Any) -> set[str]:
    return {name for name in vars(cls) if not name.startswith("_")}


class TestPortsExist(unittest.TestCase):
    def test_every_port_is_a_protocol_with_exactly_the_specified_members(self) -> None:
        for name, expected in EXPECTED.items():
            cls = getattr(repositories, name)
            with self.subTest(port=name):
                self.assertTrue(getattr(cls, "_is_protocol", False), f"{name} is not a Protocol")
                self.assertEqual(public_names(cls), expected)

    def test_no_port_offers_a_lifecycle_bypass(self) -> None:
        for name in EXPECTED:
            names = public_names(getattr(repositories, name))
            allowed_save = {"save"} if name == "PatchRepository" else set()
            with self.subTest(port=name):
                self.assertEqual((names & CONVENIENCE_NAMES) - allowed_save, set())

    def test_the_module_defines_no_other_port(self) -> None:
        classes = {
            name
            for name, value in vars(repositories).items()
            if isinstance(value, type) and value.__module__ == repositories.__name__
        }
        self.assertEqual(classes, set(EXPECTED))


class TestPortsCarryNoAdapterDependency(unittest.TestCase):
    """Doc 05 §26 and §36: the domain does not depend on a SQLite-specific implementation."""

    def test_imports_are_standard_library_and_core_domain_only(self) -> None:
        source = Path(repositories.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module is not None:
                imported.add(node.module)
        self.assertTrue(imported)
        for module in imported:
            top = module.split(".")[0]
            with self.subTest(module=module):
                self.assertTrue(
                    module.startswith("core.domain") or top in sys.stdlib_module_names,
                    f"{module} is neither core.domain nor the standard library",
                )
        self.assertNotIn("sqlite3", imported)
        self.assertFalse(any(m.startswith("core.persistence") for m in imported))


class TestPersistenceError(unittest.TestCase):
    def test_it_is_a_domain_validation_error(self) -> None:
        self.assertTrue(issubclass(PersistenceError, DomainValidationError))

    def test_it_is_not_a_lifecycle_error(self) -> None:
        self.assertFalse(issubclass(PersistenceError, IllegalTransitionError))
        self.assertFalse(issubclass(PersistenceError, StaleParentError))

    def test_a_stale_parent_is_not_a_persistence_error(self) -> None:
        self.assertFalse(issubclass(StaleParentError, PersistenceError))
        self.assertEqual(StaleParentError("a", "b").rule, "SM-010")


if __name__ == "__main__":
    unittest.main()
