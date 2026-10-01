"""Enumerations (Doc 05 §4.1, Doc 06 §5; P1a step 5).

Every expected set below is typed from the specification text, never derived
from the implementation.
"""

from __future__ import annotations

import enum
import unittest

from core.domain import enums
from core.domain.enums import (
    CandidateSource,
    CandidateStatus,
    ChangeType,
    DecisionType,
    DependencyStatus,
    IdentityStatus,
    ImpactStatus,
    InvariantCategory,
    InvariantStatus,
    PatchFormat,
    ProvenanceSourceKind,
    ReferenceResolution,
    ResourceSupport,
    StateKind,
    VerificationResult,
)

# Doc 05 §4.1
DOC05_TABLE: dict[type[enum.Enum], set[str]] = {
    CandidateSource: {"FIXED_PATCH", "LLM"},
    StateKind: {"TRUSTED", "CANDIDATE"},
    IdentityStatus: {"SAME", "DIFFERENT", "UNCERTAIN"},
    ChangeType: {"UNCHANGED", "MODIFIED", "CREATED", "DELETED", "REPLACED", "UNCERTAIN"},
    VerificationResult: {"PASS", "FAIL", "UNKNOWN", "UNSUPPORTED", "VERIFIER_ERROR"},
    DecisionType: {"PROMOTE", "REJECT", "RETRY", "ESCALATE"},
    InvariantStatus: {
        "REGISTERED",
        "VERIFYING",
        "PROTECTED",
        "AFFECTED",
        "REVERIFYING",
        "VIOLATED",
        "UNCERTAIN",
    },
    ImpactStatus: {"UNAFFECTED", "AFFECTED", "UNCERTAIN"},
    ResourceSupport: {"SUPPORTED", "UNSUPPORTED", "UNKNOWN"},
}

# Supporting enums, from the cited sections.
SUPPORTING: dict[type[enum.Enum], set[str]] = {
    # Doc 06 §5
    CandidateStatus: {
        "CREATED",
        "BUILDING",
        "FAILED",
        "READY",
        "ANALYZING",
        "REJECTED",
        "RETRY_REQUIRED",
        "ESCALATED",
        "PROMOTABLE",
        "PROMOTED",
    },
    # Doc 05 §10.1
    InvariantCategory: {"SECURITY", "FUNCTIONAL"},
    # Doc 05 §5.3
    ReferenceResolution: {"SUPPORTED", "UNKNOWN", "UNSUPPORTED"},
    # Doc 05 §6
    ProvenanceSourceKind: {
        "TERRAFORM_CONFIG",
        "TERRAFORM_PLAN",
        "TERRAFORM_STATE",
        "AWS_API",
        "LLM",
        "DERIVED",
    },
    # Doc 05 §9
    PatchFormat: {"TERRAFORM_HCL"},
    # Doc 05 §29
    DependencyStatus: {"KNOWN", "UNCERTAIN", "UNSUPPORTED"},
}

# Names removed by P1a (C-36 and the Section 3 list of old enums).
REMOVED_NAMES = {
    "InvariantLifecycleState",
    "VerificationOutcome",
    "ChangeAction",
    "IdentityOutcome",
    "PromotionDecision",
    "InvariantType",
    "ObligationCategory",
    "EvidenceKind",
}


class TestEnumValueSets(unittest.TestCase):
    def test_doc05_section_4_1_tables(self) -> None:
        for cls, expected in DOC05_TABLE.items():
            with self.subTest(enum=cls.__name__):
                self.assertEqual({member.value for member in cls}, expected)
                self.assertEqual({member.name for member in cls}, expected)

    def test_supporting_enums(self) -> None:
        for cls, expected in SUPPORTING.items():
            with self.subTest(enum=cls.__name__):
                self.assertEqual({member.value for member in cls}, expected)
                self.assertEqual({member.name for member in cls}, expected)

    def test_candidate_status_has_ten_values(self) -> None:
        self.assertEqual(len(CandidateStatus), 10)

    def test_values_are_stable_strings(self) -> None:
        for cls in (*DOC05_TABLE, *SUPPORTING):
            for member in cls:
                with self.subTest(member=f"{cls.__name__}.{member.name}"):
                    self.assertIsInstance(member, str)
                    self.assertEqual(str(member), member.value)
                    self.assertEqual(cls(member.value), member)


class TestNoOldEnums(unittest.TestCase):
    def test_removed_enums_are_gone(self) -> None:
        for name in REMOVED_NAMES:
            with self.subTest(name=name):
                self.assertFalse(hasattr(enums, name), f"{name} must not exist (C-36, Step 5)")

    def test_module_defines_exactly_the_expected_enums(self) -> None:
        defined = {
            name
            for name, obj in vars(enums).items()
            if isinstance(obj, type)
            and issubclass(obj, enum.Enum)
            and obj is not enum.StrEnum
            and obj.__module__ == enums.__name__
        }
        self.assertEqual(defined, {cls.__name__ for cls in (*DOC05_TABLE, *SUPPORTING)})


class TestVerificationResult(unittest.TestCase):
    def test_is_pass_is_true_only_for_pass(self) -> None:
        for result in VerificationResult:
            with self.subTest(result=result.value):
                self.assertEqual(result.is_pass, result.value == "PASS")

    def test_uncertain_results_are_never_a_pass(self) -> None:
        for name in ("UNKNOWN", "UNSUPPORTED", "VERIFIER_ERROR", "FAIL"):
            self.assertFalse(VerificationResult(name).is_pass)


class TestUncertaintyIsFirstClass(unittest.TestCase):
    """Doc 05 §29, §39: uncertainty is a domain value and must stay distinguishable."""

    def test_uncertain_values_exist_where_the_spec_has_them(self) -> None:
        self.assertIn("UNCERTAIN", {m.value for m in IdentityStatus})
        self.assertIn("UNCERTAIN", {m.value for m in ChangeType})
        self.assertIn("UNCERTAIN", {m.value for m in ImpactStatus})
        self.assertIn("UNKNOWN", {m.value for m in ResourceSupport})
        self.assertIn("UNSUPPORTED", {m.value for m in ResourceSupport})
        self.assertIn("UNKNOWN", {m.value for m in ReferenceResolution})
        self.assertIn("UNSUPPORTED", {m.value for m in ReferenceResolution})
        self.assertIn("UNCERTAIN", {m.value for m in DependencyStatus})
        self.assertIn("UNSUPPORTED", {m.value for m in DependencyStatus})

    def test_resource_support_and_reference_resolution_are_distinct_types(self) -> None:
        self.assertIsNot(ResourceSupport, ReferenceResolution)
        self.assertNotIsInstance(ReferenceResolution.UNKNOWN, ResourceSupport)


if __name__ == "__main__":
    unittest.main()
