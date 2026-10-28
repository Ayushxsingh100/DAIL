"""IdentityEvidence, IdentityMatch, IdentityReport (Doc 05 §12, Doc 07 §13, §26; C-122; P3b step 2).

Expected values come from the C-122 text and Doc 05 §12, not from the implementation: the table of
valid ref/status/change/confidence combinations below is written out by hand.
"""

from __future__ import annotations

import dataclasses
import itertools
import json
import random
import unittest
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from core.domain.enums import ChangeType, IdentityStatus
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.identity import (
    EVIDENCE_DEFINITIONS,
    SUMMARY_KEYS,
    EvidenceSource,
    EvidenceType,
    IdentityConfidence,
    IdentityEvidence,
    IdentityMatch,
    IdentityReport,
    match_key,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 28, 9, 0, tzinfo=UTC)
PARENT = "11111111-1111-4111-8111-111111111111"
CANDIDATE = "22222222-2222-4222-8222-222222222222"
REPORT_ID = "33333333-3333-4333-8333-333333333333"
VERSION = "dail-identity-1"

# C-122, written out by hand (see valid_combinations): change, refs set, status, confidence
# Confidence for the pair changes is HIGH or MEDIUM (MEDIUM is reserved, never produced).
VOCABULARY = {
    "EXACT_ADDRESS",
    "EXPLICIT_MOVE",
    "IMPLICIT_COUNT_MOVE",
    "FINGERPRINT_EQUAL",
    "FINGERPRINT_DIFFERENT",
    "REPLACE_TRIGGER_FIELD",
    "REPLACE_TRIGGER_UNRESOLVED",
    "AMBIGUOUS_CANDIDATES",
    "INDETERMINATE_BLOCK",
    "CONFLICTING_MOVE",
    "UNRESOLVED_CONTENT",
    "UNSUPPORTED_TYPE",
    "NO_COUNTERPART",
}


def evidence(
    trusted: str | None = "aws_vpc.a",
    candidate: str | None = "aws_vpc.a",
    kind: EvidenceType = EvidenceType.EXACT_ADDRESS,
    source: EvidenceSource = EvidenceSource.BOTH,
    observed: Any = None,
    text: str = "same address",
    version: str = VERSION,
) -> IdentityEvidence:
    return IdentityEvidence(
        trusted_ref=trusted,
        candidate_ref=candidate,
        evidence_type=kind,
        source=source,
        observed_value={"address": "aws_vpc.a"} if observed is None else observed,
        interpretation=text,
        algorithm_version=version,
    )


def match(
    trusted: str | None,
    candidate: str | None,
    change: ChangeType,
    proof: IdentityEvidence,
    rule: EvidenceType | None = None,
) -> IdentityMatch:
    return IdentityMatch.create(
        trusted_ref=trusted,
        candidate_ref=candidate,
        change_type=change,
        rule=proof.evidence_type if rule is None else rule,
        evidence_ids=[proof.evidence_id],
    )


def sample_report(**overrides: Any) -> IdentityReport:
    same = evidence("aws_vpc.a", "aws_vpc.a", EvidenceType.FINGERPRINT_EQUAL)
    changed = evidence(
        "aws_vpc.b", "aws_vpc.b", EvidenceType.FINGERPRINT_DIFFERENT, observed={"x": 1}
    )
    made = evidence(None, "aws_vpc.c", EvidenceType.NO_COUNTERPART, EvidenceSource.CANDIDATE)
    gone = evidence("aws_vpc.d", None, EvidenceType.NO_COUNTERPART, EvidenceSource.TRUSTED)
    unsure = evidence("aws_vpc.e", "aws_vpc.f", EvidenceType.CONFLICTING_MOVE, EvidenceSource.MOVES)
    values: dict[str, Any] = {
        "parent_state_id": PARENT,
        "candidate_id": CANDIDATE,
        "matches": [
            match("aws_vpc.a", "aws_vpc.a", ChangeType.UNCHANGED, same),
            match("aws_vpc.b", "aws_vpc.b", ChangeType.MODIFIED, changed),
            match(None, "aws_vpc.c", ChangeType.CREATED, made),
            match("aws_vpc.d", None, ChangeType.DELETED, gone),
            match("aws_vpc.e", "aws_vpc.f", ChangeType.UNCERTAIN, unsure),
        ],
        "evidence": [same, changed, made, gone, unsure],
        "algorithm_version": VERSION,
        "now": NOW,
        "report_id": REPORT_ID,
    }
    values.update(overrides)
    return IdentityReport.create(**values)


class TestVocabulary(unittest.TestCase):
    def test_the_evidence_vocabulary_is_closed_and_has_these_thirteen_members(self) -> None:
        self.assertEqual({member.value for member in EvidenceType}, VOCABULARY)

    def test_every_evidence_type_has_a_short_definition_in_code(self) -> None:
        self.assertEqual(set(EVIDENCE_DEFINITIONS), set(EvidenceType))
        for kind, text in EVIDENCE_DEFINITIONS.items():
            with self.subTest(kind=kind):
                self.assertTrue(text.strip())
                self.assertLess(len(text), 300)

    def test_every_evidence_type_is_defined_in_the_register_row_c_122(self) -> None:
        register = (REPO_ROOT / "docs" / "DECISIONS_REGISTER.md").read_text(encoding="utf-8")
        row = next(line for line in register.splitlines() if line.startswith("| C-122 |"))
        for name in sorted(VOCABULARY):
            with self.subTest(name=name):
                self.assertIn(f"`{name}`", row)

    def test_no_evidence_kind_for_provider_ids_plan_actions_or_similarity(self) -> None:
        # Doc 07 §7: unavailable, not negative evidence; Doc 07 §5: similarity is never sufficient
        for name in VOCABULARY:
            for word in ("PROVIDER", "PLAN", "SIMILAR", "HEURISTIC", "LLM"):
                self.assertNotIn(word, name)

    def test_the_sources_and_confidences_are_the_documented_ones(self) -> None:
        self.assertEqual(
            {s.value for s in EvidenceSource}, {"TRUSTED", "CANDIDATE", "MOVES", "BOTH"}
        )
        self.assertEqual({c.value for c in IdentityConfidence}, {"HIGH", "MEDIUM", "LOW"})


class TestIdentityEvidence(unittest.TestCase):
    def test_it_has_the_seven_fields_of_doc_07_26(self) -> None:
        names = [f.name for f in dataclasses.fields(IdentityEvidence)]
        self.assertEqual(
            names,
            [
                "trusted_ref",
                "candidate_ref",
                "evidence_type",
                "source",
                "observed_value",
                "interpretation",
                "algorithm_version",
            ],
        )

    def test_the_id_is_derived_from_the_content_and_is_stable(self) -> None:
        first = evidence()
        self.assertEqual(first.evidence_id, evidence().evidence_id)
        self.assertEqual(len(first.evidence_id), 64)

    def test_every_field_changes_the_id(self) -> None:
        base = evidence().evidence_id
        variants = [
            evidence(trusted="aws_vpc.z"),
            evidence(candidate="aws_vpc.z"),
            evidence(candidate=None),
            evidence(kind=EvidenceType.FINGERPRINT_EQUAL),
            evidence(source=EvidenceSource.TRUSTED),
            evidence(observed={"address": "other"}),
            evidence(text="another reading"),
            evidence(version="dail-identity-addr-1"),
        ]
        ids = {v.evidence_id for v in variants}
        self.assertNotIn(base, ids)
        self.assertEqual(len(ids), len(variants))

    def test_at_least_one_ref_is_required(self) -> None:
        with self.assertRaises(DomainValidationError):
            evidence(trusted=None, candidate=None)

    def test_refs_text_and_version_are_checked(self) -> None:
        for bad in ("", " a", "a ", 3):
            with self.subTest(ref=bad), self.assertRaises(DomainValidationError):
                evidence(trusted=bad)  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            evidence(text="")
        with self.assertRaises(DomainValidationError):
            evidence(version=" ")

    def test_the_vocabularies_are_strict(self) -> None:
        with self.assertRaises(DomainValidationError):
            evidence(kind="EXACT_ADDRESS")  # type: ignore[arg-type]
        with self.assertRaises(DomainValidationError):
            evidence(source="BOTH")  # type: ignore[arg-type]

    def test_floats_and_non_json_values_are_rejected(self) -> None:
        for bad in (1.5, {"a": 1.0}, [float("nan")], {1: "x"}, object(), {"a": {1, 2}}):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                evidence(observed=bad)

    def test_the_observed_value_is_frozen_and_copied(self) -> None:
        source = {"a": [1, 2]}
        item = evidence(observed=source)
        source["a"].append(3)
        self.assertEqual(item.to_dict()["observed_value"], {"a": [1, 2]})
        with self.assertRaises(TypeError):
            item.observed_value["a"] = 1  # type: ignore[index]

    def test_it_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            evidence().interpretation = "x"  # type: ignore[misc]

    def test_round_trip_and_unknown_keys(self) -> None:
        item = evidence(observed={"a": [1, "x", None, True]})
        data = json.loads(json.dumps(item.to_dict()))
        self.assertEqual(IdentityEvidence.from_dict(data), item)
        with self.assertRaises(DomainValidationError):
            IdentityEvidence.from_dict({**data, "score": 1})
        del data["source"]
        with self.assertRaises(DomainValidationError):
            IdentityEvidence.from_dict(data)

    def test_there_is_no_score_field(self) -> None:
        self.assertNotIn("score", {f.name for f in dataclasses.fields(IdentityEvidence)})


def valid_combinations() -> set[tuple[str, bool, bool, str, str | None]]:
    """(change, trusted set, candidate set, status, confidence), straight from C-122."""
    valid: set[tuple[str, bool, bool, str, str | None]] = set()
    for change in ("UNCHANGED", "MODIFIED", "REPLACED"):
        for confidence in ("HIGH", "MEDIUM"):
            valid.add((change, True, True, "SAME", confidence))
    valid.add(("CREATED", False, True, "DIFFERENT", None))
    valid.add(("DELETED", True, False, "DIFFERENT", None))
    for trusted, candidate in ((True, True), (True, False), (False, True)):
        valid.add(("UNCERTAIN", trusted, candidate, "UNCERTAIN", "LOW"))
    return valid


class TestIdentityMatch(unittest.TestCase):
    proof = evidence()

    def build(
        self,
        change: str,
        trusted: bool,
        candidate: bool,
        status: str,
        confidence: str | None,
    ) -> IdentityMatch:
        return IdentityMatch(
            trusted_resource_ref="aws_vpc.a" if trusted else None,
            candidate_resource_ref="aws_vpc.b" if candidate else None,
            identity_status=IdentityStatus(status),
            change_type=ChangeType(change),
            confidence=None if confidence is None else IdentityConfidence(confidence),
            rationale={"rule": "EXACT_ADDRESS", "evidence_ids": [self.proof.evidence_id]},
        )

    def test_exactly_the_documented_combinations_are_accepted(self) -> None:
        allowed = valid_combinations()
        total = 0
        for change, trusted, candidate, status, confidence in itertools.product(
            [c.value for c in ChangeType],
            (True, False),
            (True, False),
            [s.value for s in IdentityStatus],
            (None, "HIGH", "MEDIUM", "LOW"),
        ):
            total += 1
            combo = (change, trusted, candidate, status, confidence)
            with self.subTest(combo=combo):
                if combo in allowed:
                    self.build(*combo)
                else:
                    with self.assertRaises(DomainValidationError):
                        self.build(*combo)
        self.assertEqual(total, 288)
        self.assertEqual(len(allowed), 6 + 1 + 1 + 3)

    def test_create_derives_status_and_confidence_from_the_change(self) -> None:
        cases = {
            ChangeType.UNCHANGED: (True, True, IdentityStatus.SAME, IdentityConfidence.HIGH),
            ChangeType.MODIFIED: (True, True, IdentityStatus.SAME, IdentityConfidence.HIGH),
            ChangeType.REPLACED: (True, True, IdentityStatus.SAME, IdentityConfidence.HIGH),
            ChangeType.CREATED: (False, True, IdentityStatus.DIFFERENT, None),
            ChangeType.DELETED: (True, False, IdentityStatus.DIFFERENT, None),
            ChangeType.UNCERTAIN: (True, True, IdentityStatus.UNCERTAIN, IdentityConfidence.LOW),
        }
        for change, (trusted, candidate, status, confidence) in cases.items():
            with self.subTest(change=change):
                made = IdentityMatch.create(
                    trusted_ref="aws_vpc.a" if trusted else None,
                    candidate_ref="aws_vpc.b" if candidate else None,
                    change_type=change,
                    rule=EvidenceType.EXACT_ADDRESS,
                    evidence_ids=[self.proof.evidence_id],
                )
                self.assertEqual((made.identity_status, made.confidence), (status, confidence))

    def test_an_uncertain_match_may_have_either_ref_null_but_not_both(self) -> None:
        for trusted, candidate in (("aws_vpc.a", None), (None, "aws_vpc.a")):
            IdentityMatch.create(
                trusted_ref=trusted,
                candidate_ref=candidate,
                change_type=ChangeType.UNCERTAIN,
                rule=EvidenceType.AMBIGUOUS_CANDIDATES,
                evidence_ids=[self.proof.evidence_id],
            )
        with self.assertRaises(DomainValidationError):
            IdentityMatch.create(
                trusted_ref=None,
                candidate_ref=None,
                change_type=ChangeType.UNCERTAIN,
                rule=EvidenceType.AMBIGUOUS_CANDIDATES,
                evidence_ids=[],
            )

    def test_the_rationale_names_the_rule_and_the_evidence_ids(self) -> None:
        made = IdentityMatch.create(
            trusted_ref="aws_vpc.a",
            candidate_ref="aws_vpc.a",
            change_type=ChangeType.MODIFIED,
            rule=EvidenceType.FINGERPRINT_DIFFERENT,
            evidence_ids=["b" * 64, "a" * 64, "a" * 64],
        )
        self.assertEqual(made.rule, EvidenceType.FINGERPRINT_DIFFERENT)
        self.assertEqual(made.evidence_ids, ("a" * 64, "b" * 64))
        self.assertEqual(sorted(made.to_dict()["rationale"]), ["evidence_ids", "rule"])

    def test_a_malformed_rationale_is_rejected(self) -> None:
        good = self.proof.evidence_id
        for bad in (
            {},
            {"rule": "EXACT_ADDRESS"},
            {"rule": "NOT_A_RULE", "evidence_ids": [good]},
            {"rule": "EXACT_ADDRESS", "evidence_ids": good},
            {"rule": "EXACT_ADDRESS", "evidence_ids": ["short"]},
            {"rule": "EXACT_ADDRESS", "evidence_ids": [good.upper()]},
            {"rule": "EXACT_ADDRESS", "evidence_ids": [good, good]},
            {"rule": "EXACT_ADDRESS", "evidence_ids": ["b" * 64, "a" * 64]},
            {"rule": "EXACT_ADDRESS", "evidence_ids": [good], "score": 0.5},
            [],
            "EXACT_ADDRESS",
        ):
            with self.subTest(rationale=bad), self.assertRaises(DomainValidationError):
                IdentityMatch(
                    trusted_resource_ref="aws_vpc.a",
                    candidate_resource_ref="aws_vpc.a",
                    identity_status=IdentityStatus.SAME,
                    change_type=ChangeType.UNCHANGED,
                    confidence=IdentityConfidence.HIGH,
                    rationale=bad,  # type: ignore[arg-type]
                )

    def test_refs_must_be_text_or_null(self) -> None:
        for bad in ("", " a", 3, b"x"):
            with self.subTest(ref=bad), self.assertRaises(DomainValidationError):
                IdentityMatch.create(
                    trusted_ref=bad,  # type: ignore[arg-type]
                    candidate_ref="aws_vpc.a",
                    change_type=ChangeType.MODIFIED,
                    rule=EvidenceType.FINGERPRINT_DIFFERENT,
                    evidence_ids=[],
                )

    def test_the_enums_are_strict(self) -> None:
        with self.assertRaises(DomainValidationError):
            IdentityMatch(
                trusted_resource_ref="aws_vpc.a",
                candidate_resource_ref="aws_vpc.a",
                identity_status="SAME",  # type: ignore[arg-type]
                change_type=ChangeType.UNCHANGED,
                confidence=IdentityConfidence.HIGH,
                rationale={"rule": "EXACT_ADDRESS", "evidence_ids": []},
            )

    def test_the_key_names_the_match_with_a_dash_for_a_missing_side(self) -> None:
        self.assertEqual(match_key("aws_vpc.a", "aws_vpc.b"), "aws_vpc.a->aws_vpc.b")
        self.assertEqual(match_key(None, "aws_vpc.b"), "-->aws_vpc.b")
        self.assertEqual(match_key("aws_vpc.a", None), "aws_vpc.a->-")

    def test_matches_sort_by_trusted_then_candidate_with_nulls_last(self) -> None:
        refs = [("b", "b"), ("a", None), (None, "a"), ("a", "z"), ("a", "b"), (None, "b")]
        made = [
            IdentityMatch.create(
                trusted_ref=t,
                candidate_ref=c,
                change_type=ChangeType.UNCERTAIN,
                rule=EvidenceType.AMBIGUOUS_CANDIDATES,
                evidence_ids=[],
            )
            for t, c in refs
        ]
        ordered = sorted(made, key=IdentityMatch.sort_key)
        self.assertEqual(
            [(m.trusted_resource_ref, m.candidate_resource_ref) for m in ordered],
            [("a", "b"), ("a", "z"), ("a", None), ("b", "b"), (None, "a"), (None, "b")],
        )

    def test_round_trip(self) -> None:
        made = match("aws_vpc.a", "aws_vpc.b", ChangeType.REPLACED, self.proof)
        data = json.loads(json.dumps(made.to_dict()))
        self.assertEqual(IdentityMatch.from_dict(data), made)
        with self.assertRaises(DomainValidationError):
            IdentityMatch.from_dict({**data, "extra": 1})
        with self.assertRaises(DomainValidationError):
            IdentityMatch.from_dict({**data, "confidence": "CERTAIN"})

    def test_it_is_frozen(self) -> None:
        made = match("aws_vpc.a", "aws_vpc.a", ChangeType.UNCHANGED, self.proof)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            made.change_type = ChangeType.CREATED  # type: ignore[misc]


class TestIdentityReport(unittest.TestCase):
    def test_create_sorts_and_derives_the_summary(self) -> None:
        report = sample_report()
        self.assertEqual(
            [(m.trusted_resource_ref, m.candidate_resource_ref) for m in report.resource_matches],
            [
                ("aws_vpc.a", "aws_vpc.a"),
                ("aws_vpc.b", "aws_vpc.b"),
                ("aws_vpc.d", None),
                ("aws_vpc.e", "aws_vpc.f"),
                (None, "aws_vpc.c"),
            ],
        )
        self.assertEqual(list(report.summary), list(SUMMARY_KEYS))
        self.assertEqual(
            {k: list(v) for k, v in report.summary.items()},
            {
                "unchanged": ["aws_vpc.a->aws_vpc.a"],
                "modified": ["aws_vpc.b->aws_vpc.b"],
                "created": ["-->aws_vpc.c"],
                "deleted": ["aws_vpc.d->-"],
                "replaced": [],
                "uncertain": ["aws_vpc.e->aws_vpc.f"],
            },
        )
        keys = [item.sort_key() for item in report.evidence]
        self.assertEqual(keys, sorted(keys))

    def test_the_hash_does_not_depend_on_the_input_order(self) -> None:
        reference = sample_report()
        rng = random.Random(20261028)
        parts = (list(reference.resource_matches), list(reference.evidence))
        for _ in range(25):
            matches, records = (rng.sample(p, len(p)) for p in parts)
            shuffled = sample_report(matches=matches, evidence=records)
            self.assertEqual(shuffled.content_hash, reference.content_hash)
            self.assertEqual(shuffled.to_dict(), reference.to_dict())

    def test_duplicate_evidence_given_to_create_is_kept_once(self) -> None:
        reference = sample_report()
        doubled = sample_report(evidence=list(reference.evidence) * 2)
        self.assertEqual(doubled.content_hash, reference.content_hash)

    def test_the_hash_ignores_report_id_and_created_at(self) -> None:
        reference = sample_report()
        other = sample_report(
            report_id="44444444-4444-4444-8444-444444444444", now=NOW + timedelta(days=9)
        )
        self.assertNotEqual(other.report_id, reference.report_id)
        self.assertNotEqual(other.created_at, reference.created_at)
        self.assertEqual(other.content_hash, reference.content_hash)

    def test_a_new_report_id_is_generated_when_none_is_given(self) -> None:
        first = sample_report(report_id=None)
        second = sample_report(report_id=None)
        self.assertNotEqual(first.report_id, second.report_id)
        self.assertEqual(first.content_hash, second.content_hash)

    def test_the_hash_changes_when_anything_it_covers_changes(self) -> None:
        reference = sample_report()
        same = evidence("aws_vpc.a", "aws_vpc.a", EvidenceType.FINGERPRINT_EQUAL)
        other_parent = "55555555-5555-4555-8555-555555555555"
        changes = {
            "parent": sample_report(parent_state_id=other_parent),
            "candidate": sample_report(candidate_id=other_parent),
            "version": sample_report(algorithm_version="dail-identity-addr-1"),
        }
        # another interpretation of one piece of evidence
        edited = [
            (
                dataclasses.replace(item, interpretation="read differently")
                if item.evidence_id == same.evidence_id
                else item
            )
            for item in reference.evidence
        ]
        remap = {
            old.evidence_id: new.evidence_id
            for old, new in zip(reference.evidence, edited, strict=True)
        }
        matches = [
            IdentityMatch.create(
                trusted_ref=m.trusted_resource_ref,
                candidate_ref=m.candidate_resource_ref,
                change_type=m.change_type,
                rule=m.rule,
                evidence_ids=[remap[i] for i in m.evidence_ids],
            )
            for m in reference.resource_matches
        ]
        changes["evidence"] = sample_report(matches=matches, evidence=edited)
        # another change type for one match
        moved = [
            IdentityMatch.create(
                trusted_ref=m.trusted_resource_ref,
                candidate_ref=m.candidate_resource_ref,
                change_type=(
                    ChangeType.REPLACED if m.change_type is ChangeType.MODIFIED else m.change_type
                ),
                rule=m.rule,
                evidence_ids=m.evidence_ids,
            )
            for m in reference.resource_matches
        ]
        changes["match"] = sample_report(matches=moved, evidence=list(reference.evidence))
        for name, report in changes.items():
            with self.subTest(change=name):
                self.assertNotEqual(report.content_hash, reference.content_hash)

    def test_round_trip_through_json(self) -> None:
        report = sample_report()
        data = json.loads(json.dumps(report.to_dict()))
        again = IdentityReport.from_dict(data)
        self.assertEqual(again, report)
        self.assertEqual(again.to_dict(), report.to_dict())

    def test_the_stored_hash_is_recomputed_and_a_tampered_report_is_rejected(self) -> None:
        data = sample_report().to_dict()
        data["content_hash"] = "0" * 64
        with self.assertRaises(HashMismatchError):
            IdentityReport.from_dict(data)

    def test_tampering_with_any_covered_field_is_detected(self) -> None:
        good = sample_report().to_dict()

        def tamper_match(d: dict[str, Any]) -> None:
            d["resource_matches"][0]["change_type"] = "MODIFIED"
            d["resource_matches"][0]["rationale"]["rule"] = "FINGERPRINT_DIFFERENT"
            d["summary"] = {
                **d["summary"],
                "unchanged": [],
                "modified": sorted(d["summary"]["modified"] + ["aws_vpc.a->aws_vpc.a"]),
            }

        def tamper_evidence(d: dict[str, Any]) -> None:
            d["evidence"][0]["observed_value"] = {"tampered": True}

        def tamper_version(d: dict[str, Any]) -> None:
            d["algorithm_version"] = "dail-identity-0"

        def tamper_parent(d: dict[str, Any]) -> None:
            d["parent_state_id"] = "66666666-6666-4666-8666-666666666666"

        for name, change in (
            ("match", tamper_match),
            ("evidence", tamper_evidence),
            ("version", tamper_version),
            ("parent", tamper_parent),
        ):
            data = json.loads(json.dumps(good))
            change(data)
            with self.subTest(change=name), self.assertRaises(DomainValidationError):
                IdentityReport.from_dict(data)

    def test_a_summary_that_is_not_the_derived_one_is_rejected(self) -> None:
        data = sample_report().to_dict()
        data["summary"]["uncertain"] = []
        with self.assertRaises(DomainValidationError) as caught:
            IdentityReport.from_dict(data)
        self.assertIn("summary", str(caught.exception))
        data = sample_report().to_dict()
        data["summary"]["extra"] = []
        with self.assertRaises(DomainValidationError):
            IdentityReport.from_dict(data)

    def test_matches_must_be_in_the_documented_order(self) -> None:
        data = sample_report().to_dict()
        data["resource_matches"].reverse()
        with self.assertRaises(DomainValidationError) as caught:
            IdentityReport.from_dict(data)
        self.assertIn("sorted", str(caught.exception))

    def test_a_resource_cannot_be_in_two_matches(self) -> None:
        one = evidence("aws_vpc.a", "aws_vpc.a")
        two = evidence("aws_vpc.a", "aws_vpc.b", EvidenceType.EXPLICIT_MOVE, EvidenceSource.MOVES)
        for matches, side in (
            (
                [
                    match("aws_vpc.a", "aws_vpc.a", ChangeType.UNCHANGED, one),
                    match("aws_vpc.a", "aws_vpc.b", ChangeType.UNCHANGED, two),
                ],
                "trusted",
            ),
            (
                [
                    match("aws_vpc.a", "aws_vpc.b", ChangeType.UNCHANGED, one),
                    match("aws_vpc.c", "aws_vpc.b", ChangeType.UNCHANGED, two),
                ],
                "candidate",
            ),
        ):
            with self.subTest(side=side), self.assertRaises(DomainValidationError) as caught:
                IdentityReport.create(
                    parent_state_id=PARENT,
                    candidate_id=CANDIDATE,
                    matches=matches,
                    evidence=[one, two],
                    algorithm_version=VERSION,
                    now=NOW,
                )
            self.assertIn("two matches", str(caught.exception))

    def test_a_rationale_may_cite_only_evidence_the_report_holds(self) -> None:
        held = evidence()
        missing = evidence(text="not in the report")
        with self.assertRaises(DomainValidationError) as caught:
            IdentityReport.create(
                parent_state_id=PARENT,
                candidate_id=CANDIDATE,
                matches=[match("aws_vpc.a", "aws_vpc.a", ChangeType.UNCHANGED, missing)],
                evidence=[held],
                algorithm_version=VERSION,
                now=NOW,
            )
        self.assertIn("does not hold", str(caught.exception))

    def test_evidence_that_no_match_cites_is_rejected(self) -> None:
        cited = evidence()
        orphan = evidence(text="explains nothing")
        with self.assertRaises(DomainValidationError) as caught:
            IdentityReport.create(
                parent_state_id=PARENT,
                candidate_id=CANDIDATE,
                matches=[match("aws_vpc.a", "aws_vpc.a", ChangeType.UNCHANGED, cited)],
                evidence=[cited, orphan],
                algorithm_version=VERSION,
                now=NOW,
            )
        self.assertIn("no match cites", str(caught.exception))

    def test_evidence_about_a_resource_that_is_in_no_match_is_rejected(self) -> None:
        ghost = evidence("aws_vpc.ghost", "aws_vpc.a")
        with self.assertRaises(DomainValidationError) as caught:
            IdentityReport.create(
                parent_state_id=PARENT,
                candidate_id=CANDIDATE,
                matches=[match("aws_vpc.a", "aws_vpc.a", ChangeType.UNCHANGED, ghost)],
                evidence=[ghost],
                algorithm_version=VERSION,
                now=NOW,
            )
        self.assertIn("in no match", str(caught.exception))

    def test_ids_timestamps_and_version_are_validated(self) -> None:
        with self.assertRaises(DomainValidationError):
            sample_report(parent_state_id="not-a-uuid")
        with self.assertRaises(DomainValidationError):
            sample_report(candidate_id="AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA")
        with self.assertRaises(DomainValidationError):
            sample_report(report_id="x")
        with self.assertRaises(DomainValidationError):
            sample_report(now=datetime(2026, 10, 28, 9, 0))
        with self.assertRaises(DomainValidationError):
            sample_report(now=datetime(2026, 10, 28, 9, 0, tzinfo=timezone(timedelta(hours=2))))
        with self.assertRaises(DomainValidationError):
            sample_report(algorithm_version="")

    def test_an_empty_report_is_valid(self) -> None:
        empty = sample_report(matches=[], evidence=[])
        self.assertEqual(empty.resource_matches, ())
        self.assertEqual(
            {k: list(v) for k, v in empty.summary.items()}, {k: [] for k in SUMMARY_KEYS}
        )
        self.assertEqual(IdentityReport.from_dict(empty.to_dict()), empty)

    def test_it_is_frozen_and_its_containers_are_immutable(self) -> None:
        report = sample_report()
        with self.assertRaises(dataclasses.FrozenInstanceError):
            report.algorithm_version = "x"  # type: ignore[misc]
        self.assertIsInstance(report.resource_matches, tuple)
        self.assertIsInstance(report.evidence, tuple)
        with self.assertRaises(TypeError):
            report.summary["created"] = []  # type: ignore[index]

    def test_lookup_helpers_find_matches_and_their_evidence(self) -> None:
        report = sample_report()
        created = report.match_for_candidate("aws_vpc.c")
        assert created is not None
        self.assertEqual(created.change_type, ChangeType.CREATED)
        deleted = report.match_for_trusted("aws_vpc.d")
        assert deleted is not None
        self.assertEqual(deleted.change_type, ChangeType.DELETED)
        self.assertIsNone(report.match_for_trusted("aws_vpc.c"))
        self.assertEqual(
            [e.evidence_type for e in report.evidence_for(created)], [EvidenceType.NO_COUNTERPART]
        )

    def test_the_match_keys_of_a_report_are_unique(self) -> None:
        report = sample_report()
        keys = [m.key for m in report.resource_matches]
        self.assertEqual(len(keys), len(set(keys)))


if __name__ == "__main__":
    unittest.main()
