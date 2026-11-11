"""Invariant registry v1.1 (P6d; C-150 closed by C-178; C-179 to C-181; C-85, C-62).

Every expectation is typed from the P6d work package (sections 2, 3.2, 3.3) and the registry text:

* ``docs/specs/INVARIANT_REGISTRY_v1.1.md`` exists; ``INVARIANT_REGISTRY_v1.md`` is byte-identical
  to the file tagged ``registry-v1.0`` (C-85: after the tag a change is a new file).
* v1.1 changes exactly: §3.3 ``possible4``/``possible6`` (with a note), two §2.9 sentences, and the
  versions (registry 1.1; INV-SEC-001 and INV-SEC-002 at version 2; INV-SEC-003 and INV-FUNC-001
  stay at version 1). Each change is marked ``[v1.1]`` and listed in a change log at the top.
* DAIL's definitions for v1.1: INV-SEC-001/002 version 2 citing ``registry-v1.1``; INV-SEC-003 and
  INV-FUNC-001 the v1.0 definitions unchanged. DAIL stores registry 1.1 as the integer 2 (C-180,
  the user's decision of 11 Nov 2026: ``invariant_registry_version`` stays an int, C-32).
* Evidence for SEC v1 does not satisfy v2 (C-62: supersession and reuse need equal
  ``invariant_version``).
* The canonical scenario under v1.1: the unsafe candidate is REJECTED, the safe one PROMOTED.
"""

from __future__ import annotations

import dataclasses
import difflib
import hashlib
import unittest
from functools import cache
from pathlib import Path

from core.domain.enums import DecisionType, VerificationResult
from core.domain.impact import ReasonCode
from core.domain.invariant import Invariant
from core.domain.jsonvalue import thaw_json
from core.domain.promotion import ProofSource
from core.domain.registry_v1 import registry_v1_invariants
from core.domain.registry_v1_1 import (
    REGISTRY_TAG_V1_1,
    REGISTRY_VERSION_V1_1,
    registry_v1_1_invariants,
)
from core.verification.dispatch import DEFAULT_VERIFIERS, registry_of
from tests.domain_builders import at
from tests.pipeline_builders import inputs_for
from tests.promotion_pipeline import ROOT as FIXTURES_ROOT
from tests.promotion_pipeline import PipelineRun, fixtures_with_a_parent, pipeline, trusted_from

SPECS = Path(__file__).resolve().parents[2] / "docs" / "specs"
V1_0 = SPECS / "INVARIANT_REGISTRY_v1.md"
V1_1 = SPECS / "INVARIANT_REGISTRY_v1.1.md"
# sha256 of INVARIANT_REGISTRY_v1.md at d7c0333 (the tagged text), line endings normalized to LF
V1_0_SHA256 = "031719cd8fe18544a82e863eb83cee45c4c495b07b2123a254a86bf58800ad5a"
NOW = at(0)
S, D = "aws_instance.app", "aws_db_instance.database"
SEC1, SEC2, SEC3, FUNC = "INV-SEC-001", "INV-SEC-002", "INV-SEC-003", "INV-FUNC-001"
SAFE = "canonical_safe_repair_promote_v1"
REGRESSION = "canonical_security_repair_breaks_function_reject_v1"

NEW_POSSIBLE = """possible4(g) := exists indeterminate r in In(g) that could permit TCP/p
                (its protocol or ports unresolved, or they permit p) and
                (its IPv4 sources are unresolved or include a prefix list,
                 or its resolved IPv4 sources, together with the union of v4(r')
                 over r' in D(g), cover 0.0.0.0/0).
possible6(g) is the same for IPv6 sources and ::/0."""
OLD_POSSIBLE = "IPv4 sources are unresolved or include a prefix list."
SENTENCE_1 = (
    "In the footprint comparison, an argument that neither configuration writes compares as "
    "absent on both sides and is not changed. The predicates still treat such a value as §2.2 says."
)
SENTENCE_2 = (
    "The parent counterpart's inline-rule form (§3.5, §6.6) is compared through what it decides: "
    "whether the group is RETAINED-INLINE in that direction (§2.6). A baseline has no parent, so "
    "this is false for every group of a baseline."
)


def text(path: Path) -> str:
    return path.read_bytes().decode("utf-8").replace("\r\n", "\n")


def squash(value: str) -> str:
    """Whitespace-insensitive form, for text that a Markdown file may wrap or indent."""
    return " ".join(value.split())


class TestRegistryFiles(unittest.TestCase):
    def test_v1_0_is_byte_identical_to_the_tagged_text(self) -> None:
        data = V1_0.read_bytes().replace(b"\r\n", b"\n")
        self.assertEqual(hashlib.sha256(data).hexdigest(), V1_0_SHA256)

    def test_v1_1_exists_with_registry_version_1_1(self) -> None:
        body = text(V1_1)
        self.assertTrue(body.startswith("# Invariant Registry Specification v1.1\n"))
        self.assertIn("`invariant_registry_version = 1.1`", body)

    def test_the_new_possible_clause_replaces_the_old_one(self) -> None:
        body = squash(text(V1_1))
        self.assertIn(squash(NEW_POSSIBLE), body)
        self.assertNotIn(squash(OLD_POSSIBLE), body)
        self.assertIn(squash(OLD_POSSIBLE), squash(text(V1_0)))  # the old text was there

    def test_the_two_section_2_9_sentences(self) -> None:
        body = squash(text(V1_1))
        section = body[body.index("### 2.9") : body.index("### 2.10")]
        self.assertIn(squash(SENTENCE_1), section)
        self.assertIn(squash(SENTENCE_2), section)

    def test_invariant_versions(self) -> None:
        body = text(V1_1)
        self.assertIn("`INV-SEC-001`, version 2.", body)
        self.assertIn("`INV-SEC-002`, version 2.", body)
        self.assertIn("`INV-SEC-003`, version 1.", body)
        self.assertIn("`INV-FUNC-001`, version 1.", body)

    def test_every_change_is_marked_and_in_the_change_log(self) -> None:
        old, new = text(V1_0).splitlines(), text(V1_1).splitlines()
        top = new[: new.index("---")]  # the change log sits above the first rule of the file
        self.assertIn("## Change log (v1.0 to v1.1)", top)
        entries = [line for line in top if line.startswith("- [v1.1] ")]
        self.assertEqual(len(entries), 3, entries)  # §3.3, §2.9, §1 versioning
        for wanted in ("**§3.3 `possible4` and `possible6`**", "**§2.9 clarification**", "**§1"):
            self.assertEqual(sum(wanted in entry for entry in entries), 1, wanted)
        matcher = difflib.SequenceMatcher(a=old, b=new, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue
            if (i1, i2, j1, j2) == (0, 1, 0, 1):
                self.assertEqual(new[0], "# Invariant Registry Specification v1.1")
                continue  # the title names the file; it is not a change of the text
            if tag == "delete":
                self.fail(f"lines of v1.0 removed without a marked replacement: {old[i1:i2]}")
            # the marker is in the change or right beside it (a code block cannot hold one)
            window = "\n".join(new[max(0, j1 - 3) : j2 + 3])
            with self.subTest(lines=f"{j1 + 1}-{j2}"):
                self.assertIn("[v1.1]", window)


class TestDefinitions(unittest.TestCase):
    def setUp(self) -> None:
        self.v10 = {d.invariant_id: d for d in registry_v1_invariants(NOW, source=S, destination=D)}
        self.v11 = {
            d.invariant_id: d for d in registry_v1_1_invariants(NOW, source=S, destination=D)
        }

    def test_registry_version_and_tag(self) -> None:
        self.assertEqual(REGISTRY_TAG_V1_1, "registry-v1.1")
        self.assertEqual(REGISTRY_VERSION_V1_1, 2)

    def test_sec_001_and_002_are_version_2_and_cite_v1_1(self) -> None:
        for invariant_id, section, port in ((SEC1, "§3", 22), (SEC2, "§4", 5432)):
            definition = self.v11[invariant_id]
            with self.subTest(invariant=invariant_id):
                self.assertEqual(definition.version, 2)
                self.assertEqual(
                    dict(definition.predicate),
                    {"registry": "registry-v1.1", "section": section, "parameters": {"p": port}},
                )
                self.assertIn("registry-v1.1", definition.description)
                old = self.v10[invariant_id]
                self.assertEqual(
                    (definition.verifier_id, definition.verifier_version),
                    (old.verifier_id, old.verifier_version),
                )
                self.assertEqual(definition.scope, old.scope)
                self.assertNotEqual(definition.definition_hash(), old.definition_hash())

    def test_sec_003_and_func_001_are_the_v1_0_definitions(self) -> None:
        for invariant_id in (SEC3, FUNC):
            with self.subTest(invariant=invariant_id):
                self.assertEqual(self.v11[invariant_id].version, 1)
                self.assertEqual(
                    self.v11[invariant_id].definition_hash(),
                    self.v10[invariant_id].definition_hash(),
                )

    def test_the_definition_chooses_the_section_3_3_text(self) -> None:
        self.assertEqual(registry_of(self.v10[SEC1]), "registry-v1.0")
        self.assertEqual(registry_of(self.v11[SEC1]), "registry-v1.1")
        self.assertEqual(registry_of(self.v11[SEC2]), "registry-v1.1")
        for bad in ("registry-v9", None, 1):
            predicate = {**thaw_json(self.v11[SEC1].predicate), "registry": bad}
            with self.subTest(tag=bad), self.assertRaises(ValueError):
                registry_of(dataclasses.replace(self.v11[SEC1], predicate=predicate))

    def test_the_verifier_evaluates_each_definition_under_its_own_registry(self) -> None:
        # registry v1.0 §3.3 gives PASS for this rule (C-150); v1.1 §3.3 gives UNKNOWN (C-178)
        gap = (
            'variable "u" {}\n'
            'resource "aws_security_group" "app" {\n}\n'
            'resource "aws_security_group_rule" "r" {\n  type = "ingress"\n'
            '  security_group_id = aws_security_group.app.id\n  protocol = "tcp"\n'
            '  from_port = var.u\n  to_port = 22\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        )
        inputs = inputs_for(gap, with_graphs=False)
        cases = (
            (self.v10[SEC1], VerificationResult.PASS),
            (self.v11[SEC1], VerificationResult.UNKNOWN),
            (self.v10[SEC2], VerificationResult.PASS),
            # §3.3: "could permit TCP/p (its protocol or ports unresolved, ...)": an unresolved
            # from_port could permit 5432 whatever to_port says
            (self.v11[SEC2], VerificationResult.UNKNOWN),
        )
        for definition, expected in cases:
            with self.subTest(invariant=definition.invariant_id, version=definition.version):
                verifier = DEFAULT_VERIFIERS[(definition.verifier_id, definition.verifier_version)]
                self.assertIs(verifier(definition, inputs).result, expected)

    def test_sorted_by_id(self) -> None:
        ids = [d.invariant_id for d in registry_v1_1_invariants(NOW, source=S, destination=D)]
        self.assertEqual(ids, sorted([SEC1, SEC2, SEC3, FUNC]))


# --- the pipeline under v1.1 ----------------------------------------------------------------------


def v11_definitions(fixture_id: str) -> list[Invariant]:
    binding = fixtures_with_a_parent()[fixture_id].data["bindings"]["INV-FUNC-001"]
    return list(registry_v1_1_invariants(NOW, source=binding["S"], destination=binding["D"]))


def v10_definitions(fixture_id: str) -> list[Invariant]:
    binding = fixtures_with_a_parent()[fixture_id].data["bindings"]["INV-FUNC-001"]
    return list(registry_v1_invariants(NOW, source=binding["S"], destination=binding["D"]))


@cache
def under_v11(fixture_id: str) -> PipelineRun:
    """Parent and candidate both under v1.1 (the parent's proofs are of the v1.1 versions)."""
    return pipeline(
        fixtures_with_a_parent()[fixture_id],
        definitions=v11_definitions(fixture_id),
        registry_version=REGISTRY_VERSION_V1_1,
    )


@cache
def v10_parent_v11_candidate(fixture_id: str) -> PipelineRun:
    """The parent was proven under v1.0 (SEC proofs of version 1); the candidate is checked under
    v1.1 (SEC version 2)."""
    fixture = fixtures_with_a_parent()[fixture_id]
    from core.terraform_model.normalization import normalize_directory
    from tests.identity_builders import NOW as PIPE_NOW

    parent = fixture.data["parent"]
    before = normalize_directory(FIXTURES_ROOT / parent, None, now=PIPE_NOW)
    trusted = trusted_from(parent, before.resources, v10_definitions(fixture_id))
    return pipeline(
        fixture,
        definitions=v11_definitions(fixture_id),
        registry_version=REGISTRY_VERSION_V1_1,
        parent_trusted=trusted,
    )


def decide_v11(run: PipelineRun):  # type: ignore[no-untyped-def]
    return run.decide(policy=run.policy(invariant_registry_version=REGISTRY_VERSION_V1_1))


class TestCanonicalScenarioUnderV11(unittest.TestCase):
    def test_the_safe_repair_is_promoted(self) -> None:
        outcome = decide_v11(under_v11(SAFE))
        self.assertIs(outcome.decision.decision, DecisionType.PROMOTE)

    def test_the_repair_that_breaks_the_database_path_is_rejected(self) -> None:
        outcome = decide_v11(under_v11(REGRESSION))
        self.assertIs(outcome.decision.decision, DecisionType.REJECT)

    def test_sec_evidence_cites_version_2_and_registry_1_1(self) -> None:
        run = under_v11(SAFE)
        records = {r.target_id: r for r in run.verification.results}
        record = records["INVARIANT:INV-SEC-001:2"]
        self.assertEqual((record.invariant_id, record.invariant_version), (SEC1, 2))
        self.assertEqual(record.evidence["invariant_version"], 2)
        self.assertTrue(str(record.evidence["predicate"]).startswith("registry-v1.1 §3 "))
        self.assertEqual(
            (record.verifier_id, record.verifier_version), ("dail.verify.public_ingress", "1")
        )


class TestVersion1EvidenceDoesNotSatisfyVersion2(unittest.TestCase):
    def test_the_sec_proofs_of_version_1_are_not_carried_forward(self) -> None:
        run = v10_parent_v11_candidate(SAFE)
        refs = {r.invariant_id: r.invariant_version for r in run.trusted.invariant_refs}
        self.assertEqual(refs, {SEC1: 1, SEC2: 1, SEC3: 1, FUNC: 1})
        for invariant_id in (SEC1, SEC2):
            with self.subTest(invariant=invariant_id):
                self.assertFalse(
                    run.impact.carry_forward_ok(
                        invariant_id,
                        2,
                        candidate_id=run.candidate.candidate_id,
                        parent_state_id=run.trusted.state_id,
                    )
                )
                self.assertFalse(
                    run.impact.carry_forward_ok(
                        invariant_id,
                        1,
                        candidate_id=run.candidate.candidate_id,
                        parent_state_id=run.trusted.state_id,
                    )
                )
                unaffected = {u.key(): u for u in run.impact.unaffected}
                if (invariant_id, 2) in unaffected:
                    self.assertIs(
                        unaffected[(invariant_id, 2)].reason, ReasonCode.INVARIANT_VERSION_CHANGED
                    )
        self.assertIn("INVARIANT:INV-SEC-002:2", run.work)  # verified again, never carried

    def test_the_decision_verifies_sec_version_2_and_never_reuses_version_1(self) -> None:
        run = v10_parent_v11_candidate(SAFE)
        outcome = decide_v11(run)
        plan = {(e.invariant_id, e.invariant_version): e.source for e in outcome.proof_plan}
        self.assertEqual(plan.get((SEC2, 2)), ProofSource.VERIFIED)
        self.assertNotIn((SEC2, 1), plan)
        self.assertIs(outcome.decision.decision, DecisionType.PROMOTE)

    def test_the_default_verifier_table_is_unchanged(self) -> None:
        self.assertEqual(
            sorted(DEFAULT_VERIFIERS),
            [
                ("dail.verify.public_ingress", "1"),
                ("dail.verify.rds_public_flag", "1"),
                ("dail.verify.reachability_cfg", "1"),
            ],
        )


if __name__ == "__main__":
    unittest.main()
