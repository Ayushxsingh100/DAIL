"""Invariant definitions, registry, proofs and state-scoped references.

Doc 05 §10, §28; Doc 06 §4.2, §13, §14; C-04, C-31, C-37; P1a step 11.
The candidate-scoped ``InvariantEvaluation`` is tested in ``test_lifecycle_matrix.py``
and ``test_evaluation.py``, because it needs a ``CandidateState``.
"""

from __future__ import annotations

import dataclasses
import json
import unittest
from datetime import UTC, datetime, timedelta, timezone
from typing import Any

from core.domain.enums import InvariantCategory, InvariantStatus
from core.domain.errors import DomainValidationError, UnauthorizedConstructionError
from core.domain.invariant import (
    Invariant,
    InvariantProof,
    InvariantRef,
    InvariantRegistry,
    InvariantScope,
    new_version,
)

NOW = datetime(2026, 10, 1, 9, 30, tzinfo=UTC)
LATER = datetime(2026, 10, 2, 9, 30, tzinfo=UTC)
STATE = "123e4567-e89b-42d3-a456-426614174000"
EVIDENCE_A = "223e4567-e89b-42d3-a456-426614174001"
EVIDENCE_B = "323e4567-e89b-42d3-a456-426614174002"
CANDIDATE = "423e4567-e89b-42d3-a456-426614174003"


def make_scope(**overrides: Any) -> InvariantScope:
    fields: dict[str, Any] = {
        "resources": ["aws_security_group.web"],
        "resource_types": ["aws_security_group"],
        "relationships": ["ingress"],
        "properties": ["ingress.cidr_blocks"],
        "dependency_depth": 1,
    }
    fields.update(overrides)
    return InvariantScope(**fields)


def make_invariant(**overrides: Any) -> Invariant:
    fields: dict[str, Any] = {
        "invariant_id": "INV-SEC-001",
        "version": 1,
        "name": "no public ssh",
        "category": InvariantCategory.SECURITY,
        "description": "No security group allows ingress from 0.0.0.0/0 to port 22",
        "predicate": {"op": "no_public_ingress", "port": 22},
        "scope": make_scope(),
        "verifier_id": "sg-ssh-verifier",
        "verifier_version": "1.0.0",
        "created_at": NOW,
    }
    fields.update(overrides)
    return Invariant(**fields)


def make_proof(**overrides: Any) -> InvariantProof:
    fields: dict[str, Any] = {
        "invariant_id": "INV-SEC-001",
        "invariant_version": 1,
        "status": InvariantStatus.PROTECTED,
        "evidence_ids": (EVIDENCE_A,),
        "verified_at": NOW,
    }
    fields.update(overrides)
    return InvariantProof(**fields)


def ref_dict(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "invariant_id": "INV-SEC-001",
        "invariant_version": 1,
        "state_id": STATE,
        "status": "PROTECTED",
        "evidence_ids": [EVIDENCE_A],
        "last_verified_at": "2026-10-01T09:30:00+00:00",
        "invalidated_by_candidate_id": None,
        "invalidation_reason": None,
    }
    data.update(overrides)
    return data


class TestInvariantScope(unittest.TestCase):
    def test_valid_scope_keeps_sorted_unique_tuples(self) -> None:
        scope = make_scope(
            resources=["b.x", "a.x", "b.x"],
            resource_types=["t2", "t1"],
            relationships=["r2", "r1", "r1"],
            properties=["p2", "p1"],
        )
        self.assertEqual(scope.resources, ("a.x", "b.x"))
        self.assertEqual(scope.resource_types, ("t1", "t2"))
        self.assertEqual(scope.relationships, ("r1", "r2"))
        self.assertEqual(scope.properties, ("p1", "p2"))

    def test_order_of_input_lists_does_not_matter(self) -> None:
        self.assertEqual(make_scope(resources=["a.x", "b.x"]), make_scope(resources=["b.x", "a.x"]))

    def test_either_resources_or_resource_types_is_enough(self) -> None:
        self.assertEqual(make_scope(resources=[]).resources, ())
        self.assertEqual(make_scope(resource_types=[]).resource_types, ())

    def test_scope_with_neither_resources_nor_types_is_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            make_scope(resources=[], resource_types=[])
        with self.assertRaises(DomainValidationError):
            make_scope(resources=[], resource_types=[], relationships=["r"], properties=["p"])

    def test_dependency_depth_must_be_a_non_negative_int(self) -> None:
        self.assertEqual(make_scope(dependency_depth=0).dependency_depth, 0)
        for bad in (-1, 1.5, "1", None, True):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_scope(dependency_depth=bad)

    def test_items_must_be_clean_non_empty_text(self) -> None:
        for field in ("resources", "resource_types", "relationships", "properties"):
            for bad in ([""], [" x"], [3], [None], "abc"):
                with self.subTest(field=field, value=bad), self.assertRaises(DomainValidationError):
                    make_scope(**{field: bad})

    def test_input_list_mutation_does_not_change_the_scope(self) -> None:
        resources = ["a.x"]
        scope = make_scope(resources=resources)
        resources.append("evil.x")
        self.assertEqual(scope.resources, ("a.x",))

    def test_scope_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            make_scope().dependency_depth = 3  # type: ignore[misc]

    def test_round_trip(self) -> None:
        scope = make_scope()
        data = scope.to_dict()
        json.dumps(data)
        self.assertEqual(InvariantScope.from_dict(data), scope)
        self.assertIsInstance(data["resources"], list)

    def test_from_dict_revalidates_and_checks_keys(self) -> None:
        good = make_scope().to_dict()
        with self.assertRaises(DomainValidationError):
            InvariantScope.from_dict({**good, "dependency_depth": -2})
        with self.assertRaises(DomainValidationError):
            InvariantScope.from_dict({k: v for k, v in good.items() if k != "properties"})
        with self.assertRaises(DomainValidationError):
            InvariantScope.from_dict({**good, "extra": []})


class TestInvariantDefinition(unittest.TestCase):
    def test_valid_definition(self) -> None:
        inv = make_invariant()
        self.assertEqual(inv.invariant_id, "INV-SEC-001")
        self.assertEqual(inv.category, InvariantCategory.SECURITY)
        self.assertEqual(inv.predicate["op"], "no_public_ingress")

    def test_definition_has_no_status(self) -> None:
        """C-04: the definition is immutable; status lives on references and evaluations."""
        self.assertFalse(hasattr(make_invariant(), "status"))
        self.assertNotIn("status", make_invariant().to_dict())

    def test_invariant_id_pattern(self) -> None:
        for good in ("INV-SEC-001", "INV-FUNC-002", "INV-A1-999"):
            self.assertEqual(make_invariant(invariant_id=good).invariant_id, good)
        for bad in (
            "inv-sec-001",
            "INV-SEC-1",
            "INV-SEC-0001",
            "INV-SEC_001",
            "INV--001",
            "INV-SEC-001 ",
            "SEC-001",
            "",
            None,
            5,
        ):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_invariant(invariant_id=bad)

    def test_version_must_be_a_positive_int(self) -> None:
        for bad in (0, -1, 1.0, "1", None, True):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_invariant(version=bad)

    def test_required_text_fields(self) -> None:
        for field in ("name", "description", "verifier_id", "verifier_version"):
            for bad in ("", "  ", None, 3):
                with self.subTest(field=field, value=bad), self.assertRaises(DomainValidationError):
                    make_invariant(**{field: bad})

    def test_category_must_be_the_enum(self) -> None:
        for bad in ("SECURITY", None):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_invariant(category=bad)

    def test_predicate_must_be_a_non_empty_json_object_without_floats(self) -> None:
        for bad in ({}, [1], "x", None, {"a": 0.5}):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_invariant(predicate=bad)

    def test_scope_must_be_an_invariant_scope(self) -> None:
        for bad in ({"resources": ["a.x"]}, None):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_invariant(scope=bad)

    def test_created_at_must_be_aware_utc(self) -> None:
        with self.assertRaises(DomainValidationError):
            make_invariant(created_at=datetime(2026, 10, 1))
        with self.assertRaises(DomainValidationError):
            make_invariant(created_at=datetime(2026, 10, 1, tzinfo=timezone(timedelta(hours=2))))

    def test_definition_is_frozen_and_deeply_immutable(self) -> None:
        inv = make_invariant()
        for field in ("name", "version", "predicate", "scope", "verifier_version"):
            with self.subTest(field=field), self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(inv, field, "x")
        with self.assertRaises(TypeError):
            inv.predicate["op"] = "other"  # type: ignore[index]

    def test_callers_predicate_mutation_changes_nothing(self) -> None:
        predicate: dict[str, Any] = {"op": "x", "args": {"port": 22}}
        inv = make_invariant(predicate=predicate)
        before = inv.definition_hash()
        predicate["args"]["port"] = 80
        self.assertEqual(inv.definition_hash(), before)
        self.assertEqual(inv.predicate["args"]["port"], 22)

    def test_round_trip(self) -> None:
        inv = make_invariant()
        data = inv.to_dict()
        json.dumps(data)
        self.assertEqual(data["category"], "SECURITY")
        self.assertEqual(data["created_at"], "2026-10-01T09:30:00+00:00")
        self.assertEqual(Invariant.from_dict(data), inv)

    def test_from_dict_revalidates_and_checks_keys(self) -> None:
        good = make_invariant().to_dict()
        for key, bad in (("invariant_id", "x"), ("version", 0), ("category", "OTHER")):
            with self.subTest(key=key), self.assertRaises(DomainValidationError):
                Invariant.from_dict({**good, key: bad})
        with self.assertRaises(DomainValidationError):
            Invariant.from_dict({k: v for k, v in good.items() if k != "scope"})
        with self.assertRaises(DomainValidationError):
            Invariant.from_dict({**good, "status": "PROTECTED"})


class TestDefinitionHash(unittest.TestCase):
    def test_hash_ignores_created_at_and_is_stable(self) -> None:
        self.assertEqual(
            make_invariant().definition_hash(), make_invariant(created_at=LATER).definition_hash()
        )
        self.assertRegex(make_invariant().definition_hash(), r"^[0-9a-f]{64}$")

    def test_hash_ignores_predicate_key_order(self) -> None:
        a = make_invariant(predicate={"a": 1, "b": {"x": 1, "y": 2}})
        b = make_invariant(predicate={"b": {"y": 2, "x": 1}, "a": 1})
        self.assertEqual(a.definition_hash(), b.definition_hash())

    def test_every_other_field_changes_the_hash(self) -> None:
        base = make_invariant().definition_hash()
        changes: dict[str, Any] = {
            "invariant_id": "INV-SEC-002",
            "version": 2,
            "name": "other",
            "category": InvariantCategory.FUNCTIONAL,
            "description": "other",
            "predicate": {"op": "different"},
            "scope": make_scope(dependency_depth=2),
            "verifier_id": "other",
            "verifier_version": "2.0.0",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(make_invariant(**{field: value}).definition_hash(), base)


class TestNewVersion(unittest.TestCase):
    """Doc 06 §4.2: changing an invariant definition creates a new version."""

    def test_new_version_increments_and_applies_changes(self) -> None:
        v1 = make_invariant()
        v2 = Invariant.new_version(v1, now=LATER, description="tightened", verifier_version="1.1.0")
        self.assertEqual(v2.version, 2)
        self.assertEqual(v2.invariant_id, v1.invariant_id)
        self.assertEqual(v2.description, "tightened")
        self.assertEqual(v2.verifier_version, "1.1.0")
        self.assertEqual(v2.created_at, LATER)
        self.assertEqual(v2.name, v1.name)

    def test_the_module_level_function_is_the_same_operation(self) -> None:
        v1 = make_invariant()
        self.assertEqual(
            new_version(v1, now=LATER, description="tightened"),
            Invariant.new_version(v1, now=LATER, description="tightened"),
        )
        self.assertEqual(new_version(v1, now=LATER).version, 2)

    def test_the_original_is_untouched(self) -> None:
        v1 = make_invariant()
        before = v1.to_dict()
        Invariant.new_version(v1, now=LATER, description="changed")
        self.assertEqual(v1.to_dict(), before)
        self.assertEqual(v1.version, 1)

    def test_identity_version_and_timestamp_cannot_be_overridden(self) -> None:
        for field, value in (("invariant_id", "INV-SEC-009"), ("version", 5), ("created_at", NOW)):
            with self.subTest(field=field), self.assertRaises(DomainValidationError):
                Invariant.new_version(make_invariant(), now=LATER, **{field: value})

    def test_unknown_fields_are_rejected(self) -> None:
        with self.assertRaises(DomainValidationError):
            Invariant.new_version(make_invariant(), now=LATER, status=InvariantStatus.PROTECTED)

    def test_the_new_version_is_validated(self) -> None:
        with self.assertRaises(DomainValidationError):
            Invariant.new_version(make_invariant(), now=LATER, name="")
        with self.assertRaises(DomainValidationError):
            Invariant.new_version(make_invariant(), now=datetime(2026, 10, 2))


class TestRegistry(unittest.TestCase):
    def test_register_and_get(self) -> None:
        registry = InvariantRegistry()
        inv = make_invariant()
        registry.register(inv)
        self.assertEqual(registry.get("INV-SEC-001", 1), inv)

    def test_duplicate_id_and_version_is_rejected(self) -> None:
        registry = InvariantRegistry()
        registry.register(make_invariant())
        with self.assertRaises(DomainValidationError):
            registry.register(make_invariant())

    def test_versions_must_start_at_one_and_have_no_gaps(self) -> None:
        registry = InvariantRegistry()
        with self.assertRaises(DomainValidationError):
            registry.register(make_invariant(version=2))
        registry.register(make_invariant(version=1))
        with self.assertRaises(DomainValidationError):
            registry.register(make_invariant(version=3))
        registry.register(make_invariant(version=2))
        registry.register(make_invariant(version=3))
        self.assertEqual(registry.latest("INV-SEC-001").version, 3)

    def test_ids_are_versioned_independently(self) -> None:
        registry = InvariantRegistry()
        registry.register(make_invariant())
        registry.register(
            make_invariant(invariant_id="INV-FUNC-001", category=InvariantCategory.FUNCTIONAL)
        )
        self.assertEqual(registry.latest("INV-FUNC-001").version, 1)
        self.assertEqual(registry.latest("INV-SEC-001").version, 1)

    def test_missing_lookups_raise_a_domain_error(self) -> None:
        registry = InvariantRegistry()
        registry.register(make_invariant())
        with self.assertRaises(DomainValidationError):
            registry.get("INV-NOPE-001", 1)
        with self.assertRaises(DomainValidationError):
            registry.get("INV-SEC-001", 2)
        with self.assertRaises(DomainValidationError):
            registry.latest("INV-NOPE-001")

    def test_definitions_are_sorted_by_id_then_version(self) -> None:
        registry = InvariantRegistry()
        registry.register(make_invariant(invariant_id="INV-SEC-002"))
        registry.register(
            make_invariant(invariant_id="INV-FUNC-001", category=InvariantCategory.FUNCTIONAL)
        )
        registry.register(make_invariant(invariant_id="INV-SEC-002", version=2))
        registry.register(make_invariant(invariant_id="INV-SEC-001"))
        keys = [(d.invariant_id, d.version) for d in registry.definitions()]
        self.assertEqual(
            keys,
            [("INV-FUNC-001", 1), ("INV-SEC-001", 1), ("INV-SEC-002", 1), ("INV-SEC-002", 2)],
        )

    def test_only_invariant_objects_are_accepted(self) -> None:
        with self.assertRaises(DomainValidationError):
            InvariantRegistry().register({"invariant_id": "INV-SEC-001"})  # type: ignore[arg-type]

    def test_registry_offers_no_status_queries(self) -> None:
        registry = InvariantRegistry()
        for name in ("all_protected", "protected", "status", "set_status", "transition_to"):
            self.assertFalse(hasattr(registry, name), name)


class TestInvariantProof(unittest.TestCase):
    def test_valid_proof_for_each_trusted_status(self) -> None:
        for status in (
            InvariantStatus.PROTECTED,
            InvariantStatus.VIOLATED,
            InvariantStatus.UNCERTAIN,
        ):
            self.assertEqual(make_proof(status=status).status, status)

    def test_status_must_be_a_trusted_ref_status(self) -> None:
        for status in (
            InvariantStatus.REGISTERED,
            InvariantStatus.VERIFYING,
            InvariantStatus.AFFECTED,
            InvariantStatus.REVERIFYING,
            "PROTECTED",
            None,
        ):
            with self.subTest(status=status), self.assertRaises(DomainValidationError):
                make_proof(status=status)

    def test_evidence_is_required_sorted_and_deduplicated(self) -> None:
        proof = make_proof(evidence_ids=[EVIDENCE_B, EVIDENCE_A, EVIDENCE_B])
        self.assertEqual(proof.evidence_ids, (EVIDENCE_A, EVIDENCE_B))
        for bad in ((), [], ["not-a-uuid"], [EVIDENCE_A, 5], "abc", None):
            with self.subTest(value=bad), self.assertRaises(DomainValidationError):
                make_proof(evidence_ids=bad)

    def test_identity_fields_and_timestamp_are_validated(self) -> None:
        with self.assertRaises(DomainValidationError):
            make_proof(invariant_id="bad")
        with self.assertRaises(DomainValidationError):
            make_proof(invariant_version=0)
        with self.assertRaises(DomainValidationError):
            make_proof(verified_at=datetime(2026, 10, 1))

    def test_proof_is_frozen(self) -> None:
        with self.assertRaises(dataclasses.FrozenInstanceError):
            make_proof().status = InvariantStatus.VIOLATED  # type: ignore[misc]


class TestInvariantRef(unittest.TestCase):
    """State-scoped reference (C-31): immutable, evidence-backed, three statuses only."""

    def test_direct_construction_is_refused(self) -> None:
        with self.assertRaises(UnauthorizedConstructionError):
            InvariantRef(  # type: ignore[call-arg]
                invariant_id="INV-SEC-001",
                invariant_version=1,
                state_id=STATE,
                status=InvariantStatus.PROTECTED,
                evidence_ids=(EVIDENCE_A,),
                last_verified_at=NOW,
                invalidated_by_candidate_id=None,
                invalidation_reason=None,
            )

    def test_replace_cannot_change_a_status(self) -> None:
        ref = InvariantRef.from_dict(ref_dict(status="VIOLATED"))
        with self.assertRaises(UnauthorizedConstructionError):
            dataclasses.replace(ref, status=InvariantStatus.PROTECTED)

    def test_from_dict_builds_a_valid_reference(self) -> None:
        ref = InvariantRef.from_dict(ref_dict())
        self.assertEqual(ref.state_id, STATE)
        self.assertEqual(ref.status, InvariantStatus.PROTECTED)
        self.assertEqual(ref.evidence_ids, (EVIDENCE_A,))
        self.assertEqual(ref.last_verified_at, NOW)
        self.assertIsNone(ref.invalidated_by_candidate_id)

    def test_status_must_be_protected_violated_or_uncertain(self) -> None:
        for status in ("REGISTERED", "VERIFYING", "AFFECTED", "REVERIFYING", "NOPE", None):
            with self.subTest(status=status), self.assertRaises(DomainValidationError):
                InvariantRef.from_dict(ref_dict(status=status))
        for status in ("PROTECTED", "VIOLATED", "UNCERTAIN"):
            self.assertEqual(InvariantRef.from_dict(ref_dict(status=status)).status.value, status)

    def test_evidence_and_verification_time_are_required(self) -> None:
        for bad in ([], None, ["x"], [EVIDENCE_A, 3]):
            with self.subTest(evidence=bad), self.assertRaises(DomainValidationError):
                InvariantRef.from_dict(ref_dict(evidence_ids=bad))
        for bad in (None, "2026-10-01T09:30:00"):
            with self.subTest(last_verified_at=bad), self.assertRaises(DomainValidationError):
                InvariantRef.from_dict(ref_dict(last_verified_at=bad))

    def test_ids_are_validated(self) -> None:
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict(ref_dict(state_id="state-1"))
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict(ref_dict(invariant_id="bad"))
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict(ref_dict(invariant_version=0))

    def test_invalidation_fields_are_both_set_or_both_null(self) -> None:
        InvariantRef.from_dict(
            ref_dict(invalidated_by_candidate_id=CANDIDATE, invalidation_reason="affected")
        )
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict(ref_dict(invalidated_by_candidate_id=CANDIDATE))
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict(ref_dict(invalidation_reason="affected"))
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict(
                ref_dict(invalidated_by_candidate_id="not-a-uuid", invalidation_reason="affected")
            )
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict(
                ref_dict(invalidated_by_candidate_id=CANDIDATE, invalidation_reason="")
            )

    def test_can_satisfy_proof_only_for_a_protected_uninvalidated_ref(self) -> None:
        self.assertTrue(InvariantRef.from_dict(ref_dict()).can_satisfy_proof())
        for status in ("VIOLATED", "UNCERTAIN"):
            self.assertFalse(InvariantRef.from_dict(ref_dict(status=status)).can_satisfy_proof())
        invalidated = ref_dict(
            invalidated_by_candidate_id=CANDIDATE, invalidation_reason="affected"
        )
        self.assertFalse(InvariantRef.from_dict(invalidated).can_satisfy_proof())
        self.assertFalse(
            InvariantRef.from_dict({**invalidated, "status": "VIOLATED"}).can_satisfy_proof()
        )

    def test_reference_is_frozen(self) -> None:
        ref = InvariantRef.from_dict(ref_dict())
        for field in ("status", "state_id", "evidence_ids"):
            with self.subTest(field=field), self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(ref, field, "x")

    def test_round_trip(self) -> None:
        for data in (
            ref_dict(),
            ref_dict(
                status="UNCERTAIN",
                evidence_ids=[EVIDENCE_A, EVIDENCE_B],
                invalidated_by_candidate_id=CANDIDATE,
                invalidation_reason="affected by candidate",
            ),
        ):
            ref = InvariantRef.from_dict(data)
            out = ref.to_dict()
            json.dumps(out)
            self.assertEqual(InvariantRef.from_dict(out), ref)
        self.assertEqual(InvariantRef.from_dict(ref_dict()).to_dict(), ref_dict())

    def test_from_dict_checks_keys(self) -> None:
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict({k: v for k, v in ref_dict().items() if k != "state_id"})
        with self.assertRaises(DomainValidationError):
            InvariantRef.from_dict(ref_dict(target_state_id=STATE))

    def test_a_ref_is_built_from_a_proof_for_a_state(self) -> None:
        proof = make_proof(status=InvariantStatus.UNCERTAIN, evidence_ids=[EVIDENCE_B, EVIDENCE_A])
        ref = InvariantRef._from_proof(proof, STATE)
        self.assertEqual(ref.state_id, STATE)
        self.assertEqual(ref.status, InvariantStatus.UNCERTAIN)
        self.assertEqual(ref.evidence_ids, (EVIDENCE_A, EVIDENCE_B))
        self.assertEqual(ref.last_verified_at, NOW)
        self.assertIsNone(ref.invalidated_by_candidate_id)
        with self.assertRaises(DomainValidationError):
            InvariantRef._from_proof(proof, "state-1")


if __name__ == "__main__":
    unittest.main()
