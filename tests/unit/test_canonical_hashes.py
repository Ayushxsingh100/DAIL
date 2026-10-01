"""Canonical hashes (Doc 05 §25, §27, §30; Doc 04 §6; Doc 12 §17; C-33; P1a Section 9 items 7, 8).

Golden tests: the expected canonical JSON is typed here as a literal string from the C-33
policy, hashed with ``hashlib`` in the test, and compared with the implementation. Property
tests use ``random.Random(seed)`` with at least 200 cases each; every assertion message
carries the seed so a failure can be replayed.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

from core.domain.enums import (
    CandidateSource,
    InvariantStatus,
    ProvenanceSourceKind,
    ReferenceResolution,
    ResourceSupport,
)
from core.domain.errors import DomainValidationError
from core.domain.hashing import canonical_json
from core.domain.invariant import InvariantScope
from core.domain.patch import Patch
from core.domain.resource import Resource
from core.domain.state import TrustedState, resource_set_hash
from core.domain.values import Provenance, Reference
from tests.domain_builders import at, proof, uid

REPO_ROOT = Path(__file__).resolve().parents[2]
CASES = 200
LINEAGE = "00000000-0000-4000-8000-0000000000aa"


def sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def prov(minutes: int = 0, component: str = "fixture") -> Provenance:
    return Provenance(
        source_kind=ProvenanceSourceKind.TERRAFORM_CONFIG,
        source_component=component,
        source_reference="main.tf",
        observed_at=at(minutes),
    )


# --- golden fixtures ---------------------------------------------------------------------------

APP = Resource.create(
    address="aws_instance.app",
    resource_type="aws_instance",
    logical_identity={"name": "app"},
    attributes={"instance_type": "t3.micro", "tags": {"Name": "app", "Env": "dev"}},
    security_attributes={},
    semantic_attributes={"role": "app"},
    references=[
        Reference(
            source_address="aws_instance.app",
            source_attribute="vpc_security_group_ids",
            target_address="aws_security_group.web",
            reference_type="security_group",
            resolution_status=ReferenceResolution.SUPPORTED,
        )
    ],
    provenance=prov(),
    support_status=ResourceSupport.SUPPORTED,
    record_id=uid(501),
)
WEB = Resource.create(
    address="aws_security_group.web",
    resource_type="aws_security_group",
    logical_identity={"name": "web"},
    attributes={"name": "web"},
    security_attributes={"ingress": [{"cidr": "0.0.0.0/0", "port": 22}]},
    semantic_attributes={},
    references=[],
    provenance=prov(),
    support_status=ResourceSupport.SUPPORTED,
    record_id=uid(502),
)

# C-33: canonical JSON over {resource_type, logical_identity, attributes, security_attributes,
# semantic_attributes, references}; sorted keys, no whitespace; each reference without its
# source_address.
APP_CANONICAL = (
    '{"attributes":{"instance_type":"t3.micro","tags":{"Env":"dev","Name":"app"}},'
    '"logical_identity":{"name":"app"},'
    '"references":[{"reference_type":"security_group","resolution_status":"SUPPORTED",'
    '"source_attribute":"vpc_security_group_ids","target_address":"aws_security_group.web"}],'
    '"resource_type":"aws_instance","security_attributes":{},"semantic_attributes":{"role":"app"}}'
)
WEB_CANONICAL = (
    '{"attributes":{"name":"web"},"logical_identity":{"name":"web"},"references":[],'
    '"resource_type":"aws_security_group",'
    '"security_attributes":{"ingress":[{"cidr":"0.0.0.0/0","port":22}]},"semantic_attributes":{}}'
)


def resource_entries() -> str:
    return (
        '[{"address":"aws_instance.app","fingerprint":"' + sha(APP_CANONICAL) + '",'
        '"resource_type":"aws_instance"},'
        '{"address":"aws_security_group.web","fingerprint":"' + sha(WEB_CANONICAL) + '",'
        '"resource_type":"aws_security_group"}]'
    )


class TestGoldenHashes(unittest.TestCase):
    def test_resource_canonical_json_and_fingerprint(self) -> None:
        self.assertEqual(APP.canonical_json, APP_CANONICAL)
        self.assertEqual(APP.fingerprint, sha(APP_CANONICAL))
        self.assertEqual(WEB.canonical_json, WEB_CANONICAL)
        self.assertEqual(WEB.fingerprint, sha(WEB_CANONICAL))

    def test_candidate_state_hash_is_the_resource_set_hash(self) -> None:
        expected = '{"normalization_version":"norm-1","resources":' + resource_entries() + "}"
        self.assertEqual(
            resource_set_hash([WEB, APP], "norm-1"), sha(expected)
        )  # input order is irrelevant
        self.assertEqual(resource_set_hash([APP, WEB], "norm-1"), sha(expected))

    def test_trusted_state_hash(self) -> None:
        base = TrustedState.establish_baseline(
            lineage_id=LINEAGE,
            resources=[WEB, APP],
            invariant_proofs=[
                proof("INV-SEC-001", InvariantStatus.VIOLATED, evidence=1),
                proof("INV-FUNC-001", InvariantStatus.PROTECTED, evidence=2),
            ],
            evidence_refs=[uid(1001), uid(1002)],
            normalization_version="norm-1",
            invariant_registry_version=1,
            now=at(1),
            state_id=uid(1),
        )
        expected = (
            '{"invariants":['
            '{"invariant_id":"INV-FUNC-001","invariant_version":1,"status":"PROTECTED"},'
            '{"invariant_id":"INV-SEC-001","invariant_version":1,"status":"VIOLATED"}],'
            f'"lineage_id":"{LINEAGE}","normalization_version":"norm-1",'
            '"resources":' + resource_entries() + ',"version":0}'
        )
        self.assertEqual(base.state_hash, sha(expected))

    def test_patch_content_hash(self) -> None:
        patch = Patch.create(
            source=CandidateSource.FIXED_PATCH,
            content='a = "b"\r\nc = 1\r\n',
            parent_state_id=uid(1),
            now=at(0),
        )
        self.assertEqual(patch.content_hash, sha('a = "b"\nc = 1\n'))


class TestCrossProcessStability(unittest.TestCase):
    """The same content hashes identically under different hash randomization seeds."""

    SCRIPT = (
        "from tests.domain_builders import baseline, resource\n"
        "r = resource('aws_instance.app')\n"
        "b = baseline()\n"
        "print(r.fingerprint)\n"
        "print(b.state_hash)\n"
        "print(b.resource_set_hash())\n"
    )

    def run_with_seed(self, seed: str) -> list[str]:
        env = dict(os.environ, PYTHONHASHSEED=seed)
        result = subprocess.run(
            [sys.executable, "-c", self.SCRIPT],
            cwd=REPO_ROOT,
            env=env,
            capture_output=True,
            text=True,
            check=False,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.split()

    def test_hashes_do_not_depend_on_hash_randomization(self) -> None:
        from tests.domain_builders import baseline, resource

        here = [
            resource("aws_instance.app").fingerprint,
            baseline().state_hash,
            baseline().resource_set_hash(),
        ]
        for seed in ("0", "4242"):
            with self.subTest(PYTHONHASHSEED=seed):
                self.assertEqual(self.run_with_seed(seed), here)


# --- property tests ------------------------------------------------------------------------------


def rand_json(rng: random.Random, depth: int = 0) -> Any:
    kind = rng.randrange(7 if depth < 3 else 4)
    if kind == 0:
        return rng.choice(["a", "b", "café", "x y", ""])
    if kind == 1:
        return rng.randrange(-5, 50)
    if kind == 2:
        return rng.random() < 0.5
    if kind == 3:
        return None
    if kind == 4:
        return [rand_json(rng, depth + 1) for _ in range(rng.randrange(0, 4))]
    return rand_obj(rng, depth + 1)


def rand_obj(rng: random.Random, depth: int = 0) -> dict[str, Any]:
    keys = rng.sample(["a", "b", "c", "d", "e", "f"], rng.randrange(0, 5))
    return {key: rand_json(rng, depth + 1) for key in keys}


def shuffle_keys(value: Any, rng: random.Random) -> Any:
    """The same value with every dict's insertion order shuffled."""
    if isinstance(value, dict):
        items = list(value.items())
        rng.shuffle(items)
        return {key: shuffle_keys(item, rng) for key, item in items}
    if isinstance(value, list):
        return [shuffle_keys(item, rng) for item in value]
    return value


def rand_references(rng: random.Random, address: str) -> list[Reference]:
    return [
        Reference(
            source_address=address,
            source_attribute=rng.choice(["sg", "subnet", "vpc"]),
            target_address=f"aws_thing.t{rng.randrange(6)}",
            reference_type=rng.choice(["reference", "depends_on"]),
            resolution_status=rng.choice(list(ReferenceResolution)),
        )
        for _ in range(rng.randrange(0, 5))
    ]


class Spec:
    """The inputs of one random resource, kept so tests can rebuild or mutate it."""

    def __init__(self, rng: random.Random, address: str) -> None:
        self.address = address
        self.resource_type = rng.choice(["aws_instance", "aws_db_instance", "aws_vpc"])
        self.logical_identity = rand_obj(rng)
        self.attributes = rand_obj(rng)
        self.security_attributes = rand_obj(rng)
        self.semantic_attributes = rand_obj(rng)
        self.references = rand_references(rng, address)

    def build(self, **overrides: Any) -> Resource:
        fields: dict[str, Any] = {
            "address": self.address,
            "resource_type": self.resource_type,
            "logical_identity": self.logical_identity,
            "attributes": self.attributes,
            "security_attributes": self.security_attributes,
            "semantic_attributes": self.semantic_attributes,
            "references": self.references,
            "provenance": prov(),
            "support_status": ResourceSupport.SUPPORTED,
        }
        fields.update(overrides)
        return Resource.create(**fields)


class TestPropertyCanonicalization(unittest.TestCase):
    def test_canonicalization_is_idempotent(self) -> None:
        for i in range(CASES):
            seed = 10_000 + i
            value = rand_obj(random.Random(seed))
            once = canonical_json(value)
            twice = canonical_json(json.loads(once))
            self.assertEqual(once, twice, f"seed={seed}")

    def test_dict_insertion_order_never_changes_the_fingerprint(self) -> None:
        for i in range(CASES):
            seed = 20_000 + i
            rng = random.Random(seed)
            spec = Spec(rng, "aws_instance.app")
            original = spec.build()
            shuffled_spec = Spec(random.Random(seed), "aws_instance.app")
            for name in (
                "logical_identity",
                "attributes",
                "security_attributes",
                "semantic_attributes",
            ):
                setattr(shuffled_spec, name, shuffle_keys(getattr(shuffled_spec, name), rng))
            shuffled = shuffled_spec.build()
            self.assertEqual(original.fingerprint, shuffled.fingerprint, f"seed={seed}")
            self.assertEqual(original.canonical_json, shuffled.canonical_json, f"seed={seed}")

    def test_reference_order_never_changes_the_fingerprint(self) -> None:
        for i in range(CASES):
            seed = 30_000 + i
            rng = random.Random(seed)
            spec = Spec(rng, "aws_instance.app")
            original = spec.build()
            refs = list(spec.references)
            rng.shuffle(refs)
            shuffled = spec.build(references=refs)
            self.assertEqual(original.fingerprint, shuffled.fingerprint, f"seed={seed}")
            self.assertEqual(original.references, shuffled.references, f"seed={seed}")

    def test_resource_order_never_changes_the_set_or_state_hash(self) -> None:
        for i in range(CASES):
            seed = 40_000 + i
            rng = random.Random(seed)
            resources = [
                Spec(rng, f"aws_instance.r{n}").build() for n in range(rng.randrange(1, 6))
            ]
            shuffled = list(resources)
            rng.shuffle(shuffled)
            self.assertEqual(
                resource_set_hash(resources, "n"), resource_set_hash(shuffled, "n"), f"seed={seed}"
            )
            first = _baseline(resources)
            second = _baseline(shuffled)
            self.assertEqual(first.state_hash, second.state_hash, f"seed={seed}")

    def test_scope_list_order_never_changes_the_scope(self) -> None:
        for i in range(CASES):
            seed = 50_000 + i
            rng = random.Random(seed)
            pool = [f"aws_thing.x{n}" for n in range(6)]
            fields = {
                "resources": rng.sample(pool, rng.randrange(1, 5)),
                "resource_types": rng.sample(["t1", "t2", "t3"], rng.randrange(0, 3)),
                "relationships": rng.sample(["r1", "r2", "r3"], rng.randrange(0, 3)),
                "properties": rng.sample(["p1", "p2", "p3"], rng.randrange(0, 3)),
                "dependency_depth": rng.randrange(0, 4),
            }
            shuffled = {
                k: rng.sample(v, len(v)) if isinstance(v, list) else v for k, v in fields.items()
            }
            self.assertEqual(InvariantScope(**fields), InvariantScope(**shuffled), f"seed={seed}")


def _baseline(resources: list[Resource]) -> TrustedState:
    return TrustedState.establish_baseline(
        lineage_id=LINEAGE,
        resources=resources,
        invariant_proofs=[proof()],
        evidence_refs=list(proof().evidence_ids),
        normalization_version="n",
        invariant_registry_version=1,
        now=at(1),
        state_id=uid(1),
    )


class TestPropertySemanticSensitivity(unittest.TestCase):
    def test_changing_any_semantic_field_changes_the_fingerprint(self) -> None:
        for i in range(CASES):
            seed = 60_000 + i
            rng = random.Random(seed)
            spec = Spec(rng, "aws_instance.app")
            base = spec.build()
            field = rng.choice(
                [
                    "resource_type",
                    "logical_identity",
                    "attributes",
                    "security_attributes",
                    "semantic_attributes",
                    "references",
                ]
            )
            if field == "resource_type":
                changed = spec.build(resource_type=spec.resource_type + "_x")
            elif field == "references":
                extra = Reference(
                    source_address="aws_instance.app",
                    source_attribute="added",
                    target_address="aws_added.target",
                    reference_type="reference",
                    resolution_status=ReferenceResolution.SUPPORTED,
                )
                changed = spec.build(references=[*spec.references, extra])
            else:
                mutated = dict(getattr(spec, field))
                mutated["__changed"] = rng.randrange(1000)
                changed = spec.build(**{field: mutated})
            self.assertNotEqual(base.fingerprint, changed.fingerprint, f"seed={seed} field={field}")

    def test_a_changed_reference_status_changes_the_fingerprint(self) -> None:
        for i in range(CASES):
            seed = 70_000 + i
            rng = random.Random(seed)
            ref = rand_references(rng, "aws_instance.app") or [
                Reference(
                    "aws_instance.app",
                    "sg",
                    "aws_thing.t0",
                    "reference",
                    ReferenceResolution.SUPPORTED,
                )
            ]
            first = ref[0]
            other_status = next(s for s in ReferenceResolution if s != first.resolution_status)
            changed = [
                Reference(
                    first.source_address,
                    first.source_attribute,
                    first.target_address,
                    first.reference_type,
                    other_status,
                ),
                *ref[1:],
            ]
            spec = Spec(rng, "aws_instance.app")
            self.assertNotEqual(
                spec.build(references=ref).fingerprint,
                spec.build(references=changed).fingerprint,
                f"seed={seed}",
            )

    def test_a_changed_resource_changes_the_state_hashes(self) -> None:
        for i in range(CASES):
            seed = 80_000 + i
            rng = random.Random(seed)
            specs = [Spec(rng, f"aws_instance.r{n}") for n in range(rng.randrange(1, 5))]
            resources = [s.build() for s in specs]
            victim = rng.choice(specs)
            mutated = dict(victim.attributes)
            mutated["__changed"] = 1
            changed = [s.build(attributes=mutated) if s is victim else s.build() for s in specs]
            self.assertNotEqual(
                resource_set_hash(resources, "n"), resource_set_hash(changed, "n"), f"seed={seed}"
            )
            self.assertNotEqual(
                _baseline(resources).state_hash, _baseline(changed).state_hash, f"seed={seed}"
            )


class TestPropertyNonSemanticFields(unittest.TestCase):
    def test_ids_provenance_and_support_status_never_change_the_fingerprint(self) -> None:
        for i in range(CASES):
            seed = 90_000 + i
            rng = random.Random(seed)
            spec = Spec(rng, "aws_instance.app")
            base = spec.build(record_id=uid(rng.getrandbits(64)))
            other = spec.build(
                record_id=uid(rng.getrandbits(64) + 1),
                provenance=prov(rng.randrange(1000), component=f"c{rng.randrange(100)}"),
                support_status=rng.choice(list(ResourceSupport)),
            )
            self.assertEqual(base.fingerprint, other.fingerprint, f"seed={seed}")
            self.assertEqual(base.canonical_json, other.canonical_json, f"seed={seed}")

    def test_the_address_never_changes_the_fingerprint(self) -> None:
        for i in range(CASES):
            seed = 100_000 + i
            rng = random.Random(seed)
            spec = Spec(rng, "aws_instance.one")
            moved = Spec(random.Random(seed), "aws_instance.two")
            self.assertEqual(spec.build().fingerprint, moved.build().fingerprint, f"seed={seed}")

    def test_ids_timestamps_and_evidence_never_change_the_state_hash(self) -> None:
        for i in range(CASES):
            seed = 110_000 + i
            rng = random.Random(seed)
            resources = [
                Spec(rng, f"aws_instance.r{n}").build() for n in range(rng.randrange(1, 4))
            ]
            first = _baseline(resources)
            ev = rng.randrange(1, 90)
            again = TrustedState.establish_baseline(
                lineage_id=LINEAGE,
                resources=[
                    Resource.create(
                        address=r.address,
                        resource_type=r.resource_type,
                        logical_identity=r.logical_identity,
                        attributes=r.attributes,
                        security_attributes=r.security_attributes,
                        semantic_attributes=r.semantic_attributes,
                        references=r.references,
                        provenance=prov(rng.randrange(1000)),
                        support_status=r.support_status,
                        record_id=uid(rng.getrandbits(64)),
                    )
                    for r in resources
                ],
                invariant_proofs=[proof(evidence=ev, minutes=rng.randrange(500))],
                evidence_refs=sorted({uid(1000 + ev), uid(rng.getrandbits(40))}),
                normalization_version="n",
                invariant_registry_version=rng.randrange(1, 9),
                now=at(rng.randrange(2000)),
                state_id=uid(rng.getrandbits(64)),
            )
            self.assertEqual(first.state_hash, again.state_hash, f"seed={seed}")


def inject_float(value: Any, rng: random.Random) -> Any:
    """A copy of ``value`` with one float placed somewhere in it."""
    if isinstance(value, dict) and value and rng.random() < 0.7:
        key = rng.choice(sorted(value))
        copy = dict(value)
        copy[key] = inject_float(value[key], rng)
        return copy
    if isinstance(value, list) and value and rng.random() < 0.7:
        index = rng.randrange(len(value))
        copy_list = list(value)
        copy_list[index] = inject_float(value[index], rng)
        return copy_list
    if isinstance(value, dict):
        return {**value, "__float": rng.random() + 0.25}
    return rng.random() + 0.25


class TestPropertyFloatsAreRejected(unittest.TestCase):
    def test_a_float_anywhere_in_a_resource_payload_is_rejected(self) -> None:
        for i in range(CASES):
            seed = 120_000 + i
            rng = random.Random(seed)
            spec = Spec(rng, "aws_instance.app")
            field = rng.choice(
                ["logical_identity", "attributes", "security_attributes", "semantic_attributes"]
            )
            bad = inject_float(getattr(spec, field), rng)
            with self.assertRaises(DomainValidationError, msg=f"seed={seed} field={field}"):
                spec.build(**{field: bad})

    def test_a_float_in_patch_metadata_or_an_invariant_predicate_is_rejected(self) -> None:
        from core.domain.enums import InvariantCategory
        from core.domain.invariant import Invariant

        for i in range(CASES):
            seed = 130_000 + i
            rng = random.Random(seed)
            payload = inject_float(rand_obj(rng) or {"k": 1}, rng)
            with self.assertRaises(DomainValidationError, msg=f"seed={seed} patch"):
                Patch.create(
                    source=CandidateSource.FIXED_PATCH,
                    content="x",
                    parent_state_id=uid(1),
                    now=at(0),
                    metadata=payload,
                )
            with self.assertRaises(DomainValidationError, msg=f"seed={seed} invariant"):
                Invariant(
                    invariant_id="INV-SEC-001",
                    version=1,
                    name="n",
                    category=InvariantCategory.SECURITY,
                    description="d",
                    predicate=payload,
                    scope=InvariantScope(("a.x",), (), (), (), 0),
                    verifier_id="v",
                    verifier_version="1",
                    created_at=at(0),
                )


if __name__ == "__main__":
    unittest.main()
