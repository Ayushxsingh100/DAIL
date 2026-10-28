"""Verification requests, results and reports (Doc 05 §14; Doc 09 §4-§37; C-145; P5a).

Doc 09 §4: a verifier answers with one of five results, and only one of them is proof.

    PASS may satisfy a requirement     FAIL blocks it     UNKNOWN / UNSUPPORTED are lack of proof
    VERIFIER_ERROR is a tool failure: never property evidence, never converted to PASS or FAIL

A ``VerificationResultRecord`` is the answer for one target; a ``VerificationReport`` holds the
answers for one candidate. Three pure functions are all the Promotion Controller (P6) needs to judge
them, and they are written so that anything missing, stale or doubtful is *not* proof:

* ``sufficient`` (Doc 09 §11): a PASS from the expected verifier, for this exact target, candidate
  hash and invariant version, with every required field present.
* ``fresh`` (Doc 09 §30): the result belongs to this candidate hash and these versions.
* ``aggregate`` (Doc 09 §18): FAIL if a required target has a fresh FAIL; PASS only when every
  required target has a sufficient, fresh PASS; INSUFFICIENT_PROOF otherwise.

The ``content_hash`` of a report covers everything except ``report_id``, the ``verification_id`` and
``request_id`` of each result, and the timestamps (also inside the evidence payloads); the
constructor recomputes it (``HashMismatchError``) and checks every derived part and ordering.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from core.domain.enums import VerificationResult
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.hashing import content_hash
from core.domain.ids import new_uuid, require_uuid
from core.domain.jsonvalue import (
    freeze_json,
    iso_utc,
    parse_enum,
    parse_utc,
    require_enum,
    require_int,
    require_keys,
    require_text,
    thaw_json,
    utc,
    validate_json,
)

_HASH_TEXT = re.compile(r"[0-9a-f]{64}")

EVIDENCE_LEVELS: Final = ("L0", "L1")
CLAUSE_KEYS: Final = ("IPV4", "IPV6")
CLAUSE_INVARIANTS: Final = ("INV-SEC-001", "INV-SEC-002")
_EVIDENCE_REQUIRED: Final = ("predicate", "inputs", "observations", "result")
_EVIDENCE_VOLATILE: Final = ("verification_id", "started_at", "completed_at")
_ERROR_KEYS: Final = ("type", "message", "class")

# worst clause: FAIL is decided first, then UNSUPPORTED > UNKNOWN > PASS (registry-v1.0 §3.3, §3.4)
_CLAUSE_RANK: Final = {
    VerificationResult.PASS: 0,
    VerificationResult.UNKNOWN: 1,
    VerificationResult.UNSUPPORTED: 2,
}


class VerificationClass(StrEnum):
    """Doc 09 §5."""

    STRUCTURAL = "STRUCTURAL"
    SECURITY = "SECURITY"
    FUNCTIONAL = "FUNCTIONAL"
    BASELINE = "BASELINE"
    CONSISTENCY = "CONSISTENCY"


class VerificationTargetType(StrEnum):
    """Doc 05 §14, plus RESOURCE for the baseline items of Doc 08 §16 (C-145)."""

    INVARIANT = "INVARIANT"
    SECURITY_PREDICATE = "SECURITY_PREDICATE"
    STRUCTURAL = "STRUCTURAL"
    RESOURCE = "RESOURCE"


class AggregateResult(StrEnum):
    """Doc 09 §18. INSUFFICIENT_PROOF is never a pass."""

    PASS = "PASS"
    FAIL = "FAIL"
    INSUFFICIENT_PROOF = "INSUFFICIENT_PROOF"


class ConstructionStatus(StrEnum):
    """Whether the candidate state could be built at all (registry-v1.0 §2.8)."""

    OK = "OK"
    INVALID = "INVALID"
    UNSUPPORTED = "UNSUPPORTED"


class VerificationReason(StrEnum):
    """Why a result is not a PASS: one closed code per reason (C-145, C-146, C-147)."""

    PREDICATE_VIOLATED = "predicate.violated"
    RULE_INDETERMINATE = "rule.indeterminate"
    RULE_UNSUPPORTED = "rule.unsupported"
    GROUP_MIXED = "group.mixed"
    GROUP_RETAINED_INLINE = "group.retained_inline"
    FORMS_UNRESOLVED = "forms.unresolved"
    TYPE_RELEVANT_UNSUPPORTED = "type.relevant_unsupported"
    ATTRIBUTE_UNRESOLVED = "attribute.unresolved"
    IDENTITY_MISSING = "identity.missing"
    CONSTRUCTION_INVALID = "construction.invalid"
    INVARIANT_UNKNOWN = "invariant.unknown"
    RESOURCE_INDETERMINATE = "resource.indeterminate"
    STRUCTURAL_FINDING = "structural.finding"
    CONSISTENCY_FINDING = "consistency.finding"
    VERIFIER_NOT_AVAILABLE = "verifier.not_available"
    VERIFIER_ERROR = "verifier.error"


# --- helpers --------------------------------------------------------------------------------------


def _hash_text(value: object, field: str) -> str:
    text = require_text(value, field)
    if _HASH_TEXT.fullmatch(text) is None:
        raise DomainValidationError(f"{field}: must be a SHA-256 hex digest")
    return text


def _list_of(value: object, field: str) -> list[Any]:
    if isinstance(value, str) or not isinstance(value, list | tuple):
        raise DomainValidationError(f"{field}: must be a list")
    return list(value)


def _checked_texts(value: object, field: str) -> tuple[str, ...]:
    return tuple(
        require_text(item, f"{field}[{i}]") for i, item in enumerate(_list_of(value, field))
    )


def _sorted_texts(value: object, field: str) -> tuple[str, ...]:
    """Sorted, duplicate-free text, sorting what the caller gives (a request is built by code)."""
    items = _checked_texts(value, field)
    if len(set(items)) != len(items):
        raise DomainValidationError(f"{field}: duplicate entry")
    return tuple(sorted(items))


def _strictly_sorted_texts(value: object, field: str) -> tuple[str, ...]:
    """Sorted, duplicate-free text that is *already* in order (a stored record is not re-sorted)."""
    items = _checked_texts(value, field)
    if list(items) != sorted(set(items)):
        raise DomainValidationError(f"{field}: must be sorted and free of duplicates")
    return items


def _json_mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DomainValidationError(f"{field}: must be an object")
    validate_json(value, field)
    frozen: Mapping[str, Any] = freeze_json(value)
    return frozen


# --- request --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class VerificationRequest:
    """One unit of verification work for one candidate (Doc 05 §14, Doc 09 §3)."""

    request_id: str
    candidate_id: str
    state_id: str
    candidate_hash: str
    target_id: str
    target_type: VerificationTargetType
    invariant_refs: tuple[str, ...]
    verification_scope: tuple[str, ...]
    verifier_id: str
    verifier_version: str

    def __post_init__(self) -> None:
        require_uuid(self.request_id, "VerificationRequest.request_id")
        require_uuid(self.candidate_id, "VerificationRequest.candidate_id")
        require_uuid(self.state_id, "VerificationRequest.state_id")
        _hash_text(self.candidate_hash, "VerificationRequest.candidate_hash")
        require_text(self.target_id, "VerificationRequest.target_id")
        require_enum(self.target_type, VerificationTargetType, "VerificationRequest.target_type")
        require_text(self.verifier_id, "VerificationRequest.verifier_id")
        require_text(self.verifier_version, "VerificationRequest.verifier_version")
        object.__setattr__(
            self,
            "invariant_refs",
            _sorted_texts(self.invariant_refs, "VerificationRequest.invariant_refs"),
        )
        object.__setattr__(
            self,
            "verification_scope",
            _sorted_texts(self.verification_scope, "VerificationRequest.verification_scope"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "candidate_id": self.candidate_id,
            "state_id": self.state_id,
            "candidate_hash": self.candidate_hash,
            "target_id": self.target_id,
            "target_type": self.target_type.value,
            "invariant_refs": list(self.invariant_refs),
            "verification_scope": list(self.verification_scope),
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationRequest:
        fields = require_keys(
            data,
            (
                "request_id",
                "candidate_id",
                "state_id",
                "candidate_hash",
                "target_id",
                "target_type",
                "invariant_refs",
                "verification_scope",
                "verifier_id",
                "verifier_version",
            ),
            "VerificationRequest",
        )
        return cls(
            request_id=fields["request_id"],
            candidate_id=fields["candidate_id"],
            state_id=fields["state_id"],
            candidate_hash=fields["candidate_hash"],
            target_id=fields["target_id"],
            target_type=parse_enum(fields["target_type"], VerificationTargetType, "target_type"),
            invariant_refs=tuple(_list_of(fields["invariant_refs"], "invariant_refs")),
            verification_scope=tuple(_list_of(fields["verification_scope"], "verification_scope")),
            verifier_id=fields["verifier_id"],
            verifier_version=fields["verifier_version"],
        )


# --- result ---------------------------------------------------------------------------------------


def _clause_value(value: object, field: str) -> VerificationResult:
    result = require_enum(value, VerificationResult, field)
    if result is VerificationResult.VERIFIER_ERROR:
        raise DomainValidationError(f"{field}: a clause is never VERIFIER_ERROR (registry §3.4)")
    return result


def _result_of_clauses(clauses: Mapping[str, VerificationResult]) -> VerificationResult:
    """Registry-v1.0 §3.4: FAIL if a clause FAILs, otherwise the worst clause."""
    values = list(clauses.values())
    if VerificationResult.FAIL in values:
        return VerificationResult.FAIL
    return max(values, key=lambda value: _CLAUSE_RANK[value])


@dataclass(frozen=True)
class VerificationResultRecord:
    """What one verifier concluded about one target of one candidate."""

    verification_id: str
    request_id: str
    target_type: VerificationTargetType
    target_id: str
    candidate_id: str
    candidate_hash: str
    invariant_id: str | None
    invariant_version: int | None
    verifier_id: str
    verifier_version: str
    evidence_level: str
    verification_class: VerificationClass
    result: VerificationResult
    reason: VerificationReason | None
    applicable: bool
    clauses: Mapping[str, VerificationResult] | None
    observations: Mapping[str, Any]
    assumptions: tuple[str, ...]
    evidence: Mapping[str, Any]
    error: Mapping[str, str] | None
    started_at: datetime
    completed_at: datetime

    def __post_init__(self) -> None:
        name = "VerificationResultRecord"
        require_uuid(self.verification_id, f"{name}.verification_id")
        require_uuid(self.request_id, f"{name}.request_id")
        require_uuid(self.candidate_id, f"{name}.candidate_id")
        _hash_text(self.candidate_hash, f"{name}.candidate_hash")
        require_enum(self.target_type, VerificationTargetType, f"{name}.target_type")
        require_text(self.target_id, f"{name}.target_id")
        require_text(self.verifier_id, f"{name}.verifier_id")
        require_text(self.verifier_version, f"{name}.verifier_version")
        require_enum(self.verification_class, VerificationClass, f"{name}.verification_class")
        require_enum(self.result, VerificationResult, f"{name}.result")
        if self.evidence_level not in EVIDENCE_LEVELS:
            raise DomainValidationError(f"{name}.evidence_level: must be one of {EVIDENCE_LEVELS}")
        if not isinstance(self.applicable, bool):
            raise DomainValidationError(f"{name}.applicable: must be a boolean")
        if not self.applicable and self.result is not VerificationResult.PASS:
            raise DomainValidationError(f"{name}: only a PASS can be 'not applicable' (C-148)")
        self._check_invariant()
        self._check_reason_and_error()
        self._check_clauses()
        object.__setattr__(self, "observations", _json_mapping(self.observations, "observations"))
        object.__setattr__(
            self, "assumptions", _strictly_sorted_texts(self.assumptions, f"{name}.assumptions")
        )
        evidence = _json_mapping(self.evidence, f"{name}.evidence")
        self._check_evidence(evidence)
        object.__setattr__(self, "evidence", evidence)
        started = utc(self.started_at, f"{name}.started_at")
        completed = utc(self.completed_at, f"{name}.completed_at")
        if completed < started:
            raise DomainValidationError(f"{name}: completed_at is before started_at")
        object.__setattr__(self, "started_at", started)
        object.__setattr__(self, "completed_at", completed)

    def _check_invariant(self) -> None:
        name = "VerificationResultRecord"
        if (self.invariant_id is None) != (self.invariant_version is None):
            raise DomainValidationError(
                f"{name}: invariant id and version are both set or both null"
            )
        if self.invariant_id is not None:
            require_text(self.invariant_id, f"{name}.invariant_id")
            require_int(self.invariant_version, f"{name}.invariant_version", 1)
        if self.target_type is VerificationTargetType.INVARIANT:
            expected = f"INVARIANT:{self.invariant_id}:{self.invariant_version}"
            if self.invariant_id is None or self.target_id != expected:
                raise DomainValidationError(f"{name}: an INVARIANT target is {expected}")
        elif self.target_type is VerificationTargetType.RESOURCE:
            if self.invariant_id is not None or not self.target_id.startswith("RESOURCE:"):
                raise DomainValidationError(
                    f"{name}: a RESOURCE target starts with RESOURCE: and names no invariant"
                )

    def _check_reason_and_error(self) -> None:
        name = "VerificationResultRecord"
        is_error = self.result is VerificationResult.VERIFIER_ERROR
        if self.result is VerificationResult.PASS:
            if self.reason is not None:
                raise DomainValidationError(f"{name}: a PASS has no reason")
        else:
            require_enum(self.reason, VerificationReason, f"{name}.reason")
        if is_error != (self.reason is VerificationReason.VERIFIER_ERROR):
            raise DomainValidationError(
                f"{name}: the reason verifier.error belongs to VERIFIER_ERROR and only to it"
            )
        if (self.error is not None) != is_error:
            raise DomainValidationError(f"{name}: error is present exactly for VERIFIER_ERROR")
        if self.error is not None:
            if not isinstance(self.error, Mapping) or set(self.error) != set(_ERROR_KEYS):
                raise DomainValidationError(f"{name}.error: keys must be {_ERROR_KEYS}")
            error = {
                key: require_text(self.error[key], f"{name}.error.{key}") for key in _ERROR_KEYS
            }
            object.__setattr__(self, "error", MappingProxyType(error))

    def _check_clauses(self) -> None:
        name = "VerificationResultRecord"
        if self.clauses is None:
            return
        if self.invariant_id not in CLAUSE_INVARIANTS:
            raise DomainValidationError(f"{name}: clauses belong to {CLAUSE_INVARIANTS} only")
        if not isinstance(self.clauses, Mapping) or set(self.clauses) != set(CLAUSE_KEYS):
            raise DomainValidationError(f"{name}.clauses: keys must be {CLAUSE_KEYS}")
        clauses = {
            key: _clause_value(self.clauses[key], f"{name}.clauses.{key}") for key in CLAUSE_KEYS
        }
        if self.result is VerificationResult.VERIFIER_ERROR:
            raise DomainValidationError(f"{name}: a VERIFIER_ERROR carries no clauses")
        if _result_of_clauses(clauses) is not self.result:
            raise DomainValidationError(
                f"{name}: the result does not follow from the clauses (registry-v1.0 §3.4)"
            )
        object.__setattr__(self, "clauses", MappingProxyType(clauses))

    def _check_evidence(self, evidence: Mapping[str, Any]) -> None:
        name = "VerificationResultRecord"
        for key in _EVIDENCE_REQUIRED:
            if key not in evidence:
                raise DomainValidationError(f"{name}.evidence: '{key}' is required (Doc 11 §25)")
        if evidence["result"] != self.result.value:
            raise DomainValidationError(f"{name}.evidence: states a different result")

    def sort_key(self) -> tuple[str, str]:
        return (self.target_type.value, self.target_id)

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_id": self.verification_id,
            "request_id": self.request_id,
            "target_type": self.target_type.value,
            "target_id": self.target_id,
            "candidate_id": self.candidate_id,
            "candidate_hash": self.candidate_hash,
            "invariant_id": self.invariant_id,
            "invariant_version": self.invariant_version,
            "verifier_id": self.verifier_id,
            "verifier_version": self.verifier_version,
            "evidence_level": self.evidence_level,
            "verification_class": self.verification_class.value,
            "result": self.result.value,
            "reason": None if self.reason is None else self.reason.value,
            "applicable": self.applicable,
            "clauses": (
                None
                if self.clauses is None
                else {key: self.clauses[key].value for key in CLAUSE_KEYS}
            ),
            "observations": thaw_json(self.observations),
            "assumptions": list(self.assumptions),
            "evidence": thaw_json(self.evidence),
            "error": None if self.error is None else dict(self.error),
            "started_at": iso_utc(self.started_at),
            "completed_at": iso_utc(self.completed_at),
        }

    def hash_payload(self) -> dict[str, Any]:
        """The part of the record that is its content: no ids, no timestamps (C-145)."""
        data = self.to_dict()
        for key in ("verification_id", "request_id", "started_at", "completed_at"):
            del data[key]
        data["evidence"] = {
            key: value for key, value in data["evidence"].items() if key not in _EVIDENCE_VOLATILE
        }
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationResultRecord:
        fields = require_keys(
            data,
            (
                "verification_id",
                "request_id",
                "target_type",
                "target_id",
                "candidate_id",
                "candidate_hash",
                "invariant_id",
                "invariant_version",
                "verifier_id",
                "verifier_version",
                "evidence_level",
                "verification_class",
                "result",
                "reason",
                "applicable",
                "clauses",
                "observations",
                "assumptions",
                "evidence",
                "error",
                "started_at",
                "completed_at",
            ),
            "VerificationResultRecord",
        )
        raw_clauses = fields["clauses"]
        if raw_clauses is not None and not isinstance(raw_clauses, Mapping):
            raise DomainValidationError("VerificationResultRecord.clauses: must be an object")
        raw_reason = fields["reason"]
        return cls(
            verification_id=fields["verification_id"],
            request_id=fields["request_id"],
            target_type=parse_enum(fields["target_type"], VerificationTargetType, "target_type"),
            target_id=fields["target_id"],
            candidate_id=fields["candidate_id"],
            candidate_hash=fields["candidate_hash"],
            invariant_id=fields["invariant_id"],
            invariant_version=fields["invariant_version"],
            verifier_id=fields["verifier_id"],
            verifier_version=fields["verifier_version"],
            evidence_level=fields["evidence_level"],
            verification_class=parse_enum(
                fields["verification_class"], VerificationClass, "verification_class"
            ),
            result=parse_enum(fields["result"], VerificationResult, "result"),
            reason=(
                None if raw_reason is None else parse_enum(raw_reason, VerificationReason, "reason")
            ),
            applicable=fields["applicable"],
            clauses=(
                None
                if raw_clauses is None
                else {
                    key: parse_enum(value, VerificationResult, f"clauses.{key}")
                    for key, value in raw_clauses.items()
                }
            ),
            observations=fields["observations"],
            assumptions=tuple(_list_of(fields["assumptions"], "assumptions")),
            evidence=fields["evidence"],
            error=fields["error"],
            started_at=parse_utc(fields["started_at"], "started_at"),
            completed_at=parse_utc(fields["completed_at"], "completed_at"),
        )


# --- report ---------------------------------------------------------------------------------------


def _summary(results: tuple[VerificationResultRecord, ...], invocations: int) -> dict[str, Any]:
    by_class: dict[str, dict[str, int]] = {}
    for item in results:
        counts = by_class.setdefault(item.verification_class.value, {})
        counts[item.result.value] = counts.get(item.result.value, 0) + 1
    return {
        "results": len(results),
        "verifier_invocations": invocations,
        "by_class": {
            cls: {value: counts[value] for value in sorted(counts)}
            for cls, counts in sorted(by_class.items())
        },
    }


@dataclass(frozen=True)
class VerificationReport:
    """The verification results of one candidate (Doc 05 §14). Create it with ``create``."""

    report_id: str
    candidate_id: str
    candidate_hash: str
    results: tuple[VerificationResultRecord, ...]
    verifier_invocations: int
    verifier_set_version: str
    summary: Mapping[str, Any]
    content_hash: str

    def __post_init__(self) -> None:
        name = "VerificationReport"
        require_uuid(self.report_id, f"{name}.report_id")
        require_uuid(self.candidate_id, f"{name}.candidate_id")
        _hash_text(self.candidate_hash, f"{name}.candidate_hash")
        require_text(self.verifier_set_version, f"{name}.verifier_set_version")
        require_int(self.verifier_invocations, f"{name}.verifier_invocations", 0)
        results = tuple(_list_of(self.results, f"{name}.results"))
        if not all(isinstance(item, VerificationResultRecord) for item in results):
            raise DomainValidationError(
                f"{name}.results: must hold VerificationResultRecord objects"
            )
        if self.verifier_invocations > len(results):
            raise DomainValidationError(f"{name}: more verifier invocations than results")
        keys = [item.sort_key() for item in results]
        if keys != sorted(keys):
            raise DomainValidationError(f"{name}.results: must be sorted by target type and id")
        if len(set(keys)) != len(keys):
            raise DomainValidationError(f"{name}.results: one result per target")
        ids = [item.verification_id for item in results]
        if len(set(ids)) != len(ids):
            raise DomainValidationError(f"{name}.results: duplicate verification_id")
        for item in results:
            if item.candidate_id != self.candidate_id or item.candidate_hash != self.candidate_hash:
                raise DomainValidationError(
                    f"{name}: result {item.target_id} belongs to another candidate (Doc 09 §30)"
                )
        expected = _summary(results, self.verifier_invocations)
        if thaw_json(self.summary) != expected:
            raise DomainValidationError(f"{name}.summary: does not match the results")
        object.__setattr__(self, "results", results)
        object.__setattr__(self, "summary", freeze_json(expected))
        if self.content_hash != self.compute_hash():
            raise HashMismatchError(
                f"DATA-INT-010: VerificationReport {self.report_id} content_hash does not "
                "match its content"
            )

    def _payload(self) -> dict[str, Any]:
        return _report_payload(
            self.candidate_id,
            self.candidate_hash,
            self.results,
            self.verifier_invocations,
            self.verifier_set_version,
        )

    def compute_hash(self) -> str:
        return content_hash(self._payload())

    @classmethod
    def create(
        cls,
        *,
        candidate_id: str,
        candidate_hash: str,
        results: Iterable[VerificationResultRecord],
        verifier_invocations: int,
        verifier_set_version: str,
        report_id: str | None = None,
    ) -> VerificationReport:
        """Sort the results, derive the summary and hash."""
        ordered = tuple(sorted(results, key=VerificationResultRecord.sort_key))
        return cls(
            report_id=new_uuid() if report_id is None else report_id,
            candidate_id=candidate_id,
            candidate_hash=candidate_hash,
            results=ordered,
            verifier_invocations=verifier_invocations,
            verifier_set_version=verifier_set_version,
            summary=_summary(ordered, verifier_invocations),
            content_hash=content_hash(
                _report_payload(
                    candidate_id,
                    candidate_hash,
                    ordered,
                    verifier_invocations,
                    verifier_set_version,
                )
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "candidate_id": self.candidate_id,
            "candidate_hash": self.candidate_hash,
            "results": [item.to_dict() for item in self.results],
            "verifier_invocations": self.verifier_invocations,
            "verifier_set_version": self.verifier_set_version,
            "summary": thaw_json(self.summary),
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> VerificationReport:
        fields = require_keys(
            data,
            (
                "report_id",
                "candidate_id",
                "candidate_hash",
                "results",
                "verifier_invocations",
                "verifier_set_version",
                "summary",
                "content_hash",
            ),
            "VerificationReport",
        )
        if not isinstance(fields["summary"], Mapping):
            raise DomainValidationError("VerificationReport.summary: must be an object")
        return cls(
            report_id=fields["report_id"],
            candidate_id=fields["candidate_id"],
            candidate_hash=fields["candidate_hash"],
            results=tuple(
                VerificationResultRecord.from_dict(item)
                for item in _list_of(fields["results"], "results")
            ),
            verifier_invocations=fields["verifier_invocations"],
            verifier_set_version=fields["verifier_set_version"],
            summary=fields["summary"],
            content_hash=fields["content_hash"],
        )


def _report_payload(
    candidate_id: str,
    candidate_hash: str,
    results: tuple[VerificationResultRecord, ...],
    verifier_invocations: int,
    verifier_set_version: str,
) -> dict[str, Any]:
    return {
        "candidate_id": candidate_id,
        "candidate_hash": candidate_hash,
        "results": [item.hash_payload() for item in results],
        "verifier_invocations": verifier_invocations,
        "verifier_set_version": verifier_set_version,
    }


# --- sufficiency, freshness and aggregation (for the Promotion Controller, P6) --------------------


@dataclass(frozen=True)
class RequiredTarget:
    """What the controller expects for one required target: which verifier, at which version."""

    target_id: str
    invariant_id: str | None
    invariant_version: int | None
    verifier_id: str
    verifier_version: str

    def __post_init__(self) -> None:
        require_text(self.target_id, "RequiredTarget.target_id")
        if (self.invariant_id is None) != (self.invariant_version is None):
            raise DomainValidationError("RequiredTarget: invariant id and version go together")
        if self.invariant_id is not None:
            require_text(self.invariant_id, "RequiredTarget.invariant_id")
            require_int(self.invariant_version, "RequiredTarget.invariant_version", 1)
        require_text(self.verifier_id, "RequiredTarget.verifier_id")
        require_text(self.verifier_version, "RequiredTarget.verifier_version")


def _present(value: object) -> bool:
    return value is not None and value != "" and value != {}


def sufficient(
    result: VerificationResultRecord,
    *,
    target_id: str,
    candidate_hash: str,
    invariant_id: str | None,
    invariant_version: int | None,
    verifier_id: str,
    verifier_version: str,
) -> bool:
    """Doc 09 §11: is this result proof for exactly this requirement?

    True only for a PASS that names the expected target, candidate hash, invariant and verifier and
    carries every required field. A result with anything missing is simply not sufficient; this
    function never raises and never treats a doubtful result as proof."""
    if result.result is not VerificationResult.PASS:
        return False
    if not all(
        _present(getattr(result, field))
        for field in (
            "verifier_id",
            "verifier_version",
            "evidence_level",
            "evidence",
            "candidate_hash",
        )
    ):
        return False
    return (
        result.target_id == target_id
        and result.candidate_hash == candidate_hash
        and result.invariant_id == invariant_id
        and result.invariant_version == invariant_version
        and result.verifier_id == verifier_id
        and result.verifier_version == verifier_version
    )


def fresh(
    result: VerificationResultRecord,
    *,
    candidate_hash: str,
    invariant_version: int | None,
    verifier_version: str,
    evidence_valid: bool = True,
) -> bool:
    """Doc 09 §30: does the result still describe this candidate, with these versions?

    A result for another candidate hash, an older invariant or verifier version, or whose evidence
    was invalidated is stale and is never reused, whatever it says."""
    return (
        evidence_valid
        and result.candidate_hash == candidate_hash
        and result.invariant_version == invariant_version
        and result.verifier_version == verifier_version
    )


def aggregate(
    results: Iterable[VerificationResultRecord],
    required: Iterable[RequiredTarget],
    *,
    candidate_hash: str,
    explicitly_empty: bool = False,
) -> AggregateResult:
    """Doc 09 §18. Per required target, only fresh results count:

    * a fresh FAIL makes the target FAIL, and one FAILed target makes the whole FAIL;
    * no fresh result (missing or stale), or a fresh UNKNOWN, UNSUPPORTED or VERIFIER_ERROR, or a
      PASS that is not ``sufficient``, makes the target insufficient;
    * a target passes only when it has fresh results and every one is a sufficient PASS.

    The aggregate is PASS only when every required target passes. An empty required set is
    INSUFFICIENT_PROOF unless the caller marks it explicitly empty."""
    needs = list(required)
    if len({need.target_id for need in needs}) != len(needs):
        raise DomainValidationError("aggregate: a target is required twice")
    if explicitly_empty and needs:
        raise DomainValidationError("aggregate: explicitly_empty with required targets")
    if not needs:
        return AggregateResult.PASS if explicitly_empty else AggregateResult.INSUFFICIENT_PROOF
    held = list(results)
    failed = False
    proven = True
    for need in needs:
        mine = [
            item
            for item in held
            if item.target_id == need.target_id
            and fresh(
                item,
                candidate_hash=candidate_hash,
                invariant_version=need.invariant_version,
                verifier_version=need.verifier_version,
            )
        ]
        if any(item.result is VerificationResult.FAIL for item in mine):
            failed = True
            continue
        if not mine or not all(
            sufficient(
                item,
                target_id=need.target_id,
                candidate_hash=candidate_hash,
                invariant_id=need.invariant_id,
                invariant_version=need.invariant_version,
                verifier_id=need.verifier_id,
                verifier_version=need.verifier_version,
            )
            for item in mine
        ):
            proven = False
    if failed:
        return AggregateResult.FAIL
    return AggregateResult.PASS if proven else AggregateResult.INSUFFICIENT_PROOF
