"""Identity evidence, matches and reports (Doc 05 §12, Doc 07 §13, §26; C-122; P3b step 2).

Doc 07 §26: "Each identity result should be explainable as evidence rather than an opaque score."
An ``IdentityReport`` therefore holds one ``IdentityMatch`` per resource, and the
``IdentityEvidence`` records that explain them. The change-record concept that P1a removed from
``Resource`` returns here as ``IdentityMatch``.

Vocabularies are closed (C-122): ``EvidenceType`` has one member per kind of evidence the engine can
produce, each with a short definition in ``EVIDENCE_DEFINITIONS``. Provider IDs, plan actions and
similarity scores are not evidence kinds here: before P9 they are "simply unavailable, not negative
evidence" (Doc 07 §7), and similarity is never sufficient (Doc 07 §5).

``IdentityMatch`` guards (construction raises ``DomainValidationError``):

| change_type | trusted ref | candidate ref | identity_status | confidence |
|---|---|---|---|---|
| UNCHANGED, MODIFIED, REPLACED | set | set | SAME | HIGH (MEDIUM is reserved) |
| CREATED | null | set | DIFFERENT | null |
| DELETED | set | null | DIFFERENT | null |
| UNCERTAIN | either, not both null | | UNCERTAIN | LOW |

``IdentityReport`` is frozen. Its ``content_hash`` covers everything except ``report_id`` and
``created_at`` (C-33 helpers), so two runs over the same inputs can be compared by hash; the
constructor recomputes it (``HashMismatchError``). It also rejects a summary that is not the one
derived from the matches, a resource that is in two matches, evidence that no match explains and a
rationale that cites evidence the report does not hold.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final

from core.domain.enums import ChangeType, IdentityStatus
from core.domain.errors import DomainValidationError, HashMismatchError
from core.domain.hashing import content_hash
from core.domain.ids import new_uuid, require_uuid
from core.domain.jsonvalue import (
    freeze_json,
    iso_utc,
    optional_text,
    parse_enum,
    parse_utc,
    require_enum,
    require_keys,
    require_text,
    thaw_json,
    utc,
    validate_json,
)


class IdentityConfidence(StrEnum):
    """Doc 05 §12. MEDIUM is reserved for heuristic evidence, which is never used (C-122)."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EvidenceSource(StrEnum):
    """The input an evidence record comes from. ``BOTH`` is for comparing the two sides (C-122)."""

    TRUSTED = "TRUSTED"
    CANDIDATE = "CANDIDATE"
    MOVES = "MOVES"
    BOTH = "BOTH"


class EvidenceType(StrEnum):
    """The closed vocabulary of identity evidence (C-122). Definitions: ``EVIDENCE_DEFINITIONS``."""

    EXACT_ADDRESS = "EXACT_ADDRESS"
    EXPLICIT_MOVE = "EXPLICIT_MOVE"
    IMPLICIT_COUNT_MOVE = "IMPLICIT_COUNT_MOVE"
    FINGERPRINT_EQUAL = "FINGERPRINT_EQUAL"
    FINGERPRINT_DIFFERENT = "FINGERPRINT_DIFFERENT"
    REPLACE_TRIGGER_FIELD = "REPLACE_TRIGGER_FIELD"
    REPLACE_TRIGGER_UNRESOLVED = "REPLACE_TRIGGER_UNRESOLVED"
    AMBIGUOUS_CANDIDATES = "AMBIGUOUS_CANDIDATES"
    INDETERMINATE_BLOCK = "INDETERMINATE_BLOCK"
    CONFLICTING_MOVE = "CONFLICTING_MOVE"
    UNRESOLVED_CONTENT = "UNRESOLVED_CONTENT"
    UNSUPPORTED_TYPE = "UNSUPPORTED_TYPE"
    NO_COUNTERPART = "NO_COUNTERPART"


EVIDENCE_DEFINITIONS: Final[Mapping[EvidenceType, str]] = MappingProxyType(
    {
        EvidenceType.EXACT_ADDRESS: "Same canonical address and type on both sides, no move.",
        EvidenceType.EXPLICIT_MOVE: (
            "A moved block of the candidate, possibly chained, maps the trusted address to the "
            "candidate address, or to an address no candidate resource has."
        ),
        EvidenceType.IMPLICIT_COUNT_MOVE: (
            "Terraform's implicit move when count is added or removed (x and x[0], C-76)."
        ),
        EvidenceType.FINGERPRINT_EQUAL: "The paired resources have the same fingerprint (C-33).",
        EvidenceType.FINGERPRINT_DIFFERENT: "The paired resources have different fingerprints.",
        EvidenceType.REPLACE_TRIGGER_FIELD: (
            "A controlled ForceNew argument has a different Known value (RT-1, C-126)."
        ),
        EvidenceType.REPLACE_TRIGGER_UNRESOLVED: (
            "A controlled ForceNew argument differs but is unresolved or absent on a side, so "
            "replacement is neither concluded nor excluded."
        ),
        EvidenceType.AMBIGUOUS_CANDIDATES: (
            "Several unpaired instances of one block could correspond (AMB-1, C-125); the observed "
            "value lists all of them."
        ),
        EvidenceType.INDETERMINATE_BLOCK: (
            "The resource block, or its counterpart block, has an unknown number of instances "
            "(C-114)."
        ),
        EvidenceType.CONFLICTING_MOVE: (
            "Moves lead two objects to one address, to an occupied address, or to another type."
        ),
        EvidenceType.UNRESOLVED_CONTENT: (
            "A side of a pair has unknown or unsupported content, so equal fingerprints do not "
            "prove the resource unchanged (C-117)."
        ),
        EvidenceType.UNSUPPORTED_TYPE: (
            "A resource of an unsupported type is involved, classified on the syntactic fact "
            "(C-114)."
        ),
        EvidenceType.NO_COUNTERPART: "Nothing on the other side corresponds: CREATED or DELETED.",
    }
)

SUMMARY_KEYS: Final = ("unchanged", "modified", "created", "deleted", "replaced", "uncertain")
_SUMMARY_OF: Final[Mapping[ChangeType, str]] = MappingProxyType(
    {
        ChangeType.UNCHANGED: "unchanged",
        ChangeType.MODIFIED: "modified",
        ChangeType.CREATED: "created",
        ChangeType.DELETED: "deleted",
        ChangeType.REPLACED: "replaced",
        ChangeType.UNCERTAIN: "uncertain",
    }
)
_PAIR_CHANGES: Final = (ChangeType.UNCHANGED, ChangeType.MODIFIED, ChangeType.REPLACED)
_HEX = frozenset("0123456789abcdef")


def _require_ref(value: object, field: str) -> str | None:
    return optional_text(value, field)


def _ref_order(ref: str | None) -> tuple[bool, str]:
    """Sort key for a ref that may be null: nulls last."""
    return (ref is None, ref or "")


def match_key(trusted_ref: str | None, candidate_ref: str | None) -> str:
    """The key that names a match in a summary: ``trusted->candidate``, ``-`` for a missing side."""
    return f"{trusted_ref or '-'}->{candidate_ref or '-'}"


# --- Evidence -------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityEvidence:
    """One piece of identity evidence (Doc 07 §26): seven fields, no score.

    ``evidence_id`` is derived: the content hash of the seven fields.
    """

    trusted_ref: str | None
    candidate_ref: str | None
    evidence_type: EvidenceType
    source: EvidenceSource
    observed_value: Any
    interpretation: str
    algorithm_version: str

    def __post_init__(self) -> None:
        _require_ref(self.trusted_ref, "IdentityEvidence.trusted_ref")
        _require_ref(self.candidate_ref, "IdentityEvidence.candidate_ref")
        if self.trusted_ref is None and self.candidate_ref is None:
            raise DomainValidationError(
                "IdentityEvidence: at least one of trusted_ref and candidate_ref is required"
            )
        require_enum(self.evidence_type, EvidenceType, "IdentityEvidence.evidence_type")
        require_enum(self.source, EvidenceSource, "IdentityEvidence.source")
        validate_json(self.observed_value, "IdentityEvidence.observed_value")
        object.__setattr__(self, "observed_value", freeze_json(self.observed_value))
        require_text(self.interpretation, "IdentityEvidence.interpretation")
        require_text(self.algorithm_version, "IdentityEvidence.algorithm_version")

    @property
    def evidence_id(self) -> str:
        return content_hash(self.to_dict())

    def sort_key(self) -> tuple[bool, str, bool, str, str, str, str]:
        return (
            *_ref_order(self.trusted_ref),
            *_ref_order(self.candidate_ref),
            self.evidence_type.value,
            self.source.value,
            self.evidence_id,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "trusted_ref": self.trusted_ref,
            "candidate_ref": self.candidate_ref,
            "evidence_type": self.evidence_type.value,
            "source": self.source.value,
            "observed_value": thaw_json(self.observed_value),
            "interpretation": self.interpretation,
            "algorithm_version": self.algorithm_version,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IdentityEvidence:
        fields = require_keys(
            data,
            (
                "trusted_ref",
                "candidate_ref",
                "evidence_type",
                "source",
                "observed_value",
                "interpretation",
                "algorithm_version",
            ),
            "IdentityEvidence",
        )
        return cls(
            trusted_ref=fields["trusted_ref"],
            candidate_ref=fields["candidate_ref"],
            evidence_type=parse_enum(
                fields["evidence_type"], EvidenceType, "IdentityEvidence.evidence_type"
            ),
            source=parse_enum(fields["source"], EvidenceSource, "IdentityEvidence.source"),
            observed_value=fields["observed_value"],
            interpretation=fields["interpretation"],
            algorithm_version=fields["algorithm_version"],
        )


# --- Matches --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class IdentityMatch:
    """What happened to one resource between the trusted and the candidate state (Doc 05 §12).

    ``rationale`` is ``{"rule": <EvidenceType value>, "evidence_ids": [<evidence id>, ...]}``: the
    kind of evidence that decided, and the ids of all the evidence that explains the match.
    """

    trusted_resource_ref: str | None
    candidate_resource_ref: str | None
    identity_status: IdentityStatus
    change_type: ChangeType
    confidence: IdentityConfidence | None
    rationale: Mapping[str, Any]

    def __post_init__(self) -> None:
        trusted = _require_ref(self.trusted_resource_ref, "IdentityMatch.trusted_resource_ref")
        candidate = _require_ref(
            self.candidate_resource_ref, "IdentityMatch.candidate_resource_ref"
        )
        require_enum(self.identity_status, IdentityStatus, "IdentityMatch.identity_status")
        require_enum(self.change_type, ChangeType, "IdentityMatch.change_type")
        if self.confidence is not None:
            require_enum(self.confidence, IdentityConfidence, "IdentityMatch.confidence")
        self._check_combination(trusted, candidate)
        object.__setattr__(self, "rationale", self._canonical_rationale(self.rationale))

    def _check_combination(self, trusted: str | None, candidate: str | None) -> None:
        change = self.change_type
        status = self.identity_status
        confidence = self.confidence
        expected: tuple[IdentityStatus, IdentityConfidence | None]
        if change is ChangeType.CREATED:
            ok = trusted is None and candidate is not None
            expected = (IdentityStatus.DIFFERENT, None)
        elif change is ChangeType.DELETED:
            ok = trusted is not None and candidate is None
            expected = (IdentityStatus.DIFFERENT, None)
        elif change in _PAIR_CHANGES:
            ok = trusted is not None and candidate is not None
            expected = (IdentityStatus.SAME, None)
        else:
            ok = trusted is not None or candidate is not None
            expected = (IdentityStatus.UNCERTAIN, IdentityConfidence.LOW)
        if not ok:
            raise DomainValidationError(
                f"IdentityMatch: a {change.value} match has the wrong refs "
                f"(trusted {trusted!r}, candidate {candidate!r}; Doc 05 §12, C-122)"
            )
        if status is not expected[0]:
            raise DomainValidationError(
                f"IdentityMatch: a {change.value} match has identity_status {expected[0].value}, "
                f"not {status.value} (C-122)"
            )
        if change in _PAIR_CHANGES:
            if confidence not in (IdentityConfidence.HIGH, IdentityConfidence.MEDIUM):
                raise DomainValidationError(
                    f"IdentityMatch: a {change.value} match needs confidence HIGH or MEDIUM (C-122)"
                )
        elif confidence is not expected[1]:
            wanted = "null" if expected[1] is None else expected[1].value
            raise DomainValidationError(
                f"IdentityMatch: a {change.value} match has confidence {wanted} (C-122)"
            )

    @staticmethod
    def _canonical_rationale(value: object) -> Mapping[str, Any]:
        fields = require_keys(value, ("rule", "evidence_ids"), "IdentityMatch.rationale")
        rule = parse_enum(fields["rule"], EvidenceType, "IdentityMatch.rationale.rule")
        ids = fields["evidence_ids"]
        if isinstance(ids, str) or not isinstance(ids, list | tuple):
            raise DomainValidationError("IdentityMatch.rationale.evidence_ids: must be a list")
        for evidence_id in ids:
            if (
                not isinstance(evidence_id, str)
                or len(evidence_id) != 64
                or not _HEX.issuperset(evidence_id)
            ):
                raise DomainValidationError(
                    "IdentityMatch.rationale.evidence_ids: must be evidence ids (SHA-256 hex)"
                )
        if list(ids) != sorted(set(ids)):
            raise DomainValidationError(
                "IdentityMatch.rationale.evidence_ids: must be sorted and without duplicates"
            )
        frozen: Mapping[str, Any] = freeze_json({"rule": rule.value, "evidence_ids": list(ids)})
        return frozen

    @classmethod
    def create(
        cls,
        *,
        trusted_ref: str | None,
        candidate_ref: str | None,
        change_type: ChangeType,
        rule: EvidenceType,
        evidence_ids: Iterable[str],
    ) -> IdentityMatch:
        """A match whose status and confidence follow from the change type (C-122)."""
        if change_type in _PAIR_CHANGES:
            status, confidence = IdentityStatus.SAME, IdentityConfidence.HIGH
        elif change_type is ChangeType.UNCERTAIN:
            status, confidence = IdentityStatus.UNCERTAIN, IdentityConfidence.LOW
        else:
            status, confidence = IdentityStatus.DIFFERENT, None
        return cls(
            trusted_resource_ref=trusted_ref,
            candidate_resource_ref=candidate_ref,
            identity_status=status,
            change_type=change_type,
            confidence=confidence,
            rationale={"rule": rule.value, "evidence_ids": sorted(set(evidence_ids))},
        )

    @property
    def rule(self) -> EvidenceType:
        return EvidenceType(self.rationale["rule"])

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(self.rationale["evidence_ids"])

    @property
    def key(self) -> str:
        return match_key(self.trusted_resource_ref, self.candidate_resource_ref)

    def sort_key(self) -> tuple[bool, str, bool, str]:
        return (*_ref_order(self.trusted_resource_ref), *_ref_order(self.candidate_resource_ref))

    def to_dict(self) -> dict[str, Any]:
        return {
            "trusted_resource_ref": self.trusted_resource_ref,
            "candidate_resource_ref": self.candidate_resource_ref,
            "identity_status": self.identity_status.value,
            "change_type": self.change_type.value,
            "confidence": None if self.confidence is None else self.confidence.value,
            "rationale": thaw_json(self.rationale),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IdentityMatch:
        fields = require_keys(
            data,
            (
                "trusted_resource_ref",
                "candidate_resource_ref",
                "identity_status",
                "change_type",
                "confidence",
                "rationale",
            ),
            "IdentityMatch",
        )
        raw_confidence = fields["confidence"]
        return cls(
            trusted_resource_ref=fields["trusted_resource_ref"],
            candidate_resource_ref=fields["candidate_resource_ref"],
            identity_status=parse_enum(
                fields["identity_status"], IdentityStatus, "IdentityMatch.identity_status"
            ),
            change_type=parse_enum(fields["change_type"], ChangeType, "IdentityMatch.change_type"),
            confidence=(
                None
                if raw_confidence is None
                else parse_enum(raw_confidence, IdentityConfidence, "IdentityMatch.confidence")
            ),
            rationale=fields["rationale"],
        )


# --- Report ---------------------------------------------------------------------------------------


def derive_summary(matches: Iterable[IdentityMatch]) -> dict[str, list[str]]:
    """The six lists of Doc 07 §13, each sorted, holding match keys."""
    summary: dict[str, list[str]] = {name: [] for name in SUMMARY_KEYS}
    for match in matches:
        summary[_SUMMARY_OF[match.change_type]].append(match.key)
    return {name: sorted(keys) for name, keys in summary.items()}


def _hash_payload(
    parent_state_id: str,
    candidate_id: str,
    algorithm_version: str,
    matches: Iterable[IdentityMatch],
    summary: Mapping[str, Any],
    evidence: Iterable[IdentityEvidence],
) -> dict[str, Any]:
    return {
        "parent_state_id": parent_state_id,
        "candidate_id": candidate_id,
        "algorithm_version": algorithm_version,
        "resource_matches": [match.to_dict() for match in matches],
        "summary": thaw_json(summary),
        "evidence": [item.to_dict() for item in evidence],
    }


@dataclass(frozen=True)
class IdentityReport:
    """The answer to "what changed?" for one candidate against one trusted state (Doc 07 §13).

    Create it with ``IdentityReport.create``; the constructor checks everything ``create`` derives.
    """

    report_id: str
    parent_state_id: str
    candidate_id: str
    resource_matches: tuple[IdentityMatch, ...]
    summary: Mapping[str, Any]
    evidence: tuple[IdentityEvidence, ...]
    algorithm_version: str
    created_at: datetime
    content_hash: str

    def __post_init__(self) -> None:
        require_uuid(self.report_id, "IdentityReport.report_id")
        require_uuid(self.parent_state_id, "IdentityReport.parent_state_id")
        require_uuid(self.candidate_id, "IdentityReport.candidate_id")
        require_text(self.algorithm_version, "IdentityReport.algorithm_version")
        object.__setattr__(self, "created_at", utc(self.created_at, "IdentityReport.created_at"))
        matches = self._checked_tuple(self.resource_matches, IdentityMatch, "resource_matches")
        evidence = self._checked_tuple(self.evidence, IdentityEvidence, "evidence")
        self._check_matches(matches)
        self._check_evidence(matches, evidence)
        derived = derive_summary(matches)
        if thaw_json(self.summary) != derived:
            raise DomainValidationError(
                "IdentityReport.summary: is not the summary of the resource matches (Doc 07 §13)"
            )
        object.__setattr__(self, "resource_matches", matches)
        object.__setattr__(self, "evidence", evidence)
        object.__setattr__(self, "summary", freeze_json(derived))
        expected = content_hash(
            _hash_payload(
                self.parent_state_id,
                self.candidate_id,
                self.algorithm_version,
                matches,
                derived,
                evidence,
            )
        )
        if self.content_hash != expected:
            raise HashMismatchError(
                f"DATA-INT-010: IdentityReport {self.report_id} content_hash does not match "
                "its content"
            )

    @staticmethod
    def _checked_tuple[T](value: object, kind: type[T], name: str) -> tuple[T, ...]:
        if isinstance(value, str) or not isinstance(value, list | tuple):
            raise DomainValidationError(f"IdentityReport.{name}: must be a list")
        if not all(isinstance(item, kind) for item in value):
            raise DomainValidationError(f"IdentityReport.{name}: must hold {kind.__name__} objects")
        return tuple(value)

    @staticmethod
    def _check_matches(matches: tuple[IdentityMatch, ...]) -> None:
        keys = [match.sort_key() for match in matches]
        if keys != sorted(keys):
            raise DomainValidationError(
                "IdentityReport.resource_matches: must be sorted by trusted then candidate ref, "
                "nulls last (Doc 07 §28)"
            )
        for side, refs in (
            ("trusted", [m.trusted_resource_ref for m in matches]),
            ("candidate", [m.candidate_resource_ref for m in matches]),
        ):
            present = [ref for ref in refs if ref is not None]
            if len(present) != len(set(present)):
                raise DomainValidationError(
                    f"IdentityReport.resource_matches: a {side} resource is in two matches"
                )

    @staticmethod
    def _check_evidence(
        matches: tuple[IdentityMatch, ...], evidence: tuple[IdentityEvidence, ...]
    ) -> None:
        keys = [item.sort_key() for item in evidence]
        if keys != sorted(keys):
            raise DomainValidationError("IdentityReport.evidence: must be sorted (Doc 07 §28)")
        ids = [item.evidence_id for item in evidence]
        if len(ids) != len(set(ids)):
            raise DomainValidationError("IdentityReport.evidence: duplicate evidence")
        known = set(ids)
        trusted_refs = {m.trusted_resource_ref for m in matches}
        candidate_refs = {m.candidate_resource_ref for m in matches}
        for item in evidence:
            if item.trusted_ref is not None and item.trusted_ref not in trusted_refs:
                raise DomainValidationError(
                    f"IdentityReport.evidence: {item.trusted_ref!r} is in no match"
                )
            if item.candidate_ref is not None and item.candidate_ref not in candidate_refs:
                raise DomainValidationError(
                    f"IdentityReport.evidence: {item.candidate_ref!r} is in no match"
                )
        cited: set[str] = set()
        for match in matches:
            missing = [i for i in match.evidence_ids if i not in known]
            if missing:
                raise DomainValidationError(
                    f"IdentityReport: match {match.key} cites evidence the report does not hold"
                )
            cited.update(match.evidence_ids)
        if cited != known:
            raise DomainValidationError(
                "IdentityReport.evidence: holds evidence that no match cites"
            )

    @classmethod
    def create(
        cls,
        *,
        parent_state_id: str,
        candidate_id: str,
        matches: Iterable[IdentityMatch],
        evidence: Iterable[IdentityEvidence],
        algorithm_version: str,
        now: datetime,
        report_id: str | None = None,
    ) -> IdentityReport:
        """Sort the matches and the evidence, derive the summary and the hash."""
        ordered = tuple(sorted(matches, key=IdentityMatch.sort_key))
        unique = {item.evidence_id: item for item in evidence}
        records = tuple(sorted(unique.values(), key=IdentityEvidence.sort_key))
        summary = derive_summary(ordered)
        digest = content_hash(
            _hash_payload(
                parent_state_id, candidate_id, algorithm_version, ordered, summary, records
            )
        )
        return cls(
            report_id=new_uuid() if report_id is None else report_id,
            parent_state_id=parent_state_id,
            candidate_id=candidate_id,
            resource_matches=ordered,
            summary=summary,
            evidence=records,
            algorithm_version=algorithm_version,
            created_at=now,
            content_hash=digest,
        )

    def match_for_trusted(self, ref: str) -> IdentityMatch | None:
        return next((m for m in self.resource_matches if m.trusted_resource_ref == ref), None)

    def match_for_candidate(self, ref: str) -> IdentityMatch | None:
        return next((m for m in self.resource_matches if m.candidate_resource_ref == ref), None)

    def evidence_for(self, match: IdentityMatch) -> tuple[IdentityEvidence, ...]:
        wanted = set(match.evidence_ids)
        return tuple(item for item in self.evidence if item.evidence_id in wanted)

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "parent_state_id": self.parent_state_id,
            "candidate_id": self.candidate_id,
            "resource_matches": [match.to_dict() for match in self.resource_matches],
            "summary": thaw_json(self.summary),
            "evidence": [item.to_dict() for item in self.evidence],
            "algorithm_version": self.algorithm_version,
            "created_at": iso_utc(self.created_at),
            "content_hash": self.content_hash,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> IdentityReport:
        fields = require_keys(
            data,
            (
                "report_id",
                "parent_state_id",
                "candidate_id",
                "resource_matches",
                "summary",
                "evidence",
                "algorithm_version",
                "created_at",
                "content_hash",
            ),
            "IdentityReport",
        )
        raw_matches = fields["resource_matches"]
        raw_evidence = fields["evidence"]
        if not isinstance(raw_matches, list | tuple) or not isinstance(raw_evidence, list | tuple):
            raise DomainValidationError("IdentityReport: resource_matches and evidence are lists")
        return cls(
            report_id=fields["report_id"],
            parent_state_id=fields["parent_state_id"],
            candidate_id=fields["candidate_id"],
            resource_matches=tuple(IdentityMatch.from_dict(item) for item in raw_matches),
            summary=fields["summary"],
            evidence=tuple(IdentityEvidence.from_dict(item) for item in raw_evidence),
            algorithm_version=fields["algorithm_version"],
            created_at=parse_utc(fields["created_at"], "IdentityReport.created_at"),
            content_hash=fields["content_hash"],
        )
