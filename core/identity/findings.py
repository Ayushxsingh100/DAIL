"""The parts of the identity decision: evidence records, content scans, RT-1 and AMB-1.

Everything here is a pure function of ``Resource`` objects and strings (Doc 07 §28). The decision
order that combines them is in ``core.identity.strategy`` (C-124).

* ``Evidencer`` builds ``IdentityEvidence`` records for one algorithm version.
* ``unresolved_entries`` lists unknown or unsupported content of a resource (C-117, C-124 rule 9).
* ``replace_trigger_verdict`` implements RT-1 from the data table ``REPLACE_TRIGGER_FIELDS``
  (C-90, C-126): the table, not the function, is what a later version extends.
* ``ambiguous_blocks`` implements AMB-1 (C-90, C-125), including the symmetric case that goes
  beyond C-90's text; it is one function so that the extension can be removed.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Final

from core.domain.enums import ChangeType, ReferenceResolution, ResourceSupport
from core.domain.identity import EvidenceSource, EvidenceType, IdentityEvidence, IdentityMatch
from core.domain.resource import Resource
from core.identity.addresses import block_of

TAG: Final = "$dail"

# RT-1 (C-90, C-126): resource type -> top-level arguments the pinned provider marks ForceNew.
# AWS provider 6.53.0, internal/service/ec2/vpc_security_group.go, `name` schema entry L79-L88.
# This package adds no field; a longer list is a register decision.
REPLACE_TRIGGER_FIELDS: Final[Mapping[str, tuple[str, ...]]] = MappingProxyType(
    {"aws_security_group": ("name",)}
)


def is_placeholder(resource: Resource) -> bool:
    """A resource with an unknown number of instances (C-114)."""
    return resource.support_status is ResourceSupport.UNKNOWN


# --- Draft ----------------------------------------------------------------------------------------


@dataclass
class Draft:
    """One match under construction: the resources, the change and the evidence behind it."""

    trusted: Resource | None
    candidate: Resource | None
    change: ChangeType
    rule: EvidenceType
    evidence: list[IdentityEvidence] = field(default_factory=list)

    @property
    def trusted_ref(self) -> str | None:
        return None if self.trusted is None else self.trusted.address

    @property
    def candidate_ref(self) -> str | None:
        return None if self.candidate is None else self.candidate.address

    def match(self) -> IdentityMatch:
        return IdentityMatch.create(
            trusted_ref=self.trusted_ref,
            candidate_ref=self.candidate_ref,
            change_type=self.change,
            rule=self.rule,
            evidence_ids=[item.evidence_id for item in self.evidence],
        )


class Evidencer:
    """Builds the evidence records of one algorithm version."""

    def __init__(self, algorithm_version: str) -> None:
        self.version = algorithm_version

    def make(
        self,
        kind: EvidenceType,
        source: EvidenceSource,
        trusted: str | None,
        candidate: str | None,
        observed: Any,
        interpretation: str,
    ) -> IdentityEvidence:
        return IdentityEvidence(
            trusted_ref=trusted,
            candidate_ref=candidate,
            evidence_type=kind,
            source=source,
            observed_value=observed,
            interpretation=interpretation,
            algorithm_version=self.version,
        )

    def about(
        self,
        trusted: Resource | None,
        candidate: Resource | None,
        kind: EvidenceType,
        source: EvidenceSource,
        observed: Any,
        interpretation: str,
    ) -> IdentityEvidence:
        return self.make(
            kind,
            source,
            None if trusted is None else trusted.address,
            None if candidate is None else candidate.address,
            observed,
            interpretation,
        )

    def unsupported(
        self, trusted: Resource | None, candidate: Resource | None
    ) -> IdentityEvidence | None:
        """``UNSUPPORTED_TYPE`` when an unsupported resource is involved (C-124 rule 8)."""
        sides = {
            "trusted": trusted,
            "candidate": candidate,
        }
        statuses = {
            name: resource.support_status.value
            for name, resource in sides.items()
            if resource is not None
        }
        if all(status != ResourceSupport.UNSUPPORTED.value for status in statuses.values()):
            return None
        present = trusted if trusted is not None else candidate
        assert present is not None
        return self.about(
            trusted,
            candidate,
            EvidenceType.UNSUPPORTED_TYPE,
            _source_of(trusted, candidate),
            {
                "resource_type": present.resource_type,
                **{f"{k}_support": v for k, v in statuses.items()},
            },
            "An unsupported resource type is involved: the change is classified on the syntactic "
            "fact only (C-114).",
        )

    def unresolved(self, trusted: Resource, candidate: Resource) -> IdentityEvidence | None:
        """``UNRESOLVED_CONTENT`` for a pair with unknown or unsupported content (C-117)."""
        left, right = unresolved_entries(trusted), unresolved_entries(candidate)
        if not left and not right:
            return None
        return self.about(
            trusted,
            candidate,
            EvidenceType.UNRESOLVED_CONTENT,
            EvidenceSource.BOTH,
            {"trusted": left, "candidate": right},
            "A side of this pair has unknown or unsupported content: equal fingerprints do not "
            "prove the resource unchanged (C-117).",
        )


def _source_of(trusted: Resource | None, candidate: Resource | None) -> EvidenceSource:
    if trusted is not None and candidate is not None:
        return EvidenceSource.BOTH
    return EvidenceSource.TRUSTED if trusted is not None else EvidenceSource.CANDIDATE


# --- Unresolved content ---------------------------------------------------------------------------

_UNRESOLVED_FORMS: Final = frozenset({"unresolved", "dynamic", "mixed"})
_UNRESOLVED_REFERENCES: Final = frozenset(
    {ReferenceResolution.UNKNOWN, ReferenceResolution.UNSUPPORTED}
)


def _walk(value: Any, path: str, tags: frozenset[str], found: list[dict[str, Any]]) -> None:
    if isinstance(value, Mapping):
        tag = value.get(TAG)
        if isinstance(tag, str) and tag in tags:
            found.append({"path": path, "kind": tag, "reason": value.get("reason", "")})
            return
        for name in sorted(value):
            _walk(value[name], f"{path}.{name}" if path else str(name), tags, found)
    elif isinstance(value, list | tuple):
        for index, item in enumerate(value):
            _walk(item, f"{path}[{index}]", tags, found)


def contains_tag(value: Any, tags: Iterable[str]) -> bool:
    """Whether a canonical JSON value holds a ``$dail`` object of one of the given kinds."""
    found: list[dict[str, Any]] = []
    _walk(value, "", frozenset(tags), found)
    return bool(found)


def unresolved_entries(resource: Resource) -> list[dict[str, Any]]:
    """Unknown or unsupported content of a resource, sorted by path (C-124 rule 9).

    Three sources: a ``$dail`` unknown or unsupported value in ``attributes``; a direction form
    ``unresolved``, ``dynamic`` or ``mixed`` of a security group (``security_attributes.forms``); a
    reference whose status is UNKNOWN or UNSUPPORTED. A placeholder has no content to scan: its
    indeterminacy is ``INDETERMINATE_BLOCK``.
    """
    if is_placeholder(resource):
        return []
    found: list[dict[str, Any]] = []
    _walk(resource.attributes, "attributes", frozenset({"unknown", "unsupported"}), found)
    forms = resource.security_attributes.get("forms")
    if isinstance(forms, Mapping):
        for name in sorted(forms):
            if forms[name] in _UNRESOLVED_FORMS:
                found.append(
                    {
                        "path": f"security_attributes.forms.{name}",
                        "kind": "form",
                        "reason": forms[name],
                    }
                )
    for ref in resource.references:
        if ref.resolution_status in _UNRESOLVED_REFERENCES:
            found.append(
                {
                    "path": f"references.{ref.source_attribute}",
                    "kind": "reference",
                    "reason": f"{ref.resolution_status.value} {ref.target_address}",
                }
            )
    return sorted(found, key=lambda entry: (entry["path"], entry["kind"], str(entry["reason"])))


# --- RT-1 -----------------------------------------------------------------------------------------


def _argument_state(attributes: Mapping[str, Any], name: str) -> dict[str, Any]:
    """Whether an argument is ``known``, ``absent`` (also an explicit null, C-120) or
    ``unresolved`` (unknown, unsupported, a reference, or not written as an attribute)."""
    if name not in attributes:
        return {"state": "absent"}
    argument = attributes[name]
    if (
        isinstance(argument, Mapping)
        and argument.get("form") == "ATTRIBUTE"
        and "value" in argument
    ):
        value = argument["value"]
        if value is None:
            return {"state": "absent"}
        if contains_tag(value, ("unknown", "unsupported", "ref")):
            return {"state": "unresolved", "value": _plain(value)}
        return {"state": "known", "value": _plain(value)}
    return {"state": "unresolved", "value": _plain(argument)}


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_plain(item) for item in value]
    return value


def replace_trigger_verdict(
    trusted: Resource,
    candidate: Resource,
    evidencer: Evidencer,
    table: Mapping[str, tuple[str, ...]] = REPLACE_TRIGGER_FIELDS,
) -> tuple[ChangeType | None, list[IdentityEvidence]]:
    """RT-1 for a pair of one type with different fingerprints (C-126).

    Returns ``(REPLACED, evidence)`` when a controlled argument is Known on both sides and
    different; ``(UNCERTAIN, evidence)`` when one differs and is unresolved, or absent on exactly
    one side, and none is definitely different; ``(None, [])`` otherwise (MODIFIED).
    """
    replaced: list[IdentityEvidence] = []
    undecided: list[IdentityEvidence] = []
    for name in table.get(trusted.resource_type, ()):
        before = _argument_state(trusted.attributes, name)
        after = _argument_state(candidate.attributes, name)
        if before == after or (before["state"] == after["state"] == "absent"):
            continue
        observed = {"resource_type": trusted.resource_type, "field": name}
        if before["state"] == "known" and after["state"] == "known":
            replaced.append(
                evidencer.about(
                    trusted,
                    candidate,
                    EvidenceType.REPLACE_TRIGGER_FIELD,
                    EvidenceSource.BOTH,
                    {**observed, "trusted": before["value"], "candidate": after["value"]},
                    f"{trusted.resource_type}.{name} is ForceNew in the pinned provider and its "
                    "value differs: Terraform replaces the resource (RT-1).",
                )
            )
        else:
            undecided.append(
                evidencer.about(
                    trusted,
                    candidate,
                    EvidenceType.REPLACE_TRIGGER_UNRESOLVED,
                    EvidenceSource.BOTH,
                    {**observed, "trusted": before, "candidate": after},
                    f"{trusted.resource_type}.{name} is ForceNew and differs, but is unresolved or "
                    "absent on a side: replacement is neither concluded nor excluded (RT-1).",
                )
            )
    if replaced:
        return ChangeType.REPLACED, replaced + undecided
    if undecided:
        return ChangeType.UNCERTAIN, undecided
    return None, []


# --- AMB-1 ----------------------------------------------------------------------------------------


def ambiguous_blocks(
    unpaired_trusted: Iterable[str], unpaired_candidate: Iterable[str]
) -> dict[str, tuple[tuple[str, ...], tuple[str, ...]]]:
    """The blocks whose unpaired instances cannot be told apart (AMB-1, C-90, C-125).

    ``unpaired_trusted`` and ``unpaired_candidate`` are the addresses of the determinate instances
    that no exact address and no move paired. A block is ambiguous when both sides have members and
    either has two or more. **The symmetric case** (two or more trusted, one candidate) is
    Doc 07 §11's "or vice versa" and goes beyond C-90's text; it is the condition marked below.
    Result: block -> (trusted members, candidate members), each sorted.
    """
    trusted: dict[str, list[str]] = defaultdict(list)
    candidate: dict[str, list[str]] = defaultdict(list)
    for address in unpaired_trusted:
        trusted[block_of(address)].append(address)
    for address in unpaired_candidate:
        candidate[block_of(address)].append(address)
    found: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {}
    for block in sorted(trusted.keys() & candidate.keys()):
        one_to_many = len(candidate[block]) >= 2  # C-90: one trusted, two or more candidates
        many_to_one = len(trusted[block]) >= 2  # extension (Doc 07 §11 "or vice versa")
        if one_to_many or many_to_one:
            found[block] = (tuple(sorted(trusted[block])), tuple(sorted(candidate[block])))
    return found


def sorted_resources(resources: Sequence[Resource]) -> list[Resource]:
    return sorted(resources, key=lambda resource: resource.address)
