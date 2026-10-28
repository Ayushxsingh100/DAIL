"""RETAINED-INLINE: does the parent keep rules the candidate no longer shows? (registry §2.6, C-84)

A candidate group whose ``ingress`` argument is *absent* leaves the existing rules in place
(attributes-as-blocks). Whether it does depends on the parent counterpart of the group, "after
following moves" (§2.3), which the identity report knows and the candidate configuration does not.

For a candidate group ``g``:

* no parent, a baseline: the group is deployed fresh, nothing is retained;
* a parent but no identity report, or a report with no match for ``g``, or a counterpart that is
  not among the parent resources: it cannot be told, so ``identity.missing`` (never "fresh");
* a CREATED match has no counterpart (a group the candidate creates is deployed fresh);
* a match with a trusted side (UNCHANGED, MODIFIED, REPLACED, UNCERTAIN with a trusted ref) has that
  resource as counterpart. REPLACED is counted as a counterpart: the report pairs the two groups,
  and UNSUPPORTED never passes (conservative; the registry does not say);
* an UNCERTAIN match with no trusted side (an unpaired candidate instance that cannot be told from
  the unpaired trusted ones of its block) has as possible counterparts every trusted-only UNCERTAIN
  match of the same block (the prompt's "any possible counterpart").

The group is RETAINED-INLINE when any counterpart used inline blocks (``blocks``, ``dynamic`` or
``mixed``) in ingress. A counterpart whose ingress was ``unresolved``, or that is a placeholder or
not readable, is treated as having used blocks: the registry is silent and UNSUPPORTED is safe (R5).

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Mapping

from core.domain.enums import ChangeType, ResourceSupport
from core.domain.identity import IdentityMatch, IdentityReport
from core.domain.resource import Resource
from core.domain.verification import VerificationReason
from core.verification.views import BLOCK_FORMS, SECURITY_GROUP_TYPE, inline_form

_KEPT_FORMS = BLOCK_FORMS | {"unresolved"}


def block_of(address: str) -> str:
    """The address without its instance key: ``aws_security_group.g["a"]`` -> ``...g``."""
    return address.split("[", 1)[0]


def _counterparts(address: str, identity: IdentityReport) -> list[str] | None:
    """Trusted refs that may be the counterpart of a candidate group; ``None`` if the report has no
    match for it."""
    matches = [m for m in identity.resource_matches if m.candidate_resource_ref == address]
    if not matches:
        return None
    found: set[str] = set()
    for match in matches:
        if match.change_type is ChangeType.CREATED:
            continue
        if match.trusted_resource_ref is not None:
            found.add(match.trusted_resource_ref)
        else:  # UNCERTAIN, candidate side only
            found.update(_unpaired_trusted(block_of(address), identity.resource_matches))
    return sorted(found)


def _unpaired_trusted(block: str, matches: tuple[IdentityMatch, ...]) -> list[str]:
    return [
        m.trusted_resource_ref
        for m in matches
        if m.candidate_resource_ref is None
        and m.change_type is ChangeType.UNCERTAIN
        and m.trusted_resource_ref is not None
        and block_of(m.trusted_resource_ref) == block
    ]


def inline_retention(
    address: str,
    direction: str,
    *,
    parent: Mapping[str, Resource] | None,
    identity: IdentityReport | None,
) -> VerificationReason | None:
    """``None`` when the group retains nothing in ``direction`` (``ingress`` or ``egress``),
    ``GROUP_RETAINED_INLINE`` when it keeps the parent's inline rules of that direction,
    ``IDENTITY_MISSING`` when that cannot be told (registry §2.6, C-84)."""
    if parent is None:
        return None
    if identity is None:
        return VerificationReason.IDENTITY_MISSING
    counterparts = _counterparts(address, identity)
    if counterparts is None:
        return VerificationReason.IDENTITY_MISSING
    retained = False
    for ref in counterparts:
        resource = parent.get(ref)
        if resource is None:
            return VerificationReason.IDENTITY_MISSING
        if resource.resource_type != SECURITY_GROUP_TYPE:
            continue  # a conflicting pairing of two types: not a group, nothing inline to keep
        if resource.support_status is not ResourceSupport.SUPPORTED:
            retained = True  # a placeholder or unreadable group: cannot rule blocks out
        elif inline_form(resource, direction) in _KEPT_FORMS:
            retained = True
    return VerificationReason.GROUP_RETAINED_INLINE if retained else None


def ingress_retention(
    address: str,
    *,
    parent: Mapping[str, Resource] | None,
    identity: IdentityReport | None,
) -> VerificationReason | None:
    """``inline_retention`` for the ingress direction (INV-SEC-001, INV-SEC-002)."""
    return inline_retention(address, "ingress", parent=parent, identity=identity)
