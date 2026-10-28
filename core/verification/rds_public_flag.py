"""INV-SEC-003: RDS instances are not publicly accessible (registry §5; C-146).

For every configured ``aws_db_instance`` instance, ``publicly_accessible`` must be false.

* An absent attribute is false (the provider default, V05); an explicit null is "not set", so also
  false. The texts ``"true"`` and ``"false"`` are what Terraform converts to a bool.
* With zero instances the predicate holds vacuously and the evidence records the count, 0.
* Results (§5.3): FAIL if some instance has a resolved ``true``; UNKNOWN if some value is
  unresolved or ``aws_db_instance`` is indeterminate (an unknown ``count`` or ``for_each``);
  PASS otherwise.
* §5.3 has no row for a value that depends on an unsupported construct, or whose type is wrong.
  Registry §2.4 calls that UNSUPPORTED, so it is UNSUPPORTED, between FAIL and UNKNOWN as in §3.4
  (R5, reported as a spec gap). An unreadable ``aws_db_instance`` placeholder is UNSUPPORTED too.
* Other RDS types (``aws_rds_cluster_instance``) are out of scope.

The stored view (``normalize.SECURITY_FIELDS``, ``view_value``) holds ``publicly_accessible`` and
``vpc_security_group_ids`` as the encoded value of the argument (the whole encoding if it was
written as a block); a key that is not one of those, or a value not in the encoding, is a
``ViewError``.

Standard library and ``core.domain`` only.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Final

from core.domain.enums import ResourceSupport, VerificationResult
from core.domain.jsonvalue import thaw_json
from core.domain.resource import Resource
from core.domain.verification import VerificationReason
from core.verification.outcome import PredicateOutcome
from core.verification.values import (
    Ref,
    Unknown,
    Unsupported,
    ValueDecodeError,
    decode,
    describe,
    has_problem,
)
from core.verification.views import ViewError

DB_INSTANCE_TYPE: Final = "aws_db_instance"
TOLERATED_TYPE: Final = "aws_db_subnet_group"
TOLERATED_ASSUMPTION: Final = "tolerated type: aws_db_subnet_group (C-15)"
DEFAULT_ASSUMPTION: Final = "absent publicly_accessible is false (registry 5.2, V05)"
_SECURITY_KEYS: Final = frozenset({"publicly_accessible", "vpc_security_group_ids"})
_BLOCK_FORMS: Final = ("BLOCKS", "DYNAMIC", "MIXED")

P, F, U, S = (
    VerificationResult.PASS,
    VerificationResult.FAIL,
    VerificationResult.UNKNOWN,
    VerificationResult.UNSUPPORTED,
)


def instance_state(resource: Resource) -> tuple[VerificationResult, str]:
    """The result and shown value for one supported ``aws_db_instance``."""
    security = thaw_json(resource.security_attributes)
    if not set(security) <= _SECURITY_KEYS:
        raise ViewError(
            f"{resource.address}: security_attributes keys {sorted(security)} are not those of "
            "an aws_db_instance"
        )
    if "publicly_accessible" not in security:
        return P, "absent"
    encoded = security["publicly_accessible"]
    if isinstance(encoded, dict) and encoded.get("form") in _BLOCK_FORMS:
        return S, "unsupported:publicly_accessible.form"  # an argument written as a block
    try:
        value: Any = decode(encoded)
    except ValueDecodeError as error:
        raise ViewError(f"{resource.address}.publicly_accessible: {error}") from None
    if isinstance(value, Unknown | Ref):
        return U, describe(value)
    if isinstance(value, Unsupported):
        return S, describe(value)
    if has_problem(value):
        return S, "unsupported:publicly_accessible.nested_problem"
    if value is None:
        return P, "absent"
    if value is True or value == "true":
        return F, "true"
    if value is False or value == "false":
        return P, "false"
    return S, "unsupported:publicly_accessible.type"


def evaluate_rds_public_flag(resources: Iterable[Resource]) -> PredicateOutcome:
    """INV-SEC-003 for a candidate's resources."""
    found = list(resources)
    values: list[dict[str, str]] = []
    placeholders: list[str] = []
    results: list[VerificationResult] = []
    for resource in sorted(found, key=lambda item: item.address):
        if resource.resource_type != DB_INSTANCE_TYPE:
            continue
        if resource.support_status is ResourceSupport.UNKNOWN:
            placeholders.append(resource.address)
            results.append(U)
        elif resource.support_status is ResourceSupport.UNSUPPORTED:
            placeholders.append(resource.address)
            results.append(S)
        else:
            result, shown = instance_state(resource)
            results.append(result)
            values.append({"address": resource.address, "value": shown})
    if F in results:
        result, reason = F, VerificationReason.PREDICATE_VIOLATED
    elif S in results:
        result, reason = S, VerificationReason.RULE_UNSUPPORTED
    elif U in results:
        result, reason = U, VerificationReason.ATTRIBUTE_UNRESOLVED
    else:
        result, reason = P, None
    tolerated = any(item.resource_type == TOLERATED_TYPE for item in found)
    assumptions = tuple(
        sorted((DEFAULT_ASSUMPTION, *((TOLERATED_ASSUMPTION,) if tolerated else ())))
    )
    observations: dict[str, Any] = {
        "instances": len(values),
        "values": values,
        "placeholders": placeholders,
    }
    return PredicateOutcome(result, reason, None, observations, assumptions)


__all__ = ["PredicateOutcome", "evaluate_rds_public_flag", "instance_state"]
