"""Errors of the identity engine (P3b)."""

from __future__ import annotations

from core.domain.errors import DomainValidationError


class IdentityInputError(DomainValidationError):
    """The input of the identity engine is not one it can compare (C-121).

    Raised for resources of different normalization versions, duplicate addresses, a malformed
    address, and moves that Terraform would refuse (P3a-2 already stops those, so they cannot
    arrive through the pipeline). It is never raised for a difference between the two sides: that
    is the answer, not an error.
    """
