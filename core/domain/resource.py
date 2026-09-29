"""Resource model.

Represents one element of Delta(S_t, C_t) as defined in Section IV-F of
the paper: a tuple <address, action, before, after>. This module is
deliberately narrow -- it is the data contract, not the Identity Engine
(that is core.identity, P3) and not the Terraform-plan-JSON parser
(that is core.domain's terraform_model submodule, also P3). P1's job is
only to make this shape exist, be immutable, and be hashable.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from core.domain.enums import ChangeAction, IdentityOutcome


@dataclass(frozen=True)
class Resource:
    """One resource-level change entry within a transition.

    Attributes:
        address: Terraform resource address, e.g.
            "aws_security_group.web-node". Stable addresses are
            necessary but NOT sufficient evidence of identity
            continuity (Section IV-C) -- that is why `identity` is a
            separate field, not derived from address equality.
        action: One of ChangeAction; derived from the Candidate State
            Builder's structural diff (in practice, terraform show
            -json's resource_changes[].change.actions, mapped into
            this abstract set -- see core.domain.terraform_model, P3).
        before: Attribute snapshot prior to the transition, or None if
            the resource did not previously exist (action == CREATED).
            Deliberately typed as a plain dict, not a further-typed
            schema, since Terraform's attribute set varies per resource
            type and DAIL does not claim to model every attribute of
            every supported resource type -- only the ones its
            invariants and dependency edges care about.
        after: Attribute snapshot after the transition, or None if the
            resource no longer exists (action == DELETED).
        identity: The Identity Engine's SAME/DIFFERENT/UNCERTAIN
            resolution for this resource against its predecessor in
            the trusted state, if any. None until the Identity Engine
            (P3) has actually run; a Resource is a data contract, it
            does not resolve its own identity.
        replace_paths: Attribute paths that forced a REPLACED action,
            when action == REPLACED. This is a provider-derived signal
            for *why* a replacement occurred; per Section VI-B it is
            NOT by itself an authoritative identity determination --
            that is still the Identity Engine's job (P3).
    """

    address: str
    action: ChangeAction
    before: dict[str, Any] | None = None
    after: dict[str, Any] | None = None
    identity: IdentityOutcome | None = None
    replace_paths: tuple[tuple[str, ...], ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        if not self.address:
            raise ValueError("Resource.address must be non-empty")
        if self.action == ChangeAction.CREATED and self.before is not None:
            raise ValueError(
                f"Resource {self.address!r}: action=CREATED but 'before' is not None "
                "(a created resource has no prior attribute snapshot)"
            )
        if self.action == ChangeAction.DELETED and self.after is not None:
            raise ValueError(
                f"Resource {self.address!r}: action=DELETED but 'after' is not None "
                "(a deleted resource has no resulting attribute snapshot)"
            )
        if self.action == ChangeAction.UNCHANGED and self.before != self.after:
            raise ValueError(
                f"Resource {self.address!r}: action=UNCHANGED but before != after"
            )
        if self.replace_paths and self.action != ChangeAction.REPLACED:
            raise ValueError(
                f"Resource {self.address!r}: replace_paths is set but action "
                f"is {self.action.value}, not REPLACED"
            )

    def with_identity(self, identity: IdentityOutcome) -> Resource:
        """Return a copy with the Identity Engine's resolution attached.

        Resource is frozen (immutable) so that once the Candidate State
        Builder produces a Delta(S_t, C_t) element, nothing downstream
        can mutate the record of what actually changed -- only append
        new information (here, the identity resolution) via an
        explicit copy. This matters for evidence integrity: the raw
        diff and the Identity Engine's interpretation of it must both
        remain independently inspectable.
        """
        return Resource(
            address=self.address,
            action=self.action,
            before=copy.deepcopy(self.before),
            after=copy.deepcopy(self.after),
            identity=identity,
            replace_paths=self.replace_paths,
        )

    def canonical_dict(self) -> dict[str, Any]:
        """Deterministic dict representation for hashing (core.domain.hashing).

        Key order matters for hash stability, hence an explicit dict
        literal here rather than dataclasses.asdict(), whose key order
        follows field-declaration order but is not something we want
        this module's tests to silently depend on if the dataclass
        fields are ever reordered.
        """
        return {
            "address": self.address,
            "action": self.action.value,
            "before": self.before,
            "after": self.after,
            "identity": self.identity.value if self.identity is not None else None,
            "replace_paths": [list(p) for p in self.replace_paths],
        }
