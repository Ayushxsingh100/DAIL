"""The persistence adapter's way back into the domain (P1b step 5; C-48; Doc 05 §22, §27).

Contract rule R9 allows ``TrustedState.from_dict`` and ``CandidateState.from_dict`` only inside
``core.domain``, so that no module can rebuild a lifecycle-bearing object from data and skip a
transition. A repository still has to rebuild what it stored, with every hash recomputed. These
two functions are that route, and they live here, inside ``core.domain``, so the rule and its
allowlist stay as they are (C-48, decided by the user on 2 Oct 2026).

They add nothing beyond ``from_dict``: ``from_dict`` already validates the shape, the hashes
(DATA-INT-010) and the version-0/parent/decision rules, and rejects unexpected keys. They are not
a promotion path: the new state of a promotion still comes only from ``TrustedState.promote``
(rule R8), and ``InvariantRef`` rows are never rebuilt on their own; a reference is rebuilt only
as part of its ``TrustedState``.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from core.domain.state import CandidateState, TrustedState


def rebuild_trusted_state(data: Mapping[str, Any]) -> TrustedState:
    """A stored trusted state, rebuilt with hash re-validation. Raises ``DomainValidationError``
    (or a subclass such as ``HashMismatchError``) if the content is not a valid state."""
    return TrustedState.from_dict(data)


def rebuild_candidate(data: Mapping[str, Any]) -> CandidateState:
    """A stored candidate, rebuilt with hash re-validation. Raises ``DomainValidationError``
    (or a subclass such as ``HashMismatchError``) if the content is not a valid candidate."""
    return CandidateState.from_dict(data)
