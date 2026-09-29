"""Impact and invalidation: which protected invariants must be re-checked.

Owning spec sections: Doc 08 (changed set, direct and dependency impact,
typed traversal, uncertainty propagation, per-context evidence invalidation,
verification work set).
Built in: P4.

Import restrictions (tests/contract/test_architecture_boundaries.py):
must not import ``core.promotion`` (R5) or ``core.application`` (R2); must not
import ``llm``, ``experiments``, ``scripts``, ``apps``, ``benchmark`` or
``oracle`` (R3). Standard library only (R7). No code yet.
"""
