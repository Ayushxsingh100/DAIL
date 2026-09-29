"""Identity engine: what changed between trusted and candidate state.

Owning spec sections: Doc 07 (identity evidence priority, matching,
change classification, ambiguity handling, determinism rules).
Built in: P3b.

Import restrictions (tests/contract/test_architecture_boundaries.py):
must not import ``core.promotion`` (R5) or ``core.application`` (R2); must not
import ``llm``, ``experiments``, ``scripts``, ``apps``, ``benchmark`` or
``oracle`` (R3). Standard library only (R7). No code yet.
"""
