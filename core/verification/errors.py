"""Errors of the verification package (C-144; P5a step 5).

``VerificationInputError`` is raised for inputs that are not what the engine documents, before any
verifier runs. It is never a verification result: an exception *inside* a verifier is turned into a
VERIFIER_ERROR record by the engine, an input error stops the run.

Standard library only.
"""

from __future__ import annotations


class VerificationInputError(ValueError):
    """The inputs to a verification run are malformed (wrong type, inconsistent, missing)."""
