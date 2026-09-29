"""Terraform model: parser, normalizer, canonical security rule, fingerprints.

Owning spec sections: Doc 04 §3-12 (supported constructs, parse/normalize
pipeline, normalized resource contract, canonicalization, fingerprints,
canonical security-group rule model, dependency facts).
Built in: P3a.

Import restrictions (rule R6 in tests/contract/test_architecture_boundaries.py):
no other ``core.*`` package, no ``evidence``, no ``sqlite3``. Standard library
only (rule R7). No code yet.
"""
