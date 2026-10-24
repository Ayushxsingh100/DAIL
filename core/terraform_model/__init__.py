"""Terraform model: parser, normalizer, canonical security rule, fingerprints.

Owning spec sections: Doc 04 §3-12 (supported constructs, parse/normalize
pipeline, normalized resource contract, canonicalization, fingerprints,
canonical security-group rule model, dependency facts).
Built in: P3a (P3a-1: HCL parsing and structural validation; P3a-2: the rest).

Contents so far:
- ``hcl``: lexer, parser and immutable syntax tree for the HCL native syntax (C-91).
- ``config``: the configuration loader and structural validation (C-92 to C-94), added in
  P3a-1 step 4.

Import restrictions (rule R6 in tests/contract/test_architecture_boundaries.py):
no other ``core.*`` package except ``core.domain``, no ``evidence``, no ``sqlite3``.
Standard library only (rule R7).
"""
