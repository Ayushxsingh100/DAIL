"""Terraform model: parser, normalizer, canonical security rule, fingerprints.

Owning spec sections: Doc 04 §3-12 (supported constructs, parse/normalize
pipeline, normalized resource contract, canonicalization, fingerprints,
canonical security-group rule model, dependency facts).
Built in: P3a (P3a-1: HCL parsing and structural validation; P3a-2: expression evaluation and
instance expansion; P3a-3: normalization into ``core.domain`` ``Resource`` objects).

Contents:
- ``hcl``: lexer, parser and immutable syntax tree for the HCL native syntax (C-91).
- ``config``: the configuration loader and structural validation (C-92 to C-94).
- ``values``, ``convert``, ``functions``, ``evaluate``: the value model and the evaluator (C-102,
  C-103, C-105); ``instances``, ``evaluation``: expansion, variables, locals, moves (C-100, C-104).
- ``canonical``, ``normalize``, ``security_rules``, ``references``, ``normalization``: the canonical
  encoding (C-112), per-instance normalization (C-113, C-114), canonical security rules (C-116),
  reference extraction (C-115) and ``normalize_configuration`` (C-118).

Import restrictions (rule R6 in tests/contract/test_architecture_boundaries.py):
no other ``core.*`` package except ``core.domain``, no ``evidence``, no ``sqlite3``.
Standard library only (rule R7).
"""
