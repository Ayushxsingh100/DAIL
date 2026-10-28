"""Identity engine: what changed between the trusted and the candidate state (P3b).

Owning spec sections: Doc 07 (identity evidence priority, matching, change classification,
ambiguity handling, determinism rules). Decisions: C-121 to C-127, ADR-015.

* ``engine.compare`` is the pure function: trusted and candidate ``Resource`` objects and the
  candidate's moves in, an ``IdentityReport`` out.
* ``strategy`` holds the decision order and the strategy seam (``EvidenceIdentity``, the default).
* ``moves`` follows ``moved`` blocks and the implicit ``count`` moves as Terraform 1.15.8 does.
* ``findings`` has the evidence records, the content scans, RT-1 and AMB-1.
* ``addresses`` reads the instance key of a canonical address; ``errors`` has the input error.

Import restrictions (tests/contract/test_architecture_boundaries.py): the standard library and
``core.domain`` only (R14); in particular not ``core.terraform_model``.
"""
