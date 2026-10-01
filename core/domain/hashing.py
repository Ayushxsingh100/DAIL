"""Canonical serialization and content hashing.

P1 exit criterion: "Canonical hashes are stable." That means: the same
logical content must always produce the same hash, regardless of Python
dict insertion order, regardless of how a caller happened to construct
an equivalent-but-differently-ordered structure, and regardless of
platform. This module is the single place that decision is made; no
other module should call hashlib directly on domain content.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(payload: Any) -> str:
    """Serialize `payload` to a deterministic JSON string.

    - `sort_keys=True` makes dict key order irrelevant.
    - `separators=(",", ":")` removes whitespace variance.
    - `ensure_ascii=True` (the default) avoids encoding-dependent output
      for non-ASCII content (Terraform resource names, etc.).

    This intentionally does NOT attempt to canonicalize floating-point
    representation edge cases (e.g. NaN, -0.0) because no domain object
    in this codebase is expected to carry raw floats into a hashed
    payload; Terraform attribute values that matter to DAIL's invariants
    and identity resolution are strings, ints, bools, lists, and dicts.
    If that assumption is ever violated, this function should be
    revisited rather than silently producing an unstable hash.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_hash(payload: Any) -> str:
    """SHA-256 hex digest of `payload`'s canonical JSON form.

    Used for TrustedState.content_hash, CandidateState.patch_hash, and
    any future evidence-record content addressing (P2). SHA-256 was
    chosen over a faster non-cryptographic hash because these hashes
    are meant to function as tamper-evident content addresses in an
    evidence chain (Section IV-E: "evidence reference"), not merely as
    cache keys.
    """
    digest = hashlib.sha256(canonical_json(payload).encode("utf-8"))
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    """SHA-256 hex digest of ``text`` as UTF-8, with CRLF and CR normalized to LF.

    Used for patch content (Doc 05 §25: ``patch_hash = SHA256(canonical_patch_content)``;
    C-33), so the same patch hashes identically whatever line endings a platform wrote.
    """
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


def verify_content_hash(payload: Any, expected_hash: str) -> bool:
    """Whether `payload` actually hashes to `expected_hash`.

    Exists as a named function (rather than callers re-deriving and
    comparing inline) so that every hash-verification call site in the
    codebase is textually searchable, which matters for auditing
    evidence-integrity logic later.
    """
    return content_hash(payload) == expected_hash
