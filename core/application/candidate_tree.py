"""The hash of a candidate directory (C-188).

A built LLM candidate is bound to its directory by ``tree_hash``: SHA-256 over every regular file
under the directory, in sorted relative-path order, each as its POSIX path and its bytes. The
validator records it when it builds the candidate; ``LLMEvaluationRequest`` recomputes it before
anything is evaluated, so a directory edited after the build is refused and "the patch and the
candidate cannot disagree". A symbolic link anywhere in the tree is refused.

Standard library only.
"""

from __future__ import annotations

import hashlib
from pathlib import Path


def tree_hash(directory: Path) -> str:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError(f"tree_hash: {directory} is not a directory")
    digest = hashlib.sha256()
    entries = sorted(directory.rglob("*"), key=lambda p: p.relative_to(directory).as_posix())
    for path in entries:
        if path.is_symlink():
            raise ValueError(f"tree_hash: {path.name} is a symbolic link")
        if not path.is_file():
            continue
        name = path.relative_to(directory).as_posix().encode("utf-8")
        content = path.read_bytes()
        digest.update(len(name).to_bytes(8, "big") + name)
        digest.update(len(content).to_bytes(8, "big") + content)
    return digest.hexdigest()
