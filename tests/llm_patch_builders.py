"""Builders for the P7b patch-validation tests. Not a test module.

The parent is the canonical baseline (``fixtures/canonical_regression/baseline``: public SSH open,
EC2 to RDS on TCP/5432). Patch texts are written here by hand, as a model would write them under
the decided format (C-188): complete ``resource`` blocks, an address listed without a block is
deleted. Nothing here computes an expected value.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Sequence
from functools import cache
from pathlib import Path
from typing import Any

from core.domain.change_scope import ALL_OPERATIONS, AllowedChangeScope, OperationType
from core.domain.state import TrustedState
from core.terraform_model.normalization import normalize_directory
from llm.adapter.context import SUPPORTED_TYPES
from llm.schemas.repair_response import RESPONSE_SCHEMA_VERSION
from llm.validation.patch import PatchValidator
from tests.fixture_catalog import REPO_ROOT
from tests.identity_builders import NOW
from tests.impact_builders import registry
from tests.promotion_pipeline import trusted_from

BASELINE = REPO_ROOT / "fixtures" / "canonical_regression" / "baseline"
PARENT_NAME = "fixtures/canonical_regression/baseline"
REQUEST_ID = "00000000-0000-4000-8000-00000000a001"
PATCH_ID = "00000000-0000-4000-8000-00000000a002"

SG_APP_CLOSED = (
    'resource "aws_security_group" "app" {\n'
    '  name        = "app"\n'
    '  description = "Application security group"\n'
    "  vpc_id      = aws_vpc.main.id\n"
    "  ingress     = []\n"
    "}\n"
)
SSH_RULE = "aws_security_group_rule.app_ssh_public"
DB_RULE = "aws_security_group_rule.app_to_db_5432"
SG_APP = "aws_security_group.app"
NEW_RULE = (
    'resource "aws_security_group_rule" "app_https" {\n'
    '  type              = "ingress"\n'
    '  protocol          = "tcp"\n'
    "  from_port         = 443\n"
    "  to_port           = 443\n"
    '  cidr_blocks       = ["10.0.0.0/16"]\n'
    "  security_group_id = aws_security_group.app.id\n"
    "}\n"
)
DELETE_ONLY = "# delete the public SSH rule\n"


@cache
def trusted() -> TrustedState:
    outcome = normalize_directory(BASELINE, None, now=NOW)
    definitions = list(registry("aws_instance.app", "aws_db_instance.database").values())
    return trusted_from(PARENT_NAME, outcome.resources, definitions)


@cache
def all_addresses() -> tuple[str, ...]:
    return tuple(sorted(r.address for r in trusted().resources))


def scope(
    *,
    addresses: Sequence[str] | None = None,
    types: Sequence[str] | None = None,
    attributes: Sequence[str] = (),
    operations: Sequence[OperationType] = ALL_OPERATIONS,
) -> AllowedChangeScope:
    """The scope a test controller gives; the default allows everything in the parent (C-191)."""
    return AllowedChangeScope(
        resource_addresses=tuple(all_addresses() if addresses is None else addresses),
        resource_types=tuple(SUPPORTED_TYPES if types is None else types),
        attributes=tuple(attributes),
        operation_types=tuple(operations),
    )


def tree_digest(directory: Path) -> str:
    """A hash of every file under ``directory`` (path and bytes), for 'byte-identical' checks."""
    digest = hashlib.sha256()
    for path in sorted(p for p in directory.rglob("*") if p.is_file()):
        digest.update(path.relative_to(directory).as_posix().encode() + b"\0")
        digest.update(path.read_bytes() + b"\0")
    return digest.hexdigest()


def repair(patch: str, changed: Sequence[str], **changes: Any) -> str:
    """A PATCH response text."""
    body: dict[str, Any] = {
        "schema_version": RESPONSE_SCHEMA_VERSION,
        "status": "PATCH",
        "summary": "repair",
        "patch": patch,
        "changed_addresses": list(changed),
        "assumptions": [],
        "rationale": "minimal change",
    }
    body.update(changes)
    return json.dumps(body)


class WorkRoot:
    """A temporary directory for isolated candidate builds."""

    def __init__(self) -> None:
        self._tmp = tempfile.TemporaryDirectory(prefix="dail-p7b-")
        self.path = Path(self._tmp.name)

    def close(self) -> None:
        self._tmp.cleanup()


def validator(work: Path, change_scope: AllowedChangeScope | None = None) -> PatchValidator:
    return PatchValidator(
        parent_dir=BASELINE,
        trusted=trusted(),
        scope=change_scope or scope(),
        work_root=work,
        variables=None,
        now=NOW,
    )
