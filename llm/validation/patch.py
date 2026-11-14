"""The patch validator: from a parsed PATCH response to a built, normalized candidate directory
(Doc 10 §12-§14, §22, §27; Doc 03 §4.5-§4.7; C-188 to C-192).

``PatchValidator(parent_dir=..., trusted=..., scope=..., work_root=..., variables=..., now=...)``
checks once, at construction, that ``parent_dir`` *is* the trusted state (its normalized resource
set has the trusted state's ``resource_set_hash``; Doc 03 §4.5 step 1 "Load the exact parent Trusted
State"). ``validate(response, request_id=..., patch_id=...)`` then runs the checks in Doc 10 §13
order; the first that fails decides, and its failure class follows C-192:

==  ===========================================================================  ==================
 2  HCL syntax (DAIL's own parser)                                               INVALID_OUTPUT
    (a limit of the parser, C-93)                                                UNSUPPORTED
 3  only ``resource`` blocks at the top level (with two labels)                  POLICY_VIOLATION
 4  ``provisioner``, ``connection`` inside a block; a ``lifecycle`` that is not   POLICY_VIOLATION
    the parent's (whitespace-normalized), including a MODIFY block that drops
    the parent's ``lifecycle`` (C-221, validator 2); ``dynamic``                 UNSUPPORTED
 5  boundaries (C-188, C-189): blocks and ``changed_addresses`` agree, no         INVALID_OUTPUT
    block twice, no DELETE of an address the parent does not have
 6  scope (C-190): type outside the supported model                              UNSUPPORTED
    type outside ``resource_types``, MODIFY/DELETE outside ``resource_addresses``,
    an attribute outside a non-empty ``attributes``                              POLICY_VIOLATION
 7  credentials (§14): a secret-named argument that is not the parent's value or
    a ``var.`` reference; an AWS access key id or a PEM private-key header        POLICY_VIOLATION
 8  invented provider/runtime ids (§14) not in the parent text                   POLICY_VIOLATION
 9  build (C-189) in a fresh directory under ``work_root``; the parent is never
    written; the built directory must load (P3a-1)                               INVALID_OUTPUT
10  references: every root in the patch blocks is declared in the candidate      INVALID_OUTPUT
11  normalize (P3); INVALID                                                      INVALID_OUTPUT
    UNSUPPORTED                                                                  UNSUPPORTED
12  identity (DAIL's own engine) and the operation check (C-191)                 POLICY_VIOLATION
==  ===========================================================================  ==================

On success the outcome holds a ``CandidateBuild``: the directory, its ``tree_hash`` (which
``LLMEvaluationRequest`` checks again), the resource-set hash and the ``Patch`` record
(``source = LLM``, bound to the attempt's request and to the one parent, Doc 10 §12). On any failure
the built directory is removed and no candidate exists (Doc 03 §4.7 "Failure does not produce a
promotable candidate"). Nothing here is "fixed" or guessed: a patch is taken as written or refused.

Where a parent block lives in a ``.tf.json`` file its bytes cannot be replaced as HCL: MODIFY and
DELETE of it are UNSUPPORTED. A parent that already has a file named ``dail_llm_patch.tf`` is
UNSUPPORTED for CREATE.
"""

from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Final

from core.application.candidate_tree import tree_hash
from core.domain.change_scope import AllowedChangeScope, OperationType, operation_breaches
from core.domain.enums import CandidateSource
from core.domain.ids import new_uuid
from core.domain.patch import Patch
from core.domain.redaction import Redactor
from core.domain.state import TrustedState
from core.identity.engine import compare
from core.terraform_model.config import ParseStatus, ResourceDecl, load_configuration
from core.terraform_model.hcl.ast import (
    Attribute,
    Block,
    ForExpr,
    Literal,
    LiteralKind,
    ScopeTraversal,
    TemplateLiteral,
)
from core.terraform_model.hcl.errors import HclLimitError, HclSyntaxError
from core.terraform_model.hcl.parser import parse_file
from core.terraform_model.normalization import normalize_directory
from llm.adapter.context import SUPPORTED_TYPES
from llm.schemas.records import FailureClass
from llm.schemas.repair_response import LLMRepairResponse, RepairStatus

VALIDATOR_VERSION: Final = "dail-patch-validator-2"  # 2: the lifecycle rule (C-221)
PATCH_FILE: Final = "dail_llm_patch.tf"
F = FailureClass
OP = OperationType
_FORBIDDEN_TOP: Final = "only resource blocks are allowed at the top level of a patch (§14)"
_ACCESS_KEY = re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")
_PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_AWS_ID = re.compile(
    r"(?<![0-9A-Za-z-])(?:sg|subnet|vpc|igw|rtb|eni|i|ami)-(?:[0-9a-f]{17}|[0-9a-f]{8})(?![0-9A-Za-z])"
)
_BUILTIN_ROOTS: Final = frozenset({"count", "each", "self", "path", "terraform"})


@dataclass(frozen=True)
class CandidateBuild:
    candidate_dir: Path
    tree_hash: str
    resource_set_hash: str
    patch: Patch

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_dir": str(self.candidate_dir),
            "tree_hash": self.tree_hash,
            "resource_set_hash": self.resource_set_hash,
            "patch_id": self.patch.patch_id,
            "patch_hash": self.patch.content_hash,
        }


@dataclass(frozen=True)
class ValidationOutcome:
    failure_class: FailureClass | None
    errors: tuple[str, ...]
    build: CandidateBuild | None
    operations: tuple[tuple[str, OperationType], ...]
    patch_id: str | None
    validator_version: str = VALIDATOR_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "validator_version": self.validator_version,
            "failure_class": None if self.failure_class is None else self.failure_class.value,
            "errors": list(self.errors),
            "operations": [[address, op.value] for address, op in self.operations],
            "patch_id": self.patch_id,
            "build": None if self.build is None else self.build.to_dict(),
        }


class _Refuse(Exception):
    def __init__(self, failure: FailureClass, message: str) -> None:
        super().__init__(message)
        self.failure = failure


# --- syntax-tree helpers ----------------------------------------------------------------------


def _children(node: object) -> Iterator[object]:
    if dataclasses.is_dataclass(node) and not isinstance(node, type):
        for item in dataclasses.fields(node):
            if item.name.endswith("range"):
                continue
            yield getattr(node, item.name)
    elif isinstance(node, tuple | list):
        yield from node


def _walk(node: object) -> Iterator[object]:
    stack = [node]
    while stack:
        current = stack.pop()
        yield current
        stack.extend(reversed(list(_children(current))))


def _slice(data: bytes, start: int, end: int) -> str:
    return data[start:end].decode("utf-8", "surrogateescape")


def _squash(text: str) -> str:
    return " ".join(text.split())


def _address(block: Block) -> str:
    return f"{block.labels[0].value}.{block.labels[1].value}"


def _items_by_name(items: Sequence[Attribute | Block], data: bytes) -> dict[str, list[str]]:
    """Top-level argument and nested-block names, each with its whitespace-normalized texts."""
    found: dict[str, list[str]] = {}
    for item in items:
        name = item.name if isinstance(item, Attribute) else item.type
        found.setdefault(name, []).append(
            _squash(_slice(data, item.range.start_byte, item.range.end_byte))
        )
    return {name: sorted(texts) for name, texts in found.items()}


def _secret_attributes(
    items: Sequence[Attribute | Block], data: bytes, prefix: str = ""
) -> dict[str, list[tuple[str, Attribute]]]:
    """Secret-named arguments at any depth, by path (block types and the name)."""
    redactor = Redactor()
    found: dict[str, list[tuple[str, Attribute]]] = {}
    for item in items:
        if isinstance(item, Attribute):
            if redactor.redact({item.name: 1}).redacted:
                text = _squash(_slice(data, item.expr.range.start_byte, item.expr.range.end_byte))
                found.setdefault(prefix + item.name, []).append((text, item))
        else:
            nested = _secret_attributes(item.body.items, data, f"{prefix}{item.type}.")
            for key, values in nested.items():
                found.setdefault(key, []).extend(values)
    return found


# --- the validator ----------------------------------------------------------------------------


class PatchValidator:
    def __init__(
        self,
        *,
        parent_dir: Path,
        trusted: TrustedState,
        scope: AllowedChangeScope,
        work_root: Path,
        variables: Mapping[str, object] | None,
        now: datetime,
    ) -> None:
        if not isinstance(scope, AllowedChangeScope):
            raise ValueError(
                "PatchValidator: scope must be the caller's AllowedChangeScope (C-190)"
            )
        if not isinstance(trusted, TrustedState):
            raise ValueError("PatchValidator: trusted must be a TrustedState")
        self.parent_dir = Path(parent_dir)
        self.trusted = trusted
        self.scope = scope
        self.work_root = Path(work_root)
        self.variables = variables
        self.now = now
        parsed = load_configuration(self.parent_dir)
        if parsed.configuration is None or parsed.status is not ParseStatus.OK:
            raise ValueError(
                f"PatchValidator: the parent directory does not load ({parsed.status})"
            )
        normalized = normalize_directory(self.parent_dir, variables, now=now)
        if normalized.resource_set_hash != trusted.resource_set_hash():
            raise ValueError(
                "PatchValidator: the parent directory is not the trusted state "
                f"{trusted.state_id} (Doc 03 §4.5 step 1)"
            )
        self._parent = parsed.configuration
        self._files = {
            name: (self.parent_dir / name).read_bytes() for name in sorted(self._parent.files)
        }
        self._parent_text = "\n".join(
            data.decode("utf-8", "surrogateescape") for data in self._files.values()
        )

    def check_context(self, context: Any) -> None:
        """The context must be for this parent and this scope (C-190)."""
        if context.parent_state_id != self.trusted.state_id:
            raise ValueError("the context is for another parent state than the validator")
        if tuple(context.allowed_change_scope) != self.scope.resource_addresses:
            raise ValueError("the context does not carry the validator's change scope (C-190)")

    # --- entry point --------------------------------------------------------------------------

    def validate(
        self, response: LLMRepairResponse, *, request_id: str, patch_id: str | None = None
    ) -> ValidationOutcome:
        if response.status is not RepairStatus.PATCH or response.patch is None:
            return ValidationOutcome(
                F.INVALID_OUTPUT, ("only a PATCH response can be validated",), None, (), None
            )
        patch_id = patch_id or new_uuid()
        built: Path | None = None
        operations: tuple[tuple[str, OperationType], ...] = ()
        try:
            text = response.patch
            data = text.encode("utf-8")
            blocks = self._syntax(text)
            self._constructs(blocks, data)
            plan = self._boundaries(blocks, response.changed_addresses)
            operations = tuple((address, op) for address, op, _ in plan)
            self._scope(plan, data)
            self._credentials(blocks, data, text)
            self._ids(blocks)
            built = self._build(plan, data)
            self._references(blocks, built)
            build = self._normalize_and_check(built, response, request_id, patch_id)
        except _Refuse as refuse:
            if built is not None:
                shutil.rmtree(built.parent, ignore_errors=True)
            return ValidationOutcome(refuse.failure, (str(refuse),), None, operations, None)
        return ValidationOutcome(None, (), build, operations, patch_id)

    # --- checks -------------------------------------------------------------------------------

    def _syntax(self, text: str) -> list[Block]:
        try:
            body = parse_file(text, PATCH_FILE)
        except HclLimitError as error:
            raise _Refuse(F.UNSUPPORTED, f"the patch exceeds a parser limit: {error}") from error
        except HclSyntaxError as error:
            raise _Refuse(F.INVALID_OUTPUT, f"the patch is not valid HCL: {error}") from error
        blocks: list[Block] = []
        for item in body.items:
            if isinstance(item, Attribute):
                raise _Refuse(
                    F.POLICY_VIOLATION, f"top-level argument {item.name}: {_FORBIDDEN_TOP}"
                )
            if item.type != "resource":
                raise _Refuse(F.POLICY_VIOLATION, f"top-level {item.type} block: {_FORBIDDEN_TOP}")
            if len(item.labels) != 2:
                raise _Refuse(F.INVALID_OUTPUT, "a resource block needs a type and a name label")
            blocks.append(item)
        return blocks

    def _constructs(self, blocks: Sequence[Block], data: bytes) -> None:
        for block in blocks:
            for node in _walk(block.body):
                if not isinstance(node, Block):
                    continue
                if node.type in ("provisioner", "connection"):
                    raise _Refuse(
                        F.POLICY_VIOLATION, f"{_address(block)}: a {node.type} block is forbidden"
                    )
                if node.type == "dynamic":
                    raise _Refuse(
                        F.UNSUPPORTED, f"{_address(block)}: dynamic blocks are not supported"
                    )
            lifecycles = [
                _squash(_slice(data, i.range.start_byte, i.range.end_byte))
                for i in block.body.items
                if isinstance(i, Block) and i.type == "lifecycle"
            ]
            # compared as in validator 1; since validator 2 (C-221) a block for an address whose
            # parent block has a lifecycle block must also contain it unchanged
            parent = self._parent_lifecycles(_address(block))
            if (lifecycles or parent) and lifecycles != parent:
                raise _Refuse(
                    F.POLICY_VIOLATION,
                    f"{_address(block)}: a lifecycle block is allowed only as the parent's, and a "
                    "MODIFY must keep the parent's lifecycle block",
                )

    def _parent_decl(self, address: str) -> ResourceDecl | None:
        kind, _, name = address.partition(".")
        return self._parent.resources.get((kind, name))

    def _parent_lifecycles(self, address: str) -> list[str]:
        decl = self._parent_decl(address)
        if decl is None or decl.file.endswith(".json"):
            return []
        data = self._files[decl.file]
        return [_squash(_slice(data, b.range.start_byte, b.range.end_byte)) for b in decl.lifecycle]

    def _boundaries(
        self, blocks: Sequence[Block], changed: Sequence[str]
    ) -> list[tuple[str, OperationType, Block | None]]:
        by_address: dict[str, Block] = {}
        for block in blocks:
            address = _address(block)
            if address in by_address:
                raise _Refuse(F.INVALID_OUTPUT, f"two blocks for {address}")
            if address not in changed:
                raise _Refuse(F.INVALID_OUTPUT, f"a block for {address}, which is not listed")
            by_address[address] = block
        plan: list[tuple[str, OperationType, Block | None]] = []
        for address in changed:
            found = by_address.get(address)
            exists = self._parent_decl(address) is not None
            if found is not None:
                plan.append((address, OP.MODIFY if exists else OP.CREATE, found))
            elif exists:
                plan.append((address, OP.DELETE, None))
            else:
                raise _Refuse(
                    F.INVALID_OUTPUT, f"{address} is listed without a block and the parent has none"
                )
        return plan

    def _scope(self, plan: Sequence[tuple[str, OperationType, Block | None]], data: bytes) -> None:
        for address, operation, block in plan:
            kind = address.partition(".")[0]
            if kind not in SUPPORTED_TYPES:
                raise _Refuse(F.UNSUPPORTED, f"{address}: {kind} is outside the supported model")
            if kind not in self.scope.resource_types:
                raise _Refuse(F.POLICY_VIOLATION, f"{address}: {kind} is outside the scope's types")
            if operation is not OP.CREATE and address not in self.scope.resource_addresses:
                raise _Refuse(
                    F.POLICY_VIOLATION,
                    f"{address}: {operation.value} of an address outside the scope",
                )
            decl = self._parent_decl(address)
            if decl is not None and decl.file.endswith(".json") and operation is not OP.CREATE:
                raise _Refuse(F.UNSUPPORTED, f"{address} is defined in a JSON file ({decl.file})")
            if self.scope.attributes and operation is OP.MODIFY and block is not None:
                assert decl is not None
                parent = _items_by_name(decl.block.body.items, self._files[decl.file])
                patch = _items_by_name(block.body.items, data)
                changed = sorted(
                    n for n in set(parent) | set(patch) if parent.get(n) != patch.get(n)
                )
                outside = [n for n in changed if n not in self.scope.attributes]
                if outside:
                    raise _Refuse(
                        F.POLICY_VIOLATION,
                        f"{address}: changes {outside}, outside the scope's attributes",
                    )

    def _credentials(self, blocks: Sequence[Block], data: bytes, text: str) -> None:
        if _ACCESS_KEY.search(text) or _PRIVATE_KEY.search(text):
            raise _Refuse(
                F.POLICY_VIOLATION, "the patch holds an access key or a private key (§14)"
            )
        for block in blocks:
            address = _address(block)
            decl = self._parent_decl(address)
            parent = (
                {}
                if decl is None or decl.file.endswith(".json")
                else _secret_attributes(decl.block.body.items, self._files[decl.file])
            )
            for path, values in _secret_attributes(block.body.items, data).items():
                allowed = {t for t, _ in parent.get(path, [])}
                for value, item in values:
                    is_var = isinstance(item.expr, ScopeTraversal) and item.expr.root == "var"
                    if not is_var and value not in allowed:
                        raise _Refuse(
                            F.POLICY_VIOLATION,
                            f"{address}.{path}: a credential may only keep the parent's value or "
                            "come from a variable (§14)",
                        )

    def _ids(self, blocks: Sequence[Block]) -> None:
        for block in blocks:
            for node in _walk(block.body):
                if isinstance(node, Literal) and node.kind is LiteralKind.STRING:
                    value = str(node.value)
                elif isinstance(node, TemplateLiteral):
                    value = node.text
                else:
                    continue
                invented = [m for m in _AWS_ID.findall(value) if m not in self._parent_text]
                if value.startswith("arn:aws:") and value not in self._parent_text:
                    invented.append(value)
                if invented:
                    raise _Refuse(
                        F.POLICY_VIOLATION,
                        f"{_address(block)}: provider or runtime ids not in the parent: {invented}",
                    )

    def _build(self, plan: Sequence[tuple[str, OperationType, Block | None]], data: bytes) -> Path:
        self.work_root.mkdir(parents=True, exist_ok=True)
        holder = Path(tempfile.mkdtemp(prefix="dail-llm-candidate-", dir=self.work_root))
        target = holder / "candidate"
        shutil.copytree(self.parent_dir, target, symlinks=False)
        edits: dict[str, list[tuple[int, int, bytes]]] = {}
        created: list[bytes] = []
        for address, operation, block in plan:
            replacement = (
                b"" if block is None else data[block.range.start_byte : block.range.end_byte]
            )
            if operation is OP.CREATE:
                created.append(replacement)
                continue
            decl = self._parent_decl(address)
            assert decl is not None
            edits.setdefault(decl.file, []).append(
                (decl.block.range.start_byte, decl.block.range.end_byte, replacement)
            )
        for name, changes in edits.items():
            content = self._files[name]
            for start, end, replacement in sorted(changes, reverse=True):
                content = content[:start] + replacement + content[end:]
            (target / name).write_bytes(content)
        if created:
            path = target / PATCH_FILE
            if path.exists():
                shutil.rmtree(holder, ignore_errors=True)
                raise _Refuse(F.UNSUPPORTED, f"the parent already has a file named {PATCH_FILE}")
            path.write_bytes(b"\n\n".join(created) + b"\n")
        return target

    def _references(self, blocks: Sequence[Block], built: Path) -> None:
        parsed = load_configuration(built)
        configuration = parsed.configuration
        if configuration is None or parsed.status is ParseStatus.INVALID:
            raise _Refuse(
                F.INVALID_OUTPUT, "the built candidate does not load (construction failure)"
            )
        for block in blocks:
            nodes = list(_walk(block.body))
            iterators = {
                name
                for node in nodes
                if isinstance(node, ForExpr)
                for name in (node.key_var, node.value_var)
                if name
            }
            for node in nodes:
                if not isinstance(node, ScopeTraversal):
                    continue
                if not self._declared(node, configuration, iterators):
                    raise _Refuse(
                        F.INVALID_OUTPUT,
                        f"{_address(block)}: {node.root} reference is not declared in the "
                        "candidate",
                    )

    @staticmethod
    def _declared(node: ScopeTraversal, configuration: Any, iterators: set[str]) -> bool:
        root = node.root
        names = [getattr(step, "name", None) for step in node.steps]
        if root in _BUILTIN_ROOTS or root in iterators:
            return True
        if root == "var":
            return bool(names) and names[0] in configuration.variables
        if root == "local":
            return bool(names) and names[0] in configuration.locals
        if root == "data":
            return len(names) >= 2 and (names[0], names[1]) in configuration.data_sources
        return bool(names) and (root, names[0]) in configuration.resources

    def _normalize_and_check(
        self, built: Path, response: LLMRepairResponse, request_id: str, patch_id: str
    ) -> CandidateBuild:
        outcome = normalize_directory(built, self.variables, now=self.now)
        if outcome.status is ParseStatus.INVALID or outcome.resource_set_hash is None:
            raise _Refuse(F.INVALID_OUTPUT, "the built candidate does not normalize (P3)")
        if outcome.status is ParseStatus.UNSUPPORTED:
            raise _Refuse(F.UNSUPPORTED, "the built candidate uses an unsupported construct (P3)")
        identity = compare(
            self.trusted.resources,
            outcome.resources,
            list(outcome.moves),
            parent_state_id=self.trusted.state_id,
            candidate_id=new_uuid(),
            now=self.now,
        )
        breaches = operation_breaches(identity, self.scope)
        if breaches:
            raise _Refuse(F.POLICY_VIOLATION, "; ".join(breaches))
        digest = tree_hash(built)
        patch = Patch.create(
            source=CandidateSource.LLM,
            content=response.patch or "",
            parent_state_id=self.trusted.state_id,
            now=self.now,
            llm_request_id=request_id,
            patch_id=patch_id,
            metadata={
                "changed_addresses": list(response.changed_addresses),
                "tree_hash": digest,
                "validator_version": VALIDATOR_VERSION,
            },
        )
        return CandidateBuild(built, digest, outcome.resource_set_hash, patch)
