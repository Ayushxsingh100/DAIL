"""Configuration loader and structural validation (Doc 04 §4, §17, §18; C-91 to C-94).

Pipeline stages implemented here: "HCL / Terraform parsing" and "Structural validation"
(Doc 04 §4). ``load_configuration`` reads the root-module directory, parses each ``*.tf`` file with
``core.terraform_model.hcl`` and checks the Terraform structural rules of C-94. It does not
evaluate anything: no variables, locals, functions, ``count``/``for_each``/``dynamic`` expansion,
module expansion, supported-type filtering, references or normalization (P3a-2).

The outcome is three-way (C-92) and fails closed:

- ``OK``: valid HCL, valid Terraform structure, inside the input subset and limits;
- ``INVALID``: not valid HCL, or a Terraform structural rule is broken;
- ``UNSUPPORTED``: valid so far, but outside DAIL's input subset or limits (C-93).

``INVALID`` takes precedence over ``UNSUPPORTED`` when both occur. ``configuration`` is present
only for ``OK``; there is never a partial configuration. ``OK`` is a trust claim, so
``ParseOutcome`` and ``ParsedConfiguration`` can be built only by this module (construction
guard, as in ``core.domain``).

Terraform documentation cited below is the 1.15.x language documentation,
``hashicorp/web-unified-docs`` commit ``fefc7502dba86c70716f0109c324c85829229b2f``, directory
``content/terraform/v1.15.x/docs/language/`` (pinned in ADR-003).
"""

from __future__ import annotations

import enum
import os
from collections.abc import Mapping
from dataclasses import InitVar, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Final, TypeVar

from core.domain.errors import DomainValidationError, UnauthorizedConstructionError
from core.domain.hashing import content_hash, sha256_bytes
from core.terraform_model.hcl.ast import (
    Attribute,
    Block,
    Body,
    Expression,
    Label,
    SourceRange,
)
from core.terraform_model.hcl.errors import HclLimitError, HclSyntaxError
from core.terraform_model.hcl.parser import parse_file

# Doc 04 §22 (versioning) and Doc 05 §6 (Provenance.parser_version).
PARSER_VERSION: Final = "dail-hcl-parser-1"

# C-93 limits. Exceeding one is UNSUPPORTED, never a crash or a partial result.
MAX_FILE_BYTES: Final = 2 * 1024 * 1024
MAX_BLOCKS: Final = 10_000
# The third C-93 limit, the nesting depth of 64, is enforced by the parser (MAX_NESTING_DEPTH).

_LOADER_TOKEN: Final = object()


class ParseStatus(enum.StrEnum):
    OK = "OK"
    INVALID = "INVALID"
    UNSUPPORTED = "UNSUPPORTED"


class DiagnosticSeverity(enum.StrEnum):
    """INVALID and UNSUPPORTED decide the outcome. UNSUPPORTED_CONSTRUCT marks a construct of
    Doc 04 §3.2 that stays visible in the tree; it does not change the outcome in P3a-1."""

    INVALID = "INVALID"
    UNSUPPORTED = "UNSUPPORTED"
    UNSUPPORTED_CONSTRUCT = "UNSUPPORTED_CONSTRUCT"


@dataclass(frozen=True, slots=True)
class Diagnostic:
    """One finding. ``file`` is empty and ``line``/``column`` are 0 for a finding about the
    directory as a whole."""

    severity: DiagnosticSeverity
    code: str
    message: str
    file: str = ""
    line: int = 0
    column: int = 0

    @property
    def sort_key(self) -> tuple[str, int, int, str]:
        return (self.file, self.line, self.column, self.code)


# --- Declarations -------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Declaration:
    """A top-level block kept whole: variable, output, module, provider, terraform and the
    other block types (check, import, removed, ephemeral, action)."""

    kind: str
    labels: tuple[Label, ...]
    file: str
    block: Block

    @property
    def name(self) -> str:
        return self.labels[0].value if self.labels else ""


@dataclass(frozen=True, slots=True)
class ResourceDecl:
    """A ``resource`` or ``data`` block with its meta-arguments split out (Terraform: ``count``,
    ``for_each``, ``provider``, ``depends_on``, ``lifecycle``, ``provisioner``, ``connection``).

    Nothing is dropped: ``block`` is the whole block, and ``body`` holds every item that is not a
    meta-argument, including nested ``dynamic`` blocks.
    """

    kind: str  # "resource" or "data"
    type: str
    name: str
    labels: tuple[Label, ...]
    file: str
    block: Block
    count: Attribute | None
    for_each: Attribute | None
    provider: Attribute | None
    depends_on: Attribute | None
    lifecycle: tuple[Block, ...]
    provisioners: tuple[Block, ...]
    connections: tuple[Block, ...]
    body: Body

    @property
    def dynamic_blocks(self) -> tuple[Block, ...]:
        return tuple(
            item for item in self.body.items if isinstance(item, Block) and item.type == "dynamic"
        )


@dataclass(frozen=True, slots=True)
class LocalDecl:
    """One named value of a ``locals`` block."""

    name: str
    attribute: Attribute
    file: str


@dataclass(frozen=True, slots=True)
class MovedDecl:
    """A ``moved`` block: ``from`` and ``to`` as syntax trees (not evaluated)."""

    from_expr: Expression
    to_expr: Expression
    file: str
    block: Block


# --- Outcome ------------------------------------------------------------------------------------


def _frozen(mapping: Mapping[object, object]) -> Mapping[object, object]:
    return MappingProxyType(dict(mapping))


@dataclass(frozen=True)
class ParsedConfiguration:
    """The parsed root module. Immutable; built only by ``load_configuration``."""

    files: Mapping[str, str]  # file name -> SHA-256 of its raw bytes
    configuration_hash: str
    bodies: Mapping[str, Body]  # file name -> syntax tree
    resources: Mapping[tuple[str, str], ResourceDecl]
    data_sources: Mapping[tuple[str, str], ResourceDecl]
    variables: Mapping[str, Declaration]
    locals: Mapping[str, LocalDecl]
    outputs: Mapping[str, Declaration]
    modules: Mapping[str, Declaration]
    moved: tuple[MovedDecl, ...]
    providers: tuple[Declaration, ...]
    terraform_blocks: tuple[Declaration, ...]
    other_blocks: tuple[Declaration, ...]
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _LOADER_TOKEN:
            raise UnauthorizedConstructionError(
                "ParsedConfiguration can be created only by load_configuration (C-92)"
            )
        for name in (
            "files",
            "bodies",
            "resources",
            "data_sources",
            "variables",
            "locals",
            "outputs",
            "modules",
        ):
            object.__setattr__(self, name, _frozen(getattr(self, name)))


def _status_of(diagnostics: tuple[Diagnostic, ...]) -> ParseStatus:
    severities = {d.severity for d in diagnostics}
    if DiagnosticSeverity.INVALID in severities:
        return ParseStatus.INVALID
    if DiagnosticSeverity.UNSUPPORTED in severities:
        return ParseStatus.UNSUPPORTED
    return ParseStatus.OK


@dataclass(frozen=True)
class ParseOutcome:
    """The result of loading a directory (C-92). Built only by ``load_configuration``.

    ``configuration`` is present if and only if ``status`` is OK, and ``status`` is the one the
    diagnostics imply (INVALID, else UNSUPPORTED, else OK).
    """

    status: ParseStatus
    diagnostics: tuple[Diagnostic, ...]
    configuration: ParsedConfiguration | None
    parser_version: str
    _token: InitVar[object | None] = None

    def __post_init__(self, _token: object | None) -> None:
        if _token is not _LOADER_TOKEN:
            raise UnauthorizedConstructionError(
                "ParseOutcome can be created only by load_configuration (C-92)"
            )
        if not isinstance(self.status, ParseStatus):
            raise DomainValidationError("ParseOutcome.status must be a ParseStatus")
        if self.status is not _status_of(self.diagnostics):
            raise DomainValidationError("ParseOutcome.status does not follow from its diagnostics")
        if (self.status is ParseStatus.OK) != (self.configuration is not None):
            raise DomainValidationError(
                "a configuration is present if and only if the status is OK (no partial result)"
            )
        keys = [d.sort_key for d in self.diagnostics]
        if keys != sorted(keys):
            raise DomainValidationError("ParseOutcome.diagnostics must be sorted")


def _make_outcome(
    diagnostics: list[Diagnostic], configuration: ParsedConfiguration | None
) -> ParseOutcome:
    ordered = tuple(sorted(set(diagnostics), key=lambda d: d.sort_key + (d.message,)))
    status = _status_of(ordered)
    return ParseOutcome(
        status,
        ordered,
        configuration if status is ParseStatus.OK else None,
        PARSER_VERSION,
        _LOADER_TOKEN,
    )


# --- Terraform structural rules (C-94, C-96) ----------------------------------------------------
#
# Top-level block types of Terraform 1.15.x and their number of labels. Sources, each a page under
# content/terraform/v1.15.x/docs/language/ (see the module docstring):
#   syntax/configuration.mdx  "Each block type defines how many labels must follow the type
#                              keyword" and "limited number of top-level block types"
#   block/resource.mdx        resource "<TYPE>" "<LABEL>"        -> 2 labels  (C-94)
#   block/data.mdx            data "<TYPE>" "<LABEL>"            -> 2 labels  (C-94)
#   block/variable.mdx        variable "<LABEL>"                 -> 1 label   (C-94)
#   block/output.mdx          output "<LABEL>"                   -> 1 label   (C-94)
#   block/module.mdx          module "<LABEL>"                   -> 1 label   (C-94)
#   block/provider.mdx        provider "<PROVIDER_NAME>"         -> 1 label   (C-94)
#   block/locals.mdx          locals { ... }                     -> 0 labels  (C-94)
#   block/terraform.mdx       terraform { ... }                  -> 0 labels  (C-94)
#   block/moved.mdx           moved { ... }                      -> 0 labels  (C-94)
#   block/ephemeral.mdx       ephemeral "<TYPE>" "<LABEL>"       -> 2 labels  (C-96)
#   block/action.mdx          action "<TYPE>" "<LABEL>"          -> 2 labels  (C-96)
#   block/check.mdx           check "<LABEL>"                    -> 1 label   (C-96)
#   block/import.mdx          import { ... }                     -> 0 labels  (C-96)
#   block/removed.mdx         removed { ... }                    -> 0 labels  (C-96)
# Terraform 1.15.8 reports the same counts ("All resource blocks must have 2 labels (type, name)").
_LABEL_COUNTS: Final[Mapping[str, int]] = MappingProxyType(
    {
        "resource": 2,
        "data": 2,
        "variable": 1,
        "output": 1,
        "module": 1,
        "provider": 1,
        "locals": 0,
        "terraform": 0,
        "moved": 0,
        "ephemeral": 2,
        "action": 2,
        "check": 1,
        "import": 0,
        "removed": 0,
    }
)
_OTHER_BLOCK_TYPES: Final = frozenset({"check", "import", "removed", "ephemeral", "action"})
_META_ATTRIBUTES: Final = ("count", "for_each", "provider", "depends_on")
_K = TypeVar("_K", str, tuple[str, str])
_D = TypeVar("_D", ResourceDecl, Declaration)


# The directory loader of Terraform v1.15.8 (C-98). Sources, at tag v1.15.8 (commit
# b9e178decf87d274d25ed36bc5a4dbc857e00420), repository hashicorp/terraform:
#   internal/configs/parser_file_matcher.go
#     lines 103-105  `if info.IsDir() || IsIgnoredFile(info.Name()) { continue }`: directories and
#                    ignored files are skipped before any extension is looked at;
#     line 63        the default matcher is `moduleFiles` only (test and query files need options);
#     lines 152-159  `moduleFiles.Matches`: the extension is `.tf` or `.tf.json`;
#     lines 161-170  `isOverride`: the name without its extension is `override` or ends in
#                    `_override`.
#   internal/configs/parser_config_dir.go
#     lines 245-249  `IsIgnoredFile`: the name starts with ".", or ends with "~", or starts and
#                    ends with "#";
#     lines 225-241  `fileExt`: `.tf` and `.tf.json` are recognised by suffix.
# `p.fs.ReadDir` lists entries with lstat, so a symbolic link to a directory is not a directory
# there (it counts as a file and fails when read), and DAIL's `is_dir(follow_symlinks=False)`
# does the same.


def is_ignored_file(name: str) -> bool:
    """Terraform's `IsIgnoredFile` (parser_config_dir.go lines 245-249): hidden files, vim
    backups and emacs auto-save files."""
    return (
        name.startswith(".") or name.endswith("~") or (name.startswith("#") and name.endswith("#"))
    )


def _config_extension(name: str) -> str:
    """Terraform's `fileExt` for the extensions that the module loader matches."""
    if name.endswith(".tf"):
        return ".tf"
    if name.endswith(".tf.json"):
        return ".tf.json"
    return ""


def _is_override_file(name: str) -> bool:
    """Terraform's `isOverride` (parser_file_matcher.go lines 161-170; files/override.mdx)."""
    extension = _config_extension(name)
    if not extension:
        return False
    base = name[: -len(extension)]
    return base == "override" or base.endswith("_override")


class _Loader:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.diagnostics: list[Diagnostic] = []
        self.bodies: dict[str, Body] = {}
        self.hashes: dict[str, str] = {}

    def add(
        self,
        severity: DiagnosticSeverity,
        code: str,
        message: str,
        file: str = "",
        rng: SourceRange | None = None,
    ) -> None:
        line = rng.start_line if rng is not None else 0
        column = rng.start_column if rng is not None else 0
        self.diagnostics.append(Diagnostic(severity, code, message, file, line, column))

    def invalid(
        self, code: str, message: str, file: str = "", rng: SourceRange | None = None
    ) -> None:
        self.add(DiagnosticSeverity.INVALID, code, message, file, rng)

    def unsupported(
        self, code: str, message: str, file: str = "", rng: SourceRange | None = None
    ) -> None:
        self.add(DiagnosticSeverity.UNSUPPORTED, code, message, file, rng)

    # -- reading -----------------------------------------------------------------------------

    def _failed(self) -> bool:
        return any(
            d.severity is not DiagnosticSeverity.UNSUPPORTED_CONSTRUCT for d in self.diagnostics
        )

    def run(self) -> ParseOutcome:
        names = self._list_names()
        if names is None:
            return _make_outcome(self.diagnostics, None)
        for name in names:
            self._load_file(name)
        # Every check runs over the files that parsed, so that INVALID findings are never hidden
        # behind an UNSUPPORTED one (C-92: INVALID takes precedence).
        self._count_blocks()
        configuration = self._validate()
        return _make_outcome(self.diagnostics, None if self._failed() else configuration)

    @staticmethod
    def _is_directory(entry: os.DirEntry[str]) -> bool:
        try:
            return entry.is_dir(follow_symlinks=False)
        except OSError:
            return False

    def _list_names(self) -> list[str] | None:
        try:
            with os.scandir(self.directory) as scan:
                entries = [(entry.name, self._is_directory(entry)) for entry in scan]
        except OSError as exc:
            self.invalid("input.directory_unreadable", f"cannot list the directory: {exc.strerror}")
            return None
        # Byte-wise sorted names (C-93), the files that Terraform's loader reads (C-98).
        entries.sort(key=lambda entry: os.fsencode(entry[0]))
        names: list[str] = []
        for name, is_directory in entries:
            if is_directory or is_ignored_file(name):
                continue  # parser_file_matcher.go lines 103-105
            extension = _config_extension(name)
            if extension == ".tf.json":
                code = "input.override_file" if _is_override_file(name) else "input.tf_json"
                self.unsupported(
                    code, f"{name}: JSON configuration files are not supported (C-93)", name
                )
            elif extension == ".tf":
                if _is_override_file(name):
                    self.unsupported(
                        "input.override_file",
                        f"{name}: override files are not supported (C-93; files/override.mdx)",
                        name,
                    )
                    continue
                names.append(name)
        if not names and not self.diagnostics:
            # Terraform 1.15.8 accepts a directory without configuration files: `terraform
            # validate` succeeds with no diagnostics, and internal/configs/parser_config_dir.go
            # (tag v1.15.8, lines 41-42) says "This file does not consider a directory with no
            # files to be an error, and will simply return an empty module in that case". By the
            # C-92 rule it is valid Terraform that DAIL does not accept: UNSUPPORTED (C-96). It
            # stays fail-closed, because a wrong path must not look like an empty candidate.
            self.unsupported(
                "input.no_configuration_files",
                "the directory has no configuration files (valid Terraform, not accepted by DAIL)",
            )
        return names

    def _load_file(self, name: str) -> None:
        path = self.directory / name
        try:
            with path.open("rb") as handle:
                data = handle.read(MAX_FILE_BYTES + 1)
        except OSError as exc:
            self.invalid("input.file_unreadable", f"cannot read {name}: {exc.strerror}", name)
            return
        if len(data) > MAX_FILE_BYTES:
            self.unsupported(
                "limit.file_size",
                f"{name} is larger than {MAX_FILE_BYTES} bytes (C-93)",
                name,
            )
            return
        # Undecodable bytes (C-92, C-95): Terraform 1.15.8 rejects them outside comments (the lexer
        # then reports INVALID) but accepts them in comments and in some well-formed-looking
        # sequences, so a file that parses and still holds such bytes is valid Terraform that
        # DAIL does not support: UNSUPPORTED. A byte order mark is handled by the lexer the same
        # way (limit.byte_order_mark): Terraform accepts it, the HCL specification forbids it.
        undecodable: UnicodeDecodeError | None = None
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            undecodable = exc
            text = data.decode("utf-8", "surrogateescape")
        try:
            body = parse_file(text, name)
        except HclSyntaxError as exc:
            self.invalid(exc.code, exc.message, name, exc.range)
            return
        except HclLimitError as exc:
            self.unsupported(exc.code, exc.message, name, exc.range)
            return
        except RecursionError:
            self.unsupported("limit.nesting_depth", f"{name}: the parser ran out of stack", name)
            return
        except MemoryError:
            self.unsupported("limit.memory", f"{name}: the parser ran out of memory", name)
            return
        self.bodies[name] = body
        self.hashes[name] = sha256_bytes(data)
        if undecodable is not None:
            start = undecodable.start
            line = data.count(b"\n", 0, start) + 1
            column = start - (data.rfind(b"\n", 0, start) + 1) + 1
            self.unsupported(
                "input.invalid_utf8",
                f"{name} holds bytes that are not valid UTF-8 (first at byte {start}) where "
                "Terraform still accepts them (a comment or a well-formed-looking sequence); "
                "DAIL does not support them (C-92, C-95)",
                name,
                SourceRange(name, line, column, line, column, start, start),
            )

    # -- limits and structure ----------------------------------------------------------------

    def _count_blocks(self) -> None:
        """C-93: more than MAX_BLOCKS blocks (at any depth) in the configuration."""
        total = 0
        for name, body in self.bodies.items():
            stack = [body]
            while stack:
                for item in stack.pop().items:
                    if isinstance(item, Block):
                        total += 1
                        if total > MAX_BLOCKS:
                            self.unsupported(
                                "limit.block_count",
                                f"more than {MAX_BLOCKS} blocks in the configuration (C-93)",
                                name,
                                item.range,
                            )
                            return
                        stack.append(item.body)

    def _validate(self) -> ParsedConfiguration | None:
        """Structural validation (C-94, C-96). Collects every finding, then builds the result."""
        resources: dict[tuple[str, str], ResourceDecl] = {}
        data_sources: dict[tuple[str, str], ResourceDecl] = {}
        variables: dict[str, Declaration] = {}
        outputs: dict[str, Declaration] = {}
        modules: dict[str, Declaration] = {}
        local_values: dict[str, tuple[LocalDecl, Body]] = {}
        moved: list[MovedDecl] = []
        providers: list[Declaration] = []
        terraform_blocks: list[Declaration] = []
        other_blocks: list[Declaration] = []

        for name, body in self.bodies.items():
            self._check_duplicate_attributes(name, body)
            for item in body.items:
                if isinstance(item, Attribute):
                    # syntax/configuration.mdx: top-level block types are "blocks that can appear
                    # outside of any other block"; an argument cannot appear at the top level.
                    self.invalid(
                        "struct.top_level_attribute",
                        f"{item.name} = ... is not allowed outside a block",
                        name,
                        item.range,
                    )
                    continue
                expected = _LABEL_COUNTS.get(item.type)
                if expected is None:
                    self.invalid(
                        "struct.unknown_block_type",
                        f"blocks of type {item.type!r} are not expected at the top level",
                        name,
                        item.type_range,
                    )
                    continue
                if len(item.labels) != expected:
                    self.invalid(
                        "struct.label_count",
                        f"a {item.type} block takes {expected} label(s), found {len(item.labels)}",
                        name,
                        item.type_range,
                    )
                    continue
                kind = item.type
                if kind == "resource" or kind == "data":
                    declaration = self._resource(kind, name, item)
                    target = resources if kind == "resource" else data_sources
                    key = (declaration.type, declaration.name)
                    self._unique(target, key, declaration, f"{kind} {key[0]}.{key[1]}", name, item)
                elif kind == "variable":
                    self._unique(
                        variables,
                        item.labels[0].value,
                        Declaration(kind, item.labels, name, item),
                        f"variable {item.labels[0].value}",
                        name,
                        item,
                    )
                elif kind == "output":
                    self._unique(
                        outputs,
                        item.labels[0].value,
                        Declaration(kind, item.labels, name, item),
                        f"output {item.labels[0].value}",
                        name,
                        item,
                    )
                elif kind == "module":
                    self._unique(
                        modules,
                        item.labels[0].value,
                        Declaration(kind, item.labels, name, item),
                        f"module {item.labels[0].value}",
                        name,
                        item,
                    )
                elif kind == "provider":
                    providers.append(Declaration(kind, item.labels, name, item))
                elif kind == "terraform":
                    terraform_blocks.append(Declaration(kind, item.labels, name, item))
                elif kind == "locals":
                    self._locals(name, item, local_values)
                elif kind == "moved":
                    declaration_moved = self._moved(name, item)
                    if declaration_moved is not None:
                        moved.append(declaration_moved)
                else:
                    other_blocks.append(Declaration(kind, item.labels, name, item))

        if self._failed():
            return None
        return ParsedConfiguration(
            files=self.hashes,
            configuration_hash=content_hash([[n, h] for n, h in sorted(self.hashes.items())]),
            bodies=self.bodies,
            resources=resources,
            data_sources=data_sources,
            variables=variables,
            locals={n: decl for n, (decl, _) in local_values.items()},
            outputs=outputs,
            modules=modules,
            moved=tuple(moved),
            providers=tuple(providers),
            terraform_blocks=tuple(terraform_blocks),
            other_blocks=tuple(other_blocks),
            _token=_LOADER_TOKEN,
        )

    def _unique(
        self,
        target: dict[_K, _D],
        key: _K,
        declaration: _D,
        description: str,
        file: str,
        block: Block,
    ) -> None:
        # Duplicate addresses are INVALID (C-94). Sources: block/variable.mdx "a name for the
        # variable, which must be unique among all variables in the same module"; block/module.mdx
        # "you must use unique labels for each block"; syntax/configuration.mdx "differentiate
        # them by giving each instance a unique name" (resource and data labels); Terraform
        # 1.15.8 reports "Duplicate output definition ... Output names must be unique".
        previous = target.get(key)
        if previous is None:
            target[key] = declaration
            return
        self.invalid(
            "struct.duplicate_address",
            f"{description} is already defined at {previous.file}:"
            f"{previous.block.type_range.start_line}",
            file,
            block.type_range,
        )

    def _check_duplicate_attributes(self, file: str, body: Body) -> None:
        """Each attribute name may appear once per body, at every depth (spec, "Attribute
        Definitions": "Each distinct attribute name may be defined no more than once within a
        single body"; Terraform: "Each argument may be set only once")."""
        stack = [body]
        while stack:
            current = stack.pop()
            seen: dict[str, Attribute] = {}
            for item in current.items:
                if isinstance(item, Attribute):
                    first = seen.get(item.name)
                    if first is None:
                        seen[item.name] = item
                    else:
                        self.invalid(
                            "struct.duplicate_attribute",
                            f"the argument {item.name!r} was already set at line "
                            f"{first.name_range.start_line}",
                            file,
                            item.name_range,
                        )
                else:
                    stack.append(item.body)

    def _resource(self, kind: str, file: str, block: Block) -> ResourceDecl:
        meta: dict[str, Attribute] = {}
        lifecycle: list[Block] = []
        provisioners: list[Block] = []
        connections: list[Block] = []
        rest: list[Attribute | Block] = []
        for item in block.body.items:
            if isinstance(item, Attribute) and item.name in _META_ATTRIBUTES:
                meta[item.name] = item
            elif isinstance(item, Block) and item.type == "lifecycle":
                lifecycle.append(item)
            elif isinstance(item, Block) and item.type == "provisioner":
                provisioners.append(item)
                if kind == "resource":
                    # Doc 04 §3.2: "arbitrary provisioners and external side effects" are
                    # restricted or unsupported. Kept in the tree; P3a-2 decides the semantics.
                    self.add(
                        DiagnosticSeverity.UNSUPPORTED_CONSTRUCT,
                        "construct.provisioner",
                        "provisioner block (Doc 04 §3.2: arbitrary provisioners and external "
                        "side effects are restricted or unsupported)",
                        file,
                        item.type_range,
                    )
            elif isinstance(item, Block) and item.type == "connection":
                connections.append(item)
            else:
                rest.append(item)
        return ResourceDecl(
            kind=kind,
            type=block.labels[0].value,
            name=block.labels[1].value,
            labels=block.labels,
            file=file,
            block=block,
            count=meta.get("count"),
            for_each=meta.get("for_each"),
            provider=meta.get("provider"),
            depends_on=meta.get("depends_on"),
            lifecycle=tuple(lifecycle),
            provisioners=tuple(provisioners),
            connections=tuple(connections),
            body=Body(tuple(rest), block.body.range),
        )

    def _locals(self, file: str, block: Block, values: dict[str, tuple[LocalDecl, Body]]) -> None:
        # block/locals.mdx: a locals block holds named values; "Terraform treats them as if they
        # were all defined in a single block", so a name defined twice is a duplicate (C-94).
        # Terraform 1.15.8: "Unexpected 'x' block: Blocks are not allowed here" (C-96).
        for item in block.body.items:
            if isinstance(item, Block):
                self.invalid(
                    "struct.unexpected_block",
                    f"a locals block holds arguments only; found a {item.type!r} block",
                    file,
                    item.type_range,
                )
                continue
            previous = values.get(item.name)
            if previous is None:
                values[item.name] = (LocalDecl(item.name, item, file), block.body)
            elif previous[1] is not block.body:
                # Duplicates inside one block are reported by the duplicate-attribute check.
                self.invalid(
                    "struct.duplicate_address",
                    f"local value {item.name} is already defined at "
                    f"{previous[0].file}:{previous[0].attribute.name_range.start_line}",
                    file,
                    item.name_range,
                )

    def _moved(self, file: str, block: Block) -> MovedDecl | None:
        # block/moved.mdx: the moved block takes the required arguments ``from`` and ``to``.
        # Terraform 1.15.8: 'Missing required argument: The argument "from" is required' (C-96).
        arguments: dict[str, Attribute] = {}
        for item in block.body.items:
            if isinstance(item, Block):
                self.invalid(
                    "struct.unexpected_block",
                    f"a moved block holds arguments only; found a {item.type!r} block",
                    file,
                    item.type_range,
                )
            else:
                arguments[item.name] = item
        missing = [name for name in ("from", "to") if name not in arguments]
        for name in missing:
            self.invalid(
                "struct.moved_missing_argument",
                f"a moved block requires the argument {name!r}",
                file,
                block.type_range,
            )
        if missing or any(isinstance(i, Block) for i in block.body.items):
            return None
        return MovedDecl(arguments["from"].expr, arguments["to"].expr, file, block)


def load_configuration(directory: Path) -> ParseOutcome:
    """Load one root-module directory (C-92, C-93, C-94).

    Reads only ``*.tf`` files directly in ``directory``, in byte-wise sorted name order. Never
    raises: a failure of any kind is a non-OK outcome whose diagnostics say why. Pure apart from
    reading the files.
    """
    loader = _Loader(Path(directory))
    try:
        return loader.run()
    except Exception as exc:  # fail closed: an unexpected error is never OK
        return _make_outcome(
            [
                Diagnostic(
                    DiagnosticSeverity.UNSUPPORTED,
                    "internal.loader_error",
                    f"unexpected {type(exc).__name__} while loading the configuration",
                )
            ],
            None,
        )
