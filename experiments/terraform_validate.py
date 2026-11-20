"""The pinned ``terraform validate`` runner for LLM candidates (C-99, C-100, C-227).

C-99: "Every candidate (fixed patch, LLM or generated) must pass the pinned ``terraform validate``
(1.15.8, provider 6.53.0) before it enters DAIL ... This is enforced outside the core." C-100 names
the setting it was checked in: "filesystem mirror, ``init -backend=false`` and ``validate`` in a
scratch directory outside the repository, no credentials".

``TerraformValidateRunner(terraform=..., mirror=..., work_root=...)`` is a
``llm.validation.patch.TerraformValidate``. At construction it checks the setting once and refuses
to start otherwise: ``terraform version -json`` must report 1.15.8, and ``init -backend=false`` of a
seed configuration that requires ``hashicorp/aws`` must select 6.53.0 from the mirror (the selected
versions are kept in ``versions`` and returned with every check). Each call copies the candidate's
configuration files (``*.tf`` and ``*.tf.json`` at the top level, ``copy_configuration``) into a new
scratch directory under ``work_root/scratch``, writes the seed's lock file, runs ``init
-backend=false`` and ``validate -json``, and removes the scratch directory. A failed ``init`` or an
invalid configuration is a failed check with Terraform's error text; a runner that cannot run at all
raises.

Terraform runs with a CLI configuration that installs providers only from the mirror
(``cli_configuration``), no AWS environment variables, empty AWS credential and config files, the
instance metadata service disabled and HTTP(S) proxies pointing at a closed local port, so nothing
reaches a network. ``plan``, ``apply`` and ``destroy`` are never run. Standard library only.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Final

from llm.validation.patch import TerraformCheck

TERRAFORM_VERSION: Final = "1.15.8"
AWS_PROVIDER: Final = "registry.terraform.io/hashicorp/aws"
AWS_VERSION: Final = "6.53.0"
CONFIG_SUFFIXES: Final = (".tf", ".tf.json")
TIMEOUT_SECONDS: Final = 600
DEAD_PROXY: Final = "http://127.0.0.1:9"
SEED: Final = (
    "terraform {\n"
    "  required_providers {\n"
    '    aws = {\n      source  = "hashicorp/aws"\n      version = "6.53.0"\n    }\n'
    "  }\n"
    "}\n"
)


class RunnerError(Exception):
    """The runner cannot run (wrong versions, no mirror, Terraform missing): nothing is checked."""


def copy_configuration(source: Path, target: Path) -> Path:
    """Copy the top-level configuration files of ``source`` into a new directory ``target``."""
    target.mkdir(parents=True)
    for path in sorted(Path(source).iterdir()):
        if path.is_file() and not path.is_symlink() and path.name.endswith(CONFIG_SUFFIXES):
            shutil.copyfile(path, target / path.name)
    return target


def cli_configuration(mirror: Path) -> str:
    """A CLI configuration that installs providers from the filesystem mirror only."""
    path = Path(mirror).as_posix()
    return (
        "provider_installation {\n"
        "  filesystem_mirror {\n"
        f'    path    = "{path}"\n'
        '    include = ["registry.terraform.io/*/*"]\n'
        "  }\n"
        "  direct {\n"
        '    exclude = ["registry.terraform.io/*/*"]\n'
        "  }\n"
        "}\n"
    )


def validate_errors(stdout: str) -> tuple[bool, str]:
    """(valid, the error diagnostics as one text) from ``terraform validate -json``."""
    doc = json.loads(stdout)
    errors = []
    for d in doc.get("diagnostics") or []:
        if d.get("severity") != "error":
            continue
        text = f"Error: {d.get('summary', '')}"
        if d.get("detail"):
            text += f": {d['detail']}"
        where = (d.get("range") or {}).get("filename")
        if where:
            text += f" ({where}:{((d.get('range') or {}).get('start') or {}).get('line')})"
        errors.append(text)
    valid = bool(doc.get("valid")) and not errors
    return valid, "; ".join(errors)


def _first_error(text: str) -> str:
    for line in text.splitlines():
        if line.strip().startswith("Error:"):
            return line.strip()[:500]
    return next((ln.strip() for ln in text.splitlines() if ln.strip()), "no output")[:500]


class TerraformValidateRunner:
    def __init__(self, *, terraform: str, mirror: Path, work_root: Path) -> None:
        self.terraform = terraform
        self.mirror = Path(mirror)
        self.work_root = Path(work_root)
        if not self.mirror.is_dir():
            raise RunnerError(f"no provider mirror at {self.mirror}")
        self.work_root.mkdir(parents=True, exist_ok=True)
        (self.work_root / "scratch").mkdir(exist_ok=True)
        rc = self.work_root / "dail-terraform.tfrc"
        rc.write_text(cli_configuration(self.mirror), encoding="utf-8")
        home = self.work_root / "home"
        (home / ".aws").mkdir(parents=True, exist_ok=True)
        for name in ("credentials", "config"):
            (home / ".aws" / name).write_text("", encoding="utf-8")
        self.env = self._environment(rc, home)
        version = json.loads(self._tf(self.work_root, "version", "-json").stdout)
        if version.get("terraform_version") != TERRAFORM_VERSION:
            found = version.get("terraform_version")
            raise RunnerError(f"terraform {found} is not the pinned {TERRAFORM_VERSION}")
        seed = self.work_root / "seed"
        if seed.exists():
            shutil.rmtree(seed)
        seed.mkdir()
        (seed / "versions.tf").write_text(SEED, encoding="utf-8")
        init = self._tf(seed, "init", "-backend=false", "-input=false", "-no-color")
        if init.returncode != 0:
            raise RunnerError(f"seed init failed: {_first_error(init.stderr + init.stdout)}")
        selected = (
            json.loads(self._tf(seed, "version", "-json").stdout).get("provider_selections") or {}
        )
        if selected.get(AWS_PROVIDER) != AWS_VERSION:
            raise RunnerError(f"the mirror gave {AWS_PROVIDER} {selected.get(AWS_PROVIDER)}")
        self.lock = (seed / ".terraform.lock.hcl").read_bytes()
        self.versions: Mapping[str, str] = {
            "terraform": TERRAFORM_VERSION,
            AWS_PROVIDER: AWS_VERSION,
        }

    def _environment(self, rc: Path, home: Path) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith(("AWS_", "TF_"))}
        env.update(
            TF_CLI_CONFIG_FILE=str(rc),
            TF_DATA_DIR=str(self.work_root / "tf-data"),
            TF_IN_AUTOMATION="1",
            CHECKPOINT_DISABLE="1",
            AWS_SHARED_CREDENTIALS_FILE=str(home / ".aws" / "credentials"),
            AWS_CONFIG_FILE=str(home / ".aws" / "config"),
            AWS_EC2_METADATA_DISABLED="true",
            HTTP_PROXY=DEAD_PROXY,
            HTTPS_PROXY=DEAD_PROXY,
            http_proxy=DEAD_PROXY,
            https_proxy=DEAD_PROXY,
            NO_PROXY="",
        )
        return env

    def _tf(self, work: Path, *args: str) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                [self.terraform, f"-chdir={work}", *args],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=self.env,
                timeout=TIMEOUT_SECONDS,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise RunnerError(f"terraform {' '.join(args)}: {error}") from error

    def __call__(self, candidate_dir: Path) -> TerraformCheck:
        scratch = Path(tempfile.mkdtemp(prefix="validate-", dir=self.work_root / "scratch"))
        try:
            work = copy_configuration(Path(candidate_dir), scratch / "candidate")
            (work / ".terraform.lock.hcl").write_bytes(self.lock)
            init = self._tf(work, "init", "-backend=false", "-input=false", "-no-color")
            if init.returncode != 0:
                text = _first_error(init.stderr + "\n" + init.stdout).replace(str(work), "<work>")
                return TerraformCheck(False, f"init: {text}", self.versions)
            done = self._tf(work, "validate", "-json", "-no-color")
            try:
                valid, errors = validate_errors(done.stdout)
            except ValueError:
                return TerraformCheck(
                    False, f"validate: {_first_error(done.stderr + done.stdout)}", self.versions
                )
            return TerraformCheck(valid, errors, self.versions)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)

    def to_dict(self) -> dict[str, Any]:
        return {"versions": dict(self.versions), "mirror": str(self.mirror)}
