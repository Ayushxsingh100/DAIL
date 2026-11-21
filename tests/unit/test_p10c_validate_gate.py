"""The ``terraform validate`` gate for LLM candidates (P10c Section 3.1-3.2; C-99, C-227).

C-227: "The patch validator runs the pinned ``terraform validate`` on the built candidate directory,
after the build and before normalization. A failure refuses the patch with failure class
INVALID_OUTPUT ...; the error text is recorded, and no candidate exists. Validator version 3. The
check runs outside ``core/`` (C-99), through a runner the caller supplies. With no runner,
generation refuses to start (fail closed)."
Section 3.2: "a candidate with ``"::/0"`` in ``cidr_blocks`` -> refused (fake runner returns the
Terraform error), no candidate; a valid candidate -> unchanged path; no runner -> generation refuses
to start; a mutant that skips the check fails a test."
Section 3.1: the runner "copies the configuration-only files to a scratch directory; runs ``init
-backend=false`` with the mirror, then ``validate``; records the Terraform and provider versions. In
the default test suite a fake runner is injected. One opt-in test runs real Terraform when
``DAIL_TERRAFORM_TEST=1``."

The default tests use ``FakeTerraform``: it records the directory it is given and fails a candidate
whose ``.tf`` text holds ``"::/0"`` inside ``cidr_blocks`` with Terraform's own message for it (as
TerraPreserve's TP-L1 records show: ``"::/0" is not a valid IPv4 CIDR block``).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import unittest
from pathlib import Path
from typing import Any

from llm.adapter.fake import FakeProvider
from llm.adapter.generate import Generator
from llm.adapter.provider import ProviderReply
from llm.schemas.records import FailureClass, GenerationStatus
from llm.validation.parser import parse_response
from llm.validation.patch import VALIDATOR_VERSION, PatchValidator, TerraformCheck
from tests.identity_builders import NOW
from tests.llm_builders import Clock, Ids, budget, config, retry_policy
from tests.llm_patch_builders import (
    BASELINE,
    PATCH_ID,
    REQUEST_ID,
    SG_APP,
    SG_APP_CLOSED,
    SSH_RULE,
    WorkRoot,
    repair,
    scope,
    tree_digest,
    trusted,
)

F = FailureClass
IPV6_IN_V4 = re.compile(r"cidr_blocks\s*=\s*\[[^\]]*\"::/0\"")
SG_APP_IPV6 = SG_APP_CLOSED.replace(
    "  ingress     = []\n",
    '  ingress {\n    from_port   = 443\n    to_port     = 443\n    protocol    = "tcp"\n'
    '    cidr_blocks = ["::/0"]\n  }\n',
)


class FakeTerraform:
    """A ``TerraformCheck``: fails ``"::/0"`` in ``cidr_blocks`` as Terraform does; records each
    call."""

    def __init__(self) -> None:
        self.calls: list[tuple[Path, list[str]]] = []

    def __call__(self, candidate_dir: Path) -> TerraformCheck:
        names = sorted(p.name for p in candidate_dir.iterdir())
        self.calls.append((candidate_dir, names))
        text = "".join(p.read_text(encoding="utf-8") for p in sorted(candidate_dir.glob("*.tf")))
        if IPV6_IN_V4.search(text):
            return TerraformCheck(
                ok=False,
                error='Error: "::/0" is not a valid IPv4 CIDR block',
                versions={"terraform": "1.15.8", "registry.terraform.io/hashicorp/aws": "6.53.0"},
            )
        return TerraformCheck(
            ok=True,
            error="",
            versions={"terraform": "1.15.8", "registry.terraform.io/hashicorp/aws": "6.53.0"},
        )


class Case(unittest.TestCase):
    def setUp(self) -> None:
        self.work = WorkRoot()
        self.addCleanup(self.work.close)
        self.before = tree_digest(BASELINE)
        self.terraform = FakeTerraform()

    def tearDown(self) -> None:
        self.assertEqual(tree_digest(BASELINE), self.before)

    def validator(self, terraform: Any = "default") -> PatchValidator:
        return PatchValidator(
            parent_dir=BASELINE,
            trusted=trusted(),
            scope=scope(),
            work_root=self.work.path,
            variables=None,
            now=NOW,
            terraform_validate=self.terraform if terraform == "default" else terraform,
        )

    def run_patch(self, patch: str, changed: list[str]) -> Any:
        parsed = parse_response(repair(patch, changed))
        assert parsed.response is not None, parsed.errors
        return self.validator().validate(parsed.response, request_id=REQUEST_ID, patch_id=PATCH_ID)


class TestValidatorThree(Case):
    def test_the_version_is_3(self) -> None:
        self.assertEqual(VALIDATOR_VERSION, "dail-patch-validator-3")

    def test_ipv6_in_cidr_blocks_is_refused_with_the_terraform_error_and_no_candidate(self) -> None:
        outcome = self.run_patch(SG_APP_IPV6, [SG_APP, SSH_RULE])
        self.assertIs(outcome.failure_class, F.INVALID_OUTPUT, outcome.errors)
        self.assertIsNone(outcome.build)
        self.assertIn('"::/0" is not a valid IPv4 CIDR block', " ".join(outcome.errors))
        self.assertIn("terraform validate", " ".join(outcome.errors))
        self.assertEqual(list(self.work.path.iterdir()), [])  # the build is gone
        self.assertEqual(len(self.terraform.calls), 1)

    def test_a_valid_candidate_takes_the_unchanged_path(self) -> None:
        outcome = self.run_patch(SG_APP_CLOSED, [SG_APP, SSH_RULE])
        self.assertIsNone(outcome.failure_class, outcome.errors)
        assert outcome.build is not None
        ((called, names),) = self.terraform.calls
        self.assertEqual(called, outcome.build.candidate_dir)  # the built directory itself
        self.assertEqual(names, sorted(p.name for p in outcome.build.candidate_dir.iterdir()))
        self.assertEqual(outcome.terraform, self.terraform(outcome.build.candidate_dir).to_dict())

    def test_the_check_comes_after_the_build_and_before_normalization(self) -> None:
        # a refused build never reaches normalization: a patch DAIL's normalizer would reject (a
        # reference to an undeclared resource is caught by check 10 first, so use the IPv6 case and
        # record that normalization did not run)
        import llm.validation.patch as module

        seen: list[str] = []
        real = module.normalize_directory

        def spy(*args: Any, **kwargs: Any) -> Any:
            seen.append(str(args[0]))
            return real(*args, **kwargs)

        module.normalize_directory = spy  # type: ignore[assignment]
        try:
            v = self.validator()
            seen.clear()  # the constructor normalizes the parent
            parsed = parse_response(repair(SG_APP_IPV6, [SG_APP, SSH_RULE]))
            assert parsed.response is not None
            v.validate(parsed.response, request_id=REQUEST_ID, patch_id=PATCH_ID)
        finally:
            module.normalize_directory = real  # type: ignore[assignment]
        self.assertEqual(seen, [])
        self.assertEqual(len(self.terraform.calls), 1)

    def test_a_runner_that_cannot_run_stops_the_call_and_leaves_no_build(self) -> None:
        # a broken Terraform environment is not the model's failure: it is not recorded as one
        def broken(_: Path) -> TerraformCheck:
            raise RuntimeError("the mirror is gone")

        parsed = parse_response(repair(SG_APP_CLOSED, [SG_APP, SSH_RULE]))
        assert parsed.response is not None
        with self.assertRaises(RuntimeError):
            self.validator(broken).validate(
                parsed.response, request_id=REQUEST_ID, patch_id=PATCH_ID
            )
        self.assertEqual(list(self.work.path.iterdir()), [])


class TestFailClosed(Case):
    def test_generation_with_a_validator_but_no_runner_refuses_to_start(self) -> None:
        provider = FakeProvider(
            [ProviderReply(text=repair(SG_APP_CLOSED, [SG_APP]), latency_ms=1.0)]
        )
        with self.assertRaises(ValueError):
            Generator(
                provider=provider,
                config=config(),
                retry_policy=retry_policy(1),
                budget=budget(),
                generation_enabled=True,
                clock=Clock(),
                ids=Ids(),
                validator=self.validator(None),
            )
        self.assertEqual(provider.calls, [])

    def test_with_the_runner_a_refused_reply_is_a_generation_failure(self) -> None:
        from llm.adapter.context import ContextInputs, build_context
        from tests.impact_builders import registry

        parent = trusted()
        context = build_context(
            ContextInputs(
                parent_state_id=parent.state_id,
                trusted_state_hash=parent.state_hash,
                resources=tuple(parent.resources),
                invariants=tuple(registry("aws_instance.app", "aws_db_instance.database").values()),
                statuses={r.invariant_id: r.status.value for r in parent.invariant_refs},
                objective="Repair INV-SEC-001.",
                repair_targets=("INV-SEC-001",),
                scope=scope(),
                focus=(SG_APP, SSH_RULE),
            )
        )
        provider = FakeProvider(
            [ProviderReply(text=repair(SG_APP_IPV6, [SG_APP, SSH_RULE]), latency_ms=1.0)]
        )
        result = Generator(
            provider=provider,
            config=config(),
            retry_policy=retry_policy(1),
            budget=budget(),
            generation_enabled=True,
            clock=Clock(),
            ids=Ids(),
            validator=self.validator(),
        ).generate(context)
        self.assertIs(result.status, GenerationStatus.FAILED)
        self.assertIs(result.failure_class, F.INVALID_OUTPUT)
        self.assertIsNone(result.build)
        response = result.attempts[0].response.to_dict()
        self.assertIn(
            '"::/0" is not a valid IPv4 CIDR block', " ".join(response["validation_errors"])
        )
        self.assertEqual(response["validator_version"], "dail-patch-validator-3")


class TestRunnerParts(unittest.TestCase):
    """The parts of ``experiments.terraform_validate`` that need no Terraform."""

    def test_only_configuration_files_are_copied(self) -> None:
        from experiments.terraform_validate import copy_configuration

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "src"
            src.mkdir()
            for name in (
                "main.tf",
                "x.tf.json",
                "terraform.tfvars",
                "notes.md",
                ".terraform.lock.hcl",
            ):
                (src / name).write_text("#\n", encoding="utf-8")
            (src / ".terraform").mkdir()
            dst = Path(tmp) / "dst"
            copy_configuration(src, dst)
            self.assertEqual(sorted(p.name for p in dst.iterdir()), ["main.tf", "x.tf.json"])

    def test_the_validate_json_error_text(self) -> None:
        from experiments.terraform_validate import validate_errors

        out = json.dumps(
            {
                "valid": False,
                "diagnostics": [
                    {"severity": "warning", "summary": "w", "detail": "x"},
                    {
                        "severity": "error",
                        "summary": "Missing required argument",
                        "detail": 'The argument "to_port" is required.',
                        "range": {"filename": "dail_llm_patch.tf", "start": {"line": 9}},
                    },
                ],
            }
        )
        self.assertEqual(
            validate_errors(out),
            (
                False,
                'Error: Missing required argument: The argument "to_port" is required. '
                "(dail_llm_patch.tf:9)",
            ),
        )
        self.assertEqual(
            validate_errors(json.dumps({"valid": True, "diagnostics": []})), (True, "")
        )

    def test_the_cli_configuration_installs_from_the_mirror_only(self) -> None:
        from experiments.terraform_validate import cli_configuration

        text = cli_configuration(Path("/m/mirror"))
        self.assertIn("filesystem_mirror", text)
        self.assertIn('path    = "/m/mirror"', text)
        self.assertNotIn("direct {\n  }", text)
        self.assertIn('exclude = ["registry.terraform.io/*/*"]', text)


def _real_terraform() -> bool:
    return os.environ.get("DAIL_TERRAFORM_TEST") == "1" and bool(
        os.environ.get("DAIL_TERRAFORM_MIRROR")
    )


@unittest.skipUnless(_real_terraform(), "opt-in: DAIL_TERRAFORM_TEST=1 and DAIL_TERRAFORM_MIRROR")
class TestRealTerraform(unittest.TestCase):
    """The real runner on the canonical baseline and on it with ``"::/0"`` in ``cidr_blocks``."""

    def test_valid_and_invalid_and_the_versions(self) -> None:
        from experiments.terraform_validate import TerraformValidateRunner

        terraform = shutil.which("terraform")
        assert terraform is not None
        with tempfile.TemporaryDirectory(prefix="dail-p10c-tf-") as tmp:
            runner = TerraformValidateRunner(
                terraform=terraform,
                mirror=Path(os.environ["DAIL_TERRAFORM_MIRROR"]),
                work_root=Path(tmp) / "work",
            )
            self.assertEqual(
                runner.versions,
                {"terraform": "1.15.8", "registry.terraform.io/hashicorp/aws": "6.53.0"},
            )
            before = tree_digest(BASELINE)
            good = runner(BASELINE)
            bad_dir = Path(tmp) / "bad"
            shutil.copytree(BASELINE, bad_dir)
            main = bad_dir / "main.tf"
            probe = SG_APP_IPV6.replace(
                '"aws_security_group" "app"', '"aws_security_group" "probe"'
            )
            main.write_text(main.read_text(encoding="utf-8") + "\n" + probe, encoding="utf-8")
            bad = runner(bad_dir)
            self.assertEqual(tree_digest(BASELINE), before)
            self.assertEqual(list((Path(tmp) / "work" / "scratch").iterdir()), [])  # removed
            print(
                "\nREAL-TERRAFORM-P10C "
                + json.dumps({"good": good.to_dict(), "bad": bad.to_dict()}, sort_keys=True)
            )
            self.assertTrue(good.ok, good.error)
            self.assertFalse(bad.ok)
            self.assertIn("::/0", bad.error)


if __name__ == "__main__":
    unittest.main()
