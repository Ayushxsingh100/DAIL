"""Prompt v3, ``dail-repair-prompt-3`` (P10b work package Section 2; C-223).

Section 2: "Keep v2's text unchanged and add to the system layer's statement of the supported model,
in plain words": one rule form per security group, kept; how to change a rule of each form; no
change to a ``lifecycle`` block; no resource type outside the supported list. The user's decision
(C-223) adds two statements of registry §2.6 (C-84): no explicit empty list on a group with separate
rules, and ``ingress = []`` to remove every inline rule of a direction.
"Tests: v3 contains each of the statements above; the v2 rendering is byte-identical to before; a
template change without a new version fails." "Do not mention invariant ids beyond what v2 already
gives."

The v1 and v2 rendering hashes below were computed at 839c2d3 (before v3) from
``tests.llm_builders.canonical_context()``.
"""

from __future__ import annotations

import hashlib
import unittest

from llm.prompts import templates
from llm.prompts.templates import PROMPT_HASHES, PROMPT_VERSION, render, template_hash
from tests.llm_builders import canonical_context

V1, V2, V3 = "dail-repair-prompt-1", "dail-repair-prompt-2", "dail-repair-prompt-3"
RENDERED_AT_BASE = {
    V1: "3d0853874d321e825bc44a16fff350f49cb39f752c8418cd1417ba2a7643dfad",
    V2: "56755f56aa6af6ce00c97d90ce0a5c82ffb582f72a0dd87423c21e7439dd8f2c",
}
STATEMENTS = (
    "Each security group's rules have one form: either inline ingress/egress blocks inside the "
    "aws_security_group, or separate aws_security_group_rule resources. Keep the form the group "
    "already uses.",
    "To change a rule of a group that uses separate rules, edit or delete that "
    "aws_security_group_rule. Never add ingress or egress blocks to such a group.",
    "To change a rule of a group that uses inline blocks, edit those blocks. Never add an "
    "aws_security_group_rule for that group.",
    "Do not add, change or remove a lifecycle block.",
    "Do not add resources of any type outside the supported list.",
    # the user's decision (C-223), registry §2.6 (C-84)
    "A group that uses separate rules never gets ingress = [] or egress = [] either.",
    "To remove every inline rule of a direction, write ingress = [] (or egress = []); deleting the "
    "blocks alone keeps the old rules.",
)


def rendered_digest(version: str) -> str:
    prompt = render(canonical_context(), version=version)
    return hashlib.sha256((prompt.system + "\x00" + prompt.task).encode()).hexdigest()


def one_line(text: str) -> str:
    return " ".join(text.split())


class TestVersions(unittest.TestCase):
    def test_v3_is_current_and_pinned(self) -> None:
        self.assertEqual(PROMPT_VERSION, V3)
        self.assertEqual(PROMPT_HASHES[V3], template_hash(V3))
        self.assertEqual(len({PROMPT_HASHES[v] for v in (V1, V2, V3)}), 3)
        self.assertEqual(render(canonical_context()).prompt_version, V3)

    def test_v1_and_v2_render_byte_identical_to_before(self) -> None:
        for version, digest in RENDERED_AT_BASE.items():
            with self.subTest(version=version):
                self.assertEqual(template_hash(version), PROMPT_HASHES[version])
                self.assertEqual(rendered_digest(version), digest)

    def test_a_template_change_without_a_new_version_fails(self) -> None:
        name = "SUPPORTED_MODEL_RULES_V3"
        original = getattr(templates, name)
        try:
            setattr(templates, name, original + " ")
            with self.assertRaises(ValueError):
                templates.render(canonical_context(), version=V3)
        finally:
            setattr(templates, name, original)
        self.assertEqual(template_hash(V3), PROMPT_HASHES[V3])


class TestStatements(unittest.TestCase):
    def setUp(self) -> None:
        context = canonical_context()
        self.v2 = render(context, version=V2)
        self.v3 = render(context, version=V3)

    def test_v3_states_each_rule(self) -> None:
        system = one_line(self.v3.system)
        for statement in STATEMENTS:
            with self.subTest(statement=statement[:40]):
                self.assertIn(statement, system)
                self.assertNotIn(statement, one_line(self.v2.system))

    def test_v3_keeps_v2s_text_and_only_adds(self) -> None:
        self.assertEqual(self.v3.task, self.v2.task)
        added = templates.SUPPORTED_MODEL_RULES_V3
        self.assertEqual(self.v3.system.count(added), 1)
        self.assertEqual(self.v3.system.replace(added, ""), self.v2.system)

    def test_the_added_text_names_no_invariant_and_no_scenario(self) -> None:
        added = templates.SUPPORTED_MODEL_RULES_V3
        for word in ("INV-", "tp-v1", "F2", "F4", "F8", "SSH", "5432", "22"):
            with self.subTest(word=word):
                self.assertNotIn(word, added)

    def test_the_generator_uses_v3(self) -> None:
        from tests.llm_builders import config

        self.assertEqual(config().prompt_version, V3)


if __name__ == "__main__":
    unittest.main()


class TestSamplingPins(unittest.TestCase):
    """C-224, C-225 (P10b-1): the three models, k = 3 with temperature 0.7 and top_p 0.95, the same
    digests as P10a; the k = 1 pins keep temperature 0."""

    def test_each_model_has_a_k3_pin_with_the_p10a_digest(self) -> None:
        from experiments.generation.models import load_pins

        pins = load_pins()
        for key in ("qwen2_5-coder-7b", "granite3_3-8b", "phi4-mini-3_8b"):
            with self.subTest(model=key):
                k1, k3 = pins[key], pins[f"{key}-k3"]
                self.assertEqual((k1.temperature, k1.top_p), (0.0, 1.0))
                self.assertEqual((k3.temperature, k3.top_p), (0.7, 0.95))
                self.assertEqual((k3.tag, k3.digest, k3.seed), (k1.tag, k1.digest, k1.seed))
                rest = ("max_output_tokens", "timeout_seconds", "num_ctx", "quantization")
                self.assertEqual([getattr(k3, n) for n in rest], [getattr(k1, n) for n in rest])
