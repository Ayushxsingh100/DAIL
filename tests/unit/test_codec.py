"""``core.domain.codec``: the persistence adapter's route back into the domain (C-48; Doc 05 §22).

The wrappers must add nothing to ``from_dict``: same validation, same hash re-check, and no way to
build a promoted state.
"""

from __future__ import annotations

import unittest

from core.domain import codec
from core.domain.errors import DomainValidationError, HashMismatchError
from tests.domain_builders import baseline, canonical_resources, new_candidate, ready_candidate


class TestCodec(unittest.TestCase):
    def test_a_trusted_state_is_rebuilt_equal(self) -> None:
        v0 = baseline()
        self.assertEqual(codec.rebuild_trusted_state(v0.to_dict()), v0)

    def test_a_candidate_is_rebuilt_equal_at_every_shape(self) -> None:
        v0 = baseline()
        for candidate in (
            new_candidate(v0),
            ready_candidate(v0, canonical_resources(ssh_open=False, db_path=True)),
        ):
            with self.subTest(status=candidate.status):
                self.assertEqual(codec.rebuild_candidate(candidate.to_dict()), candidate)

    def test_a_tampered_trusted_state_is_refused_by_its_hash(self) -> None:
        data = baseline().to_dict()
        data["resources"][0]["attributes"]["size"] = "tampered"
        with self.assertRaises(HashMismatchError):
            codec.rebuild_trusted_state(data)

    def test_a_tampered_candidate_is_refused_by_its_hash(self) -> None:
        data = ready_candidate(
            baseline(), canonical_resources(ssh_open=False, db_path=True)
        ).to_dict()
        data["resources"][0]["attributes"]["size"] = "tampered"
        with self.assertRaises(HashMismatchError):
            codec.rebuild_candidate(data)

    def test_unexpected_keys_are_refused(self) -> None:
        data = baseline().to_dict()
        data["extra"] = 1
        with self.assertRaises(DomainValidationError):
            codec.rebuild_trusted_state(data)

    def test_the_module_offers_exactly_two_functions_and_no_promotion_path(self) -> None:
        public = {name for name in vars(codec) if not name.startswith("_")}
        functions = {name for name in public if callable(getattr(codec, name))}
        self.assertEqual(
            {name for name in functions if getattr(codec, name).__module__ == codec.__name__},
            {"rebuild_trusted_state", "rebuild_candidate"},
        )
        for name in ("promote", "mark_promoted", "establish_baseline"):
            self.assertNotIn(name, public)


if __name__ == "__main__":
    unittest.main()
