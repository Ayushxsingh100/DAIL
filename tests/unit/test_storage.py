import tempfile
import unittest
from pathlib import Path

from core.domain.state import TrustedState
from core.domain.storage import LocalStorage


class TestLocalStorageBootstrap(unittest.TestCase):
    """Exercises P0's 'local database/storage setup' deliverable and the
    exact command the bootstrap script (scripts/bootstrap.sh) runs."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_fresh_db_file_does_not_exist_until_initialized(self) -> None:
        self.assertFalse(self.db_path.exists())
        storage = LocalStorage(self.db_path)
        storage.initialize_schema()
        self.assertTrue(self.db_path.exists())

    def test_schema_initialization_is_idempotent(self) -> None:
        storage = LocalStorage(self.db_path)
        storage.initialize_schema()
        storage.initialize_schema()  # must not raise on second call
        self.assertEqual(storage.schema_version(), "2")

    def test_creates_parent_directory_if_missing(self) -> None:
        nested = Path(self._tmpdir.name) / "nested" / "dirs" / "test.db"
        storage = LocalStorage(nested)
        storage.initialize_schema()
        self.assertTrue(nested.exists())


class TestLocalStorageTrustedState(unittest.TestCase):
    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmpdir.name) / "test.db"
        self.storage = LocalStorage(self.db_path)
        self.storage.initialize_schema()

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def test_save_and_count_trusted_state(self) -> None:
        self.assertEqual(self.storage.count_trusted_states(), 0)
        s0 = TrustedState.genesis(content_payload={"v": 0}, invariant_registry_version=1)
        self.storage.save_trusted_state(s0)
        self.assertEqual(self.storage.count_trusted_states(), 1)

    def test_save_multiple_states_in_lineage(self) -> None:
        from core.domain.state import CandidateState

        s0 = TrustedState.genesis(content_payload={"v": 0}, invariant_registry_version=1)
        self.storage.save_trusted_state(s0)

        c1 = CandidateState.build(parent=s0, patch_payload={"p": 1})
        c1.mark_under_verification()
        c1.mark_promoted()
        s1 = TrustedState.promoted_from(
            candidate=c1, parent=s0, content_payload={"v": 1}, invariant_registry_version=1
        )
        self.storage.save_trusted_state(s1)

        self.assertEqual(self.storage.count_trusted_states(), 2)


if __name__ == "__main__":
    unittest.main()
