"""Correlation context and structured logging (Doc 11 §10, §11, §14, §15; C-39, C-55).

Migrated from the interim version: ids are canonical UUIDs (C-55), ``CorrelationContext`` carries a
required ``run_id``, and ``new_id`` (prefixed ids) is gone.
"""

import json
import tempfile
import unittest
import uuid
from datetime import UTC
from pathlib import Path

from core.domain.errors import DomainValidationError
from evidence.ids import CorrelationContext
from evidence.models import LogEvent, LogLevel
from evidence.structured_log import StructuredLogger

ATTEMPT = "00000000-0000-0000-0000-0000000a0001"
REQUEST = "00000000-0000-0000-0000-0000000b0009"


class TestCorrelationContext(unittest.TestCase):
    def test_new_context_has_distinct_ids(self) -> None:
        a, b = CorrelationContext.new(), CorrelationContext.new()
        self.assertNotEqual(a.correlation_id, b.correlation_id)
        self.assertNotEqual(a.correlation_id, a.operation_id)

    def test_new_operation_preserves_correlation(self) -> None:
        a = CorrelationContext.new()
        b = a.new_operation()
        self.assertEqual(a.correlation_id, b.correlation_id)
        self.assertEqual(a.run_id, b.run_id)
        self.assertNotEqual(a.operation_id, b.operation_id)

    def test_attempt_and_request_ids_propagate(self) -> None:
        c = CorrelationContext.new().with_attempt(ATTEMPT).with_request(REQUEST)
        self.assertEqual((c.attempt_id, c.request_id), (ATTEMPT, REQUEST))
        self.assertEqual(c.new_operation().attempt_id, ATTEMPT)

    def test_empty_ids_rejected(self) -> None:
        good = CorrelationContext.new()
        with self.assertRaises(ValueError):
            CorrelationContext(good.run_id, "", good.operation_id)
        with self.assertRaises(ValueError):
            CorrelationContext(good.run_id, good.correlation_id, "")

    def test_ids_are_canonical_uuids_and_unique(self) -> None:
        """Replaces ``test_new_id_is_prefixed_and_unique``: the prefixed ids are retired (C-55)."""
        seen: set[str] = set()
        for _ in range(100):
            ctx = CorrelationContext.new().with_attempt().with_request()
            for value in (
                ctx.run_id,
                ctx.correlation_id,
                ctx.operation_id,
                ctx.attempt_id,
                ctx.request_id,
            ):
                assert value is not None
                self.assertEqual(str(uuid.UUID(value)), value)
                seen.add(value)
        self.assertEqual(len(seen), 500)

    def test_every_id_is_validated(self) -> None:
        good = CorrelationContext.new()
        for field in ("run_id", "correlation_id", "operation_id", "attempt_id", "request_id"):
            for bad in ("corr-0123456789abcdef", str(uuid.uuid4()).upper(), "", 7):
                with self.subTest(field=field, value=bad), self.assertRaises(DomainValidationError):
                    kwargs = {
                        "run_id": good.run_id,
                        "correlation_id": good.correlation_id,
                        "operation_id": good.operation_id,
                        field: bad,
                    }
                    CorrelationContext(**kwargs)  # type: ignore[arg-type]

    def test_the_run_id_is_required(self) -> None:
        with self.assertRaises(TypeError):
            CorrelationContext(correlation_id=ATTEMPT, operation_id=REQUEST)  # type: ignore[call-arg]

    def test_new_takes_the_callers_run_or_mints_one(self) -> None:
        self.assertEqual(CorrelationContext.new(ATTEMPT).run_id, ATTEMPT)
        self.assertNotEqual(CorrelationContext.new().run_id, CorrelationContext.new().run_id)
        with self.assertRaises(DomainValidationError):
            CorrelationContext.new("run-1")


class TestStructuredLogger(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = CorrelationContext.new()

    def test_event_has_every_doc11_section14_field(self) -> None:
        log = StructuredLogger("dail")
        e = log.log(
            LogLevel.INFO,
            component="impact",
            event_name="impact_done",
            ctx=self.ctx,
            status="ok",
            candidate_id="c1",
            state_id="s1",
            duration_ms=12.5,
        )
        d = e.to_dict()
        for key in (
            "timestamp",
            "level",
            "service",
            "component",
            "event_name",
            "correlation_id",
            "operation_id",
            "candidate_id",
            "state_id",
            "duration_ms",
            "status",
            "error_code",
            "metadata",
        ):
            self.assertIn(key, d)
        self.assertEqual(d["correlation_id"], self.ctx.correlation_id)

    def test_correlation_propagates_across_operations(self) -> None:
        log = StructuredLogger("dail")
        log.log(LogLevel.INFO, component="a", event_name="x", ctx=self.ctx, status="ok")
        log.log(
            LogLevel.INFO, component="b", event_name="y", ctx=self.ctx.new_operation(), status="ok"
        )
        corr = {e.correlation_id for e in log.entries}
        ops = {e.operation_id for e in log.entries}
        self.assertEqual(len(corr), 1)
        self.assertEqual(len(ops), 2)

    def test_metadata_is_redacted(self) -> None:
        log = StructuredLogger("dail")
        e = log.log(
            LogLevel.INFO,
            component="llm",
            event_name="request",
            ctx=self.ctx,
            status="ok",
            metadata={"api_key": "sk-live-abc", "max_tokens": 1000, "model": "m"},
        )
        self.assertEqual(e.metadata["api_key"], "[REDACTED]")
        self.assertEqual(e.metadata["max_tokens"], 1000)

    def test_secret_never_reaches_the_sink_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            sink = Path(d) / "logs" / "dail.jsonl"
            log = StructuredLogger("dail", sink_path=sink)
            log.log(
                LogLevel.WARNING,
                component="tf",
                event_name="parse",
                ctx=self.ctx,
                status="ok",
                metadata={
                    "user_data": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG",  # gitleaks:allow
                },
            )
            text = sink.read_text()
            self.assertNotIn("wJalrXUtnFEMI", text)
            lines = [json.loads(x) for x in text.splitlines()]  # machine-readable JSONL
            self.assertEqual(lines[0]["component"], "tf")

    def test_error_level_requires_an_error_code(self) -> None:
        log = StructuredLogger("dail")
        with self.assertRaises(ValueError):
            log.log(LogLevel.ERROR, component="v", event_name="boom", ctx=self.ctx, status="failed")
        e = log.log(
            LogLevel.ERROR,
            component="v",
            event_name="boom",
            ctx=self.ctx,
            status="failed",
            error_code="VERIFIER_ERROR",
        )
        self.assertEqual(e.error_code, "VERIFIER_ERROR")

    def test_entries_are_kept_in_order(self) -> None:
        log = StructuredLogger("dail")
        for i in range(4):
            log.log(LogLevel.INFO, component="c", event_name=f"e{i}", ctx=self.ctx, status="ok")
        self.assertEqual([e.event_name for e in log.entries], ["e0", "e1", "e2", "e3"])

    def test_service_is_required(self) -> None:
        with self.assertRaises(ValueError):
            StructuredLogger("")

    def test_log_event_dataclass_direct_validation(self) -> None:
        from datetime import datetime

        with self.assertRaises(ValueError):
            LogEvent(datetime.now(UTC), LogLevel.ERROR, "s", "c", "n", "corr", "op", "failed")


if __name__ == "__main__":
    unittest.main()
