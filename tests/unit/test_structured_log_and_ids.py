import json
import tempfile
import unittest
from pathlib import Path

from evidence.ids import CorrelationContext, new_id
from evidence.models import LogEvent, LogLevel
from evidence.structured_log import StructuredLogger


class TestCorrelationContext(unittest.TestCase):
    def test_new_context_has_distinct_ids(self) -> None:
        a, b = CorrelationContext.new(), CorrelationContext.new()
        self.assertNotEqual(a.correlation_id, b.correlation_id)
        self.assertNotEqual(a.correlation_id, a.operation_id)

    def test_new_operation_preserves_correlation(self) -> None:
        a = CorrelationContext.new()
        b = a.new_operation()
        self.assertEqual(a.correlation_id, b.correlation_id)
        self.assertNotEqual(a.operation_id, b.operation_id)

    def test_attempt_and_request_ids_propagate(self) -> None:
        c = CorrelationContext.new().with_attempt("att-1").with_request("req-9")
        self.assertEqual((c.attempt_id, c.request_id), ("att-1", "req-9"))
        self.assertEqual(c.new_operation().attempt_id, "att-1")

    def test_empty_ids_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CorrelationContext("", "op")
        with self.assertRaises(ValueError):
            CorrelationContext("c", "")

    def test_new_id_is_prefixed_and_unique(self) -> None:
        ids = {new_id("evd") for _ in range(200)}
        self.assertEqual(len(ids), 200)
        self.assertTrue(all(i.startswith("evd-") for i in ids))


class TestStructuredLogger(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = CorrelationContext.new()

    def test_event_has_every_doc11_section14_field(self) -> None:
        log = StructuredLogger("dail")
        e = log.log(LogLevel.INFO, component="impact", event_name="impact_done", ctx=self.ctx,
                    status="ok", candidate_id="c1", state_id="s1", duration_ms=12.5)
        d = e.to_dict()
        for key in ("timestamp", "level", "service", "component", "event_name", "correlation_id",
                    "operation_id", "candidate_id", "state_id", "duration_ms", "status",
                    "error_code", "metadata"):
            self.assertIn(key, d)
        self.assertEqual(d["correlation_id"], self.ctx.correlation_id)

    def test_correlation_propagates_across_operations(self) -> None:
        log = StructuredLogger("dail")
        log.log(LogLevel.INFO, component="a", event_name="x", ctx=self.ctx, status="ok")
        log.log(LogLevel.INFO, component="b", event_name="y", ctx=self.ctx.new_operation(), status="ok")
        corr = {e.correlation_id for e in log.entries}
        ops = {e.operation_id for e in log.entries}
        self.assertEqual(len(corr), 1)
        self.assertEqual(len(ops), 2)

    def test_metadata_is_redacted(self) -> None:
        log = StructuredLogger("dail")
        e = log.log(LogLevel.INFO, component="llm", event_name="request", ctx=self.ctx, status="ok",
                    metadata={"api_key": "sk-live-abc", "max_tokens": 1000, "model": "m"})
        self.assertEqual(e.metadata["api_key"], "[REDACTED]")
        self.assertEqual(e.metadata["max_tokens"], 1000)

    def test_secret_never_reaches_the_sink_file(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            sink = Path(d) / "logs" / "dail.jsonl"
            log = StructuredLogger("dail", sink_path=sink)
            log.log(LogLevel.WARNING, component="tf", event_name="parse", ctx=self.ctx, status="ok",
                    metadata={"user_data": "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG"})
            text = sink.read_text()
            self.assertNotIn("wJalrXUtnFEMI", text)
            lines = [json.loads(x) for x in text.splitlines()]  # machine-readable JSONL
            self.assertEqual(lines[0]["component"], "tf")

    def test_error_level_requires_an_error_code(self) -> None:
        log = StructuredLogger("dail")
        with self.assertRaises(ValueError):
            log.log(LogLevel.ERROR, component="v", event_name="boom", ctx=self.ctx, status="failed")
        e = log.log(LogLevel.ERROR, component="v", event_name="boom", ctx=self.ctx,
                    status="failed", error_code="VERIFIER_ERROR")
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
        from datetime import datetime, timezone
        with self.assertRaises(ValueError):
            LogEvent(datetime.now(timezone.utc), LogLevel.ERROR, "s", "c", "n", "corr", "op", "failed")


if __name__ == "__main__":
    unittest.main()
