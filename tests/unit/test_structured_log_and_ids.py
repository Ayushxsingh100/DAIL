"""Correlation context and structured logging (Doc 11 §10, §11, §14, §15; C-39, C-55).

Migrated from the interim version: ids are canonical UUIDs (C-55), ``CorrelationContext`` carries a
required ``run_id``, and ``new_id`` (prefixed ids) is gone. P2-fix step 5 (C-58) adds the five log
levels (``WARNING`` is now ``WARN``), the logger threshold and ``ReplayMode``.
"""

import json
import tempfile
import unittest
import uuid
from datetime import UTC
from pathlib import Path

from core.application.config import LOG_LEVELS
from core.domain.errors import DomainValidationError
from core.domain.ids import new_uuid
from evidence.ids import CorrelationContext
from evidence.models import LogEvent, LogLevel, ReplayMode
from evidence.structured_log import StructuredLogger

ATTEMPT = "00000000-0000-0000-0000-0000000a0001"
REQUEST = "00000000-0000-0000-0000-0000000b0009"


class TestCorrelationContext(unittest.TestCase):
    def test_new_context_has_distinct_ids(self) -> None:
        a, b = CorrelationContext.new(new_uuid()), CorrelationContext.new(new_uuid())
        self.assertNotEqual(a.correlation_id, b.correlation_id)
        self.assertNotEqual(a.correlation_id, a.operation_id)

    def test_new_operation_preserves_correlation(self) -> None:
        a = CorrelationContext.new(new_uuid())
        b = a.new_operation()
        self.assertEqual(a.correlation_id, b.correlation_id)
        self.assertEqual(a.run_id, b.run_id)
        self.assertNotEqual(a.operation_id, b.operation_id)

    def test_attempt_and_request_ids_propagate(self) -> None:
        c = CorrelationContext.new(new_uuid()).with_attempt(ATTEMPT).with_request(REQUEST)
        self.assertEqual((c.attempt_id, c.request_id), (ATTEMPT, REQUEST))
        self.assertEqual(c.new_operation().attempt_id, ATTEMPT)

    def test_empty_ids_rejected(self) -> None:
        good = CorrelationContext.new(new_uuid())
        with self.assertRaises(ValueError):
            CorrelationContext(good.run_id, "", good.operation_id)
        with self.assertRaises(ValueError):
            CorrelationContext(good.run_id, good.correlation_id, "")

    def test_ids_are_canonical_uuids_and_unique(self) -> None:
        """Replaces ``test_new_id_is_prefixed_and_unique``: the prefixed ids are retired (C-55)."""
        seen: set[str] = set()
        for _ in range(100):
            ctx = CorrelationContext.new(new_uuid()).with_attempt().with_request()
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
        good = CorrelationContext.new(new_uuid())
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

    def test_new_requires_a_run_id_and_never_mints_one(self) -> None:
        with self.assertRaises(TypeError):
            CorrelationContext.new()  # type: ignore[call-arg]
        self.assertEqual(CorrelationContext.new(ATTEMPT).run_id, ATTEMPT)
        with self.assertRaises(DomainValidationError):
            CorrelationContext.new("run-1")


class TestStructuredLogger(unittest.TestCase):
    def setUp(self) -> None:
        self.ctx = CorrelationContext.new(new_uuid())

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
                LogLevel.WARN,
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


class TestLogLevel(unittest.TestCase):
    """Doc 11 §15: ERROR, WARN, INFO, DEBUG, TRACE (C-58)."""

    def test_the_levels_are_the_five_of_doc_11_section_15(self) -> None:
        self.assertEqual(
            {level.value for level in LogLevel}, {"ERROR", "WARN", "INFO", "DEBUG", "TRACE"}
        )

    def test_the_levels_equal_the_configuration_levels(self) -> None:
        self.assertEqual(tuple(level.value for level in LogLevel), LOG_LEVELS)

    def test_warning_is_retired(self) -> None:
        self.assertNotIn("WARNING", {level.name for level in LogLevel})
        with self.assertRaises(ValueError):
            LogLevel("WARNING")
        with self.assertRaises(ValueError) as caught:
            LogLevel.parse("WARNING")
        self.assertIn("WARN", str(caught.exception))

    def test_severity_orders_the_levels(self) -> None:
        ordered = [LogLevel.TRACE, LogLevel.DEBUG, LogLevel.INFO, LogLevel.WARN, LogLevel.ERROR]
        ranks = [level.severity for level in ordered]
        self.assertEqual(ranks, sorted(ranks))
        self.assertEqual(len(set(ranks)), 5)

    def test_parse_is_exact(self) -> None:
        for level in LogLevel:
            self.assertIs(LogLevel.parse(level.value), level)
        for bad in ("info", "Warn", "WARNING", "FATAL", "", "INFO "):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                LogLevel.parse(bad)


class TestLoggerThreshold(unittest.TestCase):
    """Doc 11 §15: TRACE is "disabled by default in production"; the default threshold is INFO."""

    def setUp(self) -> None:
        self.ctx = CorrelationContext.new(new_uuid())

    def emit(self, log: StructuredLogger, level: LogLevel) -> LogEvent | None:
        return log.log(
            level,
            component="c",
            event_name=f"e_{level.value.lower()}",
            ctx=self.ctx,
            status="ok",
            error_code="X" if level is LogLevel.ERROR else None,
        )

    def test_the_default_threshold_is_info(self) -> None:
        self.assertIs(StructuredLogger("dail").threshold, LogLevel.INFO)

    def test_trace_is_dropped_at_the_default_threshold(self) -> None:
        log = StructuredLogger("dail")
        self.assertIsNone(self.emit(log, LogLevel.TRACE))
        self.assertEqual(log.entries, [])

    def test_info_warn_and_error_pass_and_debug_does_not(self) -> None:
        log = StructuredLogger("dail")
        kept = {level: self.emit(log, level) is not None for level in LogLevel}
        self.assertEqual(
            kept,
            {
                LogLevel.ERROR: True,
                LogLevel.WARN: True,
                LogLevel.INFO: True,
                LogLevel.DEBUG: False,
                LogLevel.TRACE: False,
            },
        )
        self.assertEqual({e.event_name for e in log.entries}, {"e_error", "e_warn", "e_info"})

    def test_an_entry_below_the_threshold_is_never_written_to_the_sink(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            sink = Path(d) / "logs" / "dail.jsonl"
            log = StructuredLogger("dail", sink_path=sink)
            self.emit(log, LogLevel.TRACE)
            self.emit(log, LogLevel.DEBUG)
            self.assertFalse(sink.exists(), "nothing below the threshold may reach the sink")
            self.emit(log, LogLevel.INFO)
            lines = [json.loads(x) for x in sink.read_text().splitlines()]
            self.assertEqual([x["level"] for x in lines], ["INFO"])

    def test_a_dropped_entry_is_not_even_redacted(self) -> None:
        calls: list[object] = []

        class Spy:
            def redact(self, payload: object) -> object:
                calls.append(payload)
                raise AssertionError("a dropped entry must not be processed")

        log = StructuredLogger("dail", redactor=Spy())  # type: ignore[arg-type]
        self.assertIsNone(self.emit(log, LogLevel.TRACE))
        self.assertEqual(calls, [])

    def test_a_lower_threshold_lets_everything_through(self) -> None:
        log = StructuredLogger("dail", threshold=LogLevel.TRACE)
        for level in LogLevel:
            self.assertIsNotNone(self.emit(log, level))
        self.assertEqual(len(log.entries), 5)

    def test_a_higher_threshold_keeps_only_errors(self) -> None:
        log = StructuredLogger("dail", threshold=LogLevel.ERROR)
        for level in LogLevel:
            self.emit(log, level)
        self.assertEqual([e.level for e in log.entries], [LogLevel.ERROR])

    def test_the_threshold_can_be_set_from_a_configuration_level_name(self) -> None:
        for name in LOG_LEVELS:
            logger = StructuredLogger("dail", threshold=LogLevel.parse(name))
            self.assertEqual(logger.threshold.value, name)

    def test_level_and_threshold_must_be_log_levels(self) -> None:
        with self.assertRaises(ValueError):
            StructuredLogger("dail", threshold="INFO")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            StructuredLogger("dail").log(
                "INFO",  # type: ignore[arg-type]
                component="c",
                event_name="e",
                ctx=self.ctx,
                status="ok",
            )


class TestReplayMode(unittest.TestCase):
    """C-08, C-58: RECONSTRUCT (Doc 13 §47 calls it REPLAY), REVERIFY, RERUN, REGENERATE."""

    def test_there_are_four_modes(self) -> None:
        self.assertEqual(
            [mode.value for mode in ReplayMode], ["RECONSTRUCT", "REVERIFY", "RERUN", "REGENERATE"]
        )
        self.assertEqual(len(set(ReplayMode)), 4)  # "must not be conflated" (Doc 11 §35)

    def test_replay_parses_to_reconstruct(self) -> None:
        self.assertIs(ReplayMode.parse("REPLAY"), ReplayMode.RECONSTRUCT)

    def test_every_mode_parses_from_its_name(self) -> None:
        for mode in ReplayMode:
            self.assertIs(ReplayMode.parse(mode.value), mode)

    def test_there_are_no_other_aliases(self) -> None:
        for bad in (
            "replay",
            "Reconstruct",
            "reconstruct",
            "RECONSTRUCTION",
            "RE-RUN",
            "VERIFY",
            "",
            " REPLAY",
        ):
            with self.subTest(value=bad), self.assertRaises(ValueError):
                ReplayMode.parse(bad)

    def test_replay_is_not_a_member(self) -> None:
        self.assertNotIn("REPLAY", ReplayMode.__members__)
        with self.assertRaises(ValueError):
            ReplayMode("REPLAY")


if __name__ == "__main__":
    unittest.main()
