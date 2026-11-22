"""The main run runs on mains power only; ``powercfg /requests`` is recorded, not enforced
(P10e-prep-2 decisions 1 and 2; C-253, C-254; the external review of 77b62ac, findings 1 and 2).

Decision 1: "the preflight refuses to start unless the machine is on AC power at that moment, read
from Windows ... A value that cannot be read refuses the start. In the monitor, a Kernel-Power 105
event with ``AcOnline=false`` during the run is an interruption risk: it is recorded as an
interruption and shown in the report. The run is not stopped, and nothing is redone."

Decision 2: "The preflight runs it and stores its full output with the run. The monitor stores it
again with every poll that finds a power event. It never refuses the start."

The battery samples are what ``Get-CimInstance -Namespace root/wmi -ClassName BatteryStatus``
``PowerOnline`` prints on the author's machine (one battery, ``ACPI\\PNP0C0A\\1_0``); the
``/requests`` samples are its output there: unelevated, return code 1, nothing on stdout and the
refusal on stderr (the preflight record of 22 Nov 2026, 08:26:36Z); elevated, the sections it
prints.
"""

from __future__ import annotations

import hashlib
import json
import unittest
from pathlib import Path
from typing import Any

from experiments.mainrun.power import (
    HIBERNATE,
    LID,
    STANDBY,
    PowerMonitor,
    PreflightError,
    ac_online,
    parse_events,
    preflight_record,
)
from tests.experiment_builders import TempDirs

AWAKE = {STANDBY: 0, HIBERNATE: 0, LID: 0}
UNELEVATED = (
    "This command requires administrator privileges and must be executed from an elevated "
    "command prompt.\n"
)
ELEVATED = (
    "DISPLAY:\nNone.\n\nSYSTEM:\n[DRIVER] Realtek High Definition Audio\nAn audio stream is "
    "currently in use.\n\nAWAYMODE:\nNone.\n\nEXECUTION:\n[PROCESS] \\Device\\python.exe\n\n"
    "PERFBOOST:\nNone.\n\nACTIVELOCKSCREEN:\nNone.\n"
)


def requests_from(stdout: str, returncode: int = 0, stderr: str = "") -> Any:
    def requests() -> dict[str, Any]:
        return {
            "command": "powercfg /requests",
            "returncode": returncode,
            "output": stdout,
            "stderr": stderr,
        }

    return requests


def settings_awake() -> dict[str, int]:
    return dict(AWAKE)


class TestOnMains(unittest.TestCase):
    def test_on_ac_is_accepted(self) -> None:
        self.assertIs(ac_online(lambda: "True\r\n"), True)

    def test_on_battery_is_refused(self) -> None:
        with self.assertRaisesRegex(PreflightError, "battery"):
            ac_online(lambda: "False\r\n")

    def test_an_unreadable_value_is_refused(self) -> None:
        for text in ("", "\r\n", "Unknown\r\n", "True\r\nFalse\r\n"):
            with self.subTest(text=text), self.assertRaises(PreflightError):
                ac_online(lambda t=text: t)  # type: ignore[misc]

        def broken() -> str:
            raise OSError("powershell not found")

        with self.assertRaisesRegex(PreflightError, "cannot be read"):
            ac_online(broken)


class TestThePreflightRecord(unittest.TestCase):
    def test_on_ac_with_the_settings_at_zero_the_record_holds_everything(self) -> None:
        record = preflight_record(
            settings=settings_awake, battery=lambda: "True\r\n", requests=requests_from(ELEVATED)
        )
        self.assertEqual(record["ac_settings"], AWAKE)
        self.assertIs(record["ac_online"], True)
        self.assertEqual(record["battery_status"], "True\r\n")
        self.assertEqual(record["requests"]["output"], ELEVATED)

    def test_on_battery_the_preflight_refuses(self) -> None:
        with self.assertRaisesRegex(PreflightError, "battery"):
            preflight_record(
                settings=settings_awake,
                battery=lambda: "False\r\n",
                requests=requests_from(ELEVATED),
            )

    def test_the_settings_still_refuse(self) -> None:
        def asleep() -> dict[str, int]:
            raise PreflightError("the machine may sleep: AC lid = 1 (each must be 0)")

        with self.assertRaisesRegex(PreflightError, "lid"):
            preflight_record(
                settings=asleep, battery=lambda: "True\r\n", requests=requests_from(ELEVATED)
            )

    def test_requests_never_refuse_the_start(self) -> None:
        record = preflight_record(
            settings=settings_awake, battery=lambda: "True", requests=requests_from(ELEVATED)
        )
        self.assertEqual(record["requests"]["output"], ELEVATED)
        record = preflight_record(
            settings=settings_awake,
            battery=lambda: "True",
            requests=requests_from("", returncode=1, stderr=UNELEVATED),
        )
        self.assertEqual(
            (record["requests"]["returncode"], record["requests"]["stderr"]), (1, UNELEVATED)
        )

        def broken() -> dict[str, Any]:
            raise OSError("powercfg not found")

        record = preflight_record(settings=settings_awake, battery=lambda: "True", requests=broken)
        self.assertIn("powercfg not found", record["requests"]["error"])


def event_105(at: str, ac: str | None) -> str:
    data = "" if ac is None else f"<Data Name='AcOnline'>{ac}</Data>"
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        "<Provider Name='Microsoft-Windows-Kernel-Power' "
        "Guid='{331c3b3a-2005-44c2-ac5e-77220c37d6b4}'/>"
        f"<EventID>105</EventID><TimeCreated SystemTime='{at}'/>"
        "<EventRecordID>993732</EventRecordID></System>"
        f"<EventData>{data}<Data Name='RemainingCapacity'>39071</Data>"
        "<Data Name='FullChargeCapacity'>58805</Data></EventData></Event>"
    )


class TestTheMonitorOnBattery(unittest.TestCase):
    def setUp(self) -> None:
        self.dirs = TempDirs()
        self.addCleanup(self.dirs.close)
        self.path = self.dirs.new("dail-p10e-mains-") / "interruptions.jsonl"

    def lines(self) -> list[dict[str, Any]]:
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines()]

    def test_ac_offline_is_an_interruption_ac_online_is_not(self) -> None:
        # the event of the idle test, 2026-11-21T20:37:49.714Z (AcOnline=false)
        off, on, unknown = parse_events(
            "<Events>"
            + event_105("2026-11-21T20:37:49.7141785Z", "false")
            + event_105("2026-11-22T06:15:19.7219536Z", "true")
            + event_105("2026-11-22T07:00:00Z", None)
            + "</Events>"
        )
        self.assertIs(off["interruption"], True)
        self.assertIn("battery", off["kind"])
        self.assertIs(on["interruption"], False)
        self.assertEqual(on["kind"], "power source change")
        self.assertIs(unknown["interruption"], True)  # unreadable: fails closed

    def test_the_monitor_counts_and_shows_ac_offline(self) -> None:
        monitor = PowerMonitor(
            self.path,
            since="2026-11-21T20:22:44Z",
            query=lambda _s: "<Events>" + event_105("2026-11-21T20:37:49Z", "false") + "</Events>",
            now=lambda: "2026-11-21T20:40:00Z",
            requests=requests_from(ELEVATED),
        )
        monitor.poll()
        self.assertEqual(monitor.interruptions(), 1)
        events = [r for r in self.lines() if r["record"] == "power_event"]
        self.assertEqual(len(events), 1)
        event = events[0]
        self.assertIs(event["interruption"], True)

    def test_requests_are_stored_with_every_poll_that_finds_an_event(self) -> None:
        calls: list[int] = []

        def requests() -> dict[str, Any]:
            calls.append(1)
            return requests_from(ELEVATED)()

        replies = iter(
            [
                "<Events>" + event_105("2026-11-22T01:00:00Z", "true") + "</Events>",
                "<Events>" + event_105("2026-11-22T01:00:00Z", "true") + "</Events>",
                "<Events>"
                + event_105("2026-11-22T01:00:00Z", "true")
                + event_105("2026-11-22T01:30:00Z", "false")
                + "</Events>",
            ]
        )
        monitor = PowerMonitor(
            self.path,
            since="t0",
            query=lambda _s: next(replies),
            now=lambda: "t",
            requests=requests,
        )
        monitor.poll()
        monitor.poll()  # nothing new: /requests is not run
        monitor.poll()
        polls = [r for r in self.lines() if r["record"] == "poll"]
        self.assertEqual([p["new_events"] for p in polls], [1, 0, 1])
        self.assertEqual(len(calls), 2)
        self.assertEqual(polls[0]["requests"]["output"], ELEVATED)
        self.assertNotIn("requests", polls[1])
        self.assertEqual(polls[2]["requests"]["output"], ELEVATED)


class TestTheCommandRecordsThePreflight(unittest.TestCase):
    def test_the_command_monitor_stores_requests(self) -> None:
        from unittest import mock

        from experiments.mainrun import __main__ as command
        from experiments.mainrun import power

        dirs = TempDirs()
        self.addCleanup(dirs.close)
        built: list[dict[str, Any]] = []

        class Spy:
            def __init__(self, path: Path, **kwargs: Any) -> None:
                built.append(kwargs)
                self.path = path

            def start(self) -> None: ...

            def stop(self) -> None: ...

            def interruptions(self) -> int:
                return 0

        with mock.patch.object(command, "PowerMonitor", Spy), mock.patch("builtins.print"):
            command._monitored(dirs.new("dail-p10e-mains-"), lambda: None)
        (kwargs,) = built
        self.assertIs(kwargs["requests"], power.powercfg_requests)

    def test_the_preflight_record_is_written_with_the_run(self) -> None:
        from experiments.mainrun import __main__ as command

        dirs = TempDirs()
        self.addCleanup(dirs.close)
        root = dirs.new("dail-p10e-mains-")
        record = {"ac_settings": AWAKE, "ac_online": True, "requests": {"output": ELEVATED}}
        command._record_preflight(root, "reference", record)
        command._record_preflight(root, "generation", record)
        lines = [
            json.loads(x)
            for x in (root / command.PREFLIGHTS).read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual([x["step"] for x in lines], ["reference", "generation"])
        self.assertEqual(lines[0]["preflight"]["requests"]["output"], ELEVATED)


ROOT = Path(__file__).resolve().parents[2]


class TestThePinsHold(unittest.TestCase):
    """P10e-prep-2 changes only experiments/mainrun, tests and docs."""

    def test_the_protocol_is_unchanged(self) -> None:
        raw = (ROOT / "docs" / "PROTOCOL_v1.md").read_bytes().replace(b"\r\n", b"\n")
        self.assertEqual(
            hashlib.sha256(raw).hexdigest(),
            "f860c4c624080730b3164d56ec9adf3a30e1a5426c5a25a3028185563321bcaa",
        )

    def test_the_pinned_code_is_unchanged(self) -> None:
        from experiments.report.protocol import code_hash

        self.assertEqual(
            code_hash(("experiments/metrics", "experiments/scoring")),
            "6338cff50da03b8cba438b76f9458e51bf27313fe2964746b1a477f2c74f82ab",
        )
        self.assertEqual(
            code_hash(("experiments/stats",)),
            "ecf1cea18fd572fc56af1f93934025668335b3b90fcf40c7f51ee4d56e00ab18",
        )


if __name__ == "__main__":
    unittest.main()
