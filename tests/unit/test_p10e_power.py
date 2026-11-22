"""The machine stays awake (P10e-prep decision 6; C-250; P10b limit 3, P10d limit 5).

"Before steps 1 and 2, a preflight reads ``powercfg /query`` on the active scheme and refuses to
start unless the AC standby timeout is 0, the AC hibernate timeout is 0, and the AC lid-close action
is "do nothing". During the run, sleep, wake and hibernate events are read from the Windows System
log (Kernel-Power, Power-Troubleshooter) every 10 minutes and recorded in the run's interruption
file. Any interruption is reported; nothing is redone."

The samples are in the format ``powercfg /qh`` and ``wevtutil qe System /f:xml /e:Events`` print
on the author's machine (22 Nov 2026); the lid-close setting is hidden there, so ``/query`` does
not list it and the preflight reads ``/qh`` (the same output, hidden settings included; C-250).
"""

from __future__ import annotations

import json
import unittest
from typing import Any

from experiments.mainrun.power import (
    HIBERNATE,
    LID,
    STANDBY,
    PowerMonitor,
    PreflightError,
    events_query,
    parse_events,
    parse_setting,
    preflight,
)
from tests.experiment_builders import TempDirs


def setting(name: str, ac: int, dc: int = 0) -> str:
    return (
        "Power Scheme GUID: e6f535c0-edc3-4b6d-a83a-f6723c38aea2  (Acer)\n"
        "  Subgroup GUID: 238c9fa8-0aad-41ed-83f4-97be242c8f20  (Sleep)\n"
        "    GUID Alias: SUB_SLEEP\n"
        f"    Power Setting GUID: 29f6c1db-86da-48c5-9fdb-f2b67b1f44da  ({name})\n"
        "      Minimum Possible Setting: 0x00000000\n"
        "      Maximum Possible Setting: 0xffffffff\n"
        "      Possible Settings increment: 0x00000001\n"
        "      Possible Settings units: Seconds\n"
        f"    Current AC Power Setting Index: 0x{ac:08x}\n"
        f"    Current DC Power Setting Index: 0x{dc:08x}\n"
    )


def answers(standby: int = 0, hibernate: int = 0, lid: int = 0) -> dict[str, str]:
    return {
        STANDBY: setting("Sleep after", standby),
        HIBERNATE: setting("Hibernate after", hibernate, 0x2A30),
        LID: setting("Lid close action", lid, 1),
    }


def query_from(found: dict[str, str]) -> Any:
    return lambda name: found[name]


class TestPreflight(unittest.TestCase):
    def test_parse_the_ac_and_dc_values(self) -> None:
        self.assertEqual(parse_setting(setting("Hibernate after", 0xA8C0, 0x2A30)), (43200, 10800))

    def test_all_zero_and_lid_do_nothing_is_accepted(self) -> None:
        values = preflight(query_from(answers()))
        self.assertEqual(values, {STANDBY: 0, HIBERNATE: 0, LID: 0})

    def test_a_non_zero_value_is_refused(self) -> None:
        for name, kwargs in (
            ("standby", {"standby": 0x78}),
            ("hibernate", {"hibernate": 0xA8C0}),  # the author's value before the change
            ("lid", {"lid": 1}),  # Sleep
            ("lid", {"lid": 2}),  # Hibernate
        ):
            with self.subTest(**kwargs), self.assertRaisesRegex(PreflightError, name):
                preflight(query_from(answers(**kwargs)))

    def test_a_missing_or_unreadable_setting_is_refused(self) -> None:
        # /query on the author's machine prints only the scheme line for the hidden lid setting
        found = answers()
        found[LID] = "Power Scheme GUID: e6f535c0-edc3-4b6d-a83a-f6723c38aea2  (Acer)\n"
        with self.assertRaisesRegex(PreflightError, "lid"):
            preflight(query_from(found))

        def broken(_name: str) -> str:
            raise OSError("powercfg not found")

        with self.assertRaisesRegex(PreflightError, "powercfg"):
            preflight(broken)


def event(provider: str, event_id: int, at: str, **data: str) -> str:
    fields = "".join(f"<Data Name='{k}'>{v}</Data>" for k, v in data.items())
    return (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System>"
        f"<Provider Name='{provider}' Guid='{{331c3b3a-2005-44c2-ac5e-77220c37d6b4}}'/>"
        f"<EventID>{event_id}</EventID><Version>1</Version><Level>4</Level><Task>100</Task>"
        f"<TimeCreated SystemTime='{at}'/><EventRecordID>993724</EventRecordID>"
        "<Channel>System</Channel><Computer>host</Computer></System>"
        f"<EventData>{fields}</EventData></Event>"
    )


KP, PT = "Microsoft-Windows-Kernel-Power", "Microsoft-Windows-Power-Troubleshooter"
SAMPLE = (
    "<Events>\n"
    + event(KP, 42, "2026-11-22T01:00:00.1000000Z", TargetState="4", Reason="7")
    + event(KP, 107, "2026-11-22T01:20:00.0000000Z")
    + event(PT, 1, "2026-11-22T01:20:01.0000000Z", SleepTime="2026-11-22T01:00:01Z")
    + event(KP, 105, "2026-11-21T20:03:53.9573175Z", AcOnline="true")
    + event(KP, 506, "2026-11-22T02:00:00Z")
    + event(KP, 41, "2026-11-22T03:00:00Z")
    + "</Events>"
)


class TestEvents(unittest.TestCase):
    def test_parse_sample_events_into_interruption_records(self) -> None:
        records = parse_events(SAMPLE)
        # sorted by time
        self.assertEqual(
            [(r["provider"], r["event_id"], r["kind"], r["interruption"]) for r in records],
            [
                (KP, 105, "power source change", False),
                (KP, 42, "sleep or hibernate", True),
                (KP, 107, "resume", True),
                (PT, 1, "wake", True),
                (KP, 506, "modern standby entry", True),
                (KP, 41, "unexpected restart", True),
            ],
        )
        sleep = next(r for r in records if r["event_id"] == 42)
        self.assertEqual(sleep["time"], "2026-11-22T01:00:00.1000000Z")
        self.assertEqual(sleep["data"], {"TargetState": "4", "Reason": "7"})

    def test_an_unknown_event_is_kept_and_counted_as_an_interruption(self) -> None:
        (record,) = parse_events("<Events>" + event(KP, 999, "2026-11-22T00:00:00Z") + "</Events>")
        self.assertEqual((record["kind"], record["interruption"]), ("other", True))

    def test_no_event(self) -> None:
        self.assertEqual(parse_events("<Events></Events>"), [])
        self.assertEqual(parse_events(""), [])

    def test_the_query_names_both_providers_and_the_start(self) -> None:
        q = events_query("2026-11-22T00:00:00.000Z")
        self.assertIn(KP, q)
        self.assertIn(PT, q)
        self.assertIn("@SystemTime>='2026-11-22T00:00:00.000Z'", q)


class TestMonitor(unittest.TestCase):
    def setUp(self) -> None:
        self.dirs = TempDirs()
        self.addCleanup(self.dirs.close)
        self.path = self.dirs.new("dail-p10e-power-") / "interruptions.jsonl"

    def lines(self) -> list[dict[str, Any]]:
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines()]

    def test_each_poll_appends_the_new_events_once(self) -> None:
        polls: list[str] = []
        replies = [SAMPLE, SAMPLE, "<Events></Events>"]

        def query(since: str) -> str:
            polls.append(since)
            return replies[len(polls) - 1]

        stamps = iter(["2026-11-22T04:00:00Z", "2026-11-22T04:10:00Z", "2026-11-22T04:20:00Z"])
        monitor = PowerMonitor(
            self.path, since="2026-11-22T00:00:00Z", query=query, now=lambda: next(stamps)
        )
        monitor.poll()
        monitor.poll()  # the same events again: not recorded twice
        monitor.poll()
        self.assertEqual(polls[0], "2026-11-22T00:00:00Z")
        records = [r for r in self.lines() if r["record"] == "power_event"]
        self.assertEqual(len(records), 6)
        polled = [r for r in self.lines() if r["record"] == "poll"]
        self.assertEqual([p["new_events"] for p in polled], [6, 0, 0])
        self.assertEqual(monitor.interruptions(), 5)

    def test_a_failed_poll_is_recorded_not_hidden(self) -> None:
        def query(_since: str) -> str:
            raise OSError("wevtutil failed")

        monitor = PowerMonitor(self.path, since="t0", query=query, now=lambda: "t1")
        monitor.poll()
        (line,) = self.lines()
        self.assertEqual(line["record"], "poll_error")
        self.assertIn("wevtutil failed", line["error"])

    def test_the_interval_is_ten_minutes(self) -> None:
        monitor = PowerMonitor(self.path, since="t0", query=lambda _s: "", now=lambda: "t")
        self.assertEqual(monitor.interval_seconds, 600)


if __name__ == "__main__":
    unittest.main()
