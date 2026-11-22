"""The machine stays awake during the main run (P10e-prep decision 6; C-250; P10b limit 3, P10d
limit 5).

**Preflight** (before the reference track and before generation): the active scheme's AC standby
timeout, AC hibernate timeout and AC lid-close action, read with ``powercfg /qh SCHEME_CURRENT
<subgroup> <setting>``, must all be 0 (lid-close 0 is "Do nothing"). ``/qh`` is ``/query`` with the
hidden settings: the lid-close action is hidden on the author's machine, so ``/query`` does not
list it (C-250). A value that is not 0, or one that cannot be read, refuses the start: uncertainty
fails closed.

**Monitor**: every 10 minutes the System log's Kernel-Power and Power-Troubleshooter events since
the start of the step are read (``wevtutil qe System /f:xml``) and every new one is appended to
the run's interruption file as a ``power_event`` line, with a ``poll`` line per poll and a
``poll_error`` line when the log cannot be read. Every event is kept; sleep, resume, wake, modern
standby, an unexpected restart and any event this module does not know count as interruptions (a
power-source change does not). The main-run command reports them; nothing is redone.
"""

from __future__ import annotations

import json
import re
import subprocess
import threading
import xml.etree.ElementTree as ET
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

STANDBY: Final = "standby"
HIBERNATE: Final = "hibernate"
LID: Final = "lid"
SUB_SLEEP: Final = "238c9fa8-0aad-41ed-83f4-97be242c8f20"
SUB_BUTTONS: Final = "4f971e89-eebd-4455-a8de-9e59040e7347"
SETTINGS: Final = {
    STANDBY: (SUB_SLEEP, "29f6c1db-86da-48c5-9fdb-f2b67b1f44da"),
    HIBERNATE: (SUB_SLEEP, "9d7815a6-7ee4-497e-8888-515a05f02364"),
    LID: (SUB_BUTTONS, "5ca83367-6e45-459f-a27b-476b1d01c936"),
}
KERNEL_POWER: Final = "Microsoft-Windows-Kernel-Power"
TROUBLESHOOTER: Final = "Microsoft-Windows-Power-Troubleshooter"
KINDS: Final = {
    (KERNEL_POWER, 41): ("unexpected restart", True),
    (KERNEL_POWER, 42): ("sleep or hibernate", True),
    (KERNEL_POWER, 105): ("power source change", False),
    (KERNEL_POWER, 107): ("resume", True),
    (KERNEL_POWER, 506): ("modern standby entry", True),
    (KERNEL_POWER, 507): ("modern standby exit", True),
    (TROUBLESHOOTER, 1): ("wake", True),
}
INTERVAL_SECONDS: Final = 600
_NS: Final = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_AC = re.compile(r"Current AC Power Setting Index:\s*0x([0-9a-fA-F]+)")
_DC = re.compile(r"Current DC Power Setting Index:\s*0x([0-9a-fA-F]+)")


class PreflightError(Exception):
    """The machine may sleep during the run: the step does not start."""


def parse_setting(text: str) -> tuple[int, int]:
    """(AC, DC) of one ``powercfg /qh`` setting; ValueError if either is missing."""
    ac, dc = _AC.findall(text), _DC.findall(text)
    if len(ac) != 1 or len(dc) != 1:
        raise ValueError("not exactly one AC and one DC value")
    return int(ac[0], 16), int(dc[0], 16)


def powercfg_query(name: str) -> str:
    sub, setting = SETTINGS[name]
    done = subprocess.run(
        ["powercfg", "/qh", "SCHEME_CURRENT", sub, setting],
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout


def preflight(query: Callable[[str], str] = powercfg_query) -> dict[str, int]:
    values: dict[str, int] = {}
    for name in (STANDBY, HIBERNATE, LID):
        try:
            text = query(name)
        except (OSError, subprocess.SubprocessError) as error:
            raise PreflightError(f"powercfg cannot be read ({name}): {error}") from None
        try:
            values[name] = parse_setting(text)[0]
        except ValueError:
            raise PreflightError(f"the AC {name} setting cannot be read from powercfg") from None
    bad = [f"{name} = {value}" for name, value in values.items() if value != 0]
    if bad:
        raise PreflightError(f"the machine may sleep: AC {', '.join(bad)} (each must be 0)")
    return values


def events_query(since: str) -> str:
    return (
        f"*[System[(Provider[@Name='{KERNEL_POWER}'] or Provider[@Name='{TROUBLESHOOTER}'])"
        f" and TimeCreated[@SystemTime>='{since}']]]"
    )


def wevtutil_query(since: str) -> str:
    done = subprocess.run(
        ["wevtutil", "qe", "System", f"/q:{events_query(since)}", "/f:xml", "/e:Events"],
        capture_output=True,
        text=True,
        check=True,
    )
    return done.stdout


def parse_events(text: str) -> list[dict[str, Any]]:
    if not text.strip():
        return []
    root = ET.fromstring(text)
    events = [root] if root.tag == f"{_NS}Event" else root.findall(f"{_NS}Event")
    found = []
    for e in events:
        system = e.find(f"{_NS}System")
        if system is None:
            continue
        provider = system.find(f"{_NS}Provider")
        name = "" if provider is None else provider.get("Name", "")
        event_id = int(system.findtext(f"{_NS}EventID") or -1)
        created = system.find(f"{_NS}TimeCreated")
        kind, interruption = KINDS.get((name, event_id), ("other", True))
        data = e.find(f"{_NS}EventData")
        found.append(
            {
                "provider": name,
                "event_id": event_id,
                "time": "" if created is None else created.get("SystemTime", ""),
                "record_id": system.findtext(f"{_NS}EventRecordID") or "",
                "kind": kind,
                "interruption": interruption,
                "data": (
                    {}
                    if data is None
                    else {d.get("Name", ""): d.text or "" for d in data.findall(f"{_NS}Data")}
                ),
            }
        )
    return sorted(found, key=lambda r: (r["time"], r["record_id"], r["event_id"]))


def utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class PowerMonitor:
    """Polls the System log and appends to the interruption file (see the module docstring)."""

    interval_seconds: int = INTERVAL_SECONDS

    def __init__(
        self,
        path: Path,
        *,
        since: str,
        query: Callable[[str], str] = wevtutil_query,
        now: Callable[[], str] = utc_now,
    ) -> None:
        self.path = Path(path)
        self.since = since
        self.query = query
        self.now = now
        self._seen: dict[tuple[str, int, str, str], bool] = {}
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _append(self, record: dict[str, Any]) -> None:
        with self.path.open("a", encoding="utf-8", newline="\n") as out:
            out.write(json.dumps(record, sort_keys=True) + "\n")

    def poll(self) -> None:
        at = self.now()
        try:
            events = parse_events(self.query(self.since))
        except (OSError, subprocess.SubprocessError, ET.ParseError, ValueError) as error:
            self._append({"record": "poll_error", "at": at, "error": str(error)})
            return
        new = 0
        for r in events:
            key = (r["provider"], r["event_id"], r["time"], r["record_id"])
            if key in self._seen:
                continue
            self._seen[key] = r["interruption"]
            self._append({"record": "power_event", **r})
            new += 1
        self._append({"record": "poll", "at": at, "since": self.since, "new_events": new})

    def interruptions(self) -> int:
        return sum(self._seen.values())

    def _loop(self) -> None:
        while not self._stop.wait(self.interval_seconds):
            self.poll()

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="power-monitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        self.poll()
