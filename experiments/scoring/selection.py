"""The trials re-run for the reproducibility check (P8b Step 4).

"re-run 20 trials (one per family x class, chosen by lowest scenario id, plus the 4 F8 with most
steps)". The class is the scenario's ``gt_class``, so the choice lives in scoring. The 4 F8 with
most steps are taken in order of steps (most first), then scenario id, among the F8 scenarios not
chosen already.
"""

from __future__ import annotations

from collections.abc import Mapping

from experiments.scoring.labels import ScenarioLabels


def reproducibility_selection(
    scored: Mapping[str, ScenarioLabels], *, extra_f8: int = 4
) -> list[str]:
    chosen: dict[tuple[str, str], str] = {}
    for sid in sorted(scored):
        s = scored[sid]
        chosen.setdefault((s.family, str(s.gt_class)), sid)
    picked = set(chosen.values())
    f8 = sorted(
        (sid for sid, s in scored.items() if s.family == "F8" and sid not in picked),
        key=lambda sid: (-len(scored[sid].truth), sid),
    )
    return sorted(picked | set(f8[:extra_f8]))
