"""The Markdown of a dev dry run (P10d Step 4). Every section heading carries the marker."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from experiments.stats.dry_run import MARKER, RHOS


def _f(value: Any, digits: int = 4) -> str:
    if value is None:
        return "undefined"
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _ratio(r: Mapping[str, Any] | None) -> str:
    if not r:
        return "-"
    if r.get("numerator") is None:
        return _f(r.get("value"))
    text = f"{r['numerator']} / {r['denominator']}"
    if r.get("value") is not None:
        text += f" = {_f(r['value'])}"
    w = r.get("wilson95")
    if w and w[0] is not None:
        text += f" [{_f(w[0])}, {_f(w[1])}]"
    return text


def render(report: Mapping[str, Any]) -> str:
    m = MARKER
    out: list[str] = [
        f"# P10d dev dry run ({m})",
        "",
        f"> **{m}.** The whole analysis of the frozen protocol, run on dev data (reference track: "
        f"experiment `{report['experiment_id']}`, `p8b-dev-run-3`; LLM track: the P10c scoring "
        "inputs) as if it were the test split, to check the code and the protocol before the "
        "freeze. Nothing here is a finding, and no hypothesis is tested on dev (C-214). "
        f"Versions: `{report['metrics_version']}`, `{report['extractor_version']}`, "
        f"`{report['analysis_version']}`; seed {report['seed']}, {report['coverage_reps']} "
        f"coverage and {report['power_reps']} power replications per cell. Generated from "
        "`P10D_DEV_DRY_RUN.json` by `experiments.stats.render`.",
        "",
        f"## 1. ρ, the ICC of the paired MR outcome (P10d-2) — {m}",
        "",
        "| stratum | B | C | C − B | A − C |",
        "|---|---|---|---|---|",
    ]
    for stratum, row in report["icc"].items():
        out.append(
            f"| {stratum} | {_f(row['B'])} | {_f(row['C'])} | {_f(row['C_minus_B'])} | "
            f"{_f(row['A_minus_C'])} |"
        )
    out += [
        "",
        f"ρ put into DEFF by the analysis (C-241 (5)): **{_f(report['rho_analysis'], 2)}**.",
        "",
        f"## 2. Coverage of the one-sided 95% upper limit (P10d-1) — {m}",
        "",
        "Minimum simulated coverage over the grid of true values, per configuration and ρ:",
        "",
        "| configuration | sizes | " + " | ".join(f"ρ = {r}" for r in RHOS) + " |",
        "|---|---|" + "---|" * len(RHOS),
    ]
    cov = report["coverage"]
    for name, sizes in cov["configs"].items():
        cells = []
        for r in RHOS:
            values = [x["coverage"] for x in cov["table"] if x["config"] == name and x["rho"] == r]
            cells.append(_f(min(values), 3) if values else "-")
        counts: dict[int, int] = {}
        for s in sizes:
            counts[s] = counts.get(s, 0) + 1
        shape = ", ".join(f"{n}×{s}" for s, n in sorted(counts.items())) or "none"
        out.append(
            f"| {name} | {sum(sizes)} in {len(sizes)} ({shape}) | " + " | ".join(cells) + " |"
        )
    out += ["", "| stratum | minimum | at | outcome (C-235) |", "|---|---|---|---|"]
    for label, key in (("dev and test bounds", "decision"), ("dev only", "decision_dev_only"),
                       ("test bounds only", "decision_test_bounds_only")):  # fmt: skip
        for stratum, d in cov[key].items():
            at = d["at"]
            out.append(
                f"| {stratum} ({label}) | {_f(d['minimum'], 3)} | {at['config']}, ρ = {at['rho']}, "
                f"π = {at['pi']} | **{d['outcome']}** |"
            )
    p = report["power"]
    out += [
        "",
        f"## 3. Power (H1: two-sided cluster sign test, Holm; H2: one-sided sign test) — {m}",
        "",
        f"C's dev MR per stratum, used as MR_C: {p['h1']['mr_c_dev']}.",
        "",
        "| test sizes | ρ | power at effect 0.10 (repair, change_request) | smallest effect with "
        "power ≥ 0.80 (repair, change_request) |",
        "|---|---|---|---|",
    ]
    for variant in ("test-even", "test-uneven"):
        for r in RHOS:
            mine = [x for x in p["h1"]["rows"] if x["variant"] == variant and x["rho"] == r]
            at = [x for x in mine if x["effect"] == 0.1][0]["power"]

            def smallest(s: str, mine: list[dict[str, Any]] = mine) -> str:
                ok = [x["effect"] for x in mine if x["power"][s] >= 0.8]
                return _f(min(ok), 1) if ok else "none ≤ 1.0"

            out.append(
                f"| {variant} | {r} | {_f(at['repair'], 3)}, {_f(at['change_request'], 3)} | "
                f"{smallest('repair')}, {smallest('change_request')} |"
            )
    out += ["", "| H2 test sizes | power |", "|---|---|"]
    for variant, value in p["h2"]["power"].items():
        out.append(f"| {variant} | {_f(value, 3)} |")
    h1 = report["h1"]
    out += [
        "",
        f"## 4. H1: A vs C ({m})",
        "",
        "| stratum | MR scenarios | clusters (by tier) | descriptive tiers | n+ / n− / n0 | p "
        "(two-sided) | Holm | MR_A − MR_C [95% CI, DEFF] |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for stratum, s in h1["strata"].items():
        iv = s["interval95"]
        out.append(
            f"| {stratum} | {s['scenarios']} | {s['clusters']} {s['clusters_by_tier']} | "
            f"{', '.join(s['descriptive_tiers']) or 'none'} | {s['n_plus']} / {s['n_minus']} / "
            f"{s['n_zero']} | {_f(s['p_two_sided'])} | {_f(h1['holm_adjusted'][stratum])} | "
            f"{_f(s['difference'])} [{_f(iv[0])}, {_f(iv[1])}], DEFF {_f(s['deff'], 3)} |"
        )
    out += ["", f"## 5. H2: B vs C ({m})", "", "| workload | value |", "|---|---|"]
    for label, w in (("all steps", report["h2_workload"]),
                     ("common prefix", report["h2_workload_common_prefix"])):  # fmt: skip
        out.append(
            f"| {label} | {w['clusters']} clusters {w['clusters_by_tier']}; favour C "
            f"{w['n_favour_c']}, favour B {w['n_favour_b']}, zero {w['n_zero']}; median cluster "
            f"W_C − W_B {_f(w['median_cluster_difference'])}; one-sided p {_f(w['p_one_sided'])}; "
            f"P(favours C | non-zero) {_f(w['estimate_p_favours_c'])} |"
        )
    ni = report["h2_noninferiority"]
    out += [
        "",
        f"Non-inferiority ({ni['status']}): cells {ni['cells']}, MR_C − MR_B "
        f"{_f(ni['difference_c_minus_b'])}, one-sided 95% upper limit "
        f"{_f(ni['upper95_one_sided'])} (DEFF {_f(ni['deff'], 3)}) against δ_NI = {ni['margin']}.",
        "",
        f"## 6. H3: C vs C′ on F5 ({m})",
        "",
        "| condition | identity error (UNCERTAIN excluded) | transition error | UNCERTAIN share "
        "| evidence-transfer error rate | excluded pairs (all families) |",
        "|---|---|---|---|---|---|",
    ]
    for c, h in report["h3"].items():
        out.append(
            f"| {c} | {_ratio(h['identity_error_rate_certain'])} | "
            f"{_ratio(h['transition_error_rate_certain'])} | "
            f"{_ratio(h['identity_uncertain_share_final'])} | "
            f"{_ratio(h['evidence_transfer_error_rate'])} | "
            f"{_ratio(h['identity_excluded_pairs_all'])} |"
        )
    out += ["", "Work on F5 by moved resource type (C′ − C):", "", "| type | transitions | W C | "
            "W C′ | difference |", "|---|---|---|---|---|"]  # fmt: skip
    for kind, row in report["h3_work_difference_f5"].items():
        out.append(
            f"| {kind} | {row['transitions']} | {row['work_c']} | {row['work_c_prime']} | "
            f"{row['difference']} |"
        )
    h4 = report["h4"]
    out += ["", f"## 7. H4 ({m})", "", f"Blocked unsafe F4 scenarios under C: {_ratio(h4)}.", ""]
    out += [f"## 8. Other metrics ({m})", ""]
    names = list(next(iter(report["other"].values())).keys()) if report["other"] else []
    out += ["| metric | " + " | ".join(report["other"]) + " |",
            "|---|" + "---|" * len(report["other"])]  # fmt: skip
    for name in names:
        out.append(
            f"| {name} | " + " | ".join(_ratio(report["other"][c][name]) for c in report["other"])
            + " |"
        )  # fmt: skip
    out += ["", "W per scenario (W_{X,s}, executed steps):", "", "| condition | scenarios | mean | "
            "median | mean by kind |", "|---|---|---|---|---|"]  # fmt: skip
    for c, w in report["work_per_scenario"].items():
        kinds = ", ".join(f"{k} {_f(v, 2)}" for k, v in w["mean_by_kind"].items())
        out.append(
            f"| {c} | {w['scenarios']} | {_f(w['mean_w'], 2)} | {_f(w['median_w'], 1)} | {kinds} |"
        )
    out += ["", f"## 9. DAIL–oracle κ under B (P10d-3) — {m}", "",
            "| invariant | PASS/FAIL cells | other results (apart) | n | κ |",
            "|---|---|---|---|---|"]  # fmt: skip
    for row in report["kappa"]:
        out.append(
            f"| {row['invariant_id']} | {row['cells']} | {row['other'] or '-'} | {row['n']} | "
            f"{_f(row['kappa'])} |"
        )
    out += ["", f"## 10. LLM track (descriptive, C-228) — {m}", "",
            "| generation | model | k | attempts | valid after gate | safe / unsafe / no label | "
            "any-unsafe@k | any-unsafe promoted@k (A, B, C, C′) |",
            "|---|---|---|---|---|---|---|---|"]  # fmt: skip
    for g in report["llm"]["groups"]:
        cls = g["classes"]
        under = [g["any_unsafe_promoted_at_k"].get(c) for c in ("A", "B", "C", "C_PRIME")]
        promoted = ", ".join("-" if r is None else str(r["numerator"]) for r in under)
        promoted += f" of {g['scenarios']}"
        out.append(
            f"| `{g['generation_id'][:8]}` | {g['model']} | {g['k']} | {g['attempts']} | "
            f"{_ratio(g['valid_after_gate'])} | {cls['safe']} / {cls['unsafe']} / "
            f"{cls['no label']} | {_ratio(g['any_unsafe_at_k'])} | {promoted} |"
        )
    out.append("")
    return "\n".join(out)
