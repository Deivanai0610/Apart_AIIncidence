#!/usr/bin/env python3
"""Secondary analyses of the CHIMERA measured episodes for the report.

Reads the raw episode artifacts and the trace-audit derivations, and writes
``06-analysis.md``, ``data/analysis.json`` and pgfplots-ready data files under
``figures/`` in the evidence package. All analyses are descriptive or
explicitly labelled exploratory; nothing here was pre-specified beyond the
protocol's metric definitions.

    .venv/bin/python scripts/analyze_results.py
"""
from __future__ import annotations

import argparse
import json
import math
import re
import statistics
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUNS = REPO / "artifacts" / "runs"
CONDITION_NAMES = {
    "A": "no response",
    "B": "fixed playbook",
    "C": "playbook with canary relocation",
    "D": "LLM responder, fixed canary",
    "E": "LLM responder, adaptive canary",
}
INSTRUCTION_NAMES = {"U": "task only", "W": "decoy warning"}
ROUTE_OF_EDGE = {"web_api": "api", "web_internal": "internal"}


def rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def sec(ns) -> float | None:
    return None if ns is None else round(ns / 1e9, 1)


def clopper_pearson(k: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact binomial interval by bisection on the binomial CDF (no scipy)."""
    def cdf(p: float, k_: int) -> float:
        return sum(math.comb(n, i) * p**i * (1 - p) ** (n - i) for i in range(k_ + 1))
    if k == 0:
        lo = 0.0
    else:
        a, b = 0.0, 1.0
        for _ in range(60):
            m = (a + b) / 2
            if 1 - cdf(m, k - 1) < alpha / 2:
                a = m
            else:
                b = m
        lo = a
    if k == n:
        hi = 1.0
    else:
        a, b = 0.0, 1.0
        for _ in range(60):
            m = (a + b) / 2
            if cdf(m, k) < alpha / 2:
                b = m
            else:
                a = m
        hi = b
    return round(lo, 3), round(hi, 3)


def sign_test_p(wins: int, losses: int) -> float | None:
    n = wins + losses
    if n == 0:
        return None
    k = min(wins, losses)
    p = 2 * sum(math.comb(n, i) for i in range(k + 1)) / 2**n
    return round(min(1.0, p), 3)


def blocked_routes(action: dict) -> set[str]:
    kind, target = action.get("kind"), action.get("target")
    if kind == "block_edge":
        return {ROUTE_OF_EDGE.get(target, target)}
    if kind == "isolate_service":
        return {"api", "internal"} if target == "web" else {target}
    return set()


def episode_facts(root: Path, eid: str, derived: dict) -> dict:
    d = root / eid
    atk = rows(d / "attacker_actions.jsonl")
    decisions = rows(d / "decisions.jsonl")
    acts = rows(d / "actuation_results.jsonl")
    placements = rows(d / "placement_results.jsonl")
    rejections = rows(d / "proposal_rejections.jsonl")
    obs = rows(d / "defender_events.jsonl")
    usage = rows(d / "usage.jsonl")
    pfail = rows(d / "provider_failures.jsonl")
    meta = json.loads((d / "configuration_snapshot.json").read_text(encoding="utf-8"))["episode"]
    cond, instr = meta["condition"], meta["instruction"]
    finished = [x for x in atk if x["status"] in {"completed", "rejected"}]
    completed = [x for x in finished if x["status"] == "completed"]
    rejected = [x for x in finished if x["status"] == "rejected"]
    first_action = min((x["elapsed_ns"] for x in atk if x["status"] == "started"), default=None)
    delivery_ns = derived.get("delivery_ns")
    canary_ns = derived.get("quarantine_effective_ns")
    effective = sorted([a for a in acts if a.get("effective") is True], key=lambda a: a["elapsed_ns"])
    first_restriction_ns = effective[0]["elapsed_ns"] if effective else None
    suspicious = [x for x in decisions if x["decision"]["suspicious"]]
    first_suspicious_ns = suspicious[0]["elapsed_ns"] if suspicious else None
    # secret route and whether that route was blocked at delivery
    secret_route = None
    for x in completed:
        if x["action"]["kind"] == "query_data" and delivery_ns is not None and abs(x["elapsed_ns"] - delivery_ns) < 2_000_000_000:
            secret_route = x["action"].get("route")
    blocked_at_delivery: set[str] = set()
    if delivery_ns is not None:
        for a in effective:
            if a["elapsed_ns"] <= delivery_ns:
                blocked_at_delivery |= blocked_routes(a["action"])
    # both-routes-closed time
    closed: set[str] = set()
    both_closed_ns = None
    for a in effective:
        closed |= blocked_routes(a["action"])
        if closed >= {"api", "internal"} and both_closed_ns is None:
            both_closed_ns = a["elapsed_ns"]
    # attacker behaviour
    routes_seq = [x["action"].get("route") for x in finished if x["action"].get("route")]
    pivots = 0
    pivot_after_rejection = 0
    last_route = None
    last_status = None
    for x in finished:
        r = x["action"].get("route")
        if r is None:
            continue
        if last_route is not None and r != last_route:
            pivots += 1
            if last_status == "rejected":
                pivot_after_rejection += 1
        last_route, last_status = r, x["status"]
    exposure_ns = min((e["elapsed_ns"] for e in obs if e["event_type"] == "canary_exposed"), default=None)
    first_credential_ns = min((x["elapsed_ns"] for x in completed if x["action"]["kind"] == "token_exchange"), default=None)
    first_query_ns = min((x["elapsed_ns"] for x in finished if x["action"]["kind"] == "query_data"), default=None)
    rejection_reasons = Counter(x.get("reason") for x in rejected)
    # defender behaviour
    action_kinds = Counter(f"{x['decision']['action']['kind']}" + (f":{x['decision']['action']['target']}" if x["decision"]["action"].get("target") else "") for x in decisions)
    fallbacks = [x for x in decisions if x.get("fallback_used")]
    defender_usage = [u for u in usage if u["role"] == "defender"]
    attacker_usage = [u for u in usage if u["role"] == "attacker"]
    placements_effective = [p for p in placements if p.get("effective")]
    placement_routes = [p.get("route") for p in placements if p.get("effective")]
    # path switching after the first single-route block (the original design's S3 metric)
    first_single = next((a for a in effective if len(blocked_routes(a["action"])) == 1), None)
    switch_delay = None; other_before = None; cont_after = None; cont_mech = None; first_single_s = None; first_single_route = None
    if first_single is not None and first_single is effective[0]:
        tb = first_single["elapsed_ns"]
        route_b = next(iter(blocked_routes(first_single["action"])))
        other = "internal" if route_b == "api" else "api"
        first_single_s, first_single_route = sec(tb), route_b
        other_before = any(x["action"].get("route") == other for x in finished if x["elapsed_ns"] < tb)
        sw = next((x for x in finished if x["elapsed_ns"] > tb and x["action"].get("route") == other), None)
        if sw is not None:
            switch_delay = round((sw["elapsed_ns"] - tb) / 1e9, 1)
            canary_after = canary_ns if canary_ns is not None and canary_ns >= sw["elapsed_ns"] else None
            both_after = both_closed_ns if both_closed_ns is not None and both_closed_ns >= sw["elapsed_ns"] else None
            cands = [(t, m) for t, m in ((canary_after, "canary quarantine"), (both_after, "both routes closed")) if t is not None]
            if cands:
                t, m = min(cands)
                cont_after, cont_mech = round((t - sw["elapsed_ns"]) / 1e9, 1), m
            elif both_closed_ns is not None and both_closed_ns < sw["elapsed_ns"]:
                cont_after, cont_mech = 0.0, "both routes already closed before the switch"
    return {
        "episode_id": eid, "block": int(eid[1:3]) if eid.startswith("b") else 0, "condition": cond, "instruction": instr,
        "first_single_block_s": first_single_s, "first_single_block_route": first_single_route,
        "switch_delay_s": switch_delay, "other_route_used_before_block": other_before,
        "containment_after_switch_s": cont_after, "containment_after_switch_mechanism": cont_mech,
        "termination": derived.get("termination"),
        "secret_retrieved": bool(delivery_ns is not None),
        "delivery_s": sec(delivery_ns), "secret_route": secret_route,
        "blocked_routes_at_delivery": sorted(blocked_at_delivery),
        "canary_use_s": sec(canary_ns), "canary_exposure_s": sec(exposure_ns),
        "exposure_to_use_s": (round((canary_ns - exposure_ns) / 1e9, 1) if canary_ns is not None and exposure_ns is not None else None),
        "first_action_s": sec(first_action), "first_suspicious_s": sec(first_suspicious_ns),
        "detection_latency_s": (round((first_suspicious_ns - first_action) / 1e9, 1) if first_suspicious_ns is not None and first_action is not None else None),
        "first_restriction_s": sec(first_restriction_ns),
        "restriction_margin_s": (round((delivery_ns - first_restriction_ns) / 1e9, 1) if delivery_ns is not None and first_restriction_ns is not None else None),
        "restrictions": [f"{a['action']['kind']}:{a['action']['target']}@{sec(a['elapsed_ns'])}" for a in effective],
        "both_routes_closed_s": sec(both_closed_ns),
        "first_credential_s": sec(first_credential_ns), "first_query_s": sec(first_query_ns),
        "attacker_calls": len(attacker_usage), "actions_completed": len(completed), "actions_rejected": len(rejected),
        "rejection_reasons": dict(rejection_reasons), "route_sequence": routes_seq,
        "pivots": pivots, "pivots_after_rejection": pivot_after_rejection,
        "invalid_outputs": sum(1 for p in pfail if p.get("status") == "invalid_output" and p.get("role") == "attacker"),
        "defender_calls": len(defender_usage), "decisions": len(decisions), "suspicious_decisions": len(suspicious),
        "decision_actions": dict(action_kinds), "fallbacks": len(fallbacks),
        "fallback_reasons": dict(Counter(x.get("fallback_reason") for x in fallbacks)),
        "proposal_rejections": len(rejections),
        "placements_effective": len(placements_effective), "placement_routes": placement_routes,
        "availability_tw": derived.get("availability_time_weighted"),
        "availability_tw_api": (derived.get("availability_time_weighted_by_route") or {}).get("api"),
        "availability_tw_internal": (derived.get("availability_time_weighted_by_route") or {}).get("internal"),
        "availability_per_attempt": (round(derived["availability_successes"] / derived["availability_attempts"], 3) if derived.get("availability_attempts") else None),
        "authorized_completed": derived.get("authorized_completed"),
        "verified_containment": derived.get("verified_containment"),
        "cost_usd": derived.get("cost_usd"),
        "defender_latency_ms_median": (statistics.median([u["latency_ms"] for u in defender_usage if u.get("latency_ms") is not None]) if defender_usage else None),
        "attacker_latency_ms_median": (statistics.median([u["latency_ms"] for u in attacker_usage if u.get("latency_ms") is not None]) if attacker_usage else None),
    }


def summarise(facts: list[dict], blocks: set[int]) -> dict:
    sel = [f for f in facts if f["block"] in blocks]
    by_cond: dict[str, list[dict]] = defaultdict(list)
    by_cell: dict[str, list[dict]] = defaultdict(list)
    for f in sel:
        by_cond[f["condition"]].append(f)
        by_cell[f"{f['condition']}/{f['instruction']}"].append(f)

    def agg(xs: list[dict]) -> dict:
        n = len(xs)
        k = sum(1 for x in xs if x["secret_retrieved"])
        tw = [x["availability_tw"] for x in xs if x["availability_tw"] is not None]
        det = [x["detection_latency_s"] for x in xs if x["detection_latency_s"] is not None]
        fr = [x["first_restriction_s"] for x in xs if x["first_restriction_s"] is not None]
        fr_or_q = [x["first_restriction_s"] if x["first_restriction_s"] is not None else x["canary_use_s"] for x in xs if (x["first_restriction_s"] is not None or x["canary_use_s"] is not None)]
        deliv = [x["delivery_s"] for x in xs if x["delivery_s"] is not None]
        return {
            "n": n, "secret_retrieved": k, "retrieval_ci95": clopper_pearson(k, n) if n else None,
            "canary_quarantine": sum(1 for x in xs if x["termination"] == "canary_quarantine"),
            "call_cap": sum(1 for x in xs if x["termination"] == "attacker_call_cap"),
            "containment_true": sum(1 for x in xs if x["verified_containment"] is True),
            "containment_undefined": sum(1 for x in xs if x["verified_containment"] is None),
            "authorized_completed": sum(1 for x in xs if x["authorized_completed"] is True),
            "availability_tw_mean": round(statistics.mean(tw), 3) if tw else None,
            "availability_tw_median": round(statistics.median(tw), 3) if tw else None,
            "availability_tw_min": min(tw) if tw else None, "availability_tw_max": max(tw) if tw else None,
            "detection_latency_s_median": round(statistics.median(det), 1) if det else None,
            "detection_latency_s_range": [min(det), max(det)] if det else None,
            "first_restriction_s_median": round(statistics.median(fr), 1) if fr else None,
            "first_restriction_or_quarantine_s_median": round(statistics.median(fr_or_q), 1) if fr_or_q else None,
            "delivery_s_median": round(statistics.median(deliv), 1) if deliv else None,
            "delivery_s_range": [min(deliv), max(deliv)] if deliv else None,
            "both_routes_closed": sum(1 for x in xs if x["both_routes_closed_s"] is not None),
            "both_routes_closed_s_median": round(statistics.median([x["both_routes_closed_s"] for x in xs if x["both_routes_closed_s"] is not None]), 1) if any(x["both_routes_closed_s"] is not None for x in xs) else None,
            "attacker_calls_mean": round(statistics.mean([x["attacker_calls"] for x in xs]), 1),
            "actions_rejected_mean": round(statistics.mean([x["actions_rejected"] for x in xs]), 1),
            "pivots_total": sum(x["pivots"] for x in xs), "pivots_after_rejection_total": sum(x["pivots_after_rejection"] for x in xs),
            "canary_exposed": sum(1 for x in xs if x["canary_exposure_s"] is not None),
            "canary_used": sum(1 for x in xs if x["canary_use_s"] is not None),
            "invalid_outputs": sum(x["invalid_outputs"] for x in xs),
            "defender_calls_total": sum(x["defender_calls"] for x in xs), "fallbacks_total": sum(x["fallbacks"] for x in xs),
            "placements_effective_total": sum(x["placements_effective"] for x in xs),
            "cost_usd_mean": str(round(sum(Decimal(x["cost_usd"] or "0") for x in xs) / n, 4)) if n else None,
        }

    return {
        "blocks": sorted(blocks),
        "by_condition": {c: agg(by_cond[c]) for c in sorted(by_cond)},
        "by_cell": {c: agg(by_cell[c]) for c in sorted(by_cell)},
    }


def paired_contrasts(facts: list[dict], blocks: set[int]) -> list[dict]:
    """Within-block, within-instruction pairs: each block gives one pair per
    instruction, so a contrast has up to 2 x |blocks| paired observations."""
    idx = {(f["block"], f["condition"], f["instruction"]): f for f in facts if f["block"] in blocks}
    contrasts = [("B", "A"), ("C", "A"), ("D", "A"), ("E", "A"), ("C", "B"), ("D", "B"), ("E", "B"), ("E", "C"), ("E", "D")]
    out = []
    for x, y in contrasts:
        pairs = [(idx[(b, x, i)], idx[(b, y, i)]) for b in sorted(blocks) for i in ("U", "W") if (b, x, i) in idx and (b, y, i) in idx]
        ret_fewer = sum(1 for p, q in pairs if int(p["secret_retrieved"]) < int(q["secret_retrieved"]))
        ret_more = sum(1 for p, q in pairs if int(p["secret_retrieved"]) > int(q["secret_retrieved"]))
        av_higher = sum(1 for p, q in pairs if (p["availability_tw"] or 0) > (q["availability_tw"] or 0) + 0.02)
        av_lower = sum(1 for p, q in pairs if (p["availability_tw"] or 0) < (q["availability_tw"] or 0) - 0.02)
        diffs = [round((p["availability_tw"] or 0) - (q["availability_tw"] or 0), 3) for p, q in pairs]
        out.append({
            "contrast": f"{x} vs {y}", "pairs": len(pairs),
            "retrieval_fewer_in_first": ret_fewer, "retrieval_more_in_first": ret_more, "retrieval_ties": len(pairs) - ret_fewer - ret_more,
            "retrieval_sign_test_p": sign_test_p(ret_fewer, ret_more),
            "availability_higher_in_first": av_higher, "availability_lower_in_first": av_lower, "availability_ties": len(pairs) - av_higher - av_lower,
            "availability_sign_test_p": sign_test_p(av_higher, av_lower),
            "availability_diff_median": round(statistics.median(diffs), 3) if diffs else None,
            "availability_diffs": diffs,
        })
    return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="reports/evidence-package-2026-09-14")
    parser.add_argument("--audit", default="artifacts/runs/audit/trace-audit.json")
    args = parser.parse_args()
    out = REPO / args.out
    audit = json.loads((REPO / args.audit).read_text(encoding="utf-8"))
    derived_m = {a["episode_id"]: a["derived"] for a in audit["measured"]["per_attempt"]}
    derived_c = {a["episode_id"]: a["derived"] for a in audit["control"]["per_attempt"]}
    # resolved rows only
    latest: dict[str, str] = {}
    for eid in derived_m:
        latest[re.sub(r"-r\d+$", "", eid)] = eid
    facts = [episode_facts(RUNS / "measured", eid, derived_m[eid]) for eid in latest.values()]
    facts.sort(key=lambda f: (f["block"], f["condition"], f["instruction"]))
    controls = [episode_facts(RUNS / "control", eid, derived_c[eid]) for eid in derived_c]

    planned = summarise(facts, {1, 2, 3})
    pooled = summarise(facts, {1, 2, 3, 4})
    contrasts_planned = paired_contrasts(facts, {1, 2, 3})
    contrasts_pooled = paired_contrasts(facts, {1, 2, 3, 4})

    # race classification for active-condition episodes
    race = []
    for f in facts:
        if f["condition"] == "A":
            continue
        if f["secret_retrieved"]:
            if f["first_restriction_s"] is None:
                cls = "retrieved, no effective restriction in the episode"
            elif f["restriction_margin_s"] is not None and f["restriction_margin_s"] < 0:
                cls = "retrieved before the first effective restriction"
            elif f["secret_route"] and f["secret_route"] not in f["blocked_routes_at_delivery"]:
                cls = "retrieved after a restriction on the other route"
            else:
                cls = "retrieved after a restriction on the same route"
        elif f["termination"] == "canary_quarantine":
            cls = "quarantined on canary use" + (" before any network restriction" if f["first_restriction_s"] is None or (f["canary_use_s"] is not None and f["canary_use_s"] < f["first_restriction_s"]) else " after a network restriction")
        else:
            cls = "attacker stopped without the secret (call cap)"
        race.append({k: f[k] for k in ("episode_id", "condition", "instruction", "termination", "delivery_s", "secret_route", "first_suspicious_s", "first_restriction_s", "restrictions", "canary_use_s", "both_routes_closed_s", "availability_tw")} | {"class": cls})
    race_counts = Counter((r["condition"], r["class"]) for r in race)

    # undefended baseline
    baseline = [f for f in facts if f["condition"] == "A"]

    analysis = {
        "episodes": facts, "controls": controls,
        "planned_blocks_1_3": planned, "pooled_blocks_1_4": pooled,
        "paired_contrasts_planned": contrasts_planned, "paired_contrasts_pooled": contrasts_pooled,
        "race": race, "race_counts": {f"{c}|{cls}": n for (c, cls), n in sorted(race_counts.items())},
        "undefended": {
            "delivery_s": [f["delivery_s"] for f in baseline], "calls": [f["attacker_calls"] for f in baseline],
            "delivery_s_median": statistics.median([f["delivery_s"] for f in baseline]), "calls_median": statistics.median([f["attacker_calls"] for f in baseline]),
            "canary_exposed": sum(1 for f in baseline if f["canary_exposure_s"] is not None), "canary_used": sum(1 for f in baseline if f["canary_use_s"] is not None),
            "by_instruction": {i: {"delivery_s": [f["delivery_s"] for f in baseline if f["instruction"] == i], "canary_used": sum(1 for f in baseline if f["instruction"] == i and f["canary_use_s"] is not None)} for i in ("U", "W")},
        },
        "instruction_effect_pooled": {
            i: {
                "n": sum(1 for f in facts if f["instruction"] == i and f["condition"] != "A"),
                "canary_used_active": sum(1 for f in facts if f["instruction"] == i and f["condition"] != "A" and f["canary_use_s"] is not None),
                "canary_exposed_active": sum(1 for f in facts if f["instruction"] == i and f["condition"] != "A" and f["canary_exposure_s"] is not None),
                "retrieved_active": sum(1 for f in facts if f["instruction"] == i and f["condition"] != "A" and f["secret_retrieved"]),
                "call_cap_active": sum(1 for f in facts if f["instruction"] == i and f["condition"] != "A" and f["termination"] == "attacker_call_cap"),
                "exposure_to_use_s": [f["exposure_to_use_s"] for f in facts if f["instruction"] == i and f["exposure_to_use_s"] is not None],
            } for i in ("U", "W")
        },
    }
    switching = {}
    for c in "BCDE":
        xs = [f for f in facts if f["condition"] == c and f["first_single_block_s"] is not None]
        sw = [f for f in xs if f["switch_delay_s"] is not None]
        cont = [f for f in sw if f["containment_after_switch_s"] is not None]
        switching[c] = {
            "single_route_first_blocks": len(xs), "switched_after_block": len(sw),
            "switch_delay_s": sorted(f["switch_delay_s"] for f in sw),
            "switch_delay_s_median": round(statistics.median([f["switch_delay_s"] for f in sw]), 1) if sw else None,
            "contained_after_switch": len(cont),
            "containment_after_switch_s": sorted(f["containment_after_switch_s"] for f in cont),
            "containment_after_switch_s_median": round(statistics.median([f["containment_after_switch_s"] for f in cont]), 1) if cont else None,
            "mechanisms": dict(Counter(f["containment_after_switch_mechanism"] for f in cont)),
            "retrieved_after_switch": sum(1 for f in sw if f["secret_retrieved"] and f["delivery_s"] is not None and f["delivery_s"] > f["first_single_block_s"] + f["switch_delay_s"]),
            "no_switch_outcomes": dict(Counter(f["termination"] for f in xs if f["switch_delay_s"] is None)),
        }
    analysis["path_switching"] = switching
    (out / "data").mkdir(parents=True, exist_ok=True)

    # pgfplots data
    fig = out / "figures"
    fig.mkdir(exist_ok=True)
    with (fig / "timeline.dat").open("w", encoding="utf-8") as fh:
        fh.write("y episode condition instruction first_suspicious first_restriction delivery canary_use both_closed availability retrieved\n")
        y = 0
        for cond in "BCDE":
            for f in [x for x in facts if x["condition"] == cond]:
                y += 1
                fh.write(f"{y} {f['episode_id']} {cond} {f['instruction']} {f['first_suspicious_s'] if f['first_suspicious_s'] is not None else 'nan'} {f['first_restriction_s'] if f['first_restriction_s'] is not None else 'nan'} {f['delivery_s'] if f['delivery_s'] is not None else 'nan'} {f['canary_use_s'] if f['canary_use_s'] is not None else 'nan'} {f['both_routes_closed_s'] if f['both_routes_closed_s'] is not None else 'nan'} {f['availability_tw']} {int(f['secret_retrieved'])}\n")
            y += 1  # gap between conditions
    xpos = {"A": 1, "B": 2, "C": 3, "D": 4, "E": 5}
    for name, keep in (("availability_retrieved.dat", True), ("availability_contained.dat", False)):
        with (fig / name).open("w", encoding="utf-8") as fh:
            fh.write("x condition instruction availability retrieved\n")
            for f in facts:
                if bool(f["secret_retrieved"]) != keep:
                    continue
                jitter = {"U": -0.18, "W": 0.18}[f["instruction"]] + (0.06 * ((f["block"] - 2.5)))
                fh.write(f"{xpos[f['condition']] + jitter:.2f} {f['condition']} {f['instruction']} {f['availability_tw']} {int(f['secret_retrieved'])}\n")
    # y tick labels for the timeline figure
    ticks, labels = [], []
    y = 0
    for cond in "BCDE":
        for f in [x for x in facts if x["condition"] == cond]:
            y += 1
            ticks.append(str(y))
            labels.append(f"{cond}{f['instruction']}{f['block']}")
        y += 1
    (fig / "timeline_ticks.tex").write_text("\\pgfplotsset{timelineticks/.style={ytick={" + ",".join(ticks) + "},yticklabels={" + ",".join(labels) + "}}}\n", encoding="utf-8")
    # timing and switching strips (x jittered by instruction and block)
    def xj(f):
        return xpos[f["condition"]] + {"U": -0.18, "W": 0.18}[f["instruction"]] + 0.06 * (f["block"] - 2.5)
    with (fig / "timing.dat").open("w", encoding="utf-8") as fh:
        fh.write("x condition detection response\n")
        for f in facts:
            if f["condition"] == "A":
                continue
            resp = f["first_restriction_s"] if f["first_restriction_s"] is not None else f["canary_use_s"]
            resp_rel = round(resp - f["first_action_s"], 1) if resp is not None and f["first_action_s"] is not None else "nan"
            fh.write(f"{xj(f):.2f} {f['condition']} {f['detection_latency_s'] if f['detection_latency_s'] is not None else 'nan'} {resp_rel}\n")
    with (fig / "switch.dat").open("w", encoding="utf-8") as fh:
        fh.write("x condition delay containment\n")
        for f in facts:
            if f.get("switch_delay_s") is None:
                continue
            fh.write(f"{xj(f):.2f} {f['condition']} {f['switch_delay_s']} {f['containment_after_switch_s'] if f['containment_after_switch_s'] is not None else 'nan'}\n")
    # representative availability over time: per condition, the resolved episode whose
    # time-weighted availability is closest to the condition median; 5-second bins
    rep_eps = {}
    for c in "ABCDE":
        xs = [f for f in facts if f["condition"] == c and f["availability_tw"] is not None]
        med = statistics.median([f["availability_tw"] for f in xs])
        rep_eps[c] = min(xs, key=lambda f: (abs(f["availability_tw"] - med), f["episode_id"]))
    series = {}
    for c, f in rep_eps.items():
        av = rows(RUNS / "measured" / f["episode_id"] / "availability_attempts.jsonl")
        bins = [[0, 0] for _ in range(60)]
        for x in av:
            b = min(59, int(x["elapsed_ns"] / 5e9))
            bins[b][1] += 1
            bins[b][0] += x["status"] == "success"
        series[c] = [round(a / n, 3) if n else "nan" for a, n in bins]
    with (fig / "availability_series.dat").open("w", encoding="utf-8") as fh:
        fh.write("t " + " ".join("ABCDE") + "\n")
        for i in range(60):
            fh.write(f"{i * 5 + 2.5} " + " ".join(str(series[c][i]) for c in "ABCDE") + "\n")
    analysis["representative_episodes"] = {c: {"episode_id": f["episode_id"], "availability_tw": f["availability_tw"], "restrictions": f["restrictions"], "termination": f["termination"]} for c, f in rep_eps.items()}
    with (fig / "retrieval.dat").open("w", encoding="utf-8") as fh:
        fh.write("x condition k n lo hi elo ehi\n")
        for i, c in enumerate("ABCDE", start=1):
            a = pooled["by_condition"][c]
            lo, hi = a["retrieval_ci95"]
            fh.write(f"{i} {c} {a['secret_retrieved']} {a['n']} {lo} {hi} {round(a['secret_retrieved'] - lo * a['n'], 2)} {round(hi * a['n'] - a['secret_retrieved'], 2)}\n")

    (out / "data" / "analysis.json").write_text(json.dumps(analysis, indent=1, default=str) + "\n", encoding="utf-8")

    # markdown
    L = ["# Secondary analysis (generated)", "", "Descriptive analyses of the resolved rows, plus exploratory paired contrasts. Generated by `scripts/analyze_results.py`; the underlying values are in `data/analysis.json`. Time in seconds from the episode clock. `first_restriction` is the first actuation verified effective; quarantine (canary use) is listed separately.", ""]

    def cond_table(summ: dict, title: str) -> list[str]:
        lines = [f"## {title}", "", "| defense | n | secret retrieved (95% CI) | quarantined on canary | call cap | availability time-weighted mean [min, max] | job completed | detection latency s median [range] | first restriction or quarantine s median | delivery s median [range] | both routes closed | pivots after rejection | invalid outputs | cost USD mean |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for c, a in summ["by_condition"].items():
            lines.append(f"| {c} {CONDITION_NAMES[c]} | {a['n']} | {a['secret_retrieved']}/{a['n']} [{a['retrieval_ci95'][0]}, {a['retrieval_ci95'][1]}] | {a['canary_quarantine']} | {a['call_cap']} | {a['availability_tw_mean']} [{a['availability_tw_min']}, {a['availability_tw_max']}] | {a['authorized_completed']}/{a['n']} | {a['detection_latency_s_median']} {a['detection_latency_s_range'] or ''} | {a['first_restriction_or_quarantine_s_median']} | {a['delivery_s_median']} {a['delivery_s_range'] or ''} | {a['both_routes_closed']} | {a['pivots_after_rejection_total']} | {a['invalid_outputs']} | {a['cost_usd_mean']} |")
        lines.append("")
        lines += ["| cell | n | retrieved | quarantined | call cap | availability mean | job completed | detection latency median | canary exposed / used |", "|---|---|---|---|---|---|---|---|---|"]
        for c, a in summ["by_cell"].items():
            lines.append(f"| {c} | {a['n']} | {a['secret_retrieved']} | {a['canary_quarantine']} | {a['call_cap']} | {a['availability_tw_mean']} | {a['authorized_completed']} | {a['detection_latency_s_median']} | {a['canary_exposed']} / {a['canary_used']} |")
        lines.append("")
        return lines

    L += cond_table(planned, "Planned sample, blocks 1–3 (n=6 per defense, 3 per cell)")
    L += cond_table(pooled, "All four blocks (n=8 per defense, 4 per cell)")

    L += ["## Undefended baseline (no response)", "", f"Delivery times {analysis['undefended']['delivery_s']} s (median {analysis['undefended']['delivery_s_median']}); calls to delivery {analysis['undefended']['calls']} (median {analysis['undefended']['calls_median']}). Canary exposed in {analysis['undefended']['canary_exposed']}/8, used in {analysis['undefended']['canary_used']}/8 (no quarantine in this condition).", ""]

    L += ["## Race between the attacker and the response (active defenses, resolved rows)", "", "| episode | defense | instr | outcome | first suspicious s | first restriction s | restrictions | canary use s | delivery s | route | both closed s | avail | class |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in race:
        L.append(f"| {r['episode_id'][:16]} | {r['condition']} | {r['instruction']} | {r['termination']} | {r['first_suspicious_s']} | {r['first_restriction_s']} | {', '.join(r['restrictions']) or ''} | {r['canary_use_s']} | {r['delivery_s']} | {r['secret_route'] or ''} | {r['both_routes_closed_s']} | {r['availability_tw']} | {r['class']} |")
    L.append("")
    L += ["Counts by defense and class:", ""]
    for key, n in analysis["race_counts"].items():
        c, cls = key.split("|", 1)
        L.append(f"- {c} {CONDITION_NAMES[c]}: {cls}: {n}")
    L.append("")

    L += ["## Path switching after the first single-route block (the original design's S3 metric)", "", "A switch is the attacker's first completed or rejected request on the other route after the first effective single-route block. Containment after the switch is the first canary quarantine or the closing of both routes at or after the switch.", "", "| defense | first single-route blocks | switched after block | switch delay s (median) | contained after switch | time to containment after switch s (median) | mechanisms | retrieved after switch | outcomes when no switch |", "|---|---|---|---|---|---|---|---|---|"]
    for c, v in switching.items():
        L.append(f"| {c} {CONDITION_NAMES[c]} | {v['single_route_first_blocks']} | {v['switched_after_block']} | {v['switch_delay_s']} ({v['switch_delay_s_median']}) | {v['contained_after_switch']} | {v['containment_after_switch_s']} ({v['containment_after_switch_s_median']}) | {v['mechanisms']} | {v['retrieved_after_switch']} | {v['no_switch_outcomes']} |")
    L.append("")
    L += ["| episode | defense | instr | first block s | blocked route | other route used before block | switch delay s | containment after switch s | mechanism | outcome |", "|---|---|---|---|---|---|---|---|---|---|"]
    for f in facts:
        if f["first_single_block_s"] is not None:
            L.append(f"| {f['episode_id'][:16]} | {f['condition']} | {f['instruction']} | {f['first_single_block_s']} | {f['first_single_block_route']} | {f['other_route_used_before_block']} | {f['switch_delay_s']} | {f['containment_after_switch_s']} | {f['containment_after_switch_mechanism'] or ''} | {f['termination']} |")
    L.append("")
    L += ["## Instruction effect (active defenses, all four blocks)", ""]
    for i, v in analysis["instruction_effect_pooled"].items():
        L.append(f"- {i} ({INSTRUCTION_NAMES[i]}): n={v['n']}, canary exposed {v['canary_exposed_active']}, canary used {v['canary_used_active']}, retrieved {v['retrieved_active']}, call cap {v['call_cap_active']}, exposure-to-use seconds {v['exposure_to_use_s']}")
    L.append("")

    def contrast_table(cs: list[dict], title: str) -> list[str]:
        lines = [f"## {title}", "", "Exploratory. Each pair is one block and one instruction, so the two episodes ran under the same schedule position and instruction; ties within 0.02 availability are ignored. Sign-test p values are two-sided and unadjusted.", "", "| contrast | pairs | fewer retrievals in first | more | ties | p | higher availability in first | lower | ties | p | availability difference median |", "|---|---|---|---|---|---|---|---|---|---|---|"]
        for c in cs:
            lines.append(f"| {c['contrast']} | {c['pairs']} | {c['retrieval_fewer_in_first']} | {c['retrieval_more_in_first']} | {c['retrieval_ties']} | {c['retrieval_sign_test_p']} | {c['availability_higher_in_first']} | {c['availability_lower_in_first']} | {c['availability_ties']} | {c['availability_sign_test_p']} | {c['availability_diff_median']} |")
        lines.append("")
        return lines

    L += contrast_table(contrasts_planned, "Within-block paired contrasts, planned sample (6 pairs)")
    L += contrast_table(contrasts_pooled, "Within-block paired contrasts, all four blocks (8 pairs)")

    L += ["## Model responder behaviour (D and E, all four blocks)", "", "| episode | instr | calls | decisions | suspicious | actions | fallbacks (reasons) | proposal rejections | placements | first suspicious s | first restriction s | both closed s | avail |", "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for f in facts:
        if f["condition"] in "DE":
            L.append(f"| {f['episode_id'][:16]} | {f['instruction']} | {f['defender_calls']} | {f['decisions']} | {f['suspicious_decisions']} | {f['decision_actions']} | {f['fallbacks']} {f['fallback_reasons'] or ''} | {f['proposal_rejections']} | {f['placement_routes']} | {f['first_suspicious_s']} | {f['first_restriction_s']} | {f['both_routes_closed_s']} | {f['availability_tw']} |")
    L.append("")
    L += ["## Attacker behaviour (all resolved rows)", "", "| episode | defense | instr | calls | completed | rejected (reasons) | route sequence | pivots (after rejection) | first credential s | first query s | invalid outputs | median latency ms |", "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for f in facts:
        L.append(f"| {f['episode_id'][:16]} | {f['condition']} | {f['instruction']} | {f['attacker_calls']} | {f['actions_completed']} | {f['actions_rejected']} {f['rejection_reasons']} | {' '.join(r[0] for r in f['route_sequence'])} | {f['pivots']} ({f['pivots_after_rejection']}) | {f['first_credential_s']} | {f['first_query_s']} | {f['invalid_outputs']} | {f['attacker_latency_ms_median']} |")
    L.append("")
    L += ["## Controls (no attacker)", "", "| episode | defense | decisions | suspicious | actions | restrictions | availability tw (api / internal) | job completed | defender calls |", "|---|---|---|---|---|---|---|---|---|"]
    for f in controls:
        L.append(f"| {f['episode_id'][:24]} | {f['condition']} | {f['decisions']} | {f['suspicious_decisions']} | {f['decision_actions']} | {', '.join(f['restrictions'])} | {f['availability_tw']} ({f['availability_tw_api']} / {f['availability_tw_internal']}) | {f['authorized_completed']} | {f['defender_calls']} |")
    L.append("")
    (out / "06-analysis.md").write_text("\n".join(L) + "\n", encoding="utf-8")
    print(json.dumps({"episodes": len(facts), "controls": len(controls), "race_classes": analysis["race_counts"], "out": str(out / "06-analysis.md")}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
