#!/usr/bin/env python3
"""Assemble the CHIMERA evidence package for report writing.

Collects, into one directory, everything a report author needs and nothing
that requires the harness to interpret:

- ``data/``: flat CSV/JSON tables derived from the artifacts (one row per
  attempt, one per resolved schedule row, per-cell summaries for the
  pre-registered three blocks and for all four, controls, pilots, the full
  series history across superseded attempts, provider failures) and one
  compact event timeline per resolved episode and control;
- ``provenance/``: manifests, schedules, verification stamps, budget ledger,
  evaluator summaries, the trace audit, both frozen configuration versions
  and the prompts;
- ``raw/``: verbatim copies of every measured, control and pilot episode
  directory, plus the manifests of the superseded measured attempts;
- ``05-results-tables.md``: the tables rendered as Markdown.

The hand-written documents in the package directory (README, methodology,
architecture, artifact schema, history) are never touched by this script.

Read-only with respect to ``artifacts/``; no provider or Docker calls. Run the
trace audit first so ``artifacts/runs/audit/trace-audit.json`` is current.

    .venv/bin/python scripts/audit_traces.py
    .venv/bin/python scripts/build_report_package.py
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import statistics
import subprocess
from collections import Counter, defaultdict
from decimal import Decimal
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
RUNS = REPO / "artifacts" / "runs"
HORIZON_S = 300.0


def rows(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def s(ns: int | None) -> float | None:
    return None if ns is None else round(ns / 1e9, 1)


def fmt(v) -> str:
    if v is None:
        return ""
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".") if v != int(v) else str(int(v))
    if isinstance(v, (list, tuple, dict)):
        return json.dumps(v, separators=(",", ":"))
    return str(v)


def write_csv(path: Path, records: list[dict], columns: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        for record in records:
            writer.writerow({k: fmt(record.get(k)) for k in columns})


def md_table(records: list[dict], columns: list[str], headers: list[str] | None = None) -> str:
    headers = headers or columns
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(columns)]
    for record in records:
        out.append("| " + " | ".join(fmt(record.get(c)).replace("|", "\\|") for c in columns) + " |")
    return "\n".join(out)


# --------------------------------------------------------------------------
# per-attempt rows
# --------------------------------------------------------------------------

ATTEMPT_COLUMNS = [
    "episode_id", "row_id", "attempt_index", "rerun_of", "block", "condition", "instruction",
    "code_revision", "configuration_digest", "source_tree_digest",
    "termination", "termination_audit", "infrastructure_detail",
    "secret_retrieved", "secret_delivery_s", "canary_use_s", "quarantine_verified",
    "suspicious_declared", "first_suspicious_s", "detected", "detection_latency_s",
    "restrictions", "blocked_routes_final", "first_effective_restriction_s", "first_effective_restriction_evaluator_s",
    "restriction_effective", "verified_containment", "verified_containment_audit",
    "acquired_routes", "threatened_routes", "route_changes",
    "availability_attempts", "availability_successes", "availability_per_attempt", "availability_time_weighted",
    "availability_api_per_attempt", "availability_internal_per_attempt", "availability_api_time_weighted", "availability_internal_time_weighted",
    "authorized_job_completed", "attacker_calls", "attacker_actions_started", "attacker_actions_rejected",
    "defender_calls", "defender_fallbacks", "invalid_outputs", "provider_failures",
    "cost_usd", "uncertain_cost_usd", "duration_s", "started_at_utc", "ended_at_utc", "evidence_issues", "audit_warnings",
]


def attempt_row(root: Path, manifest: list[dict], summary: dict | None, audit: dict | None, stamps_by_source: dict[str, str]) -> dict:
    eid = manifest[0]["episode_id"]
    d = root / eid
    first = manifest[0]
    last = manifest[-1]
    terminal = rows(d / "terminal.jsonl")
    lifecycle = rows(d / "lifecycle.jsonl")
    decisions = rows(d / "decisions.jsonl")
    acts = rows(d / "actuation_results.jsonl")
    pfail = rows(d / "provider_failures.jsonl")
    infra = rows(d / "infrastructure_failure.jsonl")
    placements = rows(d / "placement_results.jsonl")
    derived = (audit or {}).get("derived", {})
    checks = (audit or {}).get("checks", [])
    t = terminal[0] if terminal else {}
    row_id = re.sub(r"-r\d+$", "", eid)
    m = re.search(r"-r(\d+)$", eid)
    restrictions = [f"{a['action']['kind']}:{a['action']['target']}@{s(a['elapsed_ns'])}s{'' if a.get('effective') else '(not effective)'}" for a in acts]
    by_route = derived.get("availability_by_route") or {}
    tw_route = derived.get("availability_time_weighted_by_route") or {}
    att = derived.get("availability_attempts") or 0
    return {
        "episode_id": eid,
        "row_id": row_id,
        "attempt_index": int(m.group(1)) if m else 1,
        "rerun_of": first.get("rerun_of"),
        "block": first["block"],
        "condition": first["condition"],
        "instruction": first["instruction"],
        "code_revision": stamps_by_source.get(first["source_tree_digest"], ""),
        "configuration_digest": first["official_configuration_digest"],
        "source_tree_digest": first["source_tree_digest"],
        "termination": last.get("termination_reason"),
        "termination_audit": derived.get("termination"),
        "infrastructure_detail": infra[0]["detail"] if infra else None,
        "secret_retrieved": derived.get("secret_delivered"),
        "secret_delivery_s": s(derived.get("delivery_ns")),
        "canary_use_s": s(derived.get("quarantine_effective_ns")),
        "quarantine_verified": derived.get("quarantine_effective_ns") is not None,
        "suspicious_declared": derived.get("suspicious_declared"),
        "first_suspicious_s": s(derived.get("first_suspicious_ns")),
        "detected": (summary or {}).get("detected"),
        "detection_latency_s": s(derived.get("detection_latency_ns")),
        "restrictions": restrictions,
        "blocked_routes_final": derived.get("blocked_routes_final"),
        "first_effective_restriction_s": s(derived.get("first_effective_restriction_ns")),
        "first_effective_restriction_evaluator_s": s((summary or {}).get("first_effective_restriction_ns")),
        "restriction_effective": derived.get("restriction_effective"),
        "verified_containment": (summary or {}).get("verified_containment"),
        "verified_containment_audit": derived.get("verified_containment"),
        "acquired_routes": derived.get("acquired_routes"),
        "threatened_routes": derived.get("threatened_routes"),
        "route_changes": (summary or {}).get("route_changes", len([p for p in placements if p.get("effective")])),
        "availability_attempts": att,
        "availability_successes": derived.get("availability_successes"),
        "availability_per_attempt": round(derived["availability_successes"] / att, 3) if att else None,
        "availability_time_weighted": derived.get("availability_time_weighted"),
        "availability_api_per_attempt": round(by_route["api"]["successes"] / by_route["api"]["attempts"], 3) if by_route.get("api", {}).get("attempts") else None,
        "availability_internal_per_attempt": round(by_route["internal"]["successes"] / by_route["internal"]["attempts"], 3) if by_route.get("internal", {}).get("attempts") else None,
        "availability_api_time_weighted": tw_route.get("api"),
        "availability_internal_time_weighted": tw_route.get("internal"),
        "authorized_job_completed": derived.get("authorized_completed"),
        "attacker_calls": derived.get("attacker_calls"),
        "attacker_actions_started": derived.get("actions_started"),
        "attacker_actions_rejected": derived.get("actions_rejected"),
        "defender_calls": derived.get("defender_calls"),
        "defender_fallbacks": sum(1 for x in decisions if x.get("fallback_used")),
        "invalid_outputs": sum(1 for p in pfail if p.get("status") == "invalid_output"),
        "provider_failures": len(pfail),
        "cost_usd": derived.get("cost_usd"),
        "uncertain_cost_usd": derived.get("uncertain_usd"),
        "duration_s": s(t.get("duration_ns")),
        "started_at_utc": lifecycle[0]["occurred_at"] if lifecycle else None,
        "ended_at_utc": lifecycle[-1]["occurred_at"] if lifecycle else None,
        "evidence_issues": (summary or {}).get("evidence_issues"),
        "audit_warnings": [c["id"] for c in checks if c["status"] in {"warn", "fail"}],
    }


def collect_root(root: Path, audit_section: dict, stamps_by_source: dict[str, str]) -> list[dict]:
    manifest = rows(root / "manifest.jsonl")
    families: dict[str, list[dict]] = defaultdict(list)
    order: list[str] = []
    for r in manifest:
        if r["episode_id"] not in families:
            order.append(r["episode_id"])
        families[r["episode_id"]].append(r)
    summary = {a["episode_id"]: a for a in json.loads((root / "summary.json").read_text(encoding="utf-8"))["attempts"]} if (root / "summary.json").exists() else {}
    audits = {a["episode_id"]: a for a in audit_section.get("per_attempt", [])}
    return [attempt_row(root, families[eid], summary.get(eid), audits.get(eid), stamps_by_source) for eid in order]


def resolved(attempts: list[dict]) -> list[dict]:
    latest: dict[str, dict] = {}
    counts: Counter = Counter()
    for a in attempts:
        latest[a["row_id"]] = a
        counts[a["row_id"]] += 1
    out = []
    for a in latest.values():
        out.append({**a, "attempts_for_row": counts[a["row_id"]]})
    return sorted(out, key=lambda a: (a["block"], a["condition"], a["instruction"]))


# --------------------------------------------------------------------------
# per-cell summaries
# --------------------------------------------------------------------------

CELL_COLUMNS = [
    "cell", "condition", "instruction", "blocks", "n", "terminations", "secret_retrieved", "suspicious_declared", "detected",
    "restriction_effective", "verified_containment_true", "verified_containment_false", "verified_containment_undefined",
    "authorized_job_completed", "availability_per_attempt_mean", "availability_per_attempt_values",
    "availability_time_weighted_mean", "availability_time_weighted_values",
    "detection_latency_s_values", "first_effective_restriction_s_values",
    "attacker_calls_mean", "defender_calls_mean", "invalid_outputs", "cost_usd_total", "cost_usd_mean",
]


def cell_summary(resolved_rows: list[dict], blocks: set[int]) -> list[dict]:
    cells: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in resolved_rows:
        if r["block"] in blocks:
            cells[(r["condition"], r["instruction"])].append(r)
    out = []
    for (cond, instr), xs in sorted(cells.items()):
        n = len(xs)
        term = Counter(x["termination"] for x in xs)
        pa = [x["availability_per_attempt"] for x in xs if x["availability_per_attempt"] is not None]
        tw = [x["availability_time_weighted"] for x in xs if x["availability_time_weighted"] is not None]
        cost = sum(Decimal(x["cost_usd"] or "0") for x in xs)
        out.append({
            "cell": f"{cond}/{instr}", "condition": cond, "instruction": instr,
            "blocks": "-".join(str(b) for b in sorted(blocks)), "n": n,
            "terminations": dict(term),
            "secret_retrieved": sum(1 for x in xs if x["secret_retrieved"]),
            "suspicious_declared": sum(1 for x in xs if x["suspicious_declared"]),
            "detected": sum(1 for x in xs if x["detected"]),
            "restriction_effective": sum(1 for x in xs if x["restriction_effective"] is True),
            "verified_containment_true": sum(1 for x in xs if x["verified_containment"] is True),
            "verified_containment_false": sum(1 for x in xs if x["verified_containment"] is False),
            "verified_containment_undefined": sum(1 for x in xs if x["verified_containment"] is None),
            "authorized_job_completed": sum(1 for x in xs if x["authorized_job_completed"] is True),
            "availability_per_attempt_mean": round(statistics.mean(pa), 3) if pa else None,
            "availability_per_attempt_values": pa,
            "availability_time_weighted_mean": round(statistics.mean(tw), 3) if tw else None,
            "availability_time_weighted_values": tw,
            "detection_latency_s_values": [x["detection_latency_s"] for x in xs if x["detection_latency_s"] is not None],
            "first_effective_restriction_s_values": [x["first_effective_restriction_s"] for x in xs if x["first_effective_restriction_s"] is not None],
            "attacker_calls_mean": round(statistics.mean([x["attacker_calls"] for x in xs if x["attacker_calls"] is not None]), 1),
            "defender_calls_mean": round(statistics.mean([x["defender_calls"] for x in xs if x["defender_calls"] is not None]), 1),
            "invalid_outputs": sum(x["invalid_outputs"] or 0 for x in xs),
            "cost_usd_total": str(cost), "cost_usd_mean": str(round(cost / n, 6)) if n else None,
        })
    return out


# --------------------------------------------------------------------------
# timelines
# --------------------------------------------------------------------------

def timeline(root: Path, eid: str) -> str:
    d = root / eid
    events: list[tuple[float, str, str, str]] = []
    for x in rows(d / "attacker_actions.jsonl"):
        a = x["action"]
        detail = f"{a['kind']}" + (f" {a['route']}" if a.get("route") else "") + (f" {a['credential_id']}" if a.get("credential_id") else "")
        if x["status"] == "started":
            continue
        if x["status"] == "completed":
            events.append((x["elapsed_ns"] / 1e9, "attacker", "completed", detail + (f" -> {x['result'].get('kind')}" if isinstance(x.get("result"), dict) and x["result"].get("kind") else "")))
        else:
            events.append((x["elapsed_ns"] / 1e9, "attacker", x["status"], detail + (f" ({x.get('reason')})" if x.get("reason") else "")))
    for x in rows(d / "decisions.jsonl"):
        dd = x["decision"]
        act = dd["action"]
        detail = f"suspicious={dd['suspicious']} reason={dd['reason_code']} action={act['kind']}" + (f":{act['target']}" if act.get("target") else "") + f" canary={dd.get('canary_location')}" + (" (fallback)" if x.get("fallback_used") else "") + (f" evidence={','.join(dd.get('evidence_event_ids', []))}" if dd.get("evidence_event_ids") else "")
        events.append((x["elapsed_ns"] / 1e9, "defender", "decision", detail))
    for x in rows(d / "actuation_results.jsonl"):
        events.append((x["elapsed_ns"] / 1e9, "actuator", "actuation", f"{x['action']['kind']}:{x['action']['target']} applied={x['applied']} effective={x['effective']}" + (f" reason={x['reason']}" if x.get("reason") else "")))
    for x in rows(d / "placement_results.jsonl"):
        events.append((x["elapsed_ns"] / 1e9, "range", "canary placement", f"route={x.get('route')} applied={x.get('applied')} effective={x.get('effective')}" + (f" reason={x['reason']}" if x.get("reason") else "")))
    for x in rows(d / "authorized_workload.jsonl"):
        if x.get("status"):
            events.append((x["elapsed_ns"] / 1e9, "authorized job", x["status"], f"route={x.get('route')}"))
        else:
            events.append((x["elapsed_ns"] / 1e9, "authorized job", "completed" if x.get("completed") else "failed", f"route={x.get('route')}" + (f" reason={x['reason']}" if x.get("reason") else "")))
    for x in rows(d / "evaluator_events.jsonl"):
        if x["event_type"] == "data_request" and x.get("secret_delivered"):
            events.append((x["elapsed_ns"] / 1e9, "evaluator", "SECRET DELIVERED", f"actor={x.get('actor_class')} event={x['event_id']}"))
        if x["event_type"] == "restriction_result" and x.get("target") == "quarantine":
            events.append((x["elapsed_ns"] / 1e9, "evaluator", "quarantine probe", f"attacker request accepted={x['result'].get('route_available')}"))
    for x in rows(d / "defender_events.jsonl"):
        if x["event_type"] in {"canary_exposed", "canary_use"}:
            events.append((x["elapsed_ns"] / 1e9, "telemetry", x["event_type"], f"target={x.get('target')} event={x['event_id']}"))
    for x in rows(d / "infrastructure_failure.jsonl"):
        events.append((x["elapsed_ns"] / 1e9, "harness", "INFRASTRUCTURE FAILURE", x["detail"]))
    for x in rows(d / "provider_failures.jsonl"):
        events.append((x["elapsed_ns"] / 1e9, x.get("role", "provider"), f"provider {x.get('status')}", f"http={x.get('http_status')} latency_ms={x.get('latency_ms')} {x.get('detail')}"))
    term = rows(d / "terminal.jsonl")
    if term:
        events.append((term[0]["elapsed_ns"] / 1e9, "harness", "terminal", f"{term[0]['termination_reason']} secret_delivered={term[0]['secret_delivered']} authorized_completed={term[0]['authorized_completed']}"))
    events.sort(key=lambda e: e[0])
    avail = rows(d / "availability_attempts.jsonl")
    lines = [f"# Timeline `{eid}`", ""]
    meta = json.loads((d / "metadata.json").read_text(encoding="utf-8")) if (d / "metadata.json").exists() else {}
    lines.append(f"Condition {meta.get('condition')}, instruction {meta.get('instruction')}, run kind {meta.get('run_kind')}, termination {meta.get('termination_reason')}, provider requests {meta.get('provider_requests')}. Availability attempts {len(avail)} (ordinary workload, one safe-data request about every 50 ms alternating api/internal; not listed individually).")
    lines.append("")
    lines.append("| t (s) | actor | event | detail |")
    lines.append("|---|---|---|---|")
    for t_s, actor, kind, detail in events:
        lines.append(f"| {t_s:.1f} | {actor} | {kind} | {detail.replace('|', '/')} |")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# series history across superseded attempts
# --------------------------------------------------------------------------

def series_history(stamps_by_source: dict[str, str]) -> list[dict]:
    out = []
    dirs = sorted(RUNS.glob("measured-attempt*")) + [RUNS / "measured"]
    for i, root in enumerate(dirs, start=1):
        manifest = rows(root / "manifest.jsonl")
        families: dict[str, list[dict]] = defaultdict(list)
        order = []
        for r in manifest:
            if r["episode_id"] not in families:
                order.append(r["episode_id"])
            families[r["episode_id"]].append(r)
        for eid in order:
            fam = families[eid]
            d = root / eid
            infra = rows(d / "infrastructure_failure.jsonl")
            usage = rows(d / "usage.jsonl")
            cost = sum(Decimal(str(u.get("actual_usd") or 0)) for u in usage)
            out.append({
                "series": root.name, "series_index": i, "code_revision": stamps_by_source.get(fam[0]["source_tree_digest"], root.name.split("-r")[-1] if "-r" in root.name else ""),
                "episode_id": eid, "block": fam[0]["block"], "condition": fam[0]["condition"], "instruction": fam[0]["instruction"],
                "rerun_of": fam[0].get("rerun_of"), "final_status": fam[-1]["status"], "termination": fam[-1].get("termination_reason"),
                "infrastructure_detail": infra[0]["detail"] if infra else None, "provider_calls": len(usage), "cost_usd": str(cost),
                "counts_toward_results": root.name == "measured",
            })
    return out


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="reports/evidence-package-2026-09-14")
    parser.add_argument("--audit", default="artifacts/runs/audit/trace-audit.json")
    parser.add_argument("--skip-raw", action="store_true", help="do not copy raw episode directories")
    args = parser.parse_args()
    out = (REPO / args.out).resolve()
    audit = json.loads((REPO / args.audit).read_text(encoding="utf-8"))
    stamps = [json.loads(p.read_text(encoding="utf-8")) for p in (RUNS / "verification").glob("*.json")]
    stamps_by_source = {st["source_tree_digest"]: st["code_revision"][:7] for st in stamps}

    measured = collect_root(RUNS / "measured", audit["measured"], stamps_by_source)
    control = collect_root(RUNS / "control", audit["control"], stamps_by_source)
    res = resolved(measured)
    cells_3 = cell_summary(res, {1, 2, 3})
    cells_4 = cell_summary(res, {1, 2, 3, 4})
    cells_b4 = cell_summary(res, {4})

    data = out / "data"
    data.mkdir(parents=True, exist_ok=True)
    write_csv(data / "all_attempts.csv", measured, ATTEMPT_COLUMNS)
    write_csv(data / "resolved_rows.csv", res, ATTEMPT_COLUMNS + ["attempts_for_row"])
    write_csv(data / "controls.csv", control, ATTEMPT_COLUMNS)
    write_csv(data / "cell_summary_blocks_1_3_preregistered.csv", cells_3, CELL_COLUMNS)
    write_csv(data / "cell_summary_blocks_1_4_pooled.csv", cells_4, CELL_COLUMNS)
    write_csv(data / "cell_summary_block_4_only.csv", cells_b4, CELL_COLUMNS)
    (data / "all_attempts.json").write_text(json.dumps(measured, indent=1, default=str) + "\n", encoding="utf-8")
    (data / "controls.json").write_text(json.dumps(control, indent=1, default=str) + "\n", encoding="utf-8")

    # pilots
    pilots = []
    pilot_summary = json.loads((RUNS / "pilot" / "summary.json").read_text(encoding="utf-8"))["attempts"] if (RUNS / "pilot" / "summary.json").exists() else []
    for a in pilot_summary:
        d = RUNS / "pilot" / a["episode_id"]
        infra = rows(d / "infrastructure_failure.jsonl")
        pfail = rows(d / "provider_failures.jsonl")
        pilots.append({
            "episode_id": a["episode_id"], "condition": a["condition"], "instruction": a["instruction"], "termination": a["termination"],
            "secret_retrieved": a.get("secret_retrieved"), "provider_calls": a.get("provider_calls"), "cost_usd": a.get("actual_cost_usd"),
            "availability_per_attempt": round(a["availability_overall"], 3) if a.get("availability_overall") is not None else None,
            "authorized_job_completed": a.get("authorized_evaluation_completed"), "provider_failures": len(pfail),
            "infrastructure_detail": infra[0]["detail"] if infra else None, "evidence_issues": a.get("evidence_issues"),
        })
    write_csv(data / "pilots.csv", pilots, ["episode_id", "condition", "instruction", "termination", "secret_retrieved", "provider_calls", "cost_usd", "availability_per_attempt", "authorized_job_completed", "provider_failures", "infrastructure_detail", "evidence_issues"])

    history = series_history(stamps_by_source)
    write_csv(data / "series_history.csv", history, ["series", "series_index", "code_revision", "episode_id", "block", "condition", "instruction", "rerun_of", "final_status", "termination", "infrastructure_detail", "provider_calls", "cost_usd", "counts_toward_results"])

    failures = []
    for root, kind in ((RUNS / "measured", "measured"), (RUNS / "control", "control"), (RUNS / "pilot", "pilot")):
        for d in sorted(root.glob("*/")):
            for p in rows(d / "provider_failures.jsonl"):
                failures.append({"run_kind": kind, "episode_id": d.name, "elapsed_s": s(p.get("elapsed_ns")), **{k: p.get(k) for k in ("role", "status", "http_status", "latency_ms", "model", "detail")}})
    write_csv(data / "provider_failures.csv", failures, ["run_kind", "episode_id", "elapsed_s", "role", "status", "http_status", "latency_ms", "model", "detail"])

    tl = data / "timelines"
    tl.mkdir(exist_ok=True)
    for a in measured:
        (tl / f"{a['episode_id']}.md").write_text(timeline(RUNS / "measured", a["episode_id"]), encoding="utf-8")
    for a in control:
        (tl / f"{a['episode_id']}.md").write_text(timeline(RUNS / "control", a["episode_id"]), encoding="utf-8")

    # provenance
    prov = out / "provenance"
    prov.mkdir(exist_ok=True)
    for src, dst in (
        (RUNS / "measured" / "manifest.jsonl", "measured-manifest.jsonl"),
        (RUNS / "measured" / "summary.json", "measured-summary.json"),
        (RUNS / "measured" / "summary.csv", "measured-summary.csv"),
        (RUNS / "control" / "manifest.jsonl", "control-manifest.jsonl"),
        (RUNS / "control" / "summary.json", "control-summary.json"),
        (RUNS / "control" / "summary.csv", "control-summary.csv"),
        (RUNS / "pilot" / "manifest.jsonl", "pilot-manifest.jsonl"),
        (RUNS / "pilot" / "summary.json", "pilot-summary.json"),
        (RUNS / "schedules" / "main.json", "schedule-4-blocks-7a3bcdd0.json"),
        (RUNS / "schedules" / "main-3blocks-db84ecf.json", "schedule-3-blocks-db84ecfd.json"),
        (RUNS / "provider-budget" / "provider-budget.json", "provider-budget-ledger.json"),
        (RUNS / "audit" / "trace-audit.json", "trace-audit.json"),
        (RUNS / "audit" / "trace-audit.md", "trace-audit-generated.md"),
    ):
        if src.exists():
            shutil.copy2(src, prov / dst)
    (prov / "verification-stamps").mkdir(exist_ok=True)
    for p in (RUNS / "verification").glob("*.json"):
        shutil.copy2(p, prov / "verification-stamps" / p.name)
    inputs = out / "inputs"
    inputs.mkdir(exist_ok=True)
    shutil.copy2(REPO / "configs" / "experiment.yaml", inputs / "experiment-4-blocks-7a3bcdd0.yaml")
    three = subprocess.run(["git", "show", "5390964:configs/experiment.yaml"], cwd=REPO, capture_output=True, text=True, check=False)
    if three.returncode == 0:
        (inputs / "experiment-3-blocks-db84ecfd.yaml").write_text(three.stdout, encoding="utf-8")
    for name in ("attacker_u.txt", "attacker_w.txt", "defender.txt"):
        shutil.copy2(REPO / "prompts" / name, inputs / name)
    shutil.copy2(REPO / "range" / "compose.yaml", inputs / "range-compose.yaml")

    # raw copies
    if not args.skip_raw:
        raw = out / "raw"
        for name in ("measured", "control", "pilot"):
            dst = raw / name
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(RUNS / name, dst)
        sup = raw / "superseded-measured-attempts"
        sup.mkdir(parents=True, exist_ok=True)
        for d in sorted(RUNS.glob("measured-attempt*")):
            (sup / d.name).mkdir(exist_ok=True)
            shutil.copy2(d / "manifest.jsonl", sup / d.name / "manifest.jsonl")

    # results markdown
    findings = audit["measured"]["findings"]
    lines = ["# Results tables (generated)", "", "Generated by `scripts/build_report_package.py` from the artifacts and the trace audit. Every number here can be recomputed from `raw/` with the two scripts. Values are per resolved schedule row (latest attempt per row) unless stated. Availability is given twice: per attempt (evaluator) and time-weighted (audit; see the audit report for why they differ in three rows). `first_effective_restriction_s` uses the canary-use moment for quarantine-only rows; the evaluator's value is given alongside.", ""]
    cell_cols = ["cell", "n", "terminations", "secret_retrieved", "detected", "restriction_effective", "verified_containment_true", "verified_containment_undefined", "authorized_job_completed", "availability_per_attempt_mean", "availability_time_weighted_mean", "detection_latency_s_values", "first_effective_restriction_s_values", "attacker_calls_mean", "cost_usd_total"]
    cell_heads = ["cell", "n", "terminations", "retrieved", "detected", "effective restriction", "containment true", "containment undefined", "job completed", "avail per attempt (mean)", "avail time-weighted (mean)", "detection latency s", "first effective restriction s", "attacker calls (mean)", "cost USD"]
    lines += ["## Pre-registered sample: blocks 1–3 (n=3 per cell)", "", md_table(cells_3, cell_cols, cell_heads), ""]
    lines += ["## Pooled sample: blocks 1–4 (n=4 per cell; block 4 was a post-hoc extension)", "", md_table(cells_4, cell_cols, cell_heads), ""]
    lines += ["## Block 4 alone (n=1 per cell)", "", md_table(cells_b4, cell_cols, cell_heads), ""]
    row_cols = ["episode_id", "block", "condition", "instruction", "attempts_for_row", "termination", "secret_delivery_s", "first_suspicious_s", "detection_latency_s", "restrictions", "canary_use_s", "verified_containment", "availability_per_attempt", "availability_time_weighted", "authorized_job_completed", "attacker_calls", "defender_calls", "invalid_outputs", "cost_usd"]
    lines += ["## Resolved rows", "", md_table(res, row_cols), ""]
    failed = [a for a in measured if a["termination"] == "infrastructure_failure"]
    lines += ["## Attempts that ended as infrastructure failure (kept in the manifest, rerun as -r2)", "", md_table(failed, ["episode_id", "block", "condition", "instruction", "infrastructure_detail", "attacker_calls", "restrictions", "availability_time_weighted", "cost_usd"]), ""]
    ctrl_cols = ["episode_id", "condition", "termination", "suspicious_declared", "restrictions", "availability_per_attempt", "availability_time_weighted", "availability_api_per_attempt", "availability_internal_per_attempt", "authorized_job_completed", "defender_calls", "cost_usd"]
    lines += ["## Benign-only controls (no attacker; one per active defense)", "", md_table(control, ctrl_cols), ""]
    lines += ["## Pilots (seven attempts before the freeze; not results)", "", md_table(pilots, ["episode_id", "condition", "instruction", "termination", "provider_calls", "cost_usd", "availability_per_attempt", "infrastructure_detail"]), ""]
    hist_counts = Counter((h["series"], h["termination"]) for h in history)
    series_rows = []
    for series in sorted({h["series"] for h in history}, key=lambda n: [h["series_index"] for h in history if h["series"] == n][0]):
        hs = [h for h in history if h["series"] == series]
        series_rows.append({"series": series, "code_revision": ", ".join(sorted({h["code_revision"] for h in hs if h["code_revision"]})), "attempts": len(hs), "terminations": dict(Counter(h["termination"] for h in hs)), "provider_calls": sum(h["provider_calls"] for h in hs), "cost_usd": str(sum(Decimal(h["cost_usd"]) for h in hs)), "counts_toward_results": hs[0]["counts_toward_results"]})
    lines += ["## Every measured attempt ever run (superseded series included)", "", md_table(series_rows, ["series", "code_revision", "attempts", "terminations", "provider_calls", "cost_usd", "counts_toward_results"]), "", f"Total measured attempts across all series: {len(history)}; total known cost across them: {sum(Decimal(h['cost_usd']) for h in history)} USD.", ""]
    lines += ["## Provider failures (all runs)", "", md_table(failures, ["run_kind", "episode_id", "elapsed_s", "role", "status", "http_status", "latency_ms", "detail"]), ""]
    lines += ["## Trace audit findings", "", md_table(findings, ["episode_id", "status", "id", "detail"]), ""]
    (out / "05-results-tables.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(out), "attempts": len(measured), "resolved_rows": len(res), "controls": len(control), "pilots": len(pilots), "history": len(history), "timelines": len(measured) + len(control), "raw_copied": not args.skip_raw}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
