#!/usr/bin/env python3
"""
build_matrix.py — render the control-by-phase-by-cost matrix.

Reads:
    data/phases.yaml     rows
    data/controls.yaml   columns (+ cost / verifiability legend)
    data/matrix.csv      cells, format "verdict|note"

Writes:
    out/matrix.md        Markdown (paste into report/report.md)
    out/matrix.html      standalone HTML (report appendix)

Only third-party dependency: PyYAML (`pip install pyyaml`).
Run from the repo root:  python3 scripts/build_matrix.py   (or `make matrix`)
"""

import csv
import html
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # keep the error friendly for beginners
    sys.exit("PyYAML missing. Run: pip install pyyaml  (or: make deps)")

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"
OUT = ROOT / "out"

VALID_VERDICTS = {"yes", "partial", "no", "TODO"}
SYMBOL = {"yes": "Y", "partial": "P", "no": "-", "TODO": "?"}


# ---------------------------------------------------------------- loading

def load_yaml(path, key):
    with open(path, encoding="utf-8") as f:
        doc = yaml.safe_load(f)
    return doc[key]


def load_matrix(path):
    """Return (control_ids, {phase_id: {control_id: (verdict, note)}})."""
    with open(path, encoding="utf-8", newline="") as f:
        lines = [ln for ln in f if not ln.lstrip().startswith("#")]
    reader = csv.reader(lines)
    header = next(reader)
    control_ids = header[1:]
    cells = {}
    for row in reader:
        if not row or not row[0].strip():
            continue
        phase_id = row[0].strip()
        cells[phase_id] = {}
        for cid, raw in zip(control_ids, row[1:]):
            verdict, _, note = raw.partition("|")
            verdict = verdict.strip()
            if verdict not in VALID_VERDICTS:
                sys.exit(f"matrix.csv: bad verdict {verdict!r} at {phase_id}/{cid}")
            cells[phase_id][cid] = (verdict, note.strip())
    return control_ids, cells


def validate(phases, controls, control_ids, cells):
    phase_ids = [p["id"] for p in phases]
    known_controls = {c["id"] for c in controls}
    problems = []
    for cid in control_ids:
        if cid not in known_controls:
            problems.append(f"matrix column {cid} not in controls.yaml")
    for pid in phase_ids:
        if pid not in cells:
            problems.append(f"phase {pid} has no row in matrix.csv")
    for pid in cells:
        if pid not in phase_ids:
            problems.append(f"matrix row {pid} not in phases.yaml")
    if problems:
        sys.exit("Validation failed:\n  " + "\n  ".join(problems))


# ---------------------------------------------------------------- stats

def summarize(phases, control_ids, cells):
    """Small numbers a judge wants: TODO count, uncovered phases, coverage per control."""
    todo = 0
    uncovered = []
    coverage = {cid: 0 for cid in control_ids}
    for p in phases:
        row = cells[p["id"]]
        has_yes = False
        for cid, (verdict, _) in row.items():
            if verdict == "TODO":
                todo += 1
            if verdict == "yes":
                has_yes = True
                coverage[cid] += 1
        if not has_yes:
            uncovered.append(p["id"])
    return {"todo": todo, "uncovered": uncovered, "coverage": coverage}


# ---------------------------------------------------------------- markdown

def render_markdown(phases, controls, control_ids, cells, stats):
    out = []
    out.append("# Control × Attack-Phase × Cost Matrix\n")
    out.append("Legend: **Y** = would interrupt, **P** = partial, **-** = no, **?** = TODO. "
               "Hover/see notes in the HTML version.\n")
    out.append(f"Status: {stats['todo']} cells still TODO. "
               f"Phases with no `yes`: {', '.join(stats['uncovered']) or 'none'}.\n")

    # matrix
    out.append("| Phase | " + " | ".join(control_ids) + " |")
    out.append("|---|" + "|".join(":-:" for _ in control_ids) + "|")
    for p in phases:
        row = cells[p["id"]]
        syms = [SYMBOL[row[cid][0]] for cid in control_ids]
        out.append(f"| {p['id']} {p['name']} | " + " | ".join(syms) + " |")
    out.append("")

    # controls legend with cost + verifiability
    out.append("## Controls legend\n")
    out.append("| ID | Control | Category | Ext. verifiable | Impl cost | Op cost | Phases interrupted |")
    out.append("|---|---|---|---|---|---|---|")
    for c in controls:
        ver = "yes" if c["verifiable_externally"]["value"] else "no"
        out.append(
            f"| {c['id']} | {c['name']} | {c['category']} | {ver} | "
            f"{c['impl_cost']['level']} | {c['operating_cost']['level']} | "
            f"{stats['coverage'].get(c['id'], 0)} |"
        )
    out.append("")

    # phase list
    out.append("## Phases\n")
    for p in phases:
        out.append(f"- **{p['id']} — {p['name']}.** {p['one_line_description'].strip()} "
                   f"_(source: {p['source_ref']})_")
    out.append("")
    return "\n".join(out)


# ---------------------------------------------------------------- html

CSS = """
body { font-family: system-ui, sans-serif; margin: 2rem; color: #222; }
table { border-collapse: collapse; margin-bottom: 2rem; }
th, td { border: 1px solid #bbb; padding: 4px 8px; font-size: 0.9rem; vertical-align: top; }
th { background: #f0f0f0; }
td.yes { background: #c8e6c9; text-align: center; }
td.partial { background: #fff3cd; text-align: center; }
td.no { background: #f5f5f5; text-align: center; color: #999; }
td.TODO { background: #ffe0e0; text-align: center; }
td.phase { white-space: nowrap; font-weight: 600; }
.small { color: #666; font-size: 0.85rem; }
"""


def render_html(phases, controls, control_ids, cells, stats):
    e = html.escape
    by_id = {c["id"]: c for c in controls}
    h = ["<!doctype html><html><head><meta charset='utf-8'>",
         "<title>Control × Phase × Cost Matrix</title>",
         f"<style>{CSS}</style></head><body>",
         "<h1>Control × Attack-Phase × Cost Matrix</h1>",
         "<p class='small'>Legend: Y = would interrupt, P = partial, - = no, ? = TODO. "
         "Hover a cell for its note; hover a column header for the control name.</p>",
         f"<p class='small'>Status: {stats['todo']} cells still TODO. "
         f"Phases with no <code>yes</code>: {e(', '.join(stats['uncovered']) or 'none')}.</p>",
         "<table><thead><tr><th>Phase</th>"]
    for cid in control_ids:
        h.append(f"<th title='{e(by_id[cid]['name'])}'>{e(cid)}</th>")
    h.append("</tr></thead><tbody>")
    for p in phases:
        h.append(f"<tr><td class='phase' title='{e(p['one_line_description'].strip())}'>"
                 f"{e(p['id'])} {e(p['name'])}</td>")
        for cid in control_ids:
            verdict, note = cells[p["id"]][cid]
            h.append(f"<td class='{verdict}' title='{e(note)}'>{SYMBOL[verdict]}</td>")
        h.append("</tr>")
    h.append("</tbody></table>")

    h.append("<h2>Controls legend</h2><table><thead><tr>"
             "<th>ID</th><th>Control</th><th>Category</th><th>Externally verifiable — how</th>"
             "<th>Impl cost</th><th>Op cost</th><th>Evidence a third party can check</th>"
             "<th>Phases interrupted</th></tr></thead><tbody>")
    for c in controls:
        v = c["verifiable_externally"]
        h.append(
            "<tr>"
            f"<td>{e(c['id'])}</td><td><b>{e(c['name'])}</b><br><span class='small'>{e(c['description'].strip())}</span></td>"
            f"<td>{e(c['category'])}</td>"
            f"<td>{'yes' if v['value'] else 'no'} — {e(v['how'])}</td>"
            f"<td>{e(c['impl_cost']['level'])}<br><span class='small'>{e(c['impl_cost']['note'])}</span></td>"
            f"<td>{e(c['operating_cost']['level'])}<br><span class='small'>{e(c['operating_cost']['note'])}</span></td>"
            f"<td>{e(c['evidence_required'])}</td>"
            f"<td>{stats['coverage'].get(c['id'], 0)}</td>"
            "</tr>"
        )
    h.append("</tbody></table>")

    h.append("<h2>Phases</h2><ol>")
    for p in phases:
        h.append(f"<li><b>{e(p['id'])} — {e(p['name'])}.</b> {e(p['one_line_description'].strip())} "
                 f"<span class='small'>(source: {e(p['source_ref'])})</span></li>")
    h.append("</ol></body></html>")
    return "\n".join(h)


# ---------------------------------------------------------------- main

def main():
    phases = load_yaml(DATA / "phases.yaml", "phases")
    controls = load_yaml(DATA / "controls.yaml", "controls")
    control_ids, cells = load_matrix(DATA / "matrix.csv")
    validate(phases, controls, control_ids, cells)
    stats = summarize(phases, control_ids, cells)

    OUT.mkdir(exist_ok=True)
    (OUT / "matrix.md").write_text(render_markdown(phases, controls, control_ids, cells, stats), encoding="utf-8")
    (OUT / "matrix.html").write_text(render_html(phases, controls, control_ids, cells, stats), encoding="utf-8")

    print(f"wrote {OUT / 'matrix.md'}")
    print(f"wrote {OUT / 'matrix.html'}")
    print(f"{len(phases)} phases × {len(control_ids)} controls; {stats['todo']} cells TODO; "
          f"uncovered phases: {', '.join(stats['uncovered']) or 'none'}")


if __name__ == "__main__":
    main()
