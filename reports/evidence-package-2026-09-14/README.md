# CHIMERA evidence package, 14 September 2026

Everything needed to write the report from the measured data, in one
directory. Built from the repository at revision `2a51392` plus the artifacts
in `artifacts/runs/` after block 4 and the benign-only controls completed.
Regenerate the derived parts at any time with:

```
.venv/bin/python scripts/audit_traces.py          # independent re-derivation of every outcome
.venv/bin/python scripts/build_report_package.py  # tables, timelines, provenance, raw copies
.venv/bin/python scripts/analyze_results.py       # secondary analysis and figure data
```

## Read in this order

| file | what it is | write from it |
|---|---|---|
| `README.md` | this index, the source-of-truth rules, the disclosures | limitations, reproducibility |
| `01-methodology-as-executed.md` | the method that actually produced the data, with every deviation from the planning protocol | methods section |
| `02-architecture.md` | range topology, control plane, episode sequence, condition matrix, artifact flow (Mermaid) | system section, figures |
| `03-artifact-schema.md` | every artifact file and field, enumerations, metric definitions | appendix, reproducibility |
| `04-history.md` | pilots, six series attempts, defects found and fixed, spend | limitations, engineering lessons |
| `05-results-tables.md` | generated tables: pre-registered 30, pooled 40, block 4 alone, resolved rows, failed attempts, controls, pilots, full attempt history, provider failures, audit findings | results section |
| `06-analysis.md` | generated secondary analysis: exact intervals, race between attacker and response per episode, response lags, attacker and responder behaviour, instruction effect, within-block paired contrasts, controls | results, discussion |
| `../trace-audit-2026-09-14.md` | the trace audit with interpretation | results caveats |
| `../../adaptive_containment_report.tex` | the report, written on the sprint template around its original research question (builds with `latexmk -pdf`) | |
| `data/` | the same tables as CSV/JSON, `analysis.json` behind `06-analysis.md`, and one event timeline per episode (`data/timelines/`) | figures, representative timeline |
| `figures/` | pgfplots data files used by the report's figures (timeline of decisive events, availability per episode) | figures |
| `provenance/` | manifests, both schedules, verification stamps, budget ledger, evaluator summaries, audit JSON | reproducibility, appendix |
| `inputs/` | both frozen configurations, the three prompts, the compose file | methods, appendix |
| `raw/` | verbatim episode directories for all 42 measured attempts, 4 controls, 7 pilots; manifests of the five superseded series | anything not already tabulated |

The planning documents (`../../CHIMERA_Experiment_Protocol.md`,
`../../CHIMERA_Build_Plan.md`) describe intent. Where they disagree with this
package, this package is what was run.

## Source-of-truth rules

1. For any number about an episode, `raw/<root>/<episode>/` is the truth; `data/` and `05-results-tables.md` are derived from it by the two scripts and can be regenerated.
2. For the design of a measured episode, use its own `configuration_snapshot.json` (blocks 1–3 carry the three-block configuration `db84ecfd…`; block 4 carries `7a3bcdd0…`; the only difference is `schedule.blocks`).
3. Result tables use the latest attempt per schedule row ("resolved row"). Every attempt, including the two that ended as infrastructure failure and were rerun, is in `data/all_attempts.csv` and stays in the manifest.
4. Availability is reported two ways. `availability_per_attempt` is the evaluator's ratio of successful ordinary requests. `availability_time_weighted` is the audit's share of the horizon during which the route was serving. They agree within 0.02 except in three rows where failed requests hung (see the audit); use the time-weighted figure or show both.
5. For quarantine-only rows, "first effective restriction" is the canary-use moment (`first_effective_restriction_s`); the evaluator's figure for those rows is the final probe at about 300 s and is given alongside.

## Disclosures the report must carry

- **Post-hoc fourth block.** The protocol pre-registered 30 episodes and said to decide any fourth block before examining comparative outcomes. The block 1–3 outcomes were examined first; block 4 was then run as one complete balanced block chosen on time and cost. Report the pre-registered 30 (`cell_summary_blocks_1_3_preregistered.csv`) and the pooled 40 (`cell_summary_blocks_1_4_pooled.csv`) separately; do not present the 40 as the planned sample.
- **Sample size forbids rate claims.** Three or four episodes per cell support descriptive tables and per-episode timelines only. The protocol (section 8) rules out precise probabilities and superiority claims.
- **Two reruns.** `b02-r02-B-U` (20 s read timeout on the first provider call) and `b04-r04-B-U` (authorized job transport exception under web isolation, a harness classification defect). Both originals are in the manifest and `data/all_attempts.csv`.
- **Planning-document drift.** The protocol names Claude as the defender and older caps; the executed defender is Gemini 3.7 Flash with 8 calls and 1536 output tokens, the attacker GLM 5.3 with 16 calls and 2048 output tokens, both through OpenRouter with pinned providers. `01-methodology-as-executed.md` lists every such difference.
- **Benign-only controls are functional checks, one per defense**, not false-positive rates.
- **The static playbook fires on the authorized job.** In the B and C controls the frozen playbook blocked `web_api` at 150 s on the scheduled authorized job's own request sequence with no attacker present. This is a property of the frozen policy, reported as such.
- **Scope.** A two-route toy application, five brokered actions, no shell, no exploits, no Internet. Nothing here speaks to production security or to the models' general capabilities.

## Headline numbers (resolved rows, pooled 40; details in `05-results-tables.md`)

| condition | secret retrieved | availability, time-weighted mean (U / W) | authorized job completed |
|---|---|---|---|
| A no containment | 8/8 | 1.00 / 1.00 | 8/8 |
| B static playbook | 0/8 | 0.57 / 0.42 | 6/8 |
| C playbook + heuristic placement | 2/8 | 0.76 / 0.49 | 4/8 |
| D LLM defender, fixed canary | 3/8 | 0.17 / 0.20 | 1/8 |
| E LLM defender, adaptive canary | 4/8 | 0.66 / 0.31 | 3/8 |

Controls (no attacker): B and C blocked `web_api` at 150 s (availability 0.75);
D and E took no action (availability 1.00).

Total known spend for everything ever run: $0.97 (132 measured attempts across
six series $0.93, seven pilots $0.03, four controls $0.003). The final data
(blocks 1–4, controls, pilots) cost $0.45; the five superseded series $0.51.
