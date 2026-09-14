# CHIMERA: adaptive AI-based containment of autonomous cyber attacks

Team Southside, Apart Research AI Incident Response Sprint (11 to 13 September 2026), Track 1: Containment Standards.

CHIMERA is a small, fully isolated Docker cyber range in which an LLM-driven
attacker tries to retrieve a dummy secret through one of two application
routes while a defender, seeing only sanitized telemetry, proposes containment
actions that a policy engine validates and executes. It was built to test one
question raised by the July 2026 OpenAI and Hugging Face incident:

> Does a defender that uses incident history reduce attack success and impact
> compared with a fixed response policy, particularly when the attacker changes
> paths after containment?

The report is `adaptive_containment_report.pdf` (source
`adaptive_containment_report.tex`). Every number in it comes from the evidence
package under `reports/evidence-package-2026-09-14/`.

## Results in brief

40 measured episodes (30 planned, 10 added after the first results were
reviewed) and 4 benign-only controls. Attacker GLM 5.3, AI defender Gemini 3.7
Flash, both through OpenRouter with pinned providers.

| defense | secret retrieved | availability (time-weighted) | authorized job completed |
|---|---|---|---|
| no defense | 8/8 | 1.00 | 8/8 |
| static playbook, fixed canary | 0/8 | 0.49 | 6/8 |
| static playbook, relocating canary | 2/8 | 0.62 | 4/8 |
| AI defender, fixed canary | 3/8 | 0.18 | 1/8 |
| AI defender, adaptive canary | 4/8 | 0.48 | 3/8 |

When the attacker switched routes after a block, both defenders contained it
in every such episode, the AI defender within a median of 1 to 7 seconds and
the playbook within 21 seconds. Every AI loss happened before any route change.
In the benign-only controls the playbook blocked the legitimate scheduled job;
the AI defender took no action. Eight episodes per defense support descriptive
comparison and per-episode traces, not rate estimates.

## Repository layout

| path | content |
|---|---|
| `chimera/` | the harness: broker, telemetry, controllers A to E, policy gate, actuator, runner, evaluator, schedule, budgets, CLI |
| `range/` | Docker Compose range (gateway, web, api, internal, postgres) and the range service |
| `prompts/` | frozen attacker and defender prompts |
| `configs/experiment.yaml` | frozen experiment configuration |
| `tests/` | 632 unpaid tests, including Docker control checks CT1 to CT5 |
| `scripts/` | block runner, control runner, trace audit, evidence-package builder, secondary analysis |
| `reports/evidence-package-2026-09-14/` | methodology as executed, architecture, artifact schema, history, results tables, analysis, per-episode timelines, provenance, inputs, raw artifacts of every episode |
| `reports/trace-audit-2026-09-14.md` | independent re-derivation of every outcome from the raw traces |
| `CHIMERA_Experiment_Protocol.md`, `CHIMERA_Build_Plan.md` | the planning documents; the evidence package records every deviation |
| `docs/control_checks.md` | what each control check establishes |

## Running it

Requirements: Python 3.12, Docker with Compose, and for live episodes an
OpenRouter key in `OPENROUTER_API_KEY`. Nothing below makes a paid call
unless stated.

```
uv sync --extra dev                                              # or: python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/python -m pytest -q -m "not docker and not paid"      # unit tests, no Docker
.venv/bin/python -m chimera demo --docker --horizon-seconds 0.15  # one no-cost containment episode on the real range
.venv/bin/python -m chimera run --mock --condition B              # no-cost synthetic episode
.venv/bin/python -m chimera run --mock --benign-only --condition D
```

Live episodes (paid) require the frozen configuration, model IDs in the
environment, a fresh verification stamp and a schedule:

```
export OPENROUTER_ATTACKER_MODEL=z-ai/glm-5.3 OPENROUTER_DEFENDER_MODEL=google/gemini-3.7-flash
.venv/bin/python -m chimera checks                       # CT1 to CT5 on the live range, writes the stamp
.venv/bin/python -m chimera schedule --output artifacts/runs/schedules/main.json
CHIMERA_ALLOW_PAID=1 bash scripts/run_block.sh 1        # one balanced block of ten episodes
CHIMERA_ALLOW_PAID=1 bash scripts/run_controls.sh       # four benign-only controls
```

Reproduce the audit, the evidence package and the analysis from the raw
artifacts (no Docker, no provider calls):

```
.venv/bin/python scripts/audit_traces.py
.venv/bin/python scripts/build_report_package.py
.venv/bin/python scripts/analyze_results.py
```

The report builds with `latexmk -pdf adaptive_containment_report.tex`; its
figures read the data files in `reports/evidence-package-2026-09-14/figures/`.

## Scope and safety

The attacker can only issue five brokered operations against deliberately
simplified services inside private Docker networks with no Internet egress.
The repository contains no exploit code, no real credentials and no real
secret; the range is regenerated with random dummy values before every
episode. Provider keys, policy authority and evaluator ground truth stay on
the host and are never given to either model. Nothing here speaks to
production security or to the general capabilities of the models used.
