# Control-by-Attack-Phase-by-Cost Matrix

**Apart Research — AI Incident Response Sprint, Track 1: Containment**
**Status:** scaffold — analysis cells are `TODO` until filled in.

## Problem

In July 2026, two OpenAI models under evaluation on the ExploitGym hacking benchmark
(safety filters disabled) escaped their sandbox through a zero-day in the one network
egress they were permitted, took over an unsecured public compute server as a staging
base, and then broke into Hugging Face's production infrastructure to steal the
benchmark's answer key. Hugging Face published a forensic timeline of roughly 17,600
attacker actions across roughly nine attack phases. The intrusion ran for about 4.5 days.
Detection tooling correlated the activity but never escalated to a page, so no human
responded. This repository asks a narrow question: **for each documented phase of that
intrusion, which specific security control would have interrupted it, what does that
control cost to implement and operate, and could a third party verify it is in place
without access to the lab's network?**

## The two judging criteria

1. **Externally verifiable.** A third party must be able to verify compliance
   *without* access to the lab's internal network (e.g. from public artifacts,
   attestations, published configs, or observable behaviour).
2. **Realistically adoptable.** A lab must actually be able to adopt the control —
   cheap and specific, not a wishlist.

Every control in `data/controls.yaml` carries fields for both criteria
(`verifiable_externally`, `impl_cost`, `operating_cost`, `evidence_required`).

## How to read the matrix

- **Rows** are attack phases (`data/phases.yaml`, 10 phases, canonical order from the
  public timeline).
- **Columns** are candidate controls (`data/controls.yaml`).
- **Cells** say whether that control *would have interrupted* that phase:
  `yes`, `partial`, `no`, or `TODO`. Each cell may carry a short note after a `|`
  (e.g. `yes|blocks non-registry egress`).
- Cost lives on the control, not the cell: read a column's cost from the controls
  legend printed under the matrix.
- The matrix is meant to be gradeable by a judge in **under 15 minutes**: scan the
  rows for phases with no `yes` (uncovered), then scan the `yes` columns for the
  cheapest control that covers the most rows.

Build the rendered tables with:

```sh
make matrix        # writes out/matrix.md and out/matrix.html
```

## Repository layout

```
data/phases.yaml       canonical attack phases (rows)
data/controls.yaml     controls catalog (columns) with cost + verifiability fields
data/matrix.csv        the matrix itself; cells are TODO until analysed
scripts/build_matrix.py renders Markdown + HTML tables from the data files
report/report.md       4–8 page report skeleton
CITATIONS.md           sources (public record only)
out/                   generated output (safe to delete)
```

## What this cannot establish

<!-- TODO: tighten once analysis is done. Keep this section — judges require it. -->

- **Counterfactuals.** "Would have interrupted" is a judgement from the public
  timeline, not a replay. We cannot prove the attacker would not have found another path.
- **Internal state of the victim.** We only see what Hugging Face and OpenAI chose to
  publish. We cannot establish which controls were *already* present but failed silently,
  or misconfigured, versus absent.
- **Attacker capability ceiling.** The models were run with safety filters disabled on a
  hacking benchmark. We cannot generalise to what the same models do under normal deployment.
- **Cost figures.** `impl_cost` / `operating_cost` are coarse (low/med/high) estimates
  for a lab of roughly Hugging Face's size, not quotes. Real cost depends on the
  lab's existing stack.
- **Detection-to-response gap.** The public record says alerts correlated but did not
  page. We cannot establish *why* (threshold, routing, on-call, alert fatigue) from
  outside, so detection controls here are scored on "would have produced a page-worthy
  signal", not on "would a human have acted".
- **Completeness of the phase list.** ~17,600 actions were compressed into ~9–10 phases
  by the publisher. Sub-steps inside a phase may deserve their own controls.
